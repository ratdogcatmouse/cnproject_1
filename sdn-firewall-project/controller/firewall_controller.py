"""D1 prototype: Ryu/OpenFlow 1.3 TCP firewall with socket event integration.

The controller learns MAC addresses, permits application TCP on port 5000,
rejects other TCP destinations, and records decisions in a TCP event logger.
A TCP APP_VIOLATION report from the application server installs a host block.
Automatic recovery, attack thresholds, and performance work are D2 scope.
"""
import json
import socket
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, in_proto, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

MGMT_IP = "10.0.0.100"
SERVER_IP = "10.0.0.2"
APP_PORT = 5000
LOGGER_ADDR = ("127.0.0.1", 5514)
CONTROL_PORT = 9999

PRIO_L2, PRIO_ALLOW, PRIO_DENY, PRIO_BLOCK = 10, 100, 150, 200


def classify(src, dst, sport, dport):
    """Demo TCP policy: management + application port allowed; others denied."""
    if src == MGMT_IP or dst == MGMT_IP:
        return "ALLOW"
    if src == SERVER_IP and sport == APP_PORT:
        return "ALLOW"
    if dst == SERVER_IP and dport == APP_PORT:
        return "ALLOW"
    return "DENY"


class D1Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.blocked = set()
        server = hub.StreamServer(("0.0.0.0", CONTROL_PORT), self._control_handler)
        hub.spawn(server.serve_forever)
        self.logger.info("D1 firewall running; app reports accepted on TCP %d", CONTROL_PORT)

    def log_event(self, event, **details):
        record = {"ts": datetime.now().isoformat(timespec="milliseconds"),
                  "source": "controller", "event": event, **details}
        self.logger.info("%s %s", event, details)
        hub.spawn(self._send_log, record)

    def _send_log(self, record):
        try:
            with socket.create_connection(LOGGER_ADDR, timeout=1) as conn:
                conn.sendall((json.dumps(record) + "\n").encode())
        except OSError:
            self.logger.warning("logger unavailable for %s", record["event"])

    def _add_flow(self, dp, priority, match, actions, idle=0):
        parser, proto = dp.ofproto_parser, dp.ofproto
        instructions = ([parser.OFPInstructionActions(proto.OFPIT_APPLY_ACTIONS, actions)]
                        if actions else [])
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=instructions, idle_timeout=idle))

    def _packet_out(self, dp, msg, in_port, out_port):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER, in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)], data=msg.data))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_ready(self, ev):
        dp = ev.msg.datapath
        parser, proto = dp.ofproto_parser, dp.ofproto
        self.datapaths[dp.id] = dp
        self.mac_to_port[dp.id] = {}
        # Each new switch/table starts with an empty block state for the demo.
        self.blocked.clear()
        self._add_flow(dp, 0, parser.OFPMatch(),
                       [parser.OFPActionOutput(proto.OFPP_CONTROLLER,
                                               proto.OFPCML_NO_BUFFER)])
        self.log_event("SWITCH_CONNECTED", dpid=dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser, proto = dp.ofproto_parser, dp.ofproto
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, proto.OFPP_FLOOD)
        ip = pkt.get_protocol(ipv4.ipv4)
        segment = pkt.get_protocol(tcp.tcp)

        if ip and segment:
            src, dst = ip.src, ip.dst
            if src in self.blocked:
                return
            rule = dict(eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=in_proto.IPPROTO_TCP, ipv4_src=src,
                        ipv4_dst=dst, tcp_src=segment.src_port,
                        tcp_dst=segment.dst_port)
            decision = classify(src, dst, segment.src_port, segment.dst_port)
            if decision == "DENY":
                self._add_flow(dp, PRIO_DENY, parser.OFPMatch(**rule), [], idle=5)
                self.log_event("DENY", src=src, dst=dst, dport=segment.dst_port)
                return

            if out_port != proto.OFPP_FLOOD:
                self._add_flow(dp, PRIO_ALLOW, parser.OFPMatch(**rule),
                               [parser.OFPActionOutput(out_port)], idle=30)
            reverse = dict(eth_type=ether_types.ETH_TYPE_IP,
                           ip_proto=in_proto.IPPROTO_TCP, ipv4_src=dst,
                           ipv4_dst=src, tcp_src=segment.dst_port,
                           tcp_dst=segment.src_port)
            self._add_flow(dp, PRIO_ALLOW, parser.OFPMatch(**reverse),
                           [parser.OFPActionOutput(in_port)], idle=30)
            self._packet_out(dp, msg, in_port, out_port)
            if MGMT_IP not in (src, dst) and segment.bits & tcp.TCP_SYN:
                self.log_event("ALLOW", src=src, dst=dst, dport=segment.dst_port)
            return

        # Forward ARP/ICMP for basic topology tests. Do not cache generic IP
        # layer-2 flows: they could bypass the TCP firewall rules.
        if out_port != proto.OFPP_FLOOD and (
                eth.ethertype == ether_types.ETH_TYPE_ARP or
                (ip is not None and ip.proto == in_proto.IPPROTO_ICMP)):
            fields = dict(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst,
                          eth_type=eth.ethertype)
            if ip is not None:
                fields["ip_proto"] = in_proto.IPPROTO_ICMP
            self._add_flow(dp, PRIO_L2, parser.OFPMatch(**fields),
                           [parser.OFPActionOutput(out_port)], idle=20)
        self._packet_out(dp, msg, in_port, out_port)

    def _block(self, src):
        if src in (SERVER_IP, MGMT_IP) or src in self.blocked or not self.datapaths:
            return
        self.blocked.add(src)
        for dp in self.datapaths.values():
            match = dp.ofproto_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
            self._add_flow(dp, PRIO_BLOCK, match, [])
        self.log_event("BLOCK", src=src, reason="application protocol violation")

    def _control_handler(self, sock, addr):
        data = b""
        try:
            while len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            try:
                report = json.loads(data.split(b"\n", 1)[0].decode())
            except (ValueError, UnicodeDecodeError):
                return
            if report.get("event") == "APP_VIOLATION" and report.get("src"):
                src = report["src"]
                self.log_event("APP_VIOLATION", src=src,
                               reason=report.get("reason", ""))
                self._block(src)
        except OSError:
            pass
        finally:
            sock.close()
