"""Ryu / OpenFlow 1.3 dynamic firewall with a centralized security-event logger.

Static layer   rules in policy.json, matched on (src IP, dst IP, dst port),
               first match wins -> OpenFlow ALLOW (forward) or DENY (drop) flow.
Dynamic layer  (mode "dynamic") watches new TCP flows reaching the controller:
                 PORT_SCAN      >= scan_ports distinct denied ports in scan_window s
                 CONN_FLOOD     >= flood_conns new allowed flows in flood_window s
                 APP_VIOLATION  reported by the application server over TCP
               and installs a priority-200 drop rule for the source with a hard
               timeout (block_seconds, doubled per repeat offence, <= block_max).
Recovery       the switch deletes the block rule at timeout and sends FlowRemoved;
               the controller logs UNBLOCK.  Mode "static" never blocks (baseline).

Control channel, TCP 9999, one JSON line in -> one JSON line out:
  {"event": "APP_VIOLATION", "src": ip, ...}        accepted only from the app server
  {"cmd": "STATUS" | "RESET" | "MODE" | "UNBLOCK"}  accepted only from localhost
"""
import ipaddress
import json
import os
import socket
import time
from collections import defaultdict, deque
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, in_proto, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

POLICY_FILE = os.environ.get(
    "FW_POLICY", os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.json"))
LOGGER_ADDR = ("127.0.0.1", 5514)
CONTROL_PORT = 9999
PRIO_L2, PRIO_ALLOW, PRIO_DENY, PRIO_BLOCK = 10, 100, 150, 200
COOKIE_FLOW, COOKIE_BLOCK = 1, 2
ALL_BITS = 0xFFFFFFFFFFFFFFFF
MGMT_PORTS = {CONTROL_PORT, LOGGER_ADDR[1]}   # the only services hosts may use on the mgmt IP
CONTROL_MAX_CONNS = 32
CONTROL_TIMEOUT = 5


def valid_ipv4(value):
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def rule_matches(rule, src, dst, dport):
    return (rule.get("src", "*") in ("*", src) and
            rule.get("dst", "*") in ("*", dst) and
            rule.get("dport", "*") in ("*", dport))


class DynamicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        with open(POLICY_FILE) as f:
            self.policy = json.load(f)
        self.mgmt = self.policy["management_ip"]
        self.never_block = set(self.policy.get("never_block", []))
        self.det = self.policy["detection"]
        self.mode = self.policy.get("mode", "dynamic")
        self.mac_to_port = {}
        self.datapaths = {}
        self.control_conns = 0
        self._reset_state()
        self.log_queue = hub.Queue()
        hub.spawn(self._log_sender)
        hub.spawn(hub.StreamServer(("0.0.0.0", CONTROL_PORT),
                                   self._control_handler).serve_forever)
        self.logger.info("firewall up: mode=%s policy=%s control=TCP %d",
                         self.mode, POLICY_FILE, CONTROL_PORT)

    def _reset_state(self):
        self.blocked = {}                       # src -> block expiry (epoch)
        self.offences = defaultdict(int)        # src -> number of blocks so far
        self.new_flows = defaultdict(deque)     # src -> times of new allowed flows
        self.denied_ports = defaultdict(dict)   # src -> {denied dport: last time}
        self.history = []                       # block records (STATUS / benchmark)

    # ---------------------------------------------------------------- logging
    def log_event(self, event, **details):
        record = {"ts": datetime.now().isoformat(timespec="milliseconds"),
                  "epoch": round(time.time(), 6), "source": "controller",
                  "event": event, **details}
        self.logger.info("%s %s", event, details)
        self.log_queue.put(record)

    def _log_sender(self):
        """One persistent TCP connection to the central logger."""
        conn = None
        while True:
            record = self.log_queue.get()
            line = (json.dumps(record) + "\n").encode()
            for _ in range(2):
                try:
                    if conn is None:
                        conn = socket.create_connection(LOGGER_ADDR, timeout=1)
                    conn.sendall(line)
                    break
                except OSError:
                    if conn is not None:
                        conn.close()
                    conn = None
            else:
                self.logger.warning("logger unavailable; dropped %s", record["event"])

    # ------------------------------------------------------------ flow helpers
    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0,
                  cookie=COOKIE_FLOW, notify=False):
        parser, proto = dp.ofproto_parser, dp.ofproto
        inst = ([parser.OFPInstructionActions(proto.OFPIT_APPLY_ACTIONS, actions)]
                if actions else [])
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, cookie=cookie, priority=priority, match=match,
            instructions=inst, idle_timeout=idle, hard_timeout=hard,
            flags=proto.OFPFF_SEND_FLOW_REM if notify else 0))

    def _delete_flows(self, dp, cookie, match=None):
        parser, proto = dp.ofproto_parser, dp.ofproto
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, cookie=cookie, cookie_mask=ALL_BITS, table_id=proto.OFPTT_ALL,
            command=proto.OFPFC_DELETE, out_port=proto.OFPP_ANY,
            out_group=proto.OFPG_ANY, match=match or parser.OFPMatch()))

    def _packet_out(self, dp, msg, in_port, out_port):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER, in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)], data=msg.data))

    # ------------------------------------------------------------ policy
    def _lookup(self, src, dst, dport):
        for rule in self.policy["rules"]:
            if rule_matches(rule, src, dst, dport):
                return rule["action"].upper(), rule.get("name", "")
        return self.policy.get("default", "deny").upper(), "default"

    def classify(self, src, dst, sport, dport, syn):
        """Return (ALLOW|DENY, rule name) for one TCP packet."""
        # Management IP: only the control channel and logger ports, in either
        # direction (requests to them, replies from them).  Anything else to or
        # from the management IP falls through to the normal policy.
        if (dst == self.mgmt and dport in MGMT_PORTS) or (src == self.mgmt and sport in MGMT_PORTS):
            return "ALLOW", "management"
        verdict = self._lookup(src, dst, dport)
        # A non-SYN packet may be the reply of a connection the policy allows.
        if verdict[0] == "DENY" and not syn and self._lookup(dst, src, sport)[0] == "ALLOW":
            return "ALLOW", "reply"
        return verdict

    def _is_blocked(self, src):
        expiry = self.blocked.get(src)
        if expiry is None:
            return False
        if time.time() < expiry + 2:        # FlowRemoved normally clears it first
            return True
        del self.blocked[src]
        return False

    # ------------------------------------------------------------ OpenFlow events
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_ready(self, ev):
        dp = ev.msg.datapath
        parser, proto = dp.ofproto_parser, dp.ofproto
        self.datapaths[dp.id] = dp
        self.mac_to_port[dp.id] = {}
        self._reset_state()                 # a new switch starts with no blocks
        self._add_flow(dp, 0, parser.OFPMatch(),
                       [parser.OFPActionOutput(proto.OFPP_CONTROLLER,
                                               proto.OFPCML_NO_BUFFER)], cookie=0)
        self.log_event("SWITCH_CONNECTED", dpid=dp.id, mode=self.mode)

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
        seg = pkt.get_protocol(tcp.tcp)

        if ip and seg:
            self._handle_tcp(dp, msg, in_port, out_port, ip.src, ip.dst, seg)
            return

        # ARP / ICMP are forwarded for connectivity.  Generic IP L2 flows are
        # not cached because they could bypass the TCP firewall rules.
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

    def _handle_tcp(self, dp, msg, in_port, out_port, src, dst, seg):
        parser, proto = dp.ofproto_parser, dp.ofproto
        if self._is_blocked(src):
            return
        syn = bool(seg.bits & tcp.TCP_SYN) and not seg.bits & tcp.TCP_ACK
        decision, rule = self.classify(src, dst, seg.src_port, seg.dst_port, syn)
        fwd = dict(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                   ipv4_src=src, ipv4_dst=dst, tcp_src=seg.src_port, tcp_dst=seg.dst_port)

        if decision == "DENY":
            self._add_flow(dp, PRIO_DENY, parser.OFPMatch(**fwd), [], idle=5)
            self.log_event("DENY", src=src, dst=dst, dport=seg.dst_port, rule=rule)
            if syn:
                self._watch_scan(src, seg.dst_port)
            return

        if out_port != proto.OFPP_FLOOD:
            self._add_flow(dp, PRIO_ALLOW, parser.OFPMatch(**fwd),
                           [parser.OFPActionOutput(out_port)], idle=30)
        rev = dict(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP,
                   ipv4_src=dst, ipv4_dst=src, tcp_src=seg.dst_port, tcp_dst=seg.src_port)
        self._add_flow(dp, PRIO_ALLOW, parser.OFPMatch(**rev),
                       [parser.OFPActionOutput(in_port)], idle=30)
        self._packet_out(dp, msg, in_port, out_port)
        if syn and rule != "management":
            self.log_event("ALLOW", src=src, dst=dst, dport=seg.dst_port, rule=rule)
            self._watch_flood(src)
        elif syn and dst == self.mgmt:
            self._watch_flood(src)          # hosts must not flood the control/log ports

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, ev):
        msg = ev.msg
        if msg.cookie != COOKIE_BLOCK:
            return
        proto = msg.datapath.ofproto
        src = msg.match.get("ipv4_src")
        self.blocked.pop(src, None)
        reason = {proto.OFPRR_HARD_TIMEOUT: "timeout",
                  proto.OFPRR_DELETE: "removed"}.get(msg.reason, str(msg.reason))
        self.log_event("UNBLOCK", src=src, reason=reason,
                       blocked_for=round(msg.duration_sec + msg.duration_nsec / 1e9, 3))

    # ------------------------------------------------------------ detection
    def _watch_scan(self, src, dport):
        if self.mode != "dynamic" or src in self.never_block:
            return
        now = time.time()
        ports = self.denied_ports[src]
        ports[dport] = now
        for port in [p for p, t in ports.items() if now - t > self.det["scan_window"]]:
            del ports[port]
        if len(ports) >= self.det["scan_ports"]:
            first, count = min(ports.values()), len(ports)
            ports.clear()
            self._block(src, "PORT_SCAN",
                        "%d denied ports in %.2fs" % (count, now - first), first)

    def _watch_flood(self, src):
        if self.mode != "dynamic" or src in self.never_block:
            return
        now = time.time()
        times = self.new_flows[src]
        times.append(now)
        while times and now - times[0] > self.det["flood_window"]:
            times.popleft()
        if len(times) >= self.det["flood_conns"]:
            first, count = times[0], len(times)
            times.clear()
            self._block(src, "CONN_FLOOD",
                        "%d new connections in %.2fs" % (count, now - first), first)

    def _block(self, src, reason, detail, first_seen=None):
        if src in self.never_block or self._is_blocked(src) or not self.datapaths:
            return
        self.offences[src] += 1
        offence = self.offences[src]
        seconds = min(self.det["block_seconds"] * 2 ** (offence - 1), self.det["block_max"])
        now = time.time()
        self.blocked[src] = now + seconds
        for dp in self.datapaths.values():
            match = dp.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
            self._add_flow(dp, PRIO_BLOCK, match, [], hard=seconds,
                           cookie=COOKIE_BLOCK, notify=True)
        record = {"src": src, "reason": reason, "detail": detail, "seconds": seconds,
                  "offence": offence, "blocked_at": now, "first_seen": first_seen}
        self.history.append(record)
        self.log_event("BLOCK", **record)

    # ------------------------------------------------------------ control channel
    def _control_handler(self, sock, addr):
        if self.control_conns >= CONTROL_MAX_CONNS:
            sock.close()
            return
        self.control_conns += 1
        data = b""
        try:
            sock.settimeout(CONTROL_TIMEOUT)
            while b"\n" not in data and len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            try:
                req = json.loads(data.split(b"\n", 1)[0].decode())
                reply = self._handle_request(req, addr[0])
            except (ValueError, UnicodeDecodeError, AttributeError):
                reply = {"ok": False, "error": "bad request"}
            except Exception as exc:        # never let one bad request kill the handler
                self.logger.exception("control request failed")
                reply = {"ok": False, "error": "internal error: %s" % type(exc).__name__}
            sock.sendall((json.dumps(reply) + "\n").encode())
        except OSError:
            pass
        finally:
            self.control_conns -= 1
            sock.close()

    def _handle_request(self, req, peer):
        if req.get("event") == "APP_VIOLATION":
            src = req.get("src")
            if peer not in (self.policy["server_ip"], "127.0.0.1"):
                self.log_event("REJECTED_REPORT", peer=peer, claimed_src=str(src)[:64])
                return {"ok": False, "error": "reports accepted only from the app server"}
            if not valid_ipv4(src):
                return {"ok": False, "error": "src must be an IPv4 address"}
            self.log_event("APP_VIOLATION", src=src, reason=req.get("reason", ""),
                           reported_at=req.get("epoch"), mode=self.mode)
            if self.mode == "dynamic":
                self._block(src, "APP_VIOLATION", req.get("reason", ""), req.get("epoch"))
            return {"ok": True, "blocked": self._is_blocked(src)}

        cmd = str(req.get("cmd", "")).upper()
        if peer != "127.0.0.1":
            self.log_event("REJECTED_COMMAND", peer=peer, cmd=cmd)
            return {"ok": False, "error": "admin commands only from localhost"}
        if cmd == "MODE":
            if req.get("mode") not in ("static", "dynamic"):
                return {"ok": False, "error": "mode must be static or dynamic"}
            self.mode = req["mode"]
            self.log_event("MODE_CHANGE", mode=self.mode)
        elif cmd == "RESET":
            for dp in self.datapaths.values():
                self._delete_flows(dp, COOKIE_FLOW)
                self._delete_flows(dp, COOKIE_BLOCK)
            self._reset_state()
            self.log_event("RESET", mode=self.mode)
        elif cmd == "UNBLOCK":
            src = req.get("src")
            if not valid_ipv4(src):
                return {"ok": False, "error": "unblock needs a valid IPv4 src"}
            for dp in self.datapaths.values():
                self._delete_flows(dp, COOKIE_BLOCK, dp.ofproto_parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src))
            self.blocked.pop(src, None)
        elif cmd != "STATUS":
            return {"ok": False, "error": "unknown command"}
        now = time.time()
        return {"ok": True, "mode": self.mode,
                "blocked": {ip: round(exp - now, 1) for ip, exp in self.blocked.items()},
                "offences": dict(self.offences), "history": self.history}
