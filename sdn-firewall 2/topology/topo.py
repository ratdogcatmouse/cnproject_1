#!/usr/bin/env python3
"""Mininet topology: 1 OVS switch (OpenFlow 1.3), remote Ryu controller.

   h1 10.0.0.1  client (also allowed on admin port 8080)
   h2 10.0.0.2  app server (:5000 app, :8080 admin, :23 decoy)
   h3 10.0.0.3  client
   h4 10.0.0.4  client / attacker
   h5 10.0.0.5  untrusted host (denied by a source rule)
   ctl0 10.0.0.100 management port in the root namespace
        (controller control channel :9999 + security logger :5514)

Usage: sudo python3 topology/topo.py [--bw MBIT]     (opens the Mininet CLI)
Set FW_DATAPATH=user if the Open vSwitch kernel module is unavailable.
"""
import argparse
import os
import subprocess
from functools import partial

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

MGMT_IP = "10.0.0.100"
HOSTS = 5


def create_network(bw=None, delay=None):
    """bw (Mbit/s) and delay (e.g. '2ms') shape every host link when given."""
    datapath = os.environ.get("FW_DATAPATH", "kernel")
    switch = partial(OVSSwitch, datapath=datapath)
    net = Mininet(controller=None, switch=switch, link=TCLink, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    shape = {k: v for k, v in (("bw", bw), ("delay", delay)) if v}
    for i in range(1, HOSTS + 1):
        net.addLink(net.addHost("h%d" % i, ip="10.0.0.%d/24" % i), s1, **shape)
    net.start()
    # management port so hosts can reach the controller/logger in the root namespace
    subprocess.call("ovs-vsctl --may-exist add-port s1 ctl0 -- set interface ctl0 type=internal",
                    shell=True)
    subprocess.call("ip addr flush dev ctl0; ip addr add %s/24 dev ctl0; ip link set ctl0 up"
                    % MGMT_IP, shell=True)
    if datapath == "user":
        # userspace OVS does not fill in offloaded TCP checksums on veth/tap ports
        for host in net.hosts:
            host.cmd("ethtool -K %s-eth0 tx off rx off" % host.name)
        subprocess.call("ethtool -K ctl0 tx off rx off >/dev/null 2>&1", shell=True)
    net.waitConnected()
    return net


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bw", type=float, help="link bandwidth in Mbit/s")
    ap.add_argument("--delay", help="link delay, e.g. 2ms")
    opts = ap.parse_args()
    setLogLevel("info")
    network = create_network(opts.bw, opts.delay)
    CLI(network)
    network.stop()
