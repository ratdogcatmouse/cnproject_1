#!/usr/bin/env python3
"""Mininet topology: 1 OVS switch (OpenFlow 1.3), remote Ryu controller.

   h1 10.0.0.1  client          h3 10.0.0.3  client
   h2 10.0.0.2  app server      h4 10.0.0.4  client / attacker
   ctl0 10.0.0.100 management port in the root namespace
        (controller control channel :9999 + security logger :5514)

Usage: sudo python3 topology/topo.py      (opens the Mininet CLI)
"""
import subprocess

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.link import Link

MGMT_IP = "10.0.0.100"


def create_network():
    net = Mininet(controller=None, switch=OVSKernelSwitch, link=Link, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    for i in range(1, 5):
        h = net.addHost("h%d" % i, ip="10.0.0.%d/24" % i)
        net.addLink(h, s1)
    net.start()
    # management port so hosts can reach the controller/logger running in the root ns
    subprocess.call("ovs-vsctl --may-exist add-port s1 ctl0 -- set interface ctl0 type=internal",
                    shell=True)
    subprocess.call("ip addr flush dev ctl0; ip addr add %s/24 dev ctl0; ip link set ctl0 up" % MGMT_IP,
                    shell=True)
    return net


if __name__ == "__main__":
    setLogLevel("info")
    network = create_network()
    CLI(network)
    network.stop()
