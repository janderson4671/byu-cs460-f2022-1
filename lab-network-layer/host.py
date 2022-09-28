#!/usr/bin/python3

import argparse
import asyncio
import os
import socket
import sys

from cougarnet.sim.host import BaseHost
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

from forwarding_table import ForwardingTable

#From /usr/include/linux/if_ether.h:
ETH_P_IP = 0x0800 # Internet Protocol packet
ETH_P_ARP = 0x0806 # Address Resolution packet

#From /usr/include/net/if_arp.h:
ARPHRD_ETHER = 1 # Ethernet 10Mbps
ARPOP_REQUEST = 1 # ARP request
ARPOP_REPLY = 2 # ARP reply

#From /usr/include/linux/in.h:
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class Host(BaseHost):
    def __init__(self, ip_forward):
        super(Host, self).__init__()

        self._ip_forward = ip_forward

        # do any additional initialization here

    def _handle_frame(self, frame, intf):
        pass

    def handle_ip(self, pkt, intf):
        pass

    def handle_tcp(self, pkt):
        pass

    def handle_udp(self, pkt):
        pass

    def handle_arp(self, pkt, intf):
        pass

    def handle_arp_response(self, pkt, intf):
        pass

    def handle_arp_request(self, pkt, intf):
        pass

    def send_packet_on_int(self, pkt, intf, next_hop):
        print(f'Attempting to send packet on {intf} with next hop {next_hop}:\n{repr(pkt)}')

    def send_packet(self, pkt):
        print(f'Attempting to send packet:\n{repr(pkt)}')

    def forward_packet(self, pkt):
        pass

    def not_my_frame(self, frame, intf):
        pass

    def not_my_packet(self, pkt, intf):
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    with Host(args.router) as host:
        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()
