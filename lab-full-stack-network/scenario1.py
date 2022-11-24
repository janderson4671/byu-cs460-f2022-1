#!/usr/bin/python3

import argparse
import asyncio
import os
import socket
import sys
import traceback

from scapy.all import IP, ICMP
from scapy.data import IP_PROTOS 

from host import BaseHost

class SimHost(BaseHost):
    def __init__(self, *args, **kwargs):
        super(SimHost, self).__init__(*args, **kwargs)

    def handle_ip(self, pkt, intf):
        try:
            ip = IP(pkt)
            if ip.proto == IP_PROTOS.icmp:
                self.log(f'Received ICMP packet {ip.src} -> {ip.dst} on {intf}.')
        except:
            traceback.print_exc()
        super(SimHost, self).handle_ip(pkt, intf)

    def not_my_packet(self, pkt, intf):
        try:
            ip = IP(pkt)
            if ip.proto == IP_PROTOS.icmp:
                self.log(f'ICMP packet not for me {ip.src} -> {ip.dst}.')
        except:
            traceback.print_exc()
        super(SimHost, self).not_my_packet(pkt, intf)

    def send_icmp_echo(self, src, dst, id, seq, ttl=None):
        ip = IP(src=src, dst=dst, proto=IP_PROTOS.icmp)
        if ttl is not None:
            ip.ttl = ttl
        icmp = ICMP(type=8, id=id, seq=seq)
        pkt = ip / icmp / b'0123456789'

        self.send_packet(bytes(pkt))

    def schedule_items(self):
        pass

class SimHostA(SimHost):
    def schedule_items(self):
        args = ('10.0.0.2', '10.0.0.255', 1, 1, 1)

        loop = asyncio.get_event_loop()
        loop.call_later(4, self.send_icmp_echo, *args)
        

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    hostname = socket.gethostname()
    if hostname == 'a':
        cls = SimHostA
    else:
        cls = SimHost

    with cls(args.router) as host:
        host.schedule_items()

        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()
