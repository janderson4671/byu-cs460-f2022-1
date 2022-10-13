#!/usr/bin/python3

import asyncio
import socket
import subprocess
import traceback

from scapy.all import Ether, IP
from scapy.data import IP_PROTOS 
from scapy.layers.inet import ETH_P_IP

from cougarnet.sim.sys_cmd import sys_cmd_pid

from dvrouter import DVRouter

class SimHost(DVRouter):
    def _handle_frame(self, frame, intf):
        try:
            eth = Ether(frame)
            if eth.type == ETH_P_IP:
                ip = eth.getlayer(IP)
                if ip.proto == IP_PROTOS.icmp:
                    self.log(f'Received ICMP packet from {ip.src} on {intf}.')
        except:
            traceback.print_exc()

    def send_icmp_echo(self, dst):
        cmd = ['ping', '-W', '1', '-c', '1', dst]
        self.log(f'Sending ICMP packet to {dst}')
        subprocess.run(cmd)

    def drop_link(self, intf):
        self.log(f'Dropping link {intf}')
        sys_cmd_pid(['set_iptables_drop', intf])

    def schedule_items(self):
        pass

class SimHost2(SimHost):
    def schedule_items(self):
        loop = asyncio.get_event_loop()
        loop.call_later(10, self.drop_link, 'r2-r8')

class SimHost8(SimHost):
    def schedule_items(self):
        loop = asyncio.get_event_loop()
        loop.call_later(10, self.drop_link, 'r8-r2')

class SimHost9(SimHost):
    def schedule_items(self):
        loop = asyncio.get_event_loop()
        loop.call_later(4, self.send_icmp_echo, 'r10')
        loop.call_later(5, self.send_icmp_echo, 'r11')
        loop.call_later(6, self.send_icmp_echo, 'r12')
        loop.call_later(7, self.send_icmp_echo, 'r13')
        loop.call_later(8, self.send_icmp_echo, 'r14')

class SimHost7(SimHost):
    def schedule_items(self):
        loop = asyncio.get_event_loop()
        loop.call_later(9, self.send_icmp_echo, 'r15')
        loop.call_later(18, self.send_icmp_echo, 'r15')

def main():
    hostname = socket.gethostname()
    if hostname == 'r2':
        cls = SimHost2
    elif hostname == 'r7':
        cls = SimHost7
    elif hostname == 'r8':
        cls = SimHost8
    elif hostname == 'r9':
        cls = SimHost9
    else:
        cls = SimHost

    with cls() as router:
        router.init_dv()
        router.schedule_items()

        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()
