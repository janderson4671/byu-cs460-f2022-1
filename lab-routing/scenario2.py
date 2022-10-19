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
        sys_cmd_pid(['set_iptables_drop', intf], check=True)

    def schedule_items(self):
        pass

class SimHost1(SimHost):
    def schedule_items(self):
        loop = asyncio.get_event_loop()
        loop.call_later(3, self.log, 'START')
        loop.call_later(6, self.drop_link, 'r1-r5')
        loop.call_later(15, self.log, 'STOP')

class SimHost2(SimHost):
    def schedule_items(self):
        loop = asyncio.get_event_loop()
        loop.call_later(4, self.send_icmp_echo, 'r5')
        loop.call_later(5, self.send_icmp_echo, 'r4')
        loop.call_later(12, self.send_icmp_echo, 'r5')
        loop.call_later(13, self.send_icmp_echo, 'r4')

class SimHost5(SimHost):
    def schedule_items(self,):
        loop = asyncio.get_event_loop()
        loop.call_later(6, self.drop_link, 'r5-r1')

def main():
    hostname = socket.gethostname()
    if hostname == 'r1':
        cls = SimHost1
    elif hostname == 'r2':
        cls = SimHost2
    elif hostname == 'r5':
        cls = SimHost5
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
