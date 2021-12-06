#!/usr/bin/env python3

import json
import socket

NEIGHBOR_CHECK_INTERVAL = 3
DV_TABLE_SEND_INTERVAL = 1
DV_PORT = 5016

from cougarnet.networksched import NetworkEventLoop

from mysocket import UDPSocket
from transporthost import TransportHost

class DVRouter(TransportHost):
    def __init__(self):
        super(DVRouter, self).__init__(True)

        self.my_dv = {}
        self.neighbor_dvs = {}

        # Forwarding table is initialized in Host.__init__();
        # Host is an ancestor class that handles IP Forwarding

        self._initialize_dv_sock()

        self.event_loop = None

        # Do any further initialization here

    def _initialize_dv_sock(self):
        '''
        Initialize the socket that will be used for sending and receiving DV
        communications to and from neighbors.
        '''

        any_intf = self.get_first_interface()
        self.sock = UDPSocket(
                self.int_to_info[any_intf].ipv4addrs[0],
                DV_PORT,
                self.send_packet, self._handle_msg)
        for intf in self.int_to_info:
            self.install_socket_udp(
                    self.int_to_info[intf].ipv4addrs[0],
                    DV_PORT, self.sock)
            self.install_socket_udp(
                    self.int_to_info[intf].ipv4broadcast,
                    DV_PORT, self.sock)

    def init_dv(self, event_loop):
        '''
        Set up our instance to work with the event loop, initialize our DV, and
        schedule our regular updates to be sent to neighbors.
        '''

        # assign event_loop variable, so we can use it to schedule
        self.event_loop = event_loop

        # Initialize our DV -- and optionally send our DV to our neighbors
        self.update_dv()

        # Schedule self.send_dv_next() to be called every second
        # (DV_TABLE_SEND_INTERVAL)
        self.event_loop.schedule_event(DV_TABLE_SEND_INTERVAL, self.send_dv_next)

    def _handle_msg(self):
        '''
        Receive and handle a message received on the UDP socket that is being
        used for DV messages.
        '''

        data, addr, port = self.sock.recvfrom()
        return self.handle_dv_message(data)

    def _send_msg(self, msg, dst):
        '''
        Send a DV message, msg, on our UDP socket to dst.
        '''

        self.sock.sendto(msg, dst, DV_PORT)

    def handle_dv_message(self, msg):
        pass

    def send_dv_next(self):
        '''
        Send DV to neighbors, and schedule this method to be called again in 1
        second (DV_TABLE_SEND_INTERVAL).
        '''
        self.send_dv()
        self.event_loop.schedule_event(DV_TABLE_SEND_INTERVAL, self.send_dv_next)

    def handle_down_link(self, neighbor):
        self.log(f'Link down: {neighbor}')

    def resolve_neighbor_dvs(self):
        '''
        Return a copy of the mapping of neighbors to distance vectors, with IP
        addresses replaced by names in every neighbor DV.
        '''

        neighbor_dvs = {}
        for neighbor in self.neighbor_dvs:
            neighbor_dvs[neighbor] = self.resolve_dv(self.neighbor_dvs[neighbor])
        return neighbor_dvs

    def resolve_dv(self, dv):
        '''
        Return a copy of distance vector dv with IP addresses replaced by
        names.
        '''

        resolved_dv = {}
        for dst, distance in dv.items():
            if '/' not in dst:
                try:
                    dst = socket.getnameinfo((dst, 0), 0)[0]
                except:
                    pass
            resolved_dv[dst] = distance
        return resolved_dv

    def update_dv(self):
        pass

    def send_dv(self):
        print('Sending DV')


def main():
    hostname = socket.gethostname()

    router = DVRouter()
    event_loop = NetworkEventLoop(router._handle_frame)
    router.init_dv(event_loop)
    event_loop.run()

if __name__ == '__main__':
    main()
