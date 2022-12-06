#!/usr/bin/env python3

import asyncio
import json
import socket

NEIGHBOR_CHECK_INTERVAL = 3
DV_TABLE_SEND_INTERVAL = 1
DV_PORT = 5016

from cougarnet.sim.host import BaseHost

from prefix import *
from mysocket import UDPSocket
from transporthost import TransportHost

from forwarding_table import ForwardingTable

class DVRouter(TransportHost):
    def __init__(self):
        super().__init__(True)

        self.my_dv = self.create_dv()
        self.neighbor_dvs = {}
        self.neighbor_ips = {}

        self._dv_socks = {}

        # Forwarding table is initialized in Host.__init__();
        # Host is an ancestor class that handles IP Forwarding

        self._initialize_dv_sock()

        # Do any further initialization here

    def _initialize_dv_sock(self) -> None:
        '''Initialize the socket that will be used for sending and receiving DV
        communications to and from neighbors.
        '''

        for intf in self.physical_interfaces:
            sock = UDPSocket(
                    self.int_to_info[intf].ipv4_addrs[0],
                    DV_PORT,
                    self.send_packet, self._handle_msg)
            self._dv_socks[intf] = sock
            self.install_socket_udp(
                    self.int_to_info[intf].ipv4_addrs[0],
                    DV_PORT, sock)
            #XXX find a better way to accept packets
            self.install_socket_udp(
                    self.bcast_for_int(intf),
                    DV_PORT, sock)

    def init_dv(self):
        '''Set up our instance to work with the event loop, initialize our DV,
        and schedule our regular updates to be sent to neighbors.
        '''

        loop = asyncio.get_event_loop()

        # Schedule self.send_dv_next() to be called in 1 second and
        # self.update_dv_next() to be called in 0.5 seconds.
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)
        loop.call_later(DV_TABLE_SEND_INTERVAL - DV_TABLE_SEND_INTERVAL / 2,
                self.update_dv_next)

    def _handle_msg(self) -> None:
        ''' Receive and handle a message received on the UDP socket that is
        being used for DV messages.
        '''

        for intf in self._dv_socks:
            #XXX This check for non-zero buffer should go in recvfrom()
            if self._dv_socks[intf].buffer:
                data, addr, port = self._dv_socks[intf].recvfrom()
                self.handle_dv_message(data)

    def _send_msg(self, msg: bytes, dst: str) -> None:
        '''Send a DV message, msg, on our UDP socket to dst.'''

        #XXX We should probably use the correct socket in the future, but this
        # will work for now
        for intf in self._dv_socks:
            self._dv_socks[intf].sendto(msg, dst, DV_PORT)
            break

    def handle_dv_message(self, msg: bytes) -> None:
        print("I Got a DV!")
        # print(f"Message: {msg}")

        # Decode the message from the data
        obj_str = msg.decode("utf-8")
        obj = json.loads(obj_str)

        # Grab information from message and store it in associated dv table
        ip = obj["ip"]
        prefix = obj["prefix"]
        name = obj["name"]
        dv = obj["dv"]

        # Discard packet if it is from me
        if (name == self.hostname):
            return

        # Save neighbor IP as a prefix
        print(f"Neighbor IP: {ip}")
        self.neighbor_ips[name] = [ip, prefix]

        # Save neighbor DV
        self.neighbor_dvs[name] = dv

        # Update my DV
        self.update_dv()


    def send_dv_next(self):
        '''Send DV to neighbors, and schedule this method to be called again in
        1 second (DV_TABLE_SEND_INTERVAL).
        '''

        self.send_dv()
        loop = asyncio.get_event_loop()
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)

    def update_dv_next(self):
        '''Update DV using neighbors' DVs.  Then schedule this method to be
        called again in 1 second (DV_TABLE_SEND_INTERVAL).
        '''

        self.update_dv()
        loop = asyncio.get_event_loop()
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.update_dv_next)

    def handle_down_link(self, neighbor: str):
        self.log(f'Link down: {neighbor}')

    def resolve_neighbor_dvs(self):
        '''Return a copy of the mapping of neighbors to distance vectors, with
        IP addresses replaced by names in every neighbor DV.
        '''

        neighbor_dvs = {}
        for neighbor in self.neighbor_dvs:
            neighbor_dvs[neighbor] = self.resolve_dv(self.neighbor_dvs[neighbor])
        return neighbor_dvs

    def resolve_dv(self, dv: dict) -> dict:
        '''Return a copy of distance vector dv with IP addresses replaced by
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

    def update_forwarding_table(self):
        # Flush the table out
        self.forwarding_table = ForwardingTable()
        self.initialize_fowarding_table(self.forwarding_table)

        # print(f"Neighbor IPS: {self.neighbor_ips}")

        # Go through my dv and add next hops to prefixes
        for prefix in self.my_dv.keys():
            dv_entry = self.my_dv[prefix]

            if (dv_entry["next_hop"] == self.hostname):
                continue

            entry = self.neighbor_ips[dv_entry["next_hop"]]
            next_hop_prefix = entry[1]
            next_hop_ip = entry[0]
            # print(f"Update DV: {dv_entry}")

            # print(f"Update Next Hop: {next_hop_prefix}")

            interface = ""
            # Using next_hop, find interface that it will go out
            for intf in self.all_interfaces:
                if (intf == "lo"):
                    continue

                # print(f"Interface: {intf}")
                # print(f"ipv4 addrs: {self.int_to_info[intf].ipv4_addrs}")

                intf_prefix_len = self.int_to_info[intf].ipv4_prefix_len
                intf_prefix = ip_prefix(ip_str_to_int(self.int_to_info[intf].ipv4_addrs[0]), socket.AF_INET, intf_prefix_len)
                intf_prefix_str = ip_int_to_str(intf_prefix, socket.AF_INET) + f"/{intf_prefix_len}"

                # print(f"Next Hop: {next_hop_prefix}")
                # print(f"intf_prefix: {intf_prefix_str}")

                if (next_hop_prefix == intf_prefix_str):
                    interface = intf
                    break

            # Add entry
            print(f"Forwarding Table Entry: Prefix {prefix}, Intf: {interface}, Next {next_hop_ip}")
            self.forwarding_table.add_entry(prefix, interface, next_hop_ip)

        print(f"Updated Forwarding Table: {self.forwarding_table.entries}")


    def create_dv(self):
        dv = {}
        # Go through interfaces and create dv entries with 0 (Add /32 prefix)
        for intf in self.all_interfaces:
            if (intf == "lo"):
                continue

            # Get IP and convert to prefix
            ip_addr = self.int_to_info[intf].ipv4_addrs[0]
            prefix_len = self.int_to_info[intf].ipv4_prefix_len
            prefix = ip_prefix(ip_str_to_int(ip_addr), socket.AF_INET, prefix_len)
            prefix_str = ip_int_to_str(prefix, socket.AF_INET) + f"/{prefix_len}"

            # Initial distance is 0
            entry = {}
            entry["dist"] = 0
            entry["next_hop"] = self.hostname
            dv[prefix_str] = entry
            
        return dv

    # Prefix Map: Prefix ==> {distance: 0, hostname: r3}
    def populate_prefix_map(self, map, name):
        print(f"Name: {name}")
        neighbor_entry = self.neighbor_dvs[name]

        for prefix in neighbor_entry.keys():
            # If the prefix does not exist, then add it
            # If it does exist, then check if the distance is less than current
            #   stored value
            if (prefix not in map.keys()):
                entry = {}
                entry["dist"] = neighbor_entry[prefix]["dist"]
                entry["next_hop"] = name

                map[prefix] = entry
            else:
                if (neighbor_entry[prefix]["dist"] < map[prefix]["dist"]):
                    map[prefix]["dist"] = neighbor_entry[prefix]["dist"]
                    map[prefix]["next_hop"] = name

    def bellman_ford(self):
        # Start from scratch
        dv = self.create_dv()
        prefix_map = {}

        # Go through each of immediate neighbors dv's and perform algorithm
        # print(f"Neighbors: {self.neighbor_dvs}")

        for name in self.neighbor_dvs.keys():
            self.populate_prefix_map(prefix_map, name)

        # Go through each entry in prefix map and add 1 to all entries (this adds my cost to get there)
        for prefix in prefix_map.keys():
            distance = prefix_map[prefix]["dist"]
            prefix_map[prefix]["dist"] = distance + 1

        # Add default dv stuff into map
        for key in dv.keys():
            entry = {}
            entry["dist"] = dv[key]["dist"]
            entry["next_hop"] = self.hostname
            # Potential Bug!!
            prefix_map[key] = entry
        
        return prefix_map

    def update_dv(self) -> None:
        # print("Updating my DV!")
        # copy my own dv
        dv = self.my_dv.copy()

        print(f"My DV: {self.my_dv}")

        new_dv = self.bellman_ford()

        # if the new_dv is different than the original then broadcast dv out
        if (dv != new_dv):
            print(f"New DV: {new_dv}")
            # Update forwarding table
            self.my_dv = new_dv
            self.update_forwarding_table()

            print("We have a new DV! We will broadcast it out!")

            self.send_dv()

    def bcast_for_int(self, intf: str) -> str:
        ip_int = ip_str_to_int(self.int_to_info[intf].ipv4_addrs[0])
        ip_prefix_int = ip_prefix(ip_int, socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        ip_bcast_int = ip_prefix_last_address(ip_prefix_int, socket.AF_INET, self.int_to_info[intf].ipv4_prefix_len)
        bcast = ip_int_to_str(ip_bcast_int, socket.AF_INET)
        return bcast

    def create_dv_message(self, intf):
        msg = {}

        # Create IP prefix
        ip_addr = self.int_to_info[intf].ipv4_addrs[0]
        prefix_len = self.int_to_info[intf].ipv4_prefix_len
        prefix = ip_prefix(ip_str_to_int(ip_addr), socket.AF_INET, prefix_len)
        prefix_str = ip_int_to_str(prefix, socket.AF_INET) + f"/{prefix_len}"

        msg["ip"] = ip_addr
        msg["prefix"] = prefix_str
        msg["name"] = self.hostname
        msg["dv"] = self.my_dv

        # print(f"Creating Message: {msg}")

        msg_str = json.dumps(msg)
        msg_bytes = msg_str.encode("utf-8")
        return msg_bytes

    def send_dv(self) -> None:
        print('Sending DV')

        # Send my DV to all interfaces (Except loopback)
        for intf in self.all_interfaces:
            if (intf == "lo"):
                continue

            msg = self.create_dv_message(intf)

            self._send_msg(msg, self.bcast_for_int(intf))


def main():
    hostname = socket.gethostname()

    with DVRouter() as router:
        router.init_dv()

        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()
