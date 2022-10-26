#!/usr/bin/python3

import argparse
import asyncio
import json
import os
import socket
from cougarnet.util import struct
from typing import Dict

from cougarnet.sim.host import BaseHost
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

from forwarding_table import ForwardingTable
from prefix import Prefix, ip_prefix_last_address, ip_str_to_int

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

    ########################## Helper Methods ############################

    def build_ether_frame(self, addr, intf, payload, e_type):
        # Lets make a Ethernet Frame!
        dest_addr = addr
        src_addr = mac_str_to_binary(self.int_to_info[intf].mac_addr)
        ether_type = struct.pack("!H", e_type)

        header = dest_addr + src_addr + ether_type

        return header + payload

    def build_arp_request(self, intf, next_hop):
        # Lets build an ARP request!
        
        sender_ip = ip_str_to_binary(self.int_to_info[intf].ipv4_addrs[0]) 
        sender_mac = mac_str_to_binary(self.int_to_info[intf].mac_addr) 
        target_ip = ip_str_to_binary(next_hop)
        target_mac = mac_str_to_binary("00:00:00:00:00:00")

        print(f"Building ARP Request with target_ip: {ip_binary_to_str(target_ip)}")

        # Constants
        op_code = struct.pack("!H", ARPOP_REQUEST) # ARPOP_REQUEST = 1
        hardware_type = struct.pack("!H", ARPHRD_ETHER)
        protocol_type = struct.pack("!H", ETH_P_IP)
        hard_addr_len = struct.pack("!B", 6)
        protocol_addr_len = struct.pack("!B", 4)

        # Build
        return hardware_type + protocol_type + hard_addr_len + protocol_addr_len + op_code + sender_mac + sender_ip + target_mac + target_ip

    def build_arp_response(self, target_ip):
        target_mac, intf = self.arp_table[ip_binary_to_str(target_ip)]
        sender_ip = ip_str_to_binary(self.int_to_info[intf].ipv4_addrs[0]) 
        sender_mac = mac_str_to_binary(self.int_to_info[intf].mac_addr)
        target_mac = mac_str_to_binary(target_mac)

        op_code = struct.pack("!H", ARPOP_REPLY)
        hardware_type = struct.pack("!H", ARPHRD_ETHER)
        protocol_type = struct.pack("!H", ETH_P_IP)
        hard_addr_len = struct.pack("!B", 6)
        protocol_addr_len = struct.pack("!B", 4)

        # Build
        return hardware_type + protocol_type + hard_addr_len + protocol_addr_len + op_code + sender_mac + sender_ip + target_mac + target_ip

    def extract_mac_addr(self, block):
        print(f"Block: {block}")
        bytes1, bytes2 = struct.unpack("HI", block)
        return bytes1 + bytes2

    def initialize_fowarding_table(self, table: ForwardingTable):
        # Grab routes from the environment
        # Route: ["Address", "intf", "next-hop"]
        routes = json.loads(os.environ["COUGARNET_ROUTES"])
        
        # Go through each of the routes and add them to table
        for route in routes:
            table.add_entry(route[0], route[1], route[2])

        # Go through each of the interfaces for this host and add them as entries in the table
        for key in self.int_to_info.keys():
            if (key == "lo"):
                continue

            entry = self.int_to_info[key]
            addr = entry.ipv4_addrs[0]
            prefix_len = entry.ipv4_prefix_len
            prefix = addr + "/" + str(prefix_len)

            table.add_entry(prefix, key, None)

    def is_destination(self, target_ip, intf):
        # Go through each of the interfaces for this host and compare target_ip
        for key in self.int_to_info.keys():
            if (key == "lo"):
                continue

            entry = self.int_to_info[key]

            print(f"Entry: {entry.ipv4_addrs[0]} Target: {target_ip}")

            if (entry.ipv4_addrs[0] == target_ip):
                print(f"Returning true for entry {entry.ipv4_addrs[0]} matching {target_ip}")
                return True

        # Check if this is the broadcast
        addr = ip_str_to_int(self.int_to_info[intf].ipv4_addrs[0])
        prefix_len = self.int_to_info[intf].ipv4_prefix_len
        
        if (ip_str_to_binary(target_ip) == ip_prefix_last_address(addr, socket.AF_INET, prefix_len)):
            return True

        return False

    ########################## Helper Methods ############################

    def __init__(self, ip_forward):
        super(Host, self).__init__()

        self._ip_forward = ip_forward

        # do any additional initialization here

        # ARP Table (Key = IP, Value = [MAC Addr, intf])
        self.arp_table = {}

        # IP Packet Queue
        # Queue Entry = [Next_Hop, intf, PKT]
        self.packet_queue = []

        # IP Forwarding Table
        # entry (Key = IP (Prefix), Value = [intf, next-hop])
        self.forwarding_table = ForwardingTable()
        self.initialize_fowarding_table(self.forwarding_table)

    def _handle_frame(self, frame, intf):
        target_mac = frame[0:6]

        print(f"Target Mac: {mac_binary_to_str(target_mac)}")

        # Check if this frame relates to me
        if (target_mac == mac_str_to_binary(self.int_to_info[intf].mac_addr) or target_mac == mac_str_to_binary("ff:ff:ff:ff:ff:ff")):
            print("I need to handle this!")
            # Grab type
            frame_type, = struct.unpack("!H", frame[12:14])
            payload = frame[14:]

            # Call appropriate handler
            if (frame_type == ETH_P_IP):
                print("HANDLE_IP")
                self.handle_ip(payload, intf)
            elif (frame_type == ETH_P_ARP):
                print("HANDLE_ARP")
                self.handle_arp(payload, intf)

        # This frame is not related to me    
        else:
            self.not_my_frame(frame, intf)

    def handle_ip(self, pkt, intf):
        # Grab target_ip
        target_ip = ip_binary_to_str(pkt[16:20])

        # Check if I am the destination
        if (self.is_destination(target_ip, intf) == True):
            # Check protocol and handle accordingly
            protocol = struct.unpack("!B", pkt[9:10])

            print(f"Protocol: {protocol}")

            if (protocol == IPPROTO_TCP):
                self.handle_tcp()
            elif (protocol == IPPROTO_UDP):
                self.handle_udp
        else:
            # Not my packet
            self.not_my_packet(pkt, intf)

    def handle_tcp(self, pkt):
        pass

    def handle_udp(self, pkt):
        pass

    def handle_arp(self, pkt, intf):
        # Pull out op_code to determine appropriate path
        # Assuming that the Mac Address will always be 6 bytes
        op_code, = struct.unpack("!H", pkt[6:8])

        if (op_code == ARPOP_REQUEST):
            self.handle_arp_request(pkt, intf)
        else:
            print(f"ARP REPLY Packet: {pkt}")
            self.handle_arp_response(pkt, intf)

    def handle_arp_response(self, pkt, intf):
        sender_mac = pkt[8:14]
        sender_ip = pkt[14:18]

        print("I GOT A RESPONSE! (For Arp)")

        # Update ARP table
        self.arp_table[ip_binary_to_str(sender_ip)] = [mac_binary_to_str(sender_mac), intf]

        # Go through queue and send packets waiting on this response
        for entry in self.packet_queue:
            print(f"ENTRY: {entry}")
            if (ip_str_to_binary(entry[0]) == sender_ip):
                # Send the packet
                print(f"Sending ICMP to {entry[0]}")
                ether_frame = self.build_ether_frame(mac_str_to_binary(self.arp_table[ip_binary_to_str(sender_ip)][0]), entry[1], entry[2], ETH_P_IP)
                self.send_frame(ether_frame, entry[1])

        # Prune Queue
        print(f"Old Queue: {self.packet_queue}")
        new_queue = []
        for i in range(len(self.packet_queue)):
            if (ip_str_to_binary(entry[0]) != sender_ip):
                new_queue.append(self.packet_queue[i])
        
        self.packet_queue = new_queue
        print(f"New Queue: {self.packet_queue}")

    def handle_arp_request(self, pkt, intf):
        # Extract source mac addr and add to ARP table
        src_mac = pkt[8:14]
        src_ip = pkt[14:18]
        self.arp_table[ip_binary_to_str(src_ip)] = [mac_binary_to_str(src_mac), intf]
        
        print(f"SRC_MAC {mac_binary_to_str(src_mac)} SRC_IP {ip_binary_to_str(src_ip)}")

        # Extract target IP and see if I should respond
        target_ip = pkt[24:28]
        print(f"TARGET_IP: {ip_binary_to_str(target_ip)}")
        if (target_ip == ip_str_to_binary(self.int_to_info[intf].ipv4_addrs[0])):
            # Build ARP Response and send it
            print("Dont worry im sending a response to you!")
            arp_response = self.build_arp_response(src_ip)
            ether_frame = self.build_ether_frame(mac_str_to_binary(self.arp_table[ip_binary_to_str(src_ip)][0]), intf, arp_response, ETH_P_ARP)
            self.send_frame(ether_frame, intf)

    def send_packet_on_int(self, pkt, intf, next_hop):
        print(f'Attempting to send packet on {intf} with next hop {next_hop}:\n{repr(pkt)}')
        
        # Check if the next_hop is in arp table
        if next_hop in self.arp_table.keys():
            print(f"Next Hop {next_hop} was found in arp table")
            entry = self.arp_table[next_hop]
            ether_frame = self.build_ether_frame(mac_str_to_binary(entry[0]), entry[1], pkt, ETH_P_IP)
            self.send_frame(ether_frame, intf)
        else:
            # Queue this packet and go to ARP Land :)
            print(f"Dont have MAC for {next_hop}, Sending ARP request")
            queue_entry = [next_hop, intf, pkt]
            self.packet_queue.append(queue_entry)

            arp_request = self.build_arp_request(intf, next_hop)
            print(f"ARP REQUEST: {arp_request}")
            ether_frame = self.build_ether_frame(mac_str_to_binary("ff:ff:ff:ff:ff:ff"), intf, arp_request, ETH_P_ARP)
            self.send_frame(ether_frame, intf)


    def send_packet(self, pkt):
        print(f'Attempting to send packet:\n{repr(pkt)}')

        # Get destination IP from pkt
        target_ip = ip_binary_to_str(pkt[16:20])

        # Get longest matching prefix from forwarding table
        prefix_entry = self.forwarding_table.get_entry(target_ip)

        print(f"Prefix Entry: {prefix_entry}")

        # If outgoing interface it None, then just return
        if (prefix_entry[0] == None):
            return

        # If next hop is None, then you target_ip as next hop
        if (prefix_entry[1] == None):
            next_hop = target_ip
        else:
            next_hop = prefix_entry[1]
        
        self.send_packet_on_int(pkt, prefix_entry[0], next_hop)

    def forward_packet(self, pkt):
        # Extract TTL and decrement
        ttl, = struct.unpack("!B", pkt[8:9])
        if (ttl <= 1):
            print("Not forwarding packet because it timed out!")
            return
        
        # Decrement TTL
        ttl = ttl - 1
        print(f"ttl: {ttl}")

        new_ttl = struct.pack("!B", ttl)
        pkt = pkt[0:8] + new_ttl + pkt[9:]
        
        # Send packet on through
        self.send_packet(pkt)

    def not_my_frame(self, frame, intf):
        pass

    def not_my_packet(self, pkt, intf):
        # Check value of "Should Forward" flag
        if (self._ip_forward == False):
            return
        else:
            self.forward_packet(pkt)

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
