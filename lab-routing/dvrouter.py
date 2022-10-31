import asyncio
import json
import socket

NEIGHBOR_CHECK_INTERVAL = 3
DV_TABLE_SEND_INTERVAL = 1
DV_PORT = 5016

from cougarnet.sim.host import BaseHost

from prefix import *
from forwarding_table_native import ForwardingTableNative as ForwardingTable

class DVRouter(BaseHost):
    def __init__(self):
        super(DVRouter, self).__init__()

        self.my_dv = self.create_dv()
        self.neighbor_dvs = {}
        self.neighbor_ips = {}

        self.forwarding_table = ForwardingTable()

        self._initialize_dv_sock()

        # Do any further initialization here

    def create_dv(self):
        dv = {}
        # Go through interfaces and create dv entries with 0 (Add /32 prefix)
        for intf in self.all_interfaces:
            if (intf == "lo"):
                continue

            # Get IP address and add /32 prefix for this lab
            prefix = self.int_to_info[intf].ipv4_addrs[0] + "/32"

            # Initial distance is 0
            entry = {}
            entry["dist"] = 0
            entry["next_hop"] = self.hostname
            dv[prefix] = entry
            
        return dv

    def update_forwarding_table(self):
        self.forwarding_table.flush()

        print(f"Neighbor IP's: {self.neighbor_ips}")
        # Go through my dv and add next hops to prefixes
        for prefix in self.my_dv.keys():
            dv_entry = self.my_dv[prefix]

            if (dv_entry["next_hop"] == self.hostname):
                continue

            next_hop = self.neighbor_ips[dv_entry["next_hop"]]

            interface = ""
            # Using next_hop, find interface that it will go out
            for intf in self.all_interfaces:
                if (intf == "lo"):
                    continue

                if (next_hop == self.int_to_info[intf].ipv4_addrs[0]):
                    interface = intf
                    break

            # Add entry
            print(f"Forwarding Table Entry: Prefix {prefix}, Intf: {interface}, Next {next_hop}")
            self.forwarding_table.add_entry(prefix, interface, next_hop)


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

    def create_dv_message(self, intf):
        msg = {}
        msg["ip"] = self.int_to_info[intf].ipv4_addrs[0]
        msg["name"] = self.hostname
        msg["dv"] = self.my_dv

        # print(f"Creating Message: {msg}")

        msg_str = json.dumps(msg)
        msg_bytes = msg_str.encode("utf-8")
        return msg_bytes

    def _initialize_dv_sock(self) -> None:
        '''Initialize the socket that will be used for sending and receiving DV
        communications to and from neighbors.
        '''

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('0.0.0.0', DV_PORT))

    def init_dv(self):
        '''Set up our instance to work with the event loop, initialize our DV,
        and schedule our regular updates to be sent to neighbors.
        '''

        loop = asyncio.get_event_loop()

        # register our socket with the event loop, so we can handle datagrams
        # as they come in
        loop.add_reader(self.sock, self._handle_msg, self.sock)

        # Initialize our DV -- and optionally send our DV to our neighbors
        self.update_dv()

        # Schedule self.send_dv_next() to be called every second
        # (DV_TABLE_SEND_INTERVAL)
        loop.call_later(DV_TABLE_SEND_INTERVAL, self.send_dv_next)


    def _handle_msg(self, sock: socket.socket) -> None:
        ''' Receive and handle a message received on the UDP socket that is
        being used for DV messages.
        '''

        data, addrinfo = sock.recvfrom(65536)
        self.handle_dv_message(data)

    def _send_msg(self, msg: bytes, dst: str) -> None:
        '''Send a DV message, msg, on our UDP socket to dst.'''

        self.sock.sendto(msg, (dst, DV_PORT))

    def handle_dv_message(self, msg: bytes) -> None:
        print("I Got a DV!")
        # print(f"Message: {msg}")

        # Decode the message from the data
        obj_str = msg.decode("utf-8")
        obj = json.loads(obj_str)

        # Grab information from message and store it in associated dv table
        ip = obj["ip"]
        name = obj["name"]
        dv = obj["dv"]

        # Discard packet if it is from me
        if (name == self.hostname):
            return

        # Save neighbor IP
        self.neighbor_ips[name] = ip

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

    def update_dv(self) -> None:
        # print("Updating my DV!")
        # copy my own dv
        dv = self.my_dv.copy()

        new_dv = self.bellman_ford()
        print(f"New DV: {new_dv}")

        # if the new_dv is different than the original then broadcast dv out
        if (dv != new_dv):
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

    def send_dv(self) -> None:
        print('Sending DV')

        # Send my DV to all interfaces (Except loopback)
        for intf in self.all_interfaces:
            if (intf == "lo"):
                continue

            msg = self.create_dv_message(intf)

            self._send_msg(msg, self.bcast_for_int(intf))
