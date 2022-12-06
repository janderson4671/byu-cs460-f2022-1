#!/usr/bin/python3

import asyncio
import binascii
import json
import os
import pprint
import time
from cougarnet.sim.host import BaseHost
from cougarnet.util import struct

# Helper Methods!!!
def createAddr(byte_array):
    bytes1, bytes2 = struct.unpack("!HI", byte_array)

    return bytes1 + bytes2

class Switch(BaseHost):

    def __init__(self):
        super(Switch, self).__init__()
        self.switchTable = {}

        # Get VLAN Configuration from Environment
        if ('COUGARNET_VLAN' in os.environ):
            self.is_vlan_configured = True
        else:
            self.is_vlan_configured = False
            
        # do any initialization here...
        print("Hey There!")

    def updateTable(self, addr, intf):
        # check if entry exists
        if (addr in self.switchTable.keys()):
            # update timestamp
            entry = self.switchTable[addr]
            entry = [intf, time.time()]
            self.switchTable[addr] = entry
        else:
            entry = [intf, time.time()]
            self.switchTable[addr] = entry

        # prune expired entries
        currTime = time.time()
        expiredKeys = []
        for addr in self.switchTable:
            entry = self.switchTable[addr]
            if (currTime - entry[1] > 8):
                print(f"Expired Entry Interface: {entry[0]}")
                expiredKeys.append(addr)

        for key in expiredKeys:
            del self.switchTable[key]

    def send_trunk_frame(self, frame, intf, vlan):
        # Create 802.1Q Frame and send it to interface
        destAddr = frame[:6]
        srcAddr = frame[6:12]
        trunkHeader = struct.pack("!HH", 0x8100, vlan)
        etherType = frame[12:14]
        payload = frame [14:]

        newFrame = destAddr + srcAddr + trunkHeader + etherType + payload

        print(f"Sending Trunk Frame to {intf}")
        self.send_frame(newFrame, intf)

    def send_frame_vlan(self, destAddr, frame, intf, vlan):
        # See if Dest is in switch table
        if (destAddr not in self.switchTable.keys()):
            print("Not found in table!")
            # send frame to all interfaces except sender
            for interface in self.all_interfaces:
                print(f"Interface Info: {self.int_to_info[interface].vlan}")
                if (interface == intf or interface == "lo"):
                    continue

                elif (self.int_to_info[interface].vlan == -1):
                    # Trunk Interface
                    self.send_trunk_frame(frame, interface, vlan)

                # Don't forward to interfaces not in VLAN
                elif (self.int_to_info[interface].vlan != vlan):
                    continue

                else:
                    print(f"Sent frame to {interface}!")
                    self.send_frame(frame, interface)
                
        else:
            print("Found frame in table (VLAN)")
            destIntf = self.switchTable[destAddr][0]
            # send frame to direct interface if part of VLAN of Trunk
            if (self.int_to_info[destIntf].vlan == vlan or self.int_to_info[destIntf].vlan == -1):
                # check if interface is trunk
                if (self._is_trunk_link(destIntf)):
                    print("Gonna send on Trunk!")
                    self.send_trunk_frame(frame, destIntf, vlan)
                else:
                    self.send_frame(frame, destIntf)
                    print(f"Sent direct frame to {destIntf}")
                    
                

    def _handle_frame(self, frame, intf):
        print('Received frame: %s' % repr(frame))

        print(f"Incomming Interface: {intf}")

        # Get VLAN info about interface
        if (self.is_vlan_configured == True):
            vlan = self.int_to_info[intf].vlan
            print(f"VLAN: {vlan}")

        # Grab Dest and Src addresses from frame
        destAddr = createAddr(frame[:6])
        srcAddr = createAddr(frame[6:12])

        # See if frame came from trunk (Remove 802.1Q Header)
        if (self._is_trunk_link(intf)):
            vlan, = struct.unpack("!H", frame[14:16])
            frame = frame[:14] + frame[16:]
            print(f"This Packet Came From Trunk! VLAN: {vlan}")

        # Add/Update SRC addr in switch table
        self.updateTable(srcAddr, intf)

        # If a vlan is configured, then do special stuff
        if (self.is_vlan_configured):
            self.send_frame_vlan(destAddr, frame, intf, vlan)
            return

        # See if Dest is in switch table
        if (destAddr not in self.switchTable.keys()):
            # send frame to all interfaces except sender
            for interface in self.all_interfaces:
                if (interface == intf or interface == "lo"):
                    continue
                print(f"Sent frame to {interface}!")
                self.send_frame(frame, interface)
        else:
            destIntf = self.switchTable[destAddr][0]
            # send frame to direct interface
            self.send_frame(frame, destIntf)
            print(f"Sent direct frame to {destIntf}")

def main():
    switch = Switch()

    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    finally:
        loop.close()

if __name__ == '__main__':
    main()
