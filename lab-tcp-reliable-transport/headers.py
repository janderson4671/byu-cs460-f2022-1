from __future__ import annotations

import struct

from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str


IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
TCP_HEADER_LEN = 20
TCPIP_HEADER_LEN = IP_HEADER_LEN + TCP_HEADER_LEN
UDPIP_HEADER_LEN = IP_HEADER_LEN + UDP_HEADER_LEN

TCP_RECEIVE_WINDOW = 64

class IPv4Header:
    def __init__(self, length: int, ttl: int, protocol: int, checksum: int,
            src: str, dst: str) -> IPv4Header:
        self.length = length
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.src = src
        self.dst = dst

    @classmethod
    def from_bytes(cls, hdr: bytes) -> IPv4Header:
        length, = struct.unpack('!H', hdr[2:4])
        ttl, = struct.unpack('!B', hdr[8:9])
        protocol, = struct.unpack('!B', hdr[9:10])
        checksum, = struct.unpack('!H', hdr[10:12])
        src_bytes, = struct.unpack('!I', hdr[12:16])
        dst_bytes, = struct.unpack('!I', hdr[16:20])
        src_bytes = src_bytes.to_bytes(4, 'big')
        dst_bytes = dst_bytes.to_bytes(4, 'big')
        src = ip_binary_to_str(src_bytes)
        dst = ip_binary_to_str(dst_bytes)

        return cls(length, ttl, protocol, checksum, src, dst)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!B', (4 << 4) + 5)  # Version and IHL
        hdr += struct.pack('!B', 0)             # Differenciated Services
        hdr += struct.pack('!H', self.length)   # Total Length
        hdr += struct.pack('!H', 0)             # Identification (For reassembly of fragmentation)  
        hdr += struct.pack('!H', 0)             # Flags and Frame Offset
        hdr += struct.pack('!B', self.ttl)      # Time to live (usually 64)
        hdr += struct.pack('!B', self.protocol) # Protocol (UDP or TCP)
        hdr += struct.pack('!H', self.checksum) # Checksum of packet
        hdr += struct.pack('!I', int.from_bytes(ip_str_to_binary(self.src), "big"))   # Source IP Address
        hdr += struct.pack('!I', int.from_bytes(ip_str_to_binary(self.dst), "big"))  # Destination IP Address

        return hdr


class UDPHeader:
    def __init__(self, sport: int, dport: int, length: int,
            checksum: int) -> UDPHeader:
        self.sport = sport
        self.dport = dport
        self.checksum = checksum
        self.length = length

    @classmethod
    def from_bytes(cls, hdr: bytes) -> UDPHeader:
        sport, = struct.unpack('!H', hdr[:2])
        dport, = struct.unpack('!H', hdr[2:4])
        length, = struct.unpack('!H', hdr[4:6])
        checksum, = struct.unpack('!H', hdr[6:8])
        return cls(sport, dport, length, checksum)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!H', self.sport)
        hdr += struct.pack('!H', self.dport)
        hdr += struct.pack('!H', self.length)
        hdr += struct.pack('!H', self.checksum)
        return hdr


class TCPHeader:
    def __init__(self, sport: int, dport: int, seq: int, ack: int,
            flags: int, checksum: int) -> TCPHeader:
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.checksum = checksum

    @classmethod
    def from_bytes(cls, hdr: bytes) -> TCPHeader:
        sport, = struct.unpack('!H', hdr[0:2])
        dport, = struct.unpack('!H', hdr[2:4])
        seq, = struct.unpack('!I', hdr[4:8])
        ack, = struct.unpack('!I', hdr[8:12])
        flags, = struct.unpack('!B', hdr[13:14])
        checksum, = struct.unpack('!H', hdr[16:18])

        return cls(sport, dport, seq, ack, flags, checksum)

    def to_bytes(self) -> bytes:
        hdr = b''
        hdr += struct.pack('!H', self.sport)    # Source Port
        hdr += struct.pack('!H', self.dport)    # Destination Port
        hdr += struct.pack('!I', self.seq)      # Sequence Number
        hdr += struct.pack('!I', self.ack)      # Acknowledgment Number
        hdr += struct.pack('!B', (5 << 4))      # Data Offset
        # Ommitting ECN
        hdr += struct.pack('!B', self.flags)
        hdr += struct.pack('!H', 64)            # Window Size (64 for this lab)
        hdr += struct.pack('!H', self.checksum) # Checksum (will be "0" for this lab)
        hdr += struct.pack('!H', 0)             # Urgent Pointer (will be "0" for this lab)

        return hdr
