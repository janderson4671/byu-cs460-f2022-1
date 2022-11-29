from __future__ import annotations

import random
import struct
from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str

TCP_FLAGS_SYN = 0x02
TCP_FLAGS_RST = 0x04
TCP_FLAGS_ACK = 0x10

TCP_STATE_LISTEN = 0
TCP_STATE_SYN_SENT = 1
TCP_STATE_SYN_RECEIVED = 2
TCP_STATE_ESTABLISHED = 3
TCP_STATE_FIN_WAIT_1 = 4
TCP_STATE_FIN_WAIT_2 = 5
TCP_STATE_CLOSE_WAIT = 6
TCP_STATE_CLOSING = 7
TCP_STATE_LAST_ACK = 8
TCP_STATE_TIME_WAIT = 9
TCP_STATE_CLOSED = 10

from headers import IPv4Header, UDPHeader, TCPHeader, \
        IP_HEADER_LEN, UDP_HEADER_LEN, TCP_HEADER_LEN, \
        TCPIP_HEADER_LEN, UDPIP_HEADER_LEN


#From /usr/include/linux/in.h:
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class UDPSocket:
    def __init__(self, local_addr: str, local_port: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> UDPSocket:

        self._local_addr = local_addr
        self._local_port = local_port
        self._send_ip_packet = send_ip_packet_func
        self._notify_on_data = notify_on_data_func

        self.buffer = []

    def handle_packet(self, pkt: bytes) -> None:

        # Parse out src address and port along with data
        src = ip_binary_to_str(pkt[12:16])
        sport, = struct.unpack("!H", pkt[20:22])
        data = pkt[28:]

        print(f"Handling UDP Packet! \n SRC: {src}\n SPORT: {sport}\n DATA: {data}")

        self.buffer.append((data, src, sport))
        self._notify_on_data()

    @classmethod
    def create_packet(cls, src: str, sport: int, dst: str, dport: int,
            data: bytes=b'') -> bytes:
        
        # Create UDP Header obj
        h_udp = UDPHeader(sport, dport, len(data) + UDP_HEADER_LEN, 0).to_bytes()

        # Append data to h_udp for IP data
        ip_data = h_udp + data

        # Create IP Header
        h_ip = IPv4Header(len(ip_data) + IP_HEADER_LEN, 64, IPPROTO_UDP, 0, src, dst).to_bytes()

        # Append ip_data to h_ip for full packet
        packet = h_ip + ip_data
        return packet

    def send_packet(self, remote_addr: str, remote_port: int,
            data: bytes) -> None:

        # Create IP Packet
        ip_packet = self.create_packet(self._local_addr, self._local_port, remote_addr, remote_port, data)

        # Send it off
        self._send_ip_packet(ip_packet)

    def recvfrom(self) -> tuple[bytes, str, int]:
        return self.buffer.pop(0)

    def sendto(self, data: bytes, remote_addr: str, remote_port: int) -> None:
        self.send_packet(remote_addr, remote_port, data)


class TCPSocketBase:
    def handle_packet(self, pkt: bytes) -> None:
        pass

class TCPListenerSocket(TCPSocketBase):
    def __init__(self, local_addr: str, local_port: int,
            handle_new_client_func: callable, send_ip_packet_func: callable,
            notify_on_data_func: callable) -> TCPListenerSocket:

        # These are all vars that are saved away for instantiation of TCPSocket
        # objects when new connections are created.
        self._local_addr = local_addr
        self._local_port = local_port
        self._handle_new_client = handle_new_client_func

        self._send_ip_packet_func = send_ip_packet_func
        self._notify_on_data_func = notify_on_data_func


    def handle_packet(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if tcp_hdr.flags & TCP_FLAGS_SYN:
            sock = TCPSocket(self._local_addr, self._local_port,
                    ip_hdr.src, tcp_hdr.sport,
                    TCP_STATE_LISTEN,
                    send_ip_packet_func=self._send_ip_packet_func,
                    notify_on_data_func=self._notify_on_data_func)

            self._handle_new_client(self._local_addr, self._local_port,
                    ip_hdr.src, tcp_hdr.sport, sock)

            sock.handle_packet(pkt)


class TCPSocket(TCPSocketBase):
    def __init__(self, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int, state: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> TCPSocket:

        # The local/remote address/port information associated with this
        # TCPConnection
        self._local_addr = local_addr
        self._local_port = local_port
        self._remote_addr = remote_addr
        self._remote_port = remote_port

        # The current state (TCP_STATE_LISTEN, TCP_STATE_CLOSED, etc.)
        self.state = state

        # Helpful methods for helping us send IP packets and
        # notifying the application that we have received data.
        self._send_ip_packet = send_ip_packet_func
        self._notify_on_data = notify_on_data_func

        # Base sequence number
        self.base_seq_self = self.initialize_seq()

        # Base sequence number for the remote side
        self.base_seq_other = None


    @classmethod
    def connect(cls, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> TCPSocket:
        sock = cls(local_addr, local_port,
                remote_addr, remote_port,
                TCP_STATE_CLOSED,
                send_ip_packet_func, notify_on_data_func)

        sock.initiate_connection()

        return sock


    def handle_packet(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if self.state != TCP_STATE_ESTABLISHED:
            self.continue_connection(pkt)

        if self.state == TCP_STATE_ESTABLISHED:
            if data:
                # handle data
                self.handle_data(pkt)
            if tcp_hdr.flags & TCP_FLAGS_ACK:
                # handle ACK
                self.handle_ack(pkt)


    def initialize_seq(self) -> int:
        return random.randint(0, 65535)

    def set_flags(self, syn: bool, ack: bool):
        flags: int = 0

        # Setting bits in proper locations when needed
        if (syn == True):
            flags = flags + 2
        if (ack == True):
            flags = flags + 16
        
        return flags

    def is_sin_flag_set(self, flags: int) -> bool:
        return (flags == 2 or flags == 18)

    def is_ack_flag_set(self, flags: int) -> bool:
        return (flags == 16 or flags == 18)

    def initiate_connection(self) -> None:
        # Lets setup a connection!
        seq = self.base_seq_self
        ack = 0

        # Set only the SYN Flag
        flags = self.set_flags(True, False)
        data = b''
        self.send_packet(seq, ack, flags, data)

        # Change state to SYN_SENT
        self.state = TCP_STATE_SYN_SENT

    def handle_syn(self, pkt: bytes) -> None:
        # Grab seq and ack information from other side
        seq, = struct.unpack("!I", pkt[24:28])
        ack, = struct.unpack("!I", pkt[28:32])
        flags, = struct.unpack("!B", pkt[33:34])

        # If SYN Flag is not set then just ignore
        if self.is_sin_flag_set(flags) == False:
            return

        print(f"Handle Syn:\n\tSEQ: {seq}\n\tACK: {ack}")

        self.base_seq_other = seq

        # Respond with a SYN/ACK packet
        packet = self.send_packet(self.base_seq_self, (self.base_seq_other + 1), self.set_flags(True, True), b'')

        # Change state to SYN_RECEIVED
        self.state = TCP_STATE_SYN_RECEIVED

    def handle_synack(self, pkt: bytes) -> None:
        # Grab information from packet
        seq, = struct.unpack("!I", pkt[24:28])
        ack, = struct.unpack("!I", pkt[28:32])
        flags, = struct.unpack("!B", pkt[33:34])

        # Ignore packet if SYN or ACK flags are not both set
        if not ((self.is_sin_flag_set(flags) == True) and (self.is_ack_flag_set(flags)) == True):
            return

        print(f"Handle SYN/ACK:\n\tSEQ: {seq}\n\tACK: {ack}")

        # If ack is not our SEQ + 1 then ignore packet
        if (ack != self.base_seq_self + 1):
            return

        self.base_seq_other = seq

        # Send ACK back to them
        self.send_packet(self.base_seq_self + 1, self.base_seq_other + 1, self.set_flags(False, True), b'')

        # Set state to ESTABLISHED
        self.state = TCP_STATE_ESTABLISHED

    def handle_ack_after_synack(self, pkt: bytes) -> None:
        # Grab seq and ack information from other side
        seq, = struct.unpack("!I", pkt[24:28])
        ack, = struct.unpack("!I", pkt[28:32])
        flags, = struct.unpack("!B", pkt[33:34])

        # Ignore packet if ack flag is not set
        if (self.is_ack_flag_set(flags) == False):
            return

        # Ignore packet if SYN flag is set
        if (self.is_sin_flag_set(flags) == True):
            return

        # Ignore packet if ack is not our base + 1
        if (ack != self.base_seq_self + 1):
            return
        
        # Transition state to ESTABLISED
        self.state = TCP_STATE_ESTABLISHED

    def continue_connection(self, pkt: bytes) -> None:
        print(f"STATE: {self.state}")
        if self.state == TCP_STATE_LISTEN:
            self.handle_syn(pkt)
        elif self.state == TCP_STATE_SYN_SENT:
            self.handle_synack(pkt)
        elif self.state == TCP_STATE_SYN_RECEIVED:
            self.handle_ack_after_synack(pkt)

    def send_data(self, data: bytes, flags: int=0) -> None:
        pass

    @classmethod
    def create_packet(cls, src: str, sport: int, dst: str, dport: int,
        seq: int, ack: int, flags: int, data: bytes=b'') -> bytes:

        # Create TCP Header
        h_tcp = TCPHeader(sport, dport, seq, ack, flags, 0).to_bytes()

        # Attach data to TCP Header
        tcp_packet = h_tcp + data

        # Create IP Header
        h_ip = IPv4Header(len(tcp_packet) + IP_HEADER_LEN, 64, IPPROTO_TCP, 0, src, dst).to_bytes()

        # Create Full Packet
        packet = h_ip + tcp_packet
        return packet

    def send_packet(self, seq: int, ack: int, flags: int,
            data: bytes=b'') -> None:

        # Create Packet
        ip_packet = self.create_packet(self._local_addr, self._local_port, self._remote_addr, self._remote_port, seq, ack, flags, data)

        # Send it off
        self._send_ip_packet(ip_packet)
        pass

    def handle_data(self, pkt: bytes) -> None:
        pass

    def handle_ack(self, pkt: bytes) -> None:
        pass
