from cougarnet.util import \
        ip_str_to_binary, ip_binary_to_str

from headers import IPv4Header, UDPHeader, TCPHeader, \
        IP_HEADER_LEN, UDP_HEADER_LEN, TCP_HEADER_LEN, \
        TCPIP_HEADER_LEN, UDPIP_HEADER_LEN
from host import Host
from mysocket import UDPSocket, TCPSocketBase
import struct

class TransportHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.socket_mapping_udp = {}
        self.socket_mapping_tcp = {}

    def handle_tcp(self, pkt: bytes) -> None:

        # Grab 4-tuple information for map key (src, sport, dst, dport)
        src = ip_binary_to_str(pkt[12:16])
        dst = ip_binary_to_str(pkt[16:20])

        sport, = struct.unpack("!H", pkt[20:22])
        dport, = struct.unpack("!H", pkt[22:24])

        key = (dst, dport, src, sport)

        print(f"Key: {key}")

        print(f"Host TCP Map Keys: {self.socket_mapping_tcp.keys()}")

        if key not in self.socket_mapping_tcp.keys():
            # Check for listening ones
            listen_key = (dst, dport, None, None)
            print(f"Listen Key: {listen_key}")

            if listen_key not in self.socket_mapping_tcp.keys():
                # Doesn't belong here
                self.no_socket_tcp(pkt)
            else:
                socket: TCPSocketBase = self.socket_mapping_tcp[listen_key]
                socket.handle_packet(pkt)
        else:
            # Call handle_packet on socket
            socket: TCPSocketBase = self.socket_mapping_tcp[key]
            socket.handle_packet(pkt)

    def handle_udp(self, pkt: bytes) -> None:

        # Grab dest ip and dest port and use it to map to socket
        dst = ip_binary_to_str(pkt[16:20])
        dport, = struct.unpack("!H", pkt[22:24])

        # See if it exists in map
        key = (dst, dport)
        if key not in self.socket_mapping_udp.keys():
            self.no_socket_udp(pkt)
        else:
            # Call handle_packet on socket
            socket: UDPSocket = self.socket_mapping_udp[key]
            socket.handle_packet(pkt)

    def install_socket_udp(self, local_addr: str, local_port: int,
            sock: UDPSocket) -> None:
        self.socket_mapping_udp[(local_addr, local_port)] = sock

    def install_listener_tcp(self, local_addr: str, local_port: int,
            sock: TCPSocketBase) -> None:
        self.socket_mapping_tcp[(local_addr, local_port, None, None)] = sock

    def install_socket_tcp(self, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int, sock: TCPSocketBase) -> None:
        self.socket_mapping_tcp[(local_addr, local_port, \
                remote_addr, remote_port)] = sock

    def no_socket_udp(self, pkt: bytes) -> None:
        pass

    def no_socket_tcp(self, pkt: bytes) -> None:
        pass
