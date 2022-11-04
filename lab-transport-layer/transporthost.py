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
        pass

    def handle_udp(self, pkt: bytes) -> None:

        # Grab dest ip and dest port and use it to map to socket
        dst = ip_binary_to_str(pkt[16:20])
        dport, = struct.unpack("!H", pkt[22:24])

        # See if it exists in map
        key = (dst, dport)
        if key not in self.socket_mapping_udp.keys():
            self.no_socket_udp(pkt)
        else:
            # Call receive on socket
            socket: UDPSocket = self.socket_mapping_udp[key]
            socket.handle_packet(pkt)

        pass

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
