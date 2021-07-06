import socket
import sys

def main():
    interface = "eth0"
    prefix_v6 = 0

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (prefix_v6, interface)
    s.bind(('enp4s0',0))

    (packet,addr) = s.recvfrom(65536)

    eth_length = 14
    eth_header = packet[:14]

    eth = struct.unpack("!6s6sH",eth_header)

    print("MAC Dst: "+bytes_to_mac(eth[0]))
    print("MAC Src: "+bytes_to_mac(eth[1]))
    print("Type: "+hex(eth[2]))




main()