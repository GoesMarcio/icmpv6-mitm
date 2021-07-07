import socket
import struct
import binascii
import sys

## Links interessantes para ICMPv6:
# https://stackoverflow.com/questions/28525124/using-sock-stream-or-sock-raw-on-sending-multicast-ipv6
# https://github.com/O-Luhishi/Python-Packet-Sniffer/blob/f855159c8ceed28191e78b42c58122f5c0bf0d10/Packet-Sniffer.py


def main():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except OSError as msg:    
        print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit(1)

    s.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, 1)

    while True:
        packet, addr = s.recvfrom(65536)
        ipv6_src = addr[0]
        print(f"IP: {ipv6_src}")

        type, code, checksum = struct.unpack('>BBH', packet[0:4])

        #Router Solicitation, tipo 133
        #Router Advertisement, tipo 134
        
        if type == 133:
            print("TO DO")
            # Gerar mensagem Router Advertisement

main()