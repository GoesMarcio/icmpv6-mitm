import socket
import struct
import binascii
import sys

## Links interessantes para ICMPv6:
# https://stackoverflow.com/questions/28525124/using-sock-stream-or-sock-raw-on-sending-multicast-ipv6
# https://github.com/O-Luhishi/Python-Packet-Sniffer/blob/f855159c8ceed28191e78b42c58122f5c0bf0d10/Packet-Sniffer.py

def send_icmpv6_advertisement(interface, rec_ip, src):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)
    
    # precisa passar interface, rec_ip?
    # Gerar mensagem Router Advertisement

    type = 134 #ok
    code = 0

    print("TO DO")
    mychecksum = 0
    identifier = 12345
    seqnumber = 0
    payload = b"istoehumteste"

    # Pack fields
    icmp_packet = struct.pack("!BBHHH13s", type, code, mychecksum, identifier, seqnumber, payload)

    # Calculate checksum
    mychecksum = checksum(icmp_packet)
    # print("Checksum: {:02x}".format(mychecksum))

    # Repack with checksum
    icmp_packet = struct.pack("!BBHHH14s", type, code, mychecksum, identifier, seqnumber, payload)

    ########################

    # Destination IP address
    dest_ip = "10.0.0.11"
    dest_addr = socket.gethostbyname(dest_ip)

    # Send icmp_packet to address = (host, port)
    s.sendto(icmp_packet, (dest_addr,0))


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
        # print(f"{type} {code} {checksum}")
        if type == 133:
            # Gerar mensagem Router Advertisement
            interface = ""
            rec_ip = ""
            send_icmpv6_advertisement(interface, rec_ip, ipv6_src)

main()