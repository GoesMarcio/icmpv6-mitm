import socket, sys
import struct

ETH_P_ALL = 0x0003
IPV6 = 0x86dd

ETH_LENGTH = 14

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

# def send_icmpv6_advertisement():
    #TO-DO

def receive_ipv6(packet): 
    first_word, payload_legth, next_header, hoplimit = struct.unpack('>IHBB', packet[0:8])
    payload = packet[40:]

    if next_header == socket.IPPROTO_ICMPV6:
        icmp_type, icmp_code, icmp_chekcsum = struct.unpack('>BBH', payload[:4])
        print("icmpv6 type: ",icmp_type)

        if icmp_type == 133:
            print("Router Solicitation")


    # ip_header = packet[:40]
    # iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

    # version_traf = iph[0]
    # version = version_traf >> 4

    # print(version)

    # ihl = version_ihl & 0xF 
    # iph_length = ihl*4
    # ttl = iph[5]
    # protocol = iph[6]
    # s_addr = socket.inet_ntoa(iph[8])
    # d_addr = socket.inet_ntoa(iph[9])
    
    # if protocol == ICMP_PROTOCOL and s_addr != IP_HOST and d_addr == IP_HOST:
    #     receiveIcmp(packet, iph_length,s_addr)


if __name__ == '__main__':
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')

    s.bind(('enp0s3',0))

    while True:
        packet, addr = s.recvfrom(65536)

        eth_length = 14
        eth_header = packet[:ETH_LENGTH]
        eth = struct.unpack("!6s6sH",eth_header)

        # checks for ipv6 packets
        if eth[2] == IPV6:
            print("here")
            mac_src = bytes_to_mac(eth[1])
            receive_ipv6(packet[ETH_LENGTH:])