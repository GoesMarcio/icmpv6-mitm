import socket, sys
import struct

ETH_P_ALL = 0x0003
IPV6 = 0x86dd

ETH_LENGTH = 14

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

def send_icmpv6_advertisement(ip_src):
    pass

def receive_ipv6(packet): 
    first_word, payload_legth, next_header, hoplimit = struct.unpack('>IHBB', packet[0:8])
    sender_ip = packet[8:24]
    payload = packet[40:]

    if next_header == socket.IPPROTO_ICMPV6:
        icmp_type, icmp_code, icmp_chekcsum = struct.unpack('>BBH', payload[:4])

        if icmp_type == 133:
            print("\n-------------------------------------------------------------")
            print("Router Solicitation: ")
            print("Sender IP: ",sender_ip)
            print("-------------------------------------------------------------\n")
            send_icmpv6_advertisement(sender_ip)

            

if __name__ == '__main__':
    ''' Next steps:
        1) avoid atacking ourselves (verify if the sender's ip == our ip)
        2) keep track of compromised machines to print instead of attacking again (add compromised machines ip to a list)
        3) implement 'send_router_advertisement'
        4) check if line 17 works (maybe necessary to change some types)
    '''
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Starting...')

    s.bind(('eth0',0))

    while True:
        packet, addr = s.recvfrom(65536)

        eth_header = packet[:ETH_LENGTH]
        eth = struct.unpack("!6s6sH",eth_header)

        # checks for ipv6 packets
        if eth[2] == IPV6:
            print("IPV6 packet received, addr:",addr)
            #mac_src = bytes_to_mac(eth[1])
            receive_ipv6(packet[ETH_LENGTH:])