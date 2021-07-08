import socket, sys
import struct
import netifaces

ETH_P_ALL = 0x0003
IPV6 = 0x86dd

INTERFACE = 'eth0'

ETH_LENGTH = 14
RTR_SOL = 133       #Router Solicitation code
RTR_ADV = 134       #Router Advertisement code

def getmac():
  try:
    mac = open('/sys/class/net/'+INTERFACE+'/address').readline()
  except:
    mac = "00:00:00:00:00:00"

  return mac[0:17]

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

def bytes_to_ipv6(bytesipv6):
    return socket.inet_ntop(socket.AF_INET6, bytesipv6)

def ipv6_to_bytes(ipv6):
    return socket.inet_pton(socket.AF_INET6, ipv6)

def get_my_ipv6():
    addrs = netifaces.ifaddresses('eth0')
    return addrs[netifaces.AF_INET6][0]['addr']

def create_eth_header(mac_dst):
    mac2bytes = lambda m: bytes.fromhex(m.replace(':',''))
    mac_src = mac2bytes(getmac())
    
    return struct.pack("!6s6sH", mac_src, mac_dst, IPV6)

def create_ipv6_header(sender_ip, payload_legth):
    version = 6
    traffic_class = 0
    flow_label = 0
    next_header = socket.IPPROTO_ICMPV6
    hop_limit = 255
    src_address = ...
    dst_address = sender_ip

#     return struct.pack('>BBH...', version, traffic_class, flow_label, next_header, payload_legth, hop_limit, src_address, dst_address)

# def create_icmpv6_header():
#     code = 0
#     checksum = 0
#     identifier = 0
#     seqnumber = 0
#     payload = 0

#     return struct.pack("!BBHHH13s", RTR_ADV, code, checksum, identifier, seqnumber, payload)

def send_icmpv6_advertisement(s, packet, mac_src, src_ip, payload):
    
    eth_header = create_eth_header(mac_src)
    ipv6_header = create_ipv6_header(src_ip, payload_legth)
    # icmpv6_header = create_icmpv6_header()
    
    # pct = eth_header + ipv6_header + icmpv6_header
    # s.send(pct)

def receive_ipv6(s, packet, mac_src): 
    first_word, payload_legth, next_header, hoplimit = struct.unpack('>IHBB', packet[0:8])
    sender_ip = packet[8:24]
    payload = packet[40:]

    # print("IP origem: ", sender_ip)
    # print("IP destino: ")
    # print("Protocolo: ", next_header)

    if next_header == socket.IPPROTO_ICMPV6:
        icmp_type, icmp_code, icmp_chekcsum = struct.unpack('>BBH', payload[:4])

        if icmp_type == RTR_SOL:
            print("\n-------------------------------------------------------------")
            print("Router Solicitation: ")
            # print("Sender IP: ",sender_ip)
            print("Sender IP: ", bytes_to_ipv6(sender_ip))
            print("-------------------------------------------------------------\n")
            if bytes_to_ipv6(sender_ip) != get_my_ipv6():
                send_icmpv6_advertisement(s, packet, mac_src, sender_ip, payload_legth)

            
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

    s.bind((INTERFACE,0))

    while True:
        packet, addr = s.recvfrom(65536)

        eth_header = packet[:ETH_LENGTH]
        eth = struct.unpack("!6s6sH",eth_header)

        # checks for ipv6 packets
        if eth[2] == IPV6:
            # print("IPV6 packet received, addr:",addr)
            
            mac_src = eth[1]
            packet_ipv6 = packet[ETH_LENGTH:]
            
            receive_ipv6(s, packet_ipv6, mac_src)