import socket, sys
import struct
import netifaces

ETH_P_ALL = 0x0003
IPV6 = 0x86dd

INTERFACE = 'eth0'

ETH_LENGTH = 14
RTR_SOL = 133       #Router Solicitation code
RTR_ADV = 134       #Router Advertisement code
compromised = []

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
    return addrs[netifaces.AF_INET6][1]['addr'].split('%')[0]

def create_eth_header(mac_dst):
    mac2bytes = lambda m: bytes.fromhex(m.replace(':',''))
    mac_src = mac2bytes(getmac())

    print("MAC DST:",bytes_to_mac(mac_dst))
    print("MAC SRC:",bytes_to_mac(mac_src))
    print("Type:",hex(IPV6))
    return struct.pack("!6s6sH", mac_dst,mac_src, IPV6)

def is_compromised(sender_ip,next_header):
    if sender_ip in compromised:
        print("IP origem: ", sender_ip)
        print("IP destino: ")
        print("Protocolo: ", next_header)
        return True
    return False

def create_ipv6_header(sender_ip, payload_legth):
    version = 6
    traffic_class = 0
    flow_label = 0
    next_header = socket.IPPROTO_ICMPV6
    hop_limit = 255
    src_address = ...
    dst_address = sender_ip
    #return struct.pack('>BBH...', version, traffic_class, flow_label, next_header, payload_legth, hop_limit, src_address, dst_address)
    return

def create_icmpv6():
    adv_type = 134
    code = 0
    cur_hop_limit = 0
    autoconfig_flags = 0
    router_lifetime = 120
    reachable_time = 100
    retrans_timer = 100
    checksum = 
    #return struct.pack("!BBHHH13s", RTR_ADV, code, checksum, identifier, seqnumber, payload)
    return

def create_icmpv6_header():
    adv_type = 134
    code = 0
    checksum = 0
    identifier = 0
    seqnumber = 0
    payload = 0
    #return struct.pack("!BBHHH13s", RTR_ADV, code, checksum, identifier, seqnumber, payload)
    return

def send_icmpv6_advertisement(s, packet, mac_src, sender_ip, payload_lenght):
    
    eth_header = create_eth_header(mac_src)
    ipv6_header = create_ipv6_header(sender_ip, payload_lenght)
    # icmpv6_header = create_icmpv6_header()
    
    # pct = eth_header + ipv6_header + icmpv6_header
    # s.send(pct)
    # compromised.append(sender_ip)

def receive_ipv6(s, packet, mac_src): 
    first_word, payload_lenght, next_header, hoplimit = struct.unpack('>IHBB', packet[0:8])
    # sender_ip = struct.unpack('!32s', packet[8:24])
    sender_ip = bytes_to_ipv6(packet[8:24])
    payload = packet[40:]

    if is_compromised(sender_ip,next_header):
        return

    if next_header == socket.IPPROTO_ICMPV6:
        icmp_type, icmp_code, icmp_chekcsum = struct.unpack('>BBH', payload[:4])

        if icmp_type == RTR_SOL:
            print("\n\n-------------------------------------------------------------")
            print("Router Solicitation: ")
            print("Sender IP: ", sender_ip)
            print("\n")
            if sender_ip != get_my_ipv6():
                send_icmpv6_advertisement(s, packet, mac_src, sender_ip, payload_lenght)

            
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
