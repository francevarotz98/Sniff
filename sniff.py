'''
Python script which parses network packets
(similar to tcpdump)
'''
#NOTE : + use it with python3
#       + necessary root privileges


import socket
import struct
from termcolor import colored as color
import textwrap
import sys
# import pyfiglet #used to create the banner


#        ----------------> ETHERNET FRAME <----------------
#      0                   1                   2                   3                   4
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                      Destination Address   6 byte                             |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                         Source Address     6 byte                             |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |           EtherType   2 byte  |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                               +
#     |                                                                                               |
#     +                                            Payload        46-1500 byte                        +
#     |                                                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


#unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) # ! : means 'network order'
                                                                     # 6s : 6 byte (for source and dest)
                                                                     # H : unsigned int (for proto)
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]

#return formatted MAC address
def get_mac_addr(data):
    tmp = map("{:02x}".format,data) #tmp: iterable which contains 2 hex. values
                                    # to take a look at it, print list(tmp)
    return ':'.join(tmp).upper()


def arp_packet(data):
    opcode, sender_mac,sender_ip, target_mac, target_ip = struct.unpack('! 2s 6s 4s 6s 4s', data[6:28])
    return int.from_bytes(opcode,"big"),get_mac_addr(sender_mac),get_ipv4(sender_ip),get_mac_addr(target_mac),get_ipv4(target_ip)


#           ----------------> IP PACKET <----------------
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   ------------
#    |Version|  IHL  |Type of Service|          Total Length         |    ^     ^
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |     |
#    |         Identification        |Flags|      Fragment Offset    |    |     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |     |
#    |  Time to Live |    Protocol   |         Header Checksum       |    |     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  20 bytes|
#    |                       Source Address    4 byte                |    |     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    |    IHL
#    |                    Destination Address  4 byte                |    |     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+    ^     |
#    |                    Options                    |    Padding    |          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  --------^----
# ip="Version:4,IHL:4,Type of Service:8,Total Length:16,Identification:16,\
# Flags:3,Fragment Offset:13,Time to Live:8,Protocol:8,Header Checksum:16,\
# Source Address:32,Destination Address:32,Options:24,Padding:8"
# unit: bit
#
# IHL (HEADER length)
# when the field Protocol=6 --> next encapsulated protocol is TCP
# when the field Protocol=1 --> next encapsulated protocol is ICMP
# when the field Protocol=17 --> next encapsulated protocol is UDP
# see https://www.eit.lth.se/ppplab/IPHeader.htm#Protocol for others

# unpack IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0] #I need to divide them using mask
    version = version_header_length >> 4
    header_length =  (version_header_length & 15) * 4 #I need it to know where data start
    ttl, proto, src, target, = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) #ip data is 20B long
    return version, header_length, ttl, proto, get_ipv4(src), get_ipv4(target), data[header_length:]

#return formatted IPv4 address
def get_ipv4(addr):
    return '.'.join(map(str,addr))


#      ----------------> ICMPv4 Generic Header <----------------
#
#      0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |      Type     |      Code     |            Checksum           |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                                               |
#     +                          Message Body                         +
#     |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#icmp="Type:8,Code:8,Checksum:16,Message Body:64"

#unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]



#       ----------------> TCP packet <----------------
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |          Source Port          |       Destination Port        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                        Sequence Number                        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Acknowledgment Number                      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    | Offset|  Res. |     Flags     |             Window            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Checksum            |         Urgent Pointer        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Options                    |    Padding    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             data                              |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#tcp="Source Port:16,Destination Port:16,Sequence Number:32,\
#  Acknowledgment Number:32,Offset:4,Res.:4,Flags:8,Window:16,Checksum:16,\
#  Urgent Pointer:16,Options:24,Padding:8"


#unpack TCP  segment
def tcp_segment(data):
    (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack('! H H L L H',data[:14])
    offset = (offset_reserved_flags >> 12)*4
    flags_urg =  (offset_reserved_flags & 32)>> 5
    flags_ack =  (offset_reserved_flags & 16)>> 4
    flags_psh =  (offset_reserved_flags & 8) >> 3
    flags_rst =  (offset_reserved_flags & 4) >> 2
    flags_syn =  (offset_reserved_flags & 2) >> 1
    flags_fin =   offset_reserved_flags & 1
    return src_port, dest_port, seq, ack, flags_urg,flags_ack,flags_psh,flags_rst,flags_syn,flags_fin,data[offset:]

#get ip address of my machine
def get_ipAddr():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8",80))
    ip = s.getsockname()[0]
    s.close()
    return ip


#if -i flag is set, print only the packets sent/received
#to/from ip address
def follow_ip(ip, max_pck=5000):
    nr_pck = 1
    while nr_pck <= int(max_pck):
        raw_data ,addr = s.recvfrom(65536)

        # Ethernet frame
        dest_mac,src_mac,eth_proto,data_eth = ethernet_frame(raw_data)

        # IPv4 protocol
        if eth_proto == 8:

            version_ip, header_length_ip, ttl_ip, proto_ip, src_ip, target_ip, data_ip = ipv4_packet(data_eth)

            #if I enter in the next if, then I print the info of packet
            if target_ip == ip or src_ip == ip:
                print('\n'+str(nr_pck)+') [+] Ethernet frame:')
                print('\tDestination: {}\n\tSource: {}\n\tProtocol: {}'.format(dest_mac, src_mac, eth_proto))

                print(color('\t [+] IPv4 packet:','red'))
                print(color('\t\tDestination: {}\n\t\tSource: {}'.format(target_ip, src_ip),'red'))
                print(color('\t\tProtocol: {}\n\t\tTTL: {}\n\t\tVersion: {}'.format(proto_ip, ttl_ip, version_ip),'red'))

                #ICMP protocol
                if proto_ip == 1:
                    icmp_type, code, checksum, data_icmp = icmp_packet(data_ip)
                    print('\t\t [+] ICMP packet:')
                    print('\t\t\tType: {}\n\t\t\tCode: {}\n\t\t\tChecksum: {}'.format(icmp_type,code,checksum))

                #TCP Protocol
                elif proto_ip == 6:
                        (src_port, dest_port, seq, ack, flags_urg,flags_ack,flags_psh,flags_rst,flags_syn,flags_fin,data_tcp) = tcp_segment(data_ip)
                        print(color('\t\t [+] TCP packet:','magenta'))
                        print(color('\t\t\tDestination port: {}\n\t\t\tSource port: {}'.format(dest_port, src_port),'magenta'))
                        print(color('\t\t\tSequence: {}\n\t\t\tAcknowledgement: {}'.format(seq,ack),'magenta'))

                        #if packet  has data, print it !
                        if len(data_tcp)>0 :

                            #HTTP Protocol DATA
                            if ( src_port == 80 or dest_port == 80 ) :
                                print(color('\t\t\tHTTP Data:','blue','on_grey'))
                                print_data(data_tcp)

                                #HTTPS Protocol DATA
                            elif ( src_port == 443 or dest_port == 443 ) :
                                print(color('\t\t\tHTTPS Data:','cyan', 'on_grey'))
                                print_data(data_tcp)

                                #other protocol data
                            else:
                                print(color('\t\t\tData:','white'))
                                for byte in data_tcp:
                                    #if it is an ascii character (not all of them),
                                    #print it as an ascii one
                                    if byte > 31 and byte <127:
                                        print_ascii(byte)
                                    else:
                                        print(color(r'\x{:02}'.format(byte),'white'),sep='')
                #DNS protocol
                elif proto_ip == 17: #TODO better
                    print(color('\t\t [+] DNS packet:','green'))
                    print_data(data_ip)

                #all the other protocol above IP
                else: #TODO WITH OTHER PROTOCOLS
                    print(color('\t\t [+] Another protocol packet:','green'))
                    print_data(data_ip)

        #ARP protocol
        elif eth_proto == 1544:
            print(color('\t\t [+] ARP packet:','red', 'on_grey'))
            print_data(data_eth)

        else:
            print(color('\t [+] NOT IP packet:','yellow'))
            print_data(data_eth)

        nr_pck += 1
    s.close()
    sys.exit(0)



def follow_all(max_pck=5000):
    nr_pck = 1 # number of packet caught

    while nr_pck <= int(max_pck):
        raw_data ,addr = s.recvfrom(65536)

        # Ethernet frame
        dest_mac,src_mac,eth_proto,data_eth = ethernet_frame(raw_data)
        print('\n'+str(nr_pck)+') [+] Ethernet frame:')
        print('\tDestination: {}\n\tSource: {}\n\tProtocol: {}'.format(dest_mac, src_mac, eth_proto))

        # IPv4 protocol
        if eth_proto == 8:
            version_ip, header_length_ip, ttl_ip, proto_ip, src_ip, target_ip, data_ip = ipv4_packet(data_eth)
            print(color('\t [+] IPv4 packet:','red'))
            print(color('\t\tDestination: {}\n\t\tSource: {}'.format(target_ip, src_ip),'red'))
            #TODO: al posto di proto_ip in numero, mettere il nome a parole
            print(color('\t\tProtocol: {}\n\t\tTTL: {}\n\t\tVersion: {}'.format(proto_ip, ttl_ip, version_ip),'red'))

            #ICMP protocol
            if proto_ip == 1:
                icmp_type, code, checksum, data_icmp = icmp_packet(data_ip)
                if icmp_type == 0:
                    icmp_type = 'Echo reply'
                elif icmp_type == 8:
                    icmp_type = 'Echo request'
                print('\t\t [+] ICMP packet:')
                print('\t\t\tType: {}\n\t\t\tCode: {}\n\t\t\tChecksum: {}'.format(icmp_type,code,checksum))

            #TCP Protocol
            elif proto_ip == 6:
                    (src_port, dest_port, seq, ack, flags_urg,flags_ack,flags_psh,flags_rst,flags_syn,flags_fin,data_tcp) = tcp_segment(data_ip)
                    print(color('\t\t [+] TCP packet:','magenta'))
                    print(color('\t\t\tDestination port: {}\n\t\t\tSource port: {}'.format(dest_port, src_port),'magenta'))
                    print(color('\t\t\tSequence: {}\n\t\t\tAcknowledgement: {}'.format(seq,ack),'magenta'))

                    #if packet  has data, print it !
                    if len(data_tcp)>0 :

                        #HTTP Protocol DATA
                        if ( src_port == 80 or dest_port == 80 ) :
                            print(color('\t\t\tHTTP Data:','blue','on_grey'))
                            print_data(data_tcp)

                        #HTTPS Protocol DATA
                        elif ( src_port == 443 or dest_port == 443 ) :
                            print(color('\t\t\tHTTPS Data:','cyan', 'on_grey'))
                            print_data(data_tcp)

                        #other protocol data
                        else:
                            print(color('\t\t\tData:','white'))
                            for byte in data_tcp:
                                #if it is an ascii character (not all of them),
                                #print it as an ascii one
                                if byte > 31 and byte <127:
                                    print_ascii(byte)
                                else:
                                    print(color(r'\x{:02}'.format(byte),'white'),sep='')

            elif proto_ip == 17: #TODO better
                print(color('\t\t [+] DNS packet:','green'))
                print_data(data_ip)

            #all the other protocol above IP
            else: #TODO WITH OTHER PROTOCOLS
                print(color('\t\t [+] Another protocol packet:','green'))
                print_data(data_ip)

        #ARP protocol
        elif eth_proto == 1544:
            opcode, sender_mac,sender_ip, target_mac, target_ip = arp_packet(data_eth)
            if opcode == 1:
                opcode = 'request'
            else:
                opcode = 'reply'
            print(color('\t [+] ARP packet:','red', 'on_grey'))
            print(color('\t\tOpcode: {}\n\t\tSender MAC: {}'.format(opcode, sender_mac),'white'))
            print(color('\t\tSender IP: {}\n\t\tTarget MAC: {}'.format(sender_ip, target_mac),'white'))
            print(color('\t\tTarget IP: {}'.format(target_ip),'white'))
            #print_data(data_eth)

        else:
            print(color('\t [+] NOT IP packet:','yellow'))
            print_data(data_eth)

        nr_pck += 1
    s.close()
    sys.exit(0)




#print ascii data character, formatted and
#aligned to the text
def print_ascii(x):
    print(color('{}'.format(chr(x)),'yellow'), end='', sep='')


#print not ascii data character, formatted and
#aligned to the text
def print_not_ascii(x):
    print(color(r'\x{:02}'.format(x),'cyan'),end='', sep='')


#print TCP data characters in a formatted and
#aligned way
def print_data(data):
    parsed_data = ''
    for byte in data:
        #if it is an ascii character (not all of them),
        #append it as an ascii one
        if byte > 31 and byte <127:
            parsed_data+='{}'.format(chr(byte))
            #parsed_data+=color('{}'.format(chr(byte)),'yellow')
        else:
            parsed_data+=r'\x{:02}'.format(byte)
    print('\t\t\t  ',end='')
    print('\n\t\t\t  '.join(textwrap.wrap(parsed_data,77)))

#print banner
def print_banner():
    print('''
---------------------------
 ____        _  __  __
/ ___| _ __ (_)/ _|/ _|
\___ \| '_ \| | |_| |_
 ___) | | | | |  _|  _|
|____/|_| |_|_|_| |_Bob098
---------------------------
    ''')

######################## MAIN ################################

if __name__ == '__main__':

    if not '-q' in sys.argv:
        print_banner()

    if ('-h' in sys.argv) or ('--help' in sys.argv):
        print('Usage :\n  sudo python3 sniff.py [flags]\n')
        print('Flags :')
        print('  -h, --help\tHelp for sniff.py')
        print('  -q      \tDo not print the banner')
        print('  -i, --ip\tPrint packets sent/received to/from IP address only')
        print('  -p      \tMax number of printed packets. Default 5000')
        print('  -n      \tAs -i but pass host name instead of IP address. Note: passing IP'
        +' address is more specific, particularly for those web sites which use more than one server.')
        sys.exit(0)


    my_ip = get_ipAddr() #ip address of my machine
    print("[+] My ip address : " +my_ip)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(3))

    #sys.exit(0) ########## TODO: TO REMOVE, for debug only <-------------------

    #follow only packets belonging to 'ip'
    if ('-i' in sys.argv) or ('--ip' in sys.argv) or ('-n' in sys.argv) :
        ip = ''

        #getting ip address passed by host name
        if ('-n' in sys.argv) :
            try:
                host = sys.argv[sys.argv.index('-n')+1]
                print('[+] Host name : '+host)
                ip = socket.gethostbyname(host)
                print('    IP associated : '+ip)
            except :
                print('[-] Not able to resolve \''+host+'\' host name.\nExit ...')
                sys.exit(1)
        #getting ip address directly passed by the user
        else:
            ip = sys.argv[sys.argv.index('-i')+1]

        #check correcteness of ip address
        try:
            socket.inet_aton(ip)
        except:
            print('[-] Not correct \''+ip+'\' IP address.\nExit ...')
            sys.exit(1)

        if ('-p' in sys.argv):
            #max number of packet to sniff
            max_pck = sys.argv[sys.argv.index('-p')+1]
            follow_ip(ip, max_pck)
        else:
            follow_ip(ip)


    #follow anything
    else:
        if ('-p' in sys.argv):
            max_pck = sys.argv[sys.argv.index('-p')+1]
            follow_all(max_pck)
        else:
            follow_all()
