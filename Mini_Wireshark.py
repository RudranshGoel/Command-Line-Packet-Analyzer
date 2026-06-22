import socket
import struct
import argparse



def Resolve_IP(IP_Packet):
    # Inputs binary form IP_Packet and returns TTL, Protocol, Source IP and Destination IP as integers and strings and TCP_Segment as binary
    # IP Header is 20 bytes 
    IP_Header = IP_Packet[:20]
    Layer_3 = IP_Packet[20:]
    TTL, Protocol, Source_IP, Destination_IP = struct.unpack("! 8x B B 2x 4s 4s", IP_Header)
    Source_IP = socket.inet_ntoa(Source_IP)
    Destination_IP = socket.inet_ntoa(Destination_IP)
    return TTL, Protocol, Source_IP, Destination_IP, Layer_3

def Resolve_TCP(TCP_Segment):
    # TCP Header is 20 bytes 
    TCP_header = TCP_Segment[:20]
    Application_Data = TCP_Segment[20:]
    Source_Port, Destination_Port, Seq_No, Ack_No, Offer_Reserved_Flags = struct.unpack("! H H L L H 6x", TCP_header)
    flag_urg = (Offer_Reserved_Flags & 32) >> 5
    flag_ack = (Offer_Reserved_Flags & 16) >> 4
    flag_psh = (Offer_Reserved_Flags & 8) >> 3
    flag_rst = (Offer_Reserved_Flags & 4) >> 2
    flag_syn = (Offer_Reserved_Flags & 2) >> 1
    flag_fin = Offer_Reserved_Flags & 1
    s = "TCP Flags: "
    if flag_urg: s +='URG '
    if flag_ack: s+=('ACK ')
    if flag_psh: s+=('PSH ')
    if flag_rst: s+=('RST ')
    if flag_syn: s+=('SYN ')
    if flag_fin: s+=('FIN ')
    return Source_Port, Destination_Port, Application_Data, s

def Resolve_UDP(UDP_Segment):
    # The UDP header is always exactly 8 bytes
    UDP_header = UDP_Segment[:8]
    Application_Data = UDP_Segment[8:]
    
    # ! = Network Byte Order
    # H = Source Port (2 bytes)
    # H = Destination Port (2 bytes)
    # 4x = Skip the remaining 4 bytes (Length and Checksum)
    Source_Port, Destination_Port = struct.unpack("! H H 4x", UDP_header)
    
    return Source_Port, Destination_Port, Application_Data

def Resolve_ICMP(ICMP_Segment):
    # We will slice the first 4 bytes to get the primary diagnostic info
    ICMP_header = ICMP_Segment[:4]
    Application_Data = ICMP_Segment[4:]
    
    # ! = Network Byte Order
    # B = Type (1 byte, unsigned char)
    # B = Code (1 byte, unsigned char)
    # 2x = Skip the 2-byte Checksum
    Type, Code = struct.unpack("! B B 2x", ICMP_header)
    
    return Type, Code, Application_Data


def get_active_ip():
    """
    Creates a temporary dummy socket to determine the machine's 
    primary local IP address facing the internet.
    """
    dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # We don't actually send any data, just forcing the OS to route
        dummy_socket.connect(('8.8.8.8', 80))
        local_ip = dummy_socket.getsockname()[0]
    except Exception:
        # Fallback in case there is no internet connection at all
        local_ip = '127.0.0.1'
    finally:
        dummy_socket.close()
    
    return local_ip

def print_options(args):
    if args.protocol is not None: 
        print(f"[*]Protocol: {args.protocol}")
    else: 
        print("[*]Protocol: Any")
    if args.source is not None: 
        print(f"[*]Source: {args.source}")
    else: 
        print("[*]Source: Any")
            
    if args.destination is not None: 
        print(f"[*]Destination: {args.destination}")
    else: 
        print("[*]Destination: Any")
    print("---------------------------------------------------------------------------")

def main():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=50)
    )

    parser.add_argument('-c', '--count', type = int, default=None, help='Number of packets to capture')
    parser.add_argument('-src', '--source', type=str, default=None, help='Filter by Source IP')
    parser.add_argument('-dst', '--destination', type=str, default=None, help='Filter by Destination IP')
    parser.add_argument('-t', '--protocol', type=str, default=None, help='Filter by Protocol (tcp, udp, icmp)')

    args = parser.parse_args()


    host = get_active_ip()
    # AF_INET: IPv4, SOCK_RAW: Capture everything (TCP, UDP, ICMP...) IPPROTO_IP: IP protocol
    IP4_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    IP4_socket.bind((host, 0))
    # Include IP header (Windows would strip this by default)
    IP4_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Setting up promiscuous mode: Capture everything 
    # Promiscuous mode would capture even the packets that are not meant for you
    IP4_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[*] Sniffer started on {host}")
    print_options(args)

    count=0
    try:
        while (args.count is None) or (count < args.count):
            raw_buffer, addr = IP4_socket.recvfrom(65565)
            TTL, Protocol, Source_IP, Destination_IP, Layer_3 = Resolve_IP(raw_buffer)

            # Protocol Map: 
            # 6--> TCP 
            # 17--> UDP 
            # 1--> ICMP
            Protocol_map = {
                1: 'ICMP',
                6: 'TCP',
                17: 'UDP'
            }

            Protocol_Name = Protocol_map.get(Protocol, 'Unknown')
            if Protocol==1: 
                Type, Code, Application_Data = Resolve_ICMP(Layer_3)
            elif Protocol==6: 
                Source_Port, Destination_Port, Application_Data, Flag_info = Resolve_TCP(Layer_3)
            elif Protocol==17: 
                Source_Port, Destination_Port, Application_Data = Resolve_UDP(Layer_3)

            drop = False
            if args.source is not None: 
                if Source_IP != args.source: 
                    drop = True
            if args.destination is not None: 
                if Destination_IP != args.destination: 
                    drop = True
            if args.protocol is not None: 
                if Protocol_Name.lower() != args.protocol.lower(): 
                    drop = True
            
            if drop == False: 
                #  Print packet 
                count += 1
                print(f"{count:<5}{Protocol_Name:<7}{Source_IP:<15}-->{Destination_IP:<15}", end="\t")
                if Protocol == 1: 
                    ICMP_Type = {
                        0: 'Echo reply',
                        3: 'Destination unreachable',
                        5: 'Redirect message',
                        8: 'Echo request',
                        11: 'Time exceeded',
                        12: 'Parameter problem',
                    }
                    print(f"Type={ICMP_Type[Type]}, Code={Code}")
                elif Protocol == 6: 
                    print(f"s_port={Source_Port}, d_port={Destination_Port}, {Flag_info}")
                else: 
                    print(f"s_port={Source_Port}, d_port={Destination_Port}")




    except KeyboardInterrupt: 
        print("\nExiting...")
    
    


    
    
    
    IP4_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        



if __name__== "__main__": 
    main()