import socket
import struct

host = '192.168.1.7'
# AF_INET: IPv4, SOCK_RAW: Capture everything (TCP, UDP, ICMP...) IPPROTO_IP: IP protocol
IP4_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
IP4_socket.bind((host, 0))
# Include IP header (Windows would strip this by default)
IP4_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Setting up promiscuous mode: Capture everything 
# Promiscuous mode would capture even the packets that are not meant for you
IP4_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
print(f"Sniffer started on {host}. Listening for traffic...")


def Resolve_IP(IP_Packet):
    # Inputs binary form IP_Packet and returns TTL, Protocol, Source IP and Destination IP as integers and strings and TCP_Segment as binary
    # IP Header is 20 bytes 
    IP_Header = IP_Packet[:20]
    TCP_Segment = IP_Packet[20:]
    TTL, Protocol, Source_IP, Destination_IP = struct.unpack("! 8x B B 2x 4s 4s", IP_Header)
    Source_IP = socket.inet_ntoa(Source_IP)
    Destination_IP = socket.inet_ntoa(Destination_IP)
    return TTL, Protocol, Source_IP, Destination_IP, TCP_Segment

def Resolve_TCP(TCP_Segment):
    # TCP Header is 20 bytes 
    TCP_header = TCP_Segment[:20]
    Application_Data = TCP_Segment[20:]
    Source_Port, Destination_Port = struct.unpack("! H H 16x", TCP_header)
    return Source_Port, Destination_Port, Application_Data

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

