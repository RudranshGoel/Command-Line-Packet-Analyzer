import socket
import os 
import struct 

host = '192.168.1.7'




def main():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print(f"Sniffer started on {host}. Listening for traffic...")

    try: 
        # while True:
            raw_buffer, addr = sniffer.recvfrom(65565)


            IP_header = raw_buffer[:20]
            ttl, protocol, source_ip, destination_ip = struct.unpack("! 8x B B 2x 4s 4s", IP_header)
            print(f"Time to live: {ttl}")
            print(f"Protcol: {protocol}")
            print(type(ttl))
            source_ip = socket.inet_ntoa(source_ip)
            destination_ip = socket.inet_ntoa(destination_ip)
            print(type(source_ip))
            print(f"Source: {source_ip}")
            print(f"Destination: {destination_ip}")
            TCP_segment = raw_buffer[20:]
            TCP_header = TCP_segment[:20]
            source_port, destination_port = struct.unpack("! H H 16x", TCP_header)
            print(f"Source port: {source_port}")
            print(f"Destination port: {destination_port}")


    except KeyboardInterrupt: 
        print("\n Exiting...")
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
if __name__== "__main__": 
    main()