import socket
import os 

host = '192.168.1.5'

def main():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print(f"Sniffer started on {host}. Listening for traffic...")

    try: 
        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            print(f"Caught raw Packet! Raw Data: {raw_buffer[:20]}")
    except KeyboardInterrupt: 
        print("\n Exiting...")
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
if __name__== "__main__": 
    main()