import socket
hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)
print(hostname)
print(ip_address)