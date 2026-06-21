import socket 

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(('0.0.0.0', 9999))
server.listen(5)

while True: 
    client, address = server.accept()
    print(client.recv(1024).decode())
    client.send("hello from server".encode())
