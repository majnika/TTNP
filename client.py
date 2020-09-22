from packet import Packet
import socket
# from server import Server

PACKET_SIZE: int = 2112
port: int = 1337
server: str = "localhost"

client: socket.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
client.connect((server,port))

pack: Packet = Packet("CHI","Ferko","0000")

print(f"Sending: {pack.contents}")

client.send(pack.contents.encode())

print(client.recvfrom(PACKET_SIZE))

client.close()
