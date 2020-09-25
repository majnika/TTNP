from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey#, DHParameters
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from packet import Packet
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from server import Server

PACKET_SIZE: int = 256
port: int = 1337
server_addr: str = "localhost"

client: socket.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
client.connect((server_addr,port))

pack: Packet = Packet("CHI","Ferko","0000")

print(f"Sending: {pack.contents}")

client.send(pack.contents.encode())

server: str = Packet.from_bytes(client.recvfrom(PACKET_SIZE)[0]).server

packets: "list[Packet]" = []

print("Listening for SDH")

server_public_key: bytes = bytes()

for i in range(4):
    segment: Packet = Packet.from_bytes(client.recvfrom(PACKET_SIZE)[0])
    packets.append(segment)
    server_public_key += segment.raw_data.split('|')[1].rstrip('#').encode("utf-8")

print("Server public key:")
print(server_public_key)

# for i in packets:
#     print(i.raw_data,end="")

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

params_numbers = dh.DHParameterNumbers(p,g,None)
parameters = params_numbers.parameters(default_backend())

# parameters: DHParameters = dh.generate_parameters(generator=2, key_size=2048,backend=default_backend()) #type: ignore

private_key: DHPrivateKey = parameters.generate_private_key() #type: ignore

public_key: DHPublicKey = private_key.public_key()

encoded_public_key: bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

print("Client public key:")
print(encoded_public_key)

segments: "list[bytes]" = []

j: int = 0

for i in range(0,800,201):
    print(i)
    flag_plus_data = f"CDHS:{j}|".encode() + encoded_public_key[i:i+201]
    segments.append(flag_plus_data + ('#'*(250 - len(flag_plus_data))).encode() + '|'.encode() + server.encode() + '\n'.encode())
    j -=- 1    

for i in segments:
    pack: Packet = Packet("CDH","",server)
    pack.packed_data = i
    client.send(pack.packed_data)

server_public_key_decoded: DHPublicKey = load_pem_public_key(server_public_key,backend=default_backend())

shared_key = private_key.exchange(server_public_key_decoded)

shared_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
print(shared_key)

client.close()
