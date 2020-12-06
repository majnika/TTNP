from base64 import urlsafe_b64encode
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey#, DHParameters
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from packet import Packet
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import math

class Client:

    MAX_PACKET_SIZE: int = 2048
    _keep_alive: bool = True
    addr: str
    port: int

    def __init__(self, addr: "tuple[str,int] | str"):
        if isinstance(addr,str):
            self.addr, self.port = addr.split(":")[0], int(addr.split(":")[1])
        else:
            self.addr, self.port = addr

    def connect(self):
        self.connect_to(self.addr,self.port)

    def connect_to(self, add:str, port:int):
        self._sock: socket.socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self._sock.connect((add,port))

        pack: Packet = Packet("CHI","Ferko","0000")

        # print(f"Sending: {pack.contents}")

        self.ship(self.pack(pack, encrypt=False))

        shi: Packet = Packet.from_bytes(self._sock.recvfrom(self.MAX_PACKET_SIZE)[0])

        self.server: str = shi.server

        self.TTL = float(shi.raw_data.split("|")[1].split(":")[1].rstrip('#'))

        print(f"TTL:{self.TTL}")

        # print("Listening for SDH")

        server_public_key: bytes = bytes()

        for i in range(4):
            segment: Packet = Packet.from_bytes(self._sock.recvfrom(self.MAX_PACKET_SIZE)[0])
            server_public_key += segment.raw_data.split('|')[1].rstrip('#').encode("utf-8")

        # print("Server public key:")
        # print(server_public_key)

        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2

        params_numbers = dh.DHParameterNumbers(p,g,None)
        parameters = params_numbers.parameters(default_backend())

        # parameters: DHParameters = dh.generate_parameters(generator=2, key_size=2048,backend=default_backend()) #type: ignore

        private_key: DHPrivateKey = parameters.generate_private_key() #type: ignore

        public_key: DHPublicKey = private_key.public_key()

        encoded_public_key: bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        # print("Client public key:")
        # print(encoded_public_key)

        j: int = 0

        for i in range(0,800,201):
            # print(i)
            flag_plus_data = f"CDH:{j}|".encode() + encoded_public_key[i:i+201]
            flag_plus_data += ('#'*(250 - len(flag_plus_data))).encode() + '|'.encode() + self.server.encode() + '\n'.encode()
            pack = Packet("SDH","",self.server)
            pack.packed_data = flag_plus_data
            self.ship(pack)
            j -=- 1

        server_public_key_decoded: DHPublicKey = load_pem_public_key(server_public_key,backend=default_backend()) #type: ignore

        shared_key = private_key.exchange(server_public_key_decoded)

        shared_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
        # print(shared_key)

        self._f = Fernet(urlsafe_b64encode(shared_key))

        packet = Packet("CCC","Hello, yes I can.",self.server)

        self.pack(packet).packed_data

        # print(len(packet.packed_data))

        self._sock.send(packet.packed_data)

        # print(self._f.decrypt(Packet.from_bytes(self._sock.recvfrom(self.MAX_PACKET_SIZE)[0]).raw_data.encode()).rstrip(b'#'))

        self._heartbeat()

    def _heartbeat(self):
        hb_thread = threading.Thread(target=self._hb_func)
        hb_thread.start()

    def _hb_func(self):
        while self._keep_alive:
            self.ship(self.pack(Packet("CHB","HB",self.server)))
            time.sleep(self.TTL-2)

    def pack(self,to_pack: Packet, encrypt: bool = True) -> Packet:
                msg: bytes = bytes()
                msg += to_pack.flag.encode()
                # print(len(to_pack.data))
                if encrypt:
                    msg += self._f.encrypt((to_pack.data).encode()) 
                else:
                    msg += to_pack.data.encode()
                    msg += (b'#' * (248 - len(to_pack.data)))
                msg += to_pack.server.encode()
                msg += "\n".encode()
                to_pack.packed_data = msg
                return to_pack

    def unpack(self, to_unpack: Packet) -> Packet:
        to_unpack.data = self._f.decrypt(to_unpack.raw_data.encode()).decode()
        return to_unpack

    def ship(self, pack:Packet) -> None:
        #print(pack.packed_data)
        self._sock.send(pack.packed_data)

    def disconnect(self):
        self._keep_alive = False
        self.ship(self.pack(Packet("CGB","Bye",self.server)))
        self._sock.recv(self.MAX_PACKET_SIZE)
        self.ship(self.pack(Packet("CFL","",self.server)))
        client._sock.close()

    def send_message(self, msg:str) -> None:
        self.ship(self.pack(Packet("CBT",f"Type:Data|Slices:{math.ceil((len(msg)/700))}",self.server)))
        self._sock.recv(self.MAX_PACKET_SIZE)
        self.ship(self.pack(Packet("CPD",f"S:0|Data:{msg}",self.server)))

if __name__ == "__main__":

    client:Client = Client(("localhost",1337))

    client.connect_to("localhost",1337)

    while (x := input()) != "exit":
        client.send_message(x)
    else:
        client.disconnect()
