from base64 import urlsafe_b64encode
from datetime import datetime
from typing import Tuple
from cryptography.fernet import Fernet
from queue import Queue
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey#, DHParameters
from packet import Packet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_public_key
from  cryptography.hazmat.primitives.serialization import PublicFormat

class Connection:

    def __init__(self, addr: Tuple[str, int], server: str, TTL:float, incoming_queue: "Queue[Packet]", outgoing_queue: "Queue[Packet]") -> None:
        self.addr: Tuple[str, int] = addr
        self.server: str = server
        self._state: str = "Initiated"
        self._q_IN = incoming_queue
        self._q_OUT = outgoing_queue
        self._last_hb: datetime
        self.TTL: float = TTL
        self._f: Fernet
        self._hanshake_sequence: "list[str]" = ["CHI","CDH","CCC"]

    def handshake(self):
        pack = Packet("SHI","Hello",self.server)
        pack.packed_data = pack.contents.encode()
        pack.addr = self.addr
        self.ship(pack)

        #TODO maybe exchange parameters in SHI
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2

        params_numbers = dh.DHParameterNumbers(p,g,None)
        parameters = params_numbers.parameters(default_backend())

        # parameters: DHParameters = dh.generate_parameters(generator=2, key_size=2048,backend=default_backend()) #type: ignore

        private_key: DHPrivateKey = parameters.generate_private_key()
        
        public_key: DHPublicKey = private_key.public_key()

        encoded_public_key: bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        segments: "list[bytes]" = []

        j: int = 0

        print("Server public key:")
        print(encoded_public_key)

        for i in range(0,800,201):
            print(i)
            flag_plus_data = f"CDHS:{j}|".encode() + encoded_public_key[i:i+201]
            segments.append(flag_plus_data + ('#'*(250 - len(flag_plus_data))).encode() + '|'.encode() + self.server.encode() + '\n'.encode())
            j -=- 1   

        for i in segments:
            pack: Packet = Packet("SDH","",self.server)
            pack.packed_data = i
            pack.addr = self.addr
            self.ship(pack)

        del segments

        packs: "list[Packet]" = []

        client_public_key: bytes = bytes()

        for _ in range(4):
            packs.append(pack := self._q_IN.get(block=True,timeout=120.0))
            # print(pack.raw_data)
            client_public_key += pack.raw_data.split('|')[1].rstrip('#').encode("utf-8")
        
        print("Client public key:")
        print(client_public_key)

        client_public_key_decoded: DHPublicKey = load_pem_public_key(client_public_key,backend=default_backend())

        shared_key = private_key.exchange(client_public_key_decoded)

        shared_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
        print(shared_key)

        self._f = Fernet(urlsafe_b64encode(shared_key))

        ccc: Packet = self._q_IN.get()

        print(self.unpack(ccc).raw_data) 

    def ship(self, pack: Packet) -> None:
        self._q_OUT.put(pack)

    def pack(self, to_pack: Packet) -> Packet:
        msg: bytes = bytes()
        msg += to_pack.flag.encode()
        msg += self._f.encrypt((to_pack.data).encode())   
        # msg += ('#'*(248 - len(msg))).encode()
        msg += to_pack.server.encode()
        msg += "\n".encode()
        to_pack.packed_data = msg
        return to_pack

    def unpack(self, to_unpack: Packet) -> Packet:
        to_unpack.data = self._f.decrypt(to_unpack.data.encode()).decode()
        return to_unpack

    @property
    def is_alive(self) -> bool:
        return (datetime.now() - self._last_hb).seconds < self.TTL

if __name__ == "__main__":

    conn: Connection = Connection(("a",80),"0001",5.0,Queue(),Queue())

    conn._last_hb = datetime.now() #type: ignore

    while True:
        print(conn.is_alive)
