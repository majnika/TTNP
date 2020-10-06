from typing import Callable, Dict
from packet import Packet
from server import Server

server: Server = Server(TTL=15)

def begin_Handshake(pack: Packet):
    pass

def begin_Diffie_Hellman(pack: Packet):
    pass

def finalize_Diffie_Hellman(pack: Packet):
    pass

def begin_Crypto_Check(pack: Packet):
    pass

def finalize_Crypto_Check(pack: Packet):
    pass

def finalize_Handshake(pack: Packet):
    pass

def handle_Heartbeat(pack: Packet):
    pass

def begin_Client_Termination(pack: Packet):
    pass

def Terminate_Client(pack: Packet):
    pass

def finalize_Client_Termination(pack: Packet):
    pass

def force_Terminate_Connection(pack: Packet):
    pass

miezdu: Dict[str, Callable[[Packet], None]] = {
    "CHI": begin_Handshake,
    "SDH": begin_Diffie_Hellman,
    "CDH": finalize_Diffie_Hellman,
    "SCC": begin_Crypto_Check,
    "CCC": finalize_Crypto_Check,
    "SHF": finalize_Handshake,
    "CHB": handle_Heartbeat,
    "CGB": begin_Client_Termination,
    "SGB": Terminate_Client,
    "CFL": finalize_Client_Termination,
    "SFL": force_Terminate_Connection
}

for key in miezdu.keys():
    server.add_handler(miezdu[key],key)

if __name__ == "__main__":
    server.listen_on(addr="localhost",port=1337)