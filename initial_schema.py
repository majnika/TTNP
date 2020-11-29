from connection import Connection
from typing import Callable, Dict
from packet import Packet
from server import Server
from connection import Connection
from transaction import Transaction, TransactionTypes

server: Server = Server(TTL=15)

def begin_Handshake(pack: Packet, conn: Connection) -> None:
    pass

def begin_Diffie_Hellman(pack: Packet, conn: Connection) -> None:
    pass

def finalize_Diffie_Hellman(pack: Packet, conn: Connection) -> None:
    pass

def begin_Crypto_Check(pack: Packet, conn: Connection) -> None:
    pass

def finalize_Crypto_Check(pack: Packet, conn: Connection) -> None:
    pass

def finalize_Handshake(pack: Packet, conn: Connection) -> None:
    pass

def handle_Heartbeat(pack: Packet, conn: Connection) -> None:
    conn.renew()
    conn.report("Connection renewed",1)

def begin_Client_Termination(pack: Packet, conn: Connection) -> None:
    conn.ship(conn.pack(Packet("SGB","Bye",conn.server)))
    conn.state = "Ready for Termination"

def Terminate_Client(pack: Packet, conn: Connection) -> None:
    pass

def finalize_Client_Termination(pack: Packet, conn: Connection) -> None:
    if conn.state == "Ready for Termination":
        conn.terminate() #TODO
        conn.report("Connection has been Terminated by remote host")

def force_Terminate_Connection(pack: Packet, conn: Connection) -> None:
    pass

def begin_Client_Transaction(pack: Packet, conn: Connection) -> None:
    conn.parse_packet_data(conn.unpack(pack))
    conn.transaction = Transaction(TransactionTypes[pack["Type"]],int(pack["Slices"])) #Add types: Data, Authorization, Querry
    conn.ship(conn.pack(Packet("SUM","",conn.server)))

def handle_Client_Data(pack: Packet, conn: Connection) -> None:

    miezdu: str = str()

    conn.parse_packet_data(conn.unpack(pack))

    if conn.transaction.type == TransactionTypes.Data:
       if int(pack["S"]) == conn.transaction.sequence:
            miezdu += pack["Data"]
            conn.transaction.sequence += 1
    
    print(conn.transaction.sequence,conn.transaction.slices)

    if conn.transaction.sequence == conn.transaction.slices:
        conn.report(miezdu)


miezdu: Dict[str, Callable[[Packet, Connection], None]] = {
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
    "SFL": force_Terminate_Connection,
    "CBT": begin_Client_Transaction,
    "CPD": handle_Client_Data,
}

for key in miezdu.keys():
    server.add_handler(miezdu[key],key)

if __name__ == "__main__":
    server.listen_on(addr="localhost",port=1337)