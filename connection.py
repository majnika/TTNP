from datetime import datetime
from typing import Tuple
from cryptography.fernet import Fernet
from queue import Queue
from packet import Packet

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
        pack.packed_data = pack.contents.encode() + '\n'.encode()
        breakpoint()
        pack.addr = self.addr
        self.ship(pack)

    def ship(self, pack: Packet) -> None:
        self._q_OUT.put(pack)

    def pack(self, to_pack: Packet) -> Packet:
        msg: bytes = bytes()
        msg += to_pack.flag.encode()
        msg += self._f.encrypt((to_pack.data).encode())   
        msg += ('#'*(251 - len(msg))).encode()
        msg += to_pack.server.encode()
        msg += "\n".encode()
        to_pack.packed_data = msg
        return to_pack

    @property
    def is_alive(self) -> bool:
        return (datetime.now() - self._last_hb).seconds < self.TTL

if __name__ == "__main__":

    conn: Connection = Connection(("a",80),"0001",5.0,Queue(),Queue())

    conn._last_hb = datetime.now() #type: ignore

    while True:
        print(conn.is_alive)
