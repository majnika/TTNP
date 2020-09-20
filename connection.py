from datetime import datetime
from typing import Tuple

class Connection:

    def __init__(self, addr: Tuple[str, int] ,TTL:float) -> None:
        self.addr: Tuple[str, int] = addr
        self.state: str = "Initiated"
        self.last_hb: datetime
        self.TTL: float = TTL

    #await received("CDH")

    @property
    def is_alive(self) -> bool:
        return (datetime.now() - self.last_hb).seconds < self.TTL

conn: Connection = Connection(("a",80),5.0)

conn.last_hb = datetime.now()

while True:
    print(conn.is_alive)
