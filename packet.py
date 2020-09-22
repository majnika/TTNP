from typing import Tuple


class Packet:

    addr: Tuple[str, int]
    packed_data: bytes

    def __init__(self,flag: str, data: str, server: str) -> None:
        self.flag = flag
        self._str_data: str = data
        self.server = server

    def __str__(self) -> str:
        return self.contents

    @classmethod
    def from_bytes(cls,raw_bytes: bytes):
        raw: str = raw_bytes.decode()
        return cls(
        raw[0:3],
        (raw[3:251]).rstrip('#'),
        raw[251:257]
        )

    @property
    def contents(self) -> str:
        return self.flag + self.data + self.server

    @property
    def raw_data(self) -> str:
        return self._str_data

    @property
    def data(self) -> str:
        return self._str_data + ('#'*(251 - len(self.flag + self._str_data)))

    @data.setter
    def data(self,raw: str) -> None:
        self._str_data = raw.rstrip('#')
