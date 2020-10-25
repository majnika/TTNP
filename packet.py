from typing import Dict, Tuple


class Packet:

    addr: Tuple[str, int]
    packed_data: bytes
    _dict: Dict[str, bytes] = dict()

    def __init__(self,flag: str, data: str, server: str) -> None:
        self.flag = flag
        self._str_data: str = data
        self.server = server
        if self.flag[2] == "D":
            for key, item in [i.split(':') for i in data.split('|')]:
                self._dict[key] = item.encode("utf-8")

    def __str__(self) -> str:
        return self.contents[0:-1]

    def __getitem__(self, key: str) -> bytes:
        return self._dict[key]

    @classmethod
    def from_bytes(cls, raw_bytes: bytes, decode: bool = True):
        raw: str = raw_bytes.decode()
        return cls(
        # raw[0:3],
        # raw[3:251],
        # raw[251:255]
        # )
        raw[0:3],
        raw[3:len(raw)-5],
        raw[len(raw)-5:len(raw)-1]
        )



    @property
    def contents(self) -> str:
        return self.flag + self.data + self.server + '\n'

    @property
    def raw_data(self) -> str:
        return self._str_data

    @property
    def data(self) -> str:
        return self._str_data + ('#'*(127 - len(self._str_data)))

    @data.setter
    def data(self,raw: str) -> None:
        self._str_data = raw.rstrip('#')
