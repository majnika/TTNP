from enum import Flag
from types import FunctionType
from typing import overload
from cryptography.fernet import Fernet
from packet import Packet
import socket
import threading
import colorama
colorama.init()
from termcolor import colored

class Server:
    """
    This is the base class of the Python "The Thing" Networking Protocol server.
    This server handles incoming packets using your created functions, which have been
    added to the mapper of the class using the `add_handler` method
    """

    _mapper = dict()
    addr = tuple
    _f = Fernet
    _cli = bool
    _cli = False
    PACKET_SIZE = 256
    _report_types = {
        0 : "white",    #Ordinary
        1 : "green",    #Success
        2 : "yellow",   #Warning
        3 : "red"       #Error
    }


    def __init__(self) -> None:
        self.f = Fernet(Fernet.generate_key())


    def _report(self, msg: str, sender: str = "REPORT", type: int = 0):
        if self._cli:
            if type in self._report_types.keys():
                msg = f"[{sender}]: {msg}"
                print(colored(msg,self._report_types[type]))
            else:
                raise Exception


    def add_handler(self, func: FunctionType, flag: str) -> None:
        self._mapper[flag] = func


    def _accept_connections(self) -> None:
        
        while True: #Change this to something sexier, maybe recursion ( ͡° ͜ʖ ͡°) 
            conn, addr = self._socket.accept()
            thread = threading.Thread(target = self._handle_incoming, args=(conn, addr))
            thread.start()
            self._report(f"New thread {thread.getName()} is serving {addr}",thread.getName().capitalize())


    def _handle_incoming(self, conn: socket, pack: Packet) -> None:

        connected = True

        while connected:

            pack = Packet(conn.recvfrom(self.PACKET_SIZE)[0])
            self._report(f"Packet with content:{pack.raw} arrived",threading.get_ident())

            self._mapper[pack.flag](pack)


    def add_address(self, addr: str, port: int) -> None:
        self.addr = tuple([addr, port])


    def add_address_socket(self, addr_port: tuple) -> None:
        self.addr = addr_port


    def listen(self, cli: bool = True) -> None: #cli: bool option specifies whether control data should be displayed to the cli
        self._report(f"Server is starting","SERVER")
        self._cli = cli
        if self.addr:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.bind(self.addr)
            self._socket.listen()
            self._report(f"Server is listening on {self.addr}","SERVER")
            self._accept_connections()
        else:
            raise Exception


    def listen_on(self, addr: str, port: int, cli: bool = True):
        self.addr = tuple([addr, port])
        self.listen(cli)


    def listen_on_socket(self, addr_port: tuple, cli: bool = True) -> None:
        self.addr = addr_port
        self.listen(cli)


    def pack(self, pack: Packet) -> bytes:
        if isinstance(pack,Packet):
            msg = bytes()
            msg += bytes(pack.flag) 
            msg += self.f.encrypt((pack.data).encode())   
            msg += ('#'*(251 - len(msg))).encode()
            msg += bytes(pack.server)
            msg += "\n".encode()
            return msg
        else:
            return TypeError
