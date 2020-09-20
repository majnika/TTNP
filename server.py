from queue import Queue
from typing import Dict, Callable, Tuple
from cryptography.fernet import Fernet
from packet import Packet
import socket
import threading
import colorama #type: ignore
colorama.init() #type: ignore
from termcolor import colored

class Server:
    """
    This is the base class of the Python "The Thing" Networking Protocol server.
    This server handles incoming packets using your created functions, which have been
    added to the mapper of the class using the `add_handler` method
    """

    #The mapper of the handler functions
    _mapper: Dict[str, Callable[[Packet], None]] = dict()
    #The address of the server 
    addr: Tuple[str, int]
    #TODO Make a unique instance for every connetion
    _f: Fernet
    #Whether control data will be displayed to the CLI
    _cli: bool = True
    #The size of the packet
    #127 Bits of actual data
    #TODO Make larger packet sizes available if 256 is not sufficient
    PACKET_SIZE: int = 256
    #The queue
    _outgoing_queue: "Queue[Packet]" = Queue(-1)

    _report_types: Dict[int, str] = {
        0 : "white",    #Ordinary
        1 : "green",    #Success
        2 : "yellow",   #Warning
        3 : "red"       #Error
    }


    def __init__(self) -> None:
        self.f = Fernet(Fernet.generate_key())


    def _report(self, msg: str, sender: str = "REPORT", type: int = 0) -> None:
        if self._cli:
            if type in self._report_types.keys():
                msg = f"[{sender}]: {msg}"
                print(colored(msg,self._report_types[type]))
            else:
                raise Exception


    def add_handler(self, func: Callable[[Packet], None], flag: str) -> None:
        self._mapper[flag] = func

    def listen(self, cli: bool = True) -> None: #cli: bool option specifies whether control data should be displayed to the cli
            self._report(f"Server is starting","SERVER")
            self._cli = cli
            if self.addr:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.bind(self.addr)
                # self._socket.listen()
                self._report(f"Server is listening on {self.addr}","SERVER")
                self._accept_connections()
            else:
                raise Exception


    def _accept_connections(self) -> None:
        #Handle incoming packets
        #All packets arrive at this function(TODO test for viability)
        
        #The sender thread handles sanding of all of the outgoing packets from the server
        # sender_thred = threading.Thread(target=self.sender_function)

        while True: #Change this to something sexier, maybe recursion ( ͡° ͜ʖ ͡°) 
            data, addr = self._socket.recvfrom(self.PACKET_SIZE)
            if (pack := Packet.from_bytes(data)).flag == "CHI" and pack.server == "0000": 
                #Packet is a fresh request for connection
                #TODO make a list of connected sockets to prevent pottential system overload from
                #falsly created threads

                pack.addr = addr
                
                #Start a new thread for every connection
                thread = threading.Thread(target = self._handle_incoming, args=(pack,))
                
                self._report(f"New thread {thread.getName()} is serving {addr}",thread.getName().capitalize())
                
                thread.start()


    def _handle_incoming(self, pack: Packet) -> None:
        self._report(f"Packet with content:{pack.raw} arrived",
                     threading.currentThread().getName().capitalize()
        )

        self._mapper[pack.flag](pack)


    def sender_function(self) -> None:
        while (outbound := self._outgoing_queue.get(block=True)).addr != ("stop",404):
            self._socket.sendto(self.pack(outbound),outbound.addr)


    def add_address(self, addr: str, port: int) -> None:
        self.addr = (addr, port)


    def add_address_socket(self, addr_port: Tuple[str, int]) -> None:
        self.addr = addr_port


    def listen_on(self, addr: str, port: int, cli: bool = True) -> None:
        self.addr = (addr, port)
        self.listen(cli)


    def listen_on_socket(self, addr_port: Tuple[str, int], cli: bool = True) -> None:
        self.addr = addr_port
        self.listen(cli)

    
    def pack(self, to_pack: Packet) -> bytes:
        msg: bytes = bytes()
        msg += to_pack.flag.encode()
        msg += self.f.encrypt((to_pack.data).encode())   
        msg += ('#'*(251 - len(msg))).encode()
        msg += to_pack.server.encode()
        msg += "\n".encode()
        return msg
