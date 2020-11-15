from datetime import datetime
from queue import Empty, Queue
from typing import Dict, Callable, Tuple
# from cryptography.fernet import Fernet
from packet import Packet
import socket
import threading
import colorama #type: ignore
colorama.init() #type: ignore
from termcolor import colored
from connection import Connection

class Server:
    """
    This is the base class of the Python "The Thing" Networking Protocol server.
    This server handles incoming packets using your created functions, which have been
    added to the mapper of the class using the `add_handler` method
    """

    #The mapper of the handler functions
    _mapper: Dict[str, Callable[[Packet,Connection], None]] = dict()
    _connection: Dict[str, "Queue[Packet]"] = dict()
    #The address of the server 
    addr: Tuple[str, int]
    #Whether control data will be displayed to the CLI
    _cli: bool = True
    #The size of the packet
    #127 Bits of actual data
    #TODO Make larger packet sizes available if 256 is not sufficient
    MAX_PACKET_SIZE: int = 2048
    #The queue for outgoing packets consumed by sender_thread
    _outgoing_queue: "Queue[Packet]" = Queue(-1)
    _next_server: int = 0

    _report_types: Dict[int, str] = {
        0 : "white",    #Ordinary
        1 : "green",    #Success
        2 : "yellow",   #Warning
        3 : "red"       #Error
    }


    def __init__(self, TTL: float=15) -> None:
        self.TTL = TTL

    @property
    def next_server(self):
        if self._next_server != 9999:
            self._next_server += 1
        else:
            self._next_server = 1  
        return ("0" * (4 - len(str(self._next_server)))) + str(self._next_server+1)


    def _report(self, msg: str, sender: str = "REPORT", type: int = 0) -> None:
        if self._cli:
            if type in self._report_types.keys():
                msg = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][{sender}]: {msg}"
                print(colored(msg,self._report_types[type]))
            else:
                raise Exception


    def add_handler(self, func: Callable[[Packet, Connection], None], flag: str) -> None:
        self._mapper[flag] = func

    def listen(self, cli: bool = True) -> None: #cli: bool option specifies whether control data should be displayed to the cli
            self._report(f"Server is starting","SERVER")
            self._cli = cli
            if self.addr:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.bind(self.addr)
                self._report(f"Server is listening on {self.addr}","SERVER")
                self._accept_connections()
            else:
                raise Exception


    def _accept_connections(self) -> None:
        #Handle incoming packets
        #All packets arrive at this function(TODO test for viability)
        
        #The sender thread handles sanding of all of the outgoing packets from the server
        sender_thred = threading.Thread(target=self._sender_function,name="Sender Thread")
        sender_thred.start()

        while True: #Change this to something sexier, maybe recursion ( ͡° ͜ʖ ͡°) 
            try:
                data, addr = self._socket.recvfrom(self.MAX_PACKET_SIZE)
                pack = Packet.from_bytes(data)
                if (pack).flag == "CHI" and pack.server == "0000": 
                    #Packet is a fresh request for connection
                    #TODO make a list of connected sockets to prevent pottential system overload from
                    #falsly created threads

                    pack.addr = addr

                    server = self.next_server

                    self._connection[server] = Queue(-1)

                    #print(self._connection)

                    #Start a new thread for every connection
                    thread = threading.Thread(
                        target = self._handle_incoming,
                        args=(Connection(
                            pack.addr,
                            server,
                            self.TTL,
                            self._connection[server],
                            self._outgoing_queue,
                            self._report),
                        )
                    )
                    
                    self._report(f"New thread {thread.getName()} is serving {addr}",thread.getName().capitalize())
                    
                    thread.start()
                
                else:
                    self._connection[pack.server].put(pack)
            except Exception:
                pass

    def _handle_incoming(self, conn: Connection) -> None:
        # #For debug purposes
        # self._report(f"Packet with content:{pack} arrived \n Data:{pack.raw_data}",
        #              threading.currentThread().getName().capitalize()
        # )

        thread_name = threading.currentThread().getName().capitalize()
        conn.thread_name = thread_name

        if conn.handshake():
            self._report("Connection has been Established",thread_name,1)
            while conn.is_alive:
                try:
                    pack: Packet = conn.get()
                    # print(pack)
                    # if pack.flag == "CHB":
                    #     conn.renew()
                    #     self._report("Connection renewed",thread_name,1)
                    # else:
                    self._mapper[pack.flag](pack,conn)
                except Empty:
                    del self._connection[conn.server]
                    self._report("Client timed out",thread_name,3)
            else:
                self._report("Connection was Terminated",thread_name)


    def _sender_function(self) -> None:
        while (outbound := self._outgoing_queue.get(block=True)).addr != ("stop",404):
            #Maybe introduce Packet.packed: bool member
            self._socket.sendto(outbound.packed_data,outbound.addr)


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
