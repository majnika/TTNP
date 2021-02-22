import enum

class TransactionTypes(enum.Enum):
    Data = enum.auto()
    Authorization = enum.auto()
    Querry = enum.auto()
    SimpleMessage = enum.auto()

class Transaction:
    
    sequence: int = 0
    buffer: str = str()

    def __init__(self, type: TransactionTypes, slices: int) -> None: 
        self.type: TransactionTypes = type
        self.slices = slices
