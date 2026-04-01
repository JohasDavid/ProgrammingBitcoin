from helper import hash256
from helper import read_varint, encode_varint

class Tx:
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet = False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        
    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
            
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,  
        )
        
    def id(self):
        """Human-readable hexadecimal of the transaction hash"""
        return self.hash().hex()
    
    def hash(self):
        """Binary hash of the legacy serializtion"""
        return hash256(self.serialize())[::-1]
    
    @classmethod
    def parse(cls, stream):
        serialized_version = stream.read(4)
        version = int.from_bytes(serialized_version, 'little')
        num_inputs = read_varint(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(stream))
        
        return version, inputs
    
class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig = None, sequence = 0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence
        
    def __repr__(self):
        return f"{self.prev_tx.hex()} : {self.prev_index}"
    
    @classmethod
    def parse(cls, stream):
        prev_tx = stream.read(32)[::-1]
        prev_index = int.from_bytes(stream.read(4), 'little')
        script_sig = Script.parse(stream)
        sequence = int.from_bytes(stream.read(4), 'little')
        return cls(prev_tx, prev_index, script_sig, sequence)
    