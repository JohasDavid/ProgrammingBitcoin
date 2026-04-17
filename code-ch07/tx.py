import requests
from helper import read_varint, encode_varint, hash256, int_to_little_endian, little_endian_to_int, SIGHASH_ALL

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
        num_outputs = read_varint(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(stream))
            
        locktime_read = stream.read(4)
        locktime = int.from_bytes(locktime_read, "little")
        testnet = False
        return cls(version, inputs, outputs, locktime, testnet)
    
    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result
    
    def fee(self):
        inputs = 0
        outputs = 0
        for tx_in in self.tx_ins:
            inputs += tx_in.value(self.testnet)
            
        for tx_out in self.tx_outs:
            outputs += tx_out.amount
            
        fee = inputs - outputs
        
        if fee < 0:
            raise ValueError("fee negativo")
        return fee
    
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
    
    def serialize(self):
        """Return the byte serialization of the transaction input"""
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result
    
    def fetch_tx(self, testnet = False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet = testnet)
    
    def value(self, testnet = False):
        """Get the output value by looking up the tx hash.
        Returns the amount in satoshi"""
        tx = self.fetch_tx(testnet = testnet)
        return tx.tx_outs[self.prev_index].amount
    
    def script_pubkey(self, testnet = False):
        """Get the ScriptPubKey by looking up the tx hash.
        Returns a Script object."""
        tx = self.fetch_tx(testnet = testnet)
        return tx.tx_outs[self.prev_index].script_pubkey
    
    def sig_hash(self, input_index):
        s = int_to_little_endian(self.version, 4)
        s += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                s += TxIn(
                    prev_tx = tx_in.prev_tx,
                    prev_index = tx_in.prev_index,
                    script_sig = tx_in.script_pubkey(self.testnet),
                    sequence = tx_in.sequence,
                ).serialize()
            else:
                s += TxIn(
                    prev_tx = tx_in.prev_tx,
                    prev_index = tx_in.prev_index,
                    sequence = tx_in.sequence,
                ).serialize()
        s += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(s)
        return int.from_bytes(h256,'big')
        
    
class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey
        
    def __repr__(self):
        return f"{self.amount} : {self.script_pubkey}"
    
    @classmethod
    def parse(cls, stream):
        amount = int.from_bytes(stream.read(8), 'little')
        script_pubkey = Script.parse(stream)
        return cls(amount, script_pubkey)
    
    def serialize(self):
        """Returns the byte serialization of the transaction output"""
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result
        
class TxFetcher:
    cache = {}
    
    @classmethod
    def get_url(cls, testnet = False):
        if testnet:
            return 'http://testnet.programmingbitcoin.com'
        else:
            return 'http://mainnet.programmingbitcoin.com'
        
    @classmethod
    def fetch(cls, tx_id, testnet = False, fresh = False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet = testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet = testnet)
                
            if tx.id() != tx_id:
                raise ValueError('not the same id: {} vs {}'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]