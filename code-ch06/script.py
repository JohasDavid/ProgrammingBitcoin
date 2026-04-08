from helper import hash256, hash160, read_varint,little_endian_to_int

def op_dup(stack):
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True

def op_hash256(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True

def op_hash160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash160(element))
    return True

OP_CODE_FUNCTIONS = {
    
    118: op_dup,
    170: op_hash256,
    0xa9: op_hash160,
}

class Script:
    def __init__(self, cmds = None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds
    
    @classmethod
    def parse(cls, s):
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]
            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                op_code = current_byte
                cmds.appends(op_code)
                
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)