from unittest import TestCase
from random import randint

import hashlib
import hmac
from helper import hash256
from helper import hash160

class FieldElement:

    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f"Num {num} not in field range 0 to {prime - 1}"
            raise ValueError(error)
        self.num = num
        self.prime = prime
        
    def __repr__ (self):
        return f"FieldElement({self.num})_{self.prime}"
    
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime
    
    def __ne__(self, other):
        if other is None:
            return False
        return self.num != other.num or self.prime != other.prime
    
    def __add__ (self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in diffent Fields')
        
        num = ( self.num + other.num ) % self.prime
        return self.__class__ (num, self.prime)
    
    def __sub__ (self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot substract two numbers in diffent Fields')
        
        num = ( self.num - other.num ) % self.prime
        return self.__class__ (num, self.prime)
    
    def __mul__ (self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in diffent Fields')
        
        num = ( self.num * other.num ) % self.prime
        return self.__class__ (num, self.prime)

    
    def __pow__ (self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__ (num, self.prime)
    
    def __truediv__ (self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in diffent Fields')
        
        if other.num == 0:
            raise ZeroDivisionError("Cannot divide by zero.")
        
        num = (self.num * pow(other.num, self.prime - 2, self.prime) ) % self.prime
        return self.__class__(num, self.prime)
    
    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)
        


class Point:
    def __init__ (self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return        
        if self.y ** 2 != (self.x ** 3) + (a * x) + b:
            raise ValueError(f"({x}, {y}) is not in the curve")
    
        
    def __eq__ (self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b
    
    def __ne__ (self, other):
        return not self.__eq__ (other)
    
    def __repr__ (self):
        if self.x == None and self.y == None:
            return "Point(infinity)"
        else:
            return f"Point({self.x.num}, {self.y.num})_{self.x.prime}"
    
    def __add__ (self, other):
        
        if self.a != other.a or self.b != other.b:
            raise ValueError(f"Points {self}, {other} are not in the same curve")
        
        if self.x is None:
            return other
        
        if other.x is None:
            return self
        
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
        
        if self.x != other.x:
            s = ( other.y - self.y )/(other.x - self.x)
            x_f = (s ** 2) - (self.x + other.x)
            y_f = s * (self.x - x_f) - self.y
            
            return self.__class__ (x_f, y_f, self.a, self.b) 
        
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        
        if self == other:
            
            s = (3 * (self.x ** 2) + self.a )/(2 * self.y)
            x_f = (s ** 2) - 2*self.x
            y_f = s * (self.x - x_f ) - self.y
            
            return self.__class__(x_f, y_f, self.a, self.b)
        
    def __rmul__(self, coefficient):
        coef = coefficient
        current = self  # <1>
        result = self.__class__(None, None, self.a, self.b)  # <2>
        while coef:
            if coef & 1:  # <3>
                result += current
            current += current  # <4>
            coef >>= 1  # <5>
        return result
    # end::source3[]
        
        
p = 2 ** 256 - 2 ** 32 - 977

class S256Field(FieldElement):
    def __init__(self, num, prime = None):
        super().__init__ (num = num, prime = p)
    
    def __repr__(self):
        return f"{self.num}".zfill(64)
    
    def sqrt(self):
        return self ** ((p + 1) // 4)
    
    
A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class S256Point(Point):
    def __init__(self, x, y, a = None, b = None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x = S256Field(x), y = S256Field(y), a = a, b = b)
        else:
            super().__init__(x = x, y = y, a = a, b = b)
        
    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)
    
    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r
    
    def sec(self, compressed = True):
        """returns the binary version of the SEC format"""
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')
        
    @classmethod
    def parse(self, sec_bin):
        """Returns a Point object from a SEC binary (not hex)"""
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33, 65], 'big')
            return S256Point(x = x, y = y)
        
        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        alpha = x ** 3 + S256Field(B)
        beta = alpha.sqrt()
        
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(p - beta.num)
        else:
            even_beta = S256Field(p - beta.num)
            odd_beta = beta
        
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)
        
    def hash160(self, compressed = True):
        return hash160(self.sec(compressed))
    
    def address(self, compressed = True, testnet = False):
        """Returns the adress string"""
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
            
        else:
            prefix = b'\x00'
        
        return encode_base58_checksum(prefix + h160)
    
G = S256Point(
0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
        
class ECCTest(TestCase):
    def test_on_curve(self):
        prime = 233
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        
        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))
        
        for x_raw, y_raw in valid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            
        for x_raw, y_raw in invalid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            with self.assertRaises(ValueError):
                Point(x, y, a, b)
                
    def test_add(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)
        
        points = [
            (170, 142, 60, 139, 220, 181),
            (47, 71, 17, 56, 215, 68),
            (143, 98, 76, 66, 47, 71)            
        ]
        
       
        for x_raw1, y_raw1, x_raw2, y_raw2, x_raw3, y_raw3 in points:
            x1 = FieldElement(x_raw1, prime)
            y1 = FieldElement(y_raw1, prime)
            x2 = FieldElement(x_raw2, prime)
            y2 = FieldElement(y_raw2, prime)
            x3 = FieldElement(x_raw3, prime)
            y3 = FieldElement(y_raw3, prime)
                        
            p1 = Point(x1, y1, a, b)
            p2 = Point(x2, y2, a, b)
            p3 = Point(x3, y3, a, b)
            
            self.assertEqual(p1 + p2, p3)
            
            print(p3)
            
class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s
        
    def __repr__(self):
        return f"Signature({self.r},{self.s})"
    
    def der(self):
        rbin = self.r.to_bytes(32, byteorder = 'big')
        # remove all null bytes at the beginning
        rbin = rbin.lstrip(b'\x00')
        # if rbin has a high bit, add a \x00
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
            
        result = bytes([2, len(rbin)]) + rbin
        sbin = self.s.to_bytes(32, byteorder = 'big')
        # remove all null bytes at the beggining
        sbin = sbin.lstrip(b'\x00')
        # if sbin has a high bit, add a \x00
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result
    
class PrivateKey:
    
    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G
        
    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)
    
    def sign(self, z):
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N -2, N)
        s = ( z + r * self.secret ) * k_inv % N
        
        if s > N/2:
            s = N - s
        return Signature(r, s)
    
    def deterministic_k(self, z):
        k = '\x00' * 32
        v = '\x01' * 32
        if z > N:
            z -= N
        
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()
            
    def wif(self, compressed = True, testnet = False):
        secret_bytes = self.secret.to_bytes(32, 'big')
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
            
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
            
        return encode_base58_checksum(prefix + secret_bytes + suffix)
                    
                
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])

