import ecdsa
import hashlib
import base58
from binascii import hexlify, unhexlify


class NumberReceiver(object):
    def __init__(self, numbers_list):
        self.numbers_list = numbers_list

    def generate_private_key(self, number):
        pass

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def base58encode(n):
    return base58encode(n//58) + b58[n%58:n%58+1] if n else ''

# Will be used to decode raw bytes and then encode them to the base58
def base256decode(s):
    result = 0
    print(s)
    for c in str(s):
        result = result * 256 + ord(c)
    return result


def countLeadingZeroes(s):
    count = 0
    for c in s:
        if c == '\0':
            count += 1
        else:
            break
    return count


def base58CheckEncode(prefix, payload):

    # Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    s = prefix + payload

    # Add the 4 checksum bytes at the end of extended RIPEMD-160 hash. This is the 25-byte binary Bitcoin Address.
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]

    result = s + checksum

    return '1' * countLeadingZeroes(result) + base58.b58encode(result)

curve = ecdsa.curves.SECP256k1

from_secret_exponent = ecdsa.keys.SigningKey.generate
private_key = from_secret_exponent(curve)

# print( hexlify(private_key.to_string()).decode('ascii'))
public_key = private_key.get_verifying_key()

# print( hexlify(public_key.to_string()).decode('ascii'))


def privateKeyToWif(key_hex):
    return base58CheckEncode(b'\x80', unhexlify(key_hex))


def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(s), curve=ecdsa.SECP256k1)

    return hexlify(b'\04' + sk.verifying_key.to_string())


# print(bytes.fromhex('00010966776006953D5567439E5E39F86A0D273BEED61967F6'))
# print(base58.b58encode(bytes.fromhex('00010966776006953D5567439E5E39F86A0D273BEED61967F6')))

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')

    hash_sha256 = hashlib.new('SHA256')
    # bytearray.fromhex(s)

    # Perform SHA-256 hashing on the public key
    hash_sha256.update(bytes.fromhex(s))

    # Perform RIPEMD-160 hashing on the result of SHA-256
    ripemd160.update(hash_sha256.digest())

    print(ripemd160.hexdigest())

    # return base58.b58encode(bytes.fromhex(ripemd160.hexdigest()))

    return base58CheckEncode(b'\0', ripemd160.digest())

# print "Private key in WIF format:",

# print(privateKeyToWif('0a56184c7a383d8bcce0c78e6e7a4b4b161b2f80a126caa48bde823a4625521f'))
pk = '18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725'
pb_key = privateKeyToPublicKey(pk).decode("utf-8")

address = pubKeyToAddr(pb_key)

print(address)

# (2**256 - 2**32 - 2 ** 9 - 2 ** 8 - 2** 7 - 2 ** 6 - 2 **4 - 1)
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
# print((x ** 3 + 7) % p == y**2 % p)

