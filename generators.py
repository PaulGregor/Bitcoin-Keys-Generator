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

    s = prefix + payload

    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]

    result = s + checksum

    # return '1' * countLeadingZeroes(result) + base58encode(base256decode(hexlify(result)))
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
    vk = sk.verifying_key
    return hexlify(b'\04' + sk.verifying_key.to_string())


# print(bytes.fromhex('00010966776006953D5567439E5E39F86A0D273BEED61967F6'))
# print(base58.b58encode(bytes.fromhex('00010966776006953D5567439E5E39F86A0D273BEED61967F6')))

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')

    hash_sha256 = hashlib.new('SHA256')
    hash_sha256.update(s.encode('utf-8'))
    print(hash_sha256.hexdigest())

   # print( ripemd160.hexdigest())



    ripemd160.update(hash_sha256.digest())

    return base58.b58encode(bytes.fromhex(ripemd160.hexdigest()))


   # return base58CheckEncode(b'0', ripemd160.digest())

# print "Private key in WIF format:",

#print(privateKeyToWif('0a56184c7a383d8bcce0c78e6e7a4b4b161b2f80a126caa48bde823a4625521f'))
print(privateKeyToPublicKey('45b0c38fa54766354cf3409d38b873255dfa9ed3407a542ba48eb9cab9dfca67'))

#print( 'address')

print(pubKeyToAddr('04162ebcd38c90b56fbdb4b0390695afb471c944a6003cb334bbf030a89c42b584f089012beb4842483692bdff9fcab8676fed42c47bffb081001209079bbcb8db'))

# (2**256 - 2**32 - 2 ** 9 - 2 ** 8 - 2** 7 - 2 ** 6 - 2 **4 - 1)
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
#print((x ** 3 + 7) % p == y**2 % p)

