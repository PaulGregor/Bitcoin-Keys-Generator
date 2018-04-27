import base58
from binascii import hexlify, unhexlify
import ecdsa
import hashlib
from struct import Struct

PACKER = Struct('>QQQQ')


def countLeadingZeroes(s):
    count = 0
    for c in s:
        if c == '\0':
            count += 1
        else:
            break
    return count


def base58CheckEncode(prefix, payload, compressed=False):

    # Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    s = prefix + payload
    if compressed:
        s = prefix + payload + b'\x01'

    # Add the 4 checksum bytes at the end of extended RIPEMD-160 hash. This is the 25-byte binary Bitcoin Address.
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]

    result = s + checksum

    return '1' * countLeadingZeroes(result) + base58.b58encode(result)


def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')

    hash_sha256 = hashlib.new('SHA256')
    # bytearray.fromhex(s)

    # Perform SHA-256 hashing on the public key
    hash_sha256.update(bytes.fromhex(s))

    # Perform RIPEMD-160 hashing on the result of SHA-256
    ripemd160.update(hash_sha256.digest())

    # return base58.b58encode(bytes.fromhex(ripemd160.hexdigest()))

    return base58CheckEncode(b'\0', ripemd160.digest())


def int_to_address(number):

    number0 = number >> 192
    number1 = (number >> 128) & 0xffffffffffffffff
    number2 = (number >> 64) & 0xffffffffffffffff
    number3 = number & 0xffffffffffffffff

    private_key = hexlify(PACKER.pack(number0, number1, number2, number3)).decode("utf-8")

    print(int(str(number), 16))

    uncompressed_key = base58CheckEncode(b'\x80', unhexlify(private_key))
    print(uncompressed_key + ' - uncompressed key')

    # wif compressed key
    compressed_key = base58CheckEncode(b'\x80', unhexlify(private_key), True)
    print(compressed_key + ' - compressed key')

    # public keys
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)

    print(hexlify(b'\04' + sk.verifying_key.to_string()).decode('utf-8') + ' - uncompressed public key')

    pk_prefix = b'\02'
    if not int(hexlify(sk.verifying_key.to_string()[32:]), 16) % 2 == 0:
        pk_prefix = b'\03'

    print(hexlify(pk_prefix + sk.verifying_key.to_string()[:32]).decode('utf-8') + ' - compressed public key')

    uncompressed_public_key = hexlify(b'\04' + sk.verifying_key.to_string()).decode('utf-8')
    compressed_public_key = hexlify(pk_prefix + sk.verifying_key.to_string()[:32]).decode('utf-8')
    # address

    print(pubKeyToAddr(uncompressed_public_key) + ' - un compressed address')
    print(pubKeyToAddr(compressed_public_key) + ' - compressed address')


def wif_to_key(wif):
    slicer = 4
    if wif[0] in ['K', 'L']:
        slicer = 5

    return hexlify(base58.b58decode(wif)[1:-slicer]).decode('utf-8')

int_to_address(1)

