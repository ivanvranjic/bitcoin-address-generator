#!/usr/bin/env python
import ecdsa
import hashlib
import os
from base58 import b58encode_check, b58decode_check


def privateKeyToWIF(key, compressed=True):
    if not compressed:
        return b58encode_check(chr(0x80) + key.decode('hex'))
    else:
        return b58encode_check(chr(0x80) + key.decode('hex') + chr(0x01))


def privateKeyToPublicKey(key, compressed=True):
    sk = ecdsa.SigningKey.from_string(key.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key.to_string()
    if not compressed:
        return (chr(0x04) + vk).encode('hex')
    else:
        vk_is_odd = vk.encode('hex')[-1:] in ['1', '3', '5', '7', '9', 'b', 'd', 'f']
        prefix = chr(0x03) if vk_is_odd else chr(0x02)
        return (prefix + vk[:32]).encode('hex')


def publicKeyToAddress(key):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(key.decode('hex')).digest())
    return b58encode_check(chr(0x00) + ripemd160.digest())


def privateWIFKeyToPublicAddress(key, compressed):
    if not compressed:
        return publicKeyToAddress(privateKeyToPublicKey(b58decode_check(key)[1:].encode('hex'), compressed=compressed))
    else:
        return publicKeyToAddress(privateKeyToPublicKey(b58decode_check(key)[1:-1].encode('hex'), compressed=compressed))


private_key = os.urandom(32).encode('hex')

wif_uncompressed = privateKeyToWIF(private_key, compressed=False)
pub_key_uncompressed = privateKeyToPublicKey(private_key, compressed=False)
address_uncompressed = publicKeyToAddress(privateKeyToPublicKey(private_key, compressed=False))

wif_compressed = privateKeyToWIF(private_key, compressed=True)
pub_key_compressed = privateKeyToPublicKey(private_key, compressed=True)
address_compressed = publicKeyToAddress(privateKeyToPublicKey(private_key, compressed=True))

assert privateWIFKeyToPublicAddress(wif_uncompressed, compressed=False) == address_uncompressed
assert privateWIFKeyToPublicAddress(wif_compressed, compressed=True) == address_compressed

print "Private Key     : %s " % private_key
print "---------------------------------------------------------------------------------------------------"
print "Private Key WIF : %s " % wif_uncompressed
print "Public Key      : %s " % pub_key_uncompressed
print "Address         : %s " % address_uncompressed
print "---------------------------------------------------------------------------------------------------"
print "Private Key WIF Compressed : %s " % wif_compressed
print "Public Key Compressed      : %s " % pub_key_compressed
print "Address Compressed         : %s " % address_compressed
