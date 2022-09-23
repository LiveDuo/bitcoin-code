# https://pypi.python.org/pypi/ecdsa/0.10
import ecdsa
import ecdsa.der
import ecdsa.util
import hashlib
import unittest

import utils

# https://en.bitcoin.it/wiki/Wallet_import_format
def privateKeyToWif(key_hex):    
    return utils.base58CheckEncode(0x80, key_hex.decode('hex'))

def wifToPrivateKey(s):
    b = utils.base58CheckDecode(s)
    return b.encode('hex')

# Input is a hex-encoded, DER-encoded signature
# Output is a 64-byte hex-encoded signature
def derSigToHexSig(s):
    s, junk = ecdsa.der.remove_sequence(s.decode('hex'))
    if junk != '':
        print ('JUNK', junk.encode('hex'))
    assert(junk == '')
    x, s = ecdsa.der.remove_integer(s)
    y, s = ecdsa.der.remove_integer(s)
    return '%064x%064x' % (x, y)

# Input is hex string
def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

# Input is hex string
def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return utils.base58CheckEncode(0, ripemd160.digest())

def addrHashToScriptPubKey(b58str):
    assert(len(b58str) == 34)
    # 76     A9      14 (20 bytes)                                 88             AC
    return '76a914' + utils.base58CheckDecode(b58str).encode('hex') + '88ac'

