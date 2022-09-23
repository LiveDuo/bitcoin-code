import random, hashlib, ecdsa

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, '\0')
    return '1' * leadingZeros + base58encode(base256decode(result))

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return base58CheckEncode(0, ripemd160.digest())

# Input is hex string
def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

# Input is hex string
def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))

# https://en.bitcoin.it/wiki/Wallet_import_format
def privateKeyToWif(key_hex):    
    return base58CheckEncode(0x80, key_hex.decode('hex'))

private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
print (privateKeyToWif(private_key))
print (keyToAddr(private_key))

