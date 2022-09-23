# https://pypi.python.org/pypi/ecdsa/0.10

import ecdsa
import hashlib
import struct

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def wifToPrivateKey(s):
    b = base58CheckDecode(s)
    return b.encode('hex')

def addrHashToScriptPubKey(b58str):
    assert(len(b58str) == 34)
    # 76     A9      14 (20 bytes)                                 88             AC
    return '76a914' + base58CheckDecode(b58str).encode('hex') + '88ac'

# Returns byte string value, not hex string
def varint(n):
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n < 0xffff:
        return struct.pack('<cH', '\xfd', n)
    elif n < 0xffffffff:
        return struct.pack('<cL', '\xfe', n)
    else:
        return struct.pack('<cQ', '\xff', n)

# Takes and returns byte string value, not hex string
def varstr(s):
    return varint(len(s)) + s

# 60002
def netaddr(ipaddr, port):
    services = 1
    return (struct.pack('<Q12s', services, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff') +
                       struct.pack('>4sH', ipaddr, port))
# return value, len
def processVarInt(payload):
    n0 = ord(payload[0])
    if n0 < 0xfd:
        return [n0, 1]
    elif n0 == 0xfd:
        return [struct.unpack('<H', payload[1:3])[0], 3]
    elif n0 == 0xfe:
        return [struct.unpack('<L', payload[1:5])[0], 5]
    else:
        return [struct.unpack('<Q', payload[1:5])[0], 7]

# return value, len
def processVarStr(payload):
    n, length = processVarInt(payload)
    return [payload[length:length+n], length + n]

# takes 26 byte input, returns string  
def processAddr(payload):
    assert(len(payload) >= 26)
    return '%d.%d.%d.%d:%d' % (ord(payload[20]), ord(payload[21]),
                               ord(payload[22]), ord(payload[23]),
                               struct.unpack('!H', payload[24:26])[0])


def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def base58decode(s):
    result = 0
    for i in range(0, len(s)):
        result = result * 58 + b58.index(s[i])
    return result

def base256encode(n):
    result = ''
    while n > 0:
        result = chr(n % 256) + result
        n /= 256
    return result

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
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

def base58CheckDecode(s):
    leadingOnes = countLeadingChars(s, '1')
    s = base256encode(base58decode(s))
    result = '\0' * leadingOnes + s[:-4]
    chk = s[-4:]
    checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
    assert(chk == checksum)
    version = result[0]
    return result[1:]


def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return base58CheckEncode(0, ripemd160.digest())

# Input is hex string
def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

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

# Makes a transaction from the inputs
# outputs is a list of [redemptionSatoshis, outputScript]
def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
    def makeOutput(data):
        redemptionSatoshis, outputScript = data
        return (struct.pack("<Q", redemptionSatoshis).encode('hex') +
        '%02x' % len(outputScript.decode('hex')) + outputScript)
    formattedOutputs = ''.join(map(makeOutput, outputs))
    return (
        "01000000" + # 4 bytes version
        "01" + # varint for number of inputs
        outputTransactionHash.decode('hex')[::-1].encode('hex') + # reverse outputTransactionHash
        struct.pack('<L', sourceIndex).encode('hex') +
        '%02x' % len(scriptSig.decode('hex')) + scriptSig +
        "ffffffff" + # sequence
        "%02x" % len(outputs) + # number of outputs
        formattedOutputs +
        "00000000" # lockTime
        )

# Returns [first, sig, pub, rest]
def parseTxn(txn):
    first = txn[0:41*2]
    scriptLen = int(txn[41*2:42*2], 16)
    script = txn[42*2:42*2+2*scriptLen]
    sigLen = int(script[0:2], 16)
    sig = script[2:2+sigLen*2]
    pubLen = int(script[2+sigLen*2:2+sigLen*2+2], 16)
    pub = script[2+sigLen*2+2:]
            
    assert(len(pub) == pubLen*2)
    rest = txn[42*2+2*scriptLen:]
    return [first, sig, pub, rest]         

# Substitutes the scriptPubKey into the transaction, appends SIGN_ALL to make the version
# of the transaction that can be signed
def getSignableTxn(parsed):
    first, sig, pub, rest = parsed
    inputAddr = base58CheckDecode(pubKeyToAddr(pub))
    return first + "1976a914" + inputAddr.encode('hex') + "88ac" + rest + "01000000"

# Verifies that a transaction is properly signed, assuming the generated scriptPubKey matches
# the one in the previous transaction's output
def verifyTxnSignature(txn):                    
    parsed = parseTxn(txn)      
    signableTxn = getSignableTxn(parsed)
    hashToSign = hashlib.sha256(hashlib.sha256(signableTxn.decode('hex')).digest()).digest().encode('hex')
    assert(parsed[1][-2:] == '01') # hashtype
    sig = derSigToHexSig(parsed[1][:-2])
    public_key = parsed[2]
    vk = ecdsa.VerifyingKey.from_string(public_key[2:].decode('hex'), curve=ecdsa.SECP256k1)
    assert(vk.verify_digest(sig.decode('hex'), hashToSign.decode('hex')))

def makeSignedTransaction(privateKey, outputTransactionHash, sourceIndex, scriptPubKey, outputs):
    myTxn_forSig = (makeRawTransaction(outputTransactionHash, sourceIndex, scriptPubKey, outputs)
         + "01000000") # hash code

    s256 = hashlib.sha256(hashlib.sha256(myTxn_forSig.decode('hex')).digest()).digest()
    sk = ecdsa.SigningKey.from_string(privateKey.decode('hex'), curve=ecdsa.SECP256k1)
    sig = sk.sign_digest(s256, sigencode=ecdsa.util.sigencode_der) + '\01' # 01 is hashtype
    pubKey = privateKeyToPublicKey(privateKey)
    scriptSig = varstr(sig).encode('hex') + varstr(pubKey.decode('hex')).encode('hex')
    signed_txn = makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs)
    verifyTxnSignature(signed_txn)
    return signed_txn
    
