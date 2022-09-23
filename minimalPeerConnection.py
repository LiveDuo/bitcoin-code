import struct
import socket

import utils
import msgUtils

# dig +short seed.bitcoin.jonasschnelli.ch

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("193.198.68.185", 8333))

sock.send(msgUtils.getVersionMsg())

while 1:
    sock.recv(1000) # Throw away data
    print ('got packet')
    break
    
