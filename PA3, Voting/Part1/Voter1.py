import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1


HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # connect to the CTF server
    s.connect((HOST, PORT))
    # load CTF's public Key
    publicKeyCTF = RSA.import_key(open('publicKeyCTF.pem', 'r').read())
    # Taking the voter Id as input
    voterId = input("Enter your voter Id\n")
    # load the voter's private key
    privateKeyVoter = RSA.import_key(open('privateKeyVoter{}.pem'.format(voterId), 'r').read())
    # take the voter's vote
    yourVote = input("Please enter your vote, YES or NO\n")
    # calculating the hash of the vote
    h = SHA1.new(yourVote.encode('utf-8'))
    # signing the hashed vote with the voter's private key (PKCS1 used here, based on RSA)
    signature = pkcs1_15.new(privateKeyVoter).sign(h)
    # print(signature)
    signature = signature + b'$' + voterId.encode()
    #Instantiating PKCS1_OAEP object with the private key for signing the vote
    confidence = PKCS1_OAEP.new(key=publicKeyCTF)
    # encrypting the signed vote with the CTF public key
    signedPlusEncryptedVote = confidence.encrypt(signature)
    # sending signedPlusEncryptedVote to CTF server
    s.sendall(signedPlusEncryptedVote)
    # receiving CTF's response
    data = s.recv(1024)

# printing CTF's response
print(repr(data))