import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1

message = b'YES'

# publicKeyCTF = RSA.import_key(open('publicKeyCTF.pem', 'r').read())
privateKeyVoter = RSA.import_key(open('privateKeyVoter1.pem', 'r').read())
# privateKeyCTF = RSA.import_key(open('privateKeyCTF.pem', 'r').read())
publicKeyVoter = RSA.import_key(open('publicKeyVoter1.pem', 'r').read())

cipher = PKCS1_OAEP.new(key=privateKeyVoter)
cipher_text = cipher.encrypt(message)

decrypt = PKCS1_OAEP.new(key=publicKeyVoter)
decrypted_message = decrypt.decrypt(cipher_text)
