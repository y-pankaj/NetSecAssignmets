import socket
import time
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

# set of registered eligible voters, recognised by their registration ids
registeredVoters = set()
registeredVoters.update({"1", "2", "3"})
# mainting the vote count
voteCount = {"YES": 0, "NO":0}
# maintaining the final votes of the registered voters
finalVote = {"1":"DidNotVote","2":"DidNotVote","3":"DidNotVote"}

# maintaining a set of people who have already voted. No duplicate are allowed in a set.
hasVoted = set()

# using socket library to establish connection with the voter
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Address at which CTF server listens for connections
    s.bind((HOST, PORT))
    # specifying the end time of the elections, currently set to 60s
    # time for election start ticking backwards as soon as you run the CTF.py program
    t_end = time.time() + 60 * 1
    while time.time() < t_end:
        # listening to the voters request to connect
        s.listen()
        # accepting the connection if a request is made
        conn, addr = s.accept()
        with conn:
            # printing the address of the connected voter
            print('Connected by', addr)
            # receiving the signed plus encrypted vote from the voter
            data = conn.recv(1024)
            # uncomment the below line to print the reveived data
            #print("Signed plus encrypted vote",data)
            # loading the private key of CTF
            pr_key = RSA.import_key(open('privateKeyCTF.pem', 'r').read())
            decrypt = PKCS1_OAEP.new(key=pr_key)
            # decrypting the meassage
            decrypted_message = decrypt.decrypt(data)
            # decrpyted message contains the signed vote as well as the voter ID of the voter
            # operation to get the sinature and voterId
            decrypted_message = decrypted_message[::-1]
            voterId, signature = decrypted_message.split(b'$', 1)
            signature = signature[::-1]
            voterId = voterId[::-1]
            # converting the voterID of the voter from byte string to string
            voterId = voterId.decode()

            voterHasVoted = False
            isRegistered = True
            # checking cases if the voter has registerd or not
            if voterId in registeredVoters:
                if voterId in hasVoted:   # checking if the voter has voted before or not
                    conn.sendall(b'You have already voted')
                    conn.close()
                    continue
                else:
                    voterHasVoted = True
            else:
                isRegistered = False    # sending message to the user if he's not registered
                conn.sendall(b'You are not a registered voter')
                conn.close()    # closing the connection with the voter
                continue
            
            # maintaining a variable for checking if the vote is valid
            validVote = False
            # for checking if the signature is valid or not
            message = b'YES'
            h = SHA1.new(message)
            # importing the publicKey of the voter form the VoterID
            key = RSA.import_key(open('publicKeyVoter{}.pem'.format(voterId), 'r').read())
            try:
                # PKCS#1 v1.5 (RSA), An old but still solid digital signature scheme based on RSA.
                pkcs1_15.new(key).verify(h, signature)
                # if the signature is valid, add the voter to the hasVoted database
                hasVoted.add(voterId)
                print ("The signature is valid.")
                validVote = True
                # keeping record of the voters vote
                finalVote[voterId] = "YES"
                # maintaing the tally of the votes
                voteCount["YES"] = voteCount["YES"] + 1
                # sending message to the voter
                conn.sendall(b'You have successfully voted')
            except (ValueError, TypeError):
                pass
            
            # checking the validity of the signature again with "NO" being the vote of the user
            if validVote==True:
                pass
            else:
                message = b'NO'
                h = SHA1.new(message)
                try:
                    # PKCS#1 v1.5 (RSA), An old but still solid digital signature scheme based on RSA.
                    pkcs1_15.new(key).verify(h, signature)
                    # if the signature is valid, add the voter to the hasVoted database
                    hasVoted.add(voterId)
                    print ("The signature is valid.")
                    validVote = True
                    # keeping record of the voters vote
                    finalVote[voterId] = "NO"
                    # maintaing the tally of the votes
                    voteCount["NO"] = voteCount["NO"] + 1
                    # sending message to the voter
                    conn.sendall(b'You have successfully voted')
                except:
                    pass
            if validVote == False:
                # if the signatur or the vote is invalid
                print("Signature or the vote is invalid")
                conn.sendall(b'You vote is invalid')
    print("Election has ended")
    # Print the outcome of the election
    print("Vote count YES = {} , NO = {}".format(voteCount["YES"],voteCount["NO"]))
    # Publish the votes of the voter with their voting IDs, only the voters know their voting IDs here
    for vote in finalVote:
        print("Voter with voterID {} voted {}".format(vote, finalVote[vote]))
    

        