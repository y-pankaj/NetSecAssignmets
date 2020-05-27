import time
from fractions import gcd
from random import randrange, random, randint
from collections import namedtuple
from math import log
from binascii import hexlify, unhexlify
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1

# function for checking if n is prime or not
def is_prime(n, k=30):
    if n <= 3:
        return n == 2 or n == 3
    neg_one = n - 1

    s, d = 0, neg_one
    while not d & 1:
        s, d = s+1, d>>1
    assert 2 ** s * d == neg_one and d & 1

    for i in range(k):
        a = randrange(2, neg_one)
        x = pow(a, d, n)
        if x in (1, neg_one):
            continue
        for r in range(1, s):
            x = x ** 2 % n
            if x == 1:
                return False
            if x == neg_one:
                break
        else:
            return False
    return True

# function for choosing random prime number
def randprime(N=10**8):
    p = 1
    while not is_prime(p):
        p = randrange(N)
    return p

# funtion to calculate the inverve of some number value given a modulo
def multinv(modulus, value):
    x, lastx = 0, 1
    a, b = modulus, value
    while b:
        a, q, b = b, a // b, a % b
        x, lastx = lastx - q * x, x
    result = (1 - lastx * modulus) // value
    if result < 0:
        result += modulus
    assert 0 <= result < modulus and value * result % modulus == 1
    return result

# tuple to store public and private keys
KeyPair = namedtuple('KeyPair', 'public private')
# a key consists of exponent and a modulo
Key = namedtuple('Key', 'exponent modulus')

# function to generate a pair of keys with base 10
def keygen(N, public=None):
    prime1 = randprime(N)
    prime2 = randprime(N)
    composite = prime1 * prime2
    totient = (prime1 - 1) * (prime2 - 1)
    if public is None:
        while True:
            private = randrange(totient)
            if gcd(private, totient) == 1:
                break
        public = multinv(totient, private)
    else:
        private = multinv(totient, public)
    assert public * private % totient == gcd(public, totient) == gcd(private, totient) == 1
    assert pow(pow(1234567, public, composite), private, composite) == 1234567
    return KeyPair(Key(public, composite), Key(private, composite))

# function to sign a message using private key
def signature(msg, privkey):
    coded = pow(int(msg), *privkey)% privkey[1]
    return coded

# function to calculate blinding factor used in blinding
# for more info visit https://en.wikipedia.org/wiki/Blind_signature
def blindingfactor(N):
    b=random()*(N-1)
    r=int(b)
    while (gcd(r,N)!=1):
        r=r+1
    return r

# blinding a message with a given blinding factor
def blindGivenFactor(msg,pubkey,r):
    m=int(msg)
    blindmsg=(pow(r,*pubkey)*m)% pubkey[1]
    return blindmsg

# unblinding a message using a given blinding factor
def unblind(msg,r,pubkey):
    bsm=int(msg)
    ubsm=(bsm*multinv(pubkey[1],r))% pubkey[1]
    return ubsm

# verifying a signed message
def verify(msg,pubkey):
    return pow(int(msg),*pubkey)%pubkey[1]

# converting strings to their decimal representation
def convert(s):
    if s == "YES":
        return 896983
    else:
        return 7879

# function to check for the validity of blind votes
def check(blVote, blKey, pubkey):
    if unblind(blVote[0],blKey,pubkey)!=896983:
        return True
    if unblind(blVote[1],blKey,pubkey)!=7879:
        return True
    return False


# set of registered eligible voters, recognised by their registration ids
registeredVoters = set()
registeredVoters.update({"1", "2", "3", "4", "5"})
# mainting the vote count
voteCount = {convert("YES"): 0, convert("NO"):0}
# maintaining the final votes of the serialIDs
finalVote = []
# the blind votes which have been used
usedBlindVote = set()
# voters who have generated blind votes
geneBL = set()
# generating keys to be used for blinding
pubkey, privkey = keygen(2 ** 128)
# key Generated using KeyGeneration.py for confidentiality
privateKeyCTF = RSA.import_key(open('private_pem.pem', 'r').read())
publicKeyCTF = RSA.import_key(open('public_pem.pem', 'r').read())

# specifying the endtime for elections 
t_end = time.time() + 30 * 1
while time.time() < t_end:
    action = input("Press 1 to generate your blind vote and 2 to submit your vote\n")
    if time.time() > t_end:
        break

    if action=="1":
        voterId = input("Please enter your voterID (should be between 1 to 5 if you are a registered voter)\n")
        try:
            int(voterId)
        except:
            print("Format of your voterID is incorrect\n")
        if int(voterId)>5 or int(voterId)<1:
            print("You are not a registered voter\n")
            continue
        if int(voterId) in geneBL:
            print("You have already generated your blind votes\n")
            continue
        # variable for terminating the session if anything goes wrong
        terminateSession = False
        # generate 10 set of messages with vote "YES", "NO" and serialID of the vote
        blindVotes = []
        # corresponding blinding factors
        blindingFactors = []
        # serialIDs appended with the votes
        for i in range (10):
            blindVotes.append([convert('YES'),convert('NO'),randint(1000000000,100000000000)])
        # blinding all sets of messages
        for i in range (10):
            blfac = blindingfactor(pubkey[1])
            blindVotes[i][0] = blindGivenFactor(blindVotes[i][0],pubkey,blfac)
            blindVotes[i][1] = blindGivenFactor(blindVotes[i][1],pubkey,blfac)
            blindVotes[i][2] = blindGivenFactor(blindVotes[i][2],pubkey,blfac)
            blindingFactors.append(blfac)
        
        # choosing a random integer between 0 and 9
        # CTF will not open the content of the message with index idx
        idx = randint(0,9)
        # checking if the message sets are properly formed
        for i in range(10):
            if i==idx:
                continue
            if check(blindVotes[i],blindingFactors[i],pubkey)==False:
                terminateSession=True
                break
        if terminateSession == True:
            print("Format of blind votes is not correct\n")
            continue
        # signing the blinded votes with the CTF's private KEY and sending them to the voter
        for i in range(10):
            blindVotes[i][0] = signature(blindVotes[i][0], privkey)
            blindVotes[i][1] = signature(blindVotes[i][1], privkey)
            blindVotes[i][2] = signature(blindVotes[i][2], privkey)
        # the voter unblinds the votes
        for i in range(10):
            blindVotes[i][0] = unblind(blindVotes[i][0],blindingFactors[i],pubkey)
            blindVotes[i][1] = unblind(blindVotes[i][1],blindingFactors[i],pubkey)
            blindVotes[i][2] = unblind(blindVotes[i][2],blindingFactors[i],pubkey)

        # voter checks if he has received the signed votes correctly
        if verify(blindVotes[idx][0],pubkey)==convert('YES') and verify(blindVotes[idx][1],pubkey)==convert('NO'):
            pass
        else:
            print("The recived votes are not correct\n")
            continue
        # if the generated votes are correct mark this user
        # i.e. set generatedBlind Votes true for this user
        geneBL.add(int(voterId))
        # giving the user it's signed vote for YES and NO
        print("Use {} for voting YES\n".format(str(blindVotes[idx][2])+"."+str(blindVotes[idx][0])))
        print("Use {} for voting NO\n".format(str(blindVotes[idx][2])+"."+str(blindVotes[idx][1])))
        
    elif action == "2":
        print("Please enter your signed vote\n")
        voterInput = input()
        #Instantiating PKCS1_OAEP object with the private key for encrypting the vote
        confidence = PKCS1_OAEP.new(key=publicKeyCTF)
        # encrypting the signed vote with the CTF public key
        signedPlusEncryptedVote = confidence.encrypt(voterInput.encode())

        # CTF receives the encrpted vote and decrypts it
        decrypt = PKCS1_OAEP.new(key=privateKeyCTF)
        # decrypting the message
        decrypted_vote = decrypt.decrypt(signedPlusEncryptedVote)
        decrypted_vote = decrypted_vote.decode()
        try:
            serialID, vote = decrypted_vote.split('.')
        except:
            print("The vote is tampered\n")
            continue
        # verifying if the signature is correct
        vote = verify(vote,pubkey)
        serialID = verify(serialID,pubkey)
        # checking if this serialID has been used before
        if serialID in usedBlindVote:
            print("This serialID has been used before")
            continue
        # if the vote is garbage/tampered stop processing the vote
        if vote!=convert('YES') and vote!=convert('NO'):
            print("Your vote is tampered")
            continue
        # checking validity of the serialIDs
        if serialID <10000000 or serialID>100000000000:
            print("Your vote is tampered")
            continue
        # maintaining the vote corresponding to the serialIDs
        if vote==convert('YES'):
            finalVote.append([serialID, 'YES'])
        else:
            finalVote.append([serialID,'NO'])
        # adding the serialID to used serialIDs
        usedBlindVote.add(serialID)
        voteCount[vote] = voteCount[vote] + 1

    else:
        pass

print("Election has ended")
# Print the outcome of the election
print("Vote count YES = {} , NO = {}".format(voteCount[convert("YES")],voteCount[convert("NO")]))
# Publish the votes of the voter with their voting IDs, only the voters know their voting IDs here
for vote in finalVote:
    print("Voter with serialID {} voted {}".format(vote[0], vote[1]))