import rsa

class Election:

    def __init__(self):
        self.question = "Do you want this semester to get cancelled?"
        self.voters = []
        (self.pubkey, self.privkey) = rsa.newkeys(512)

    def pubKey(self):
        return self.pubkey


class Voter:

    def __init__(self):
        pass


# print("hello")
CTF = Election()
print(CTF.pubKey())
# print("end")
