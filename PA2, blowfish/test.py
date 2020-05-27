def splitIntoBlocks(message):
    blocks = []
    while message>0:
        message1 = message%(10**15)
        blocks.append(message1)
        message = message//(10**15)
    blocks = blocks[::-1] 
    return blocks

message = int(input())
print(splitIntoBlocks(message))