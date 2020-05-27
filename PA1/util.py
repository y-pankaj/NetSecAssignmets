from random import seed
from random import choice

def hammingDistance( x, y):
	a = 0
	for i in range(31,-1,-1):
		b1= x>>i&1
		b2 = y>>i&1
		a+= not(b1==b2)
	return a

chk = [[1, 13, 8, 3, 7, 0, 2, 14, 10, 6, 15, 5, 9, 12, 4, 11],
[14, 3, 7, 9, 13, 0, 11, 6, 1, 10, 4, 15, 2, 12, 8, 5],
[1, 10, 12, 3, 2, 4, 7, 13, 14, 0, 5, 9, 8, 15, 11, 6],
[14, 7, 0, 9, 11, 12, 5, 2, 4, 8, 13, 3, 1, 6, 10, 15],
[3, 5, 12, 10, 15, 9, 6, 0, 4, 11, 7, 13, 1, 2, 8, 14],
[11, 2, 12, 1, 5, 15, 6, 8, 4, 14, 10, 7, 9, 0, 3, 13],
[5, 3, 0, 6, 12, 9, 15, 10, 8, 4, 11, 13, 2, 14, 1, 7],
[2, 9, 11, 6, 4, 10, 14, 5, 8, 3, 7, 12, 1, 15, 13, 0],
[3, 14, 9, 4, 0, 7, 10, 13, 12, 11, 15, 2, 6, 1, 5, 8],
[3, 4, 10, 1, 9, 14, 12, 2, 0, 15, 13, 6, 7, 8, 11, 5],
[3, 12, 6, 15, 9, 0, 5, 10, 13, 1, 11, 2, 7, 14, 8, 4],
[4, 11, 8, 13, 15, 6, 2, 1, 14, 7, 3, 10, 5, 0, 9, 12],
[12, 3, 2, 15, 7, 4, 9, 10, 0, 13, 11, 1, 14, 8, 5, 6],
[10, 4, 0, 13, 9, 7, 5, 11, 6, 8, 12, 1, 15, 2, 3, 14],
[12, 1, 6, 13, 10, 4, 0, 7, 3, 8, 5, 11, 15, 2, 9, 14],
[1, 4, 12, 2, 6, 11, 10, 13, 8, 7, 5, 9, 15, 0, 3, 14],
[0, 12, 10, 1, 7, 2, 9, 15, 13, 6, 4, 11, 14, 8, 3, 5],
[15, 4, 0, 11, 12, 2, 6, 13, 5, 14, 9, 7, 10, 1, 3, 8],
[2, 9, 12, 7, 15, 0, 1, 10, 5, 14, 11, 4, 8, 13, 6, 3],
[12, 7, 10, 13, 0, 11, 6, 1, 15, 2, 9, 4, 3, 8, 5, 14],
[0, 6, 13, 3, 10, 9, 7, 12, 14, 8, 11, 5, 4, 2, 1, 15],
[0, 10, 7, 4, 12, 3, 11, 13, 14, 1, 9, 15, 5, 6, 2, 8],
[0, 10, 11, 13, 6, 1, 12, 7, 5, 9, 8, 2, 3, 14, 15, 4],
[1, 15, 13, 6, 7, 9, 14, 0, 11, 12, 8, 3, 4, 10, 2, 5],
[7, 1, 9, 14, 4, 2, 10, 13, 12, 6, 3, 8, 15, 5, 0, 11],
[9, 0, 5, 12, 2, 11, 14, 7, 10, 15, 6, 1, 13, 8, 3, 4],
[2, 11, 8, 14, 7, 13, 4, 1, 12, 6, 5, 9, 0, 10, 3, 15],
[8, 4, 7, 1, 13, 2, 11, 14, 5, 3, 9, 12, 10, 15, 6, 0],
[11, 12, 7, 0, 2, 15, 14, 5, 1, 10, 13, 3, 8, 6, 4, 9],
[7, 14, 11, 1, 8, 13, 2, 4, 0, 9, 12, 6, 15, 10, 5, 3],
[15, 6, 12, 10, 3, 9, 0, 5, 4, 11, 7, 1, 13, 2, 14, 8],
[11, 0, 14, 5, 4, 3, 1, 12, 13, 6, 8, 15, 7, 10, 2, 9],
[11, 6, 12, 10, 1, 13, 7, 0, 14, 9, 2, 5, 8, 3, 4, 15],
[0, 6, 10, 5, 12, 9, 15, 3, 14, 11, 1, 8, 7, 4, 2, 13],
[4, 7, 14, 8, 1, 11, 13, 2, 3, 9, 5, 6, 10, 12, 0, 15],
[8, 11, 2, 7, 13, 14, 1, 4, 3, 5, 12, 9, 6, 0, 10, 15],
[12, 9, 10, 6, 3, 15, 5, 0, 11, 7, 4, 13, 8, 1, 2, 14],
[1, 4, 7, 9, 10, 15, 12, 3, 6, 13, 11, 2, 5, 8, 0, 14],
[6, 13, 3, 0, 5, 10, 8, 7, 12, 11, 9, 14, 2, 4, 15, 1],
[2, 5, 8, 15, 11, 0, 13, 3, 4, 10, 1, 6, 14, 9, 7, 12],
[14, 1, 5, 15, 0, 10, 3, 12, 11, 4, 8, 2, 13, 7, 6, 9],
[6, 3, 9, 10, 5, 15, 12, 0, 8, 4, 2, 13, 14, 1, 11, 7],
[7, 9, 0, 14, 12, 5, 10, 3, 13, 6, 11, 1, 2, 8, 4, 15],
[9, 2, 3, 13, 12, 7, 15, 4, 10, 1, 6, 11, 0, 14, 5, 8],
[11, 4, 8, 14, 2, 9, 1, 7, 12, 3, 5, 0, 15, 6, 10, 13],
[4, 9, 8, 3, 13, 6, 14, 5, 2, 15, 7, 12, 1, 10, 11, 0],
[0, 13, 12, 10, 11, 7, 6, 1, 5, 8, 3, 15, 14, 4, 9, 2],
[9, 2, 6, 12, 5, 11, 15, 1, 14, 7, 3, 0, 8, 13, 4, 10],
[11, 4, 8, 7, 5, 9, 6, 10, 1, 13, 2, 14, 12, 3, 15, 0],
[5, 6, 0, 15, 3, 9, 12, 10, 8, 11, 14, 1, 13, 4, 2, 7],
[4, 3, 7, 12, 10, 5, 9, 6, 15, 0, 8, 11, 1, 14, 2, 13],
[10, 12, 0, 9, 3, 5, 15, 6, 13, 7, 11, 4, 14, 2, 1, 8],
[14, 3, 13, 10, 1, 15, 2, 12, 4, 9, 8, 6, 11, 5, 7, 0],
[8, 4, 11, 13, 6, 1, 5, 10, 14, 3, 7, 0, 9, 15, 2, 12],
[15, 6, 12, 3, 1, 13, 10, 0, 9, 5, 7, 8, 2, 14, 4, 11],
[12, 9, 6, 5, 10, 0, 3, 14, 7, 4, 11, 8, 1, 15, 13, 2],
[7, 10, 12, 1, 11, 6, 0, 13, 9, 15, 3, 4, 5, 8, 14, 2],
[11, 4, 2, 14, 12, 3, 5, 9, 0, 15, 13, 1, 7, 8, 10, 6],
[14, 4, 2, 11, 8, 1, 7, 13, 0, 3, 9, 12, 5, 15, 10, 6],
[0, 5, 6, 11, 13, 8, 3, 14, 7, 12, 9, 2, 10, 15, 4, 1],
[1, 4, 12, 3, 7, 8, 10, 13, 6, 11, 9, 5, 0, 14, 15, 2],
[11, 5, 12, 2, 6, 9, 0, 14, 13, 8, 7, 4, 1, 15, 10, 3],
[1, 13, 8, 3, 7, 0, 2, 14, 10, 6, 15, 5, 9, 12, 4, 11],
[14, 3, 7, 9, 13, 0, 11, 6, 1, 10, 4, 15, 2, 12, 8, 5],
[1, 10, 12, 3, 2, 4, 7, 13, 14, 0, 5, 9, 8, 15, 11, 6],
[14, 7, 0, 9, 11, 12, 5, 2, 4, 8, 13, 3, 1, 6, 10, 15],
[3, 5, 12, 10, 15, 9, 6, 0, 4, 11, 7, 13, 1, 2, 8, 14],
[11, 2, 12, 1, 5, 15, 6, 8, 4, 14, 10, 7, 9, 0, 3, 13],
[5, 3, 0, 6, 12, 9, 15, 10, 8, 4, 11, 13, 2, 14, 1, 7],
[2, 9, 11, 6, 4, 10, 14, 5, 8, 3, 7, 12, 1, 15, 13, 0],
[3, 14, 9, 4, 0, 7, 10, 13, 12, 11, 15, 2, 6, 1, 5, 8],
[3, 4, 10, 1, 9, 14, 12, 2, 0, 15, 13, 6, 7, 8, 11, 5],
[3, 12, 6, 15, 9, 0, 5, 10, 13, 1, 11, 2, 7, 14, 8, 4],
[4, 11, 8, 13, 15, 6, 2, 1, 14, 7, 3, 10, 5, 0, 9, 12],
[12, 3, 2, 15, 7, 4, 9, 10, 0, 13, 11, 1, 14, 8, 5, 6],
[10, 4, 0, 13, 9, 7, 5, 11, 6, 8, 12, 1, 15, 2, 3, 14],
[12, 1, 6, 13, 10, 4, 0, 7, 3, 8, 5, 11, 15, 2, 9, 14],
[1, 4, 12, 2, 6, 11, 10, 13, 8, 7, 5, 9, 15, 0, 3, 14],
[0, 12, 10, 1, 7, 2, 9, 15, 13, 6, 4, 11, 14, 8, 3, 5],
[15, 4, 0, 11, 12, 2, 6, 13, 5, 14, 9, 7, 10, 1, 3, 8],
[2, 9, 12, 7, 15, 0, 1, 10, 5, 14, 11, 4, 8, 13, 6, 3]]
chk1 = []
while True:
	ans = []
	brk=0
	seq = [i for i in range(16)]
	for i in range(16):
		k=0
		cmd=0
		s2="{0:04b}".format(i)
		while len(ans)<=i:
			cmd=1
			sel = choice(seq)
			#print(i,sel)
			for j in range(i):
				s1="{0:04b}".format(j)
				if(s1[0]==s2[0] and s1[3]==s2[3]):
					if(hammingDistance(sel,ans[j])<2):
						k=k+1
						cmd=0
						if(k==15):
							brk=1
						break
			if(cmd==1):
				ans.append(sel)
				seq.remove(sel)
			if(brk==1):
				break
		if(brk==1):
			break
	if(brk==0 and not (ans in chk)):
		chk.append(ans)
		chk1.append(ans)
		print(ans)
		#ans = [14,4,13 ,1, 2, 15, 11, 8 ,3, 10, 6, 12, 5, 9, 0, 7]
		for i in range(16):
			for j in range(i+1,16):
				s1="{0:04b}".format(i)
				s2="{0:04b}".format(j)
				if((hammingDistance(i,j)==1) or (s1[0]==s2[0] and s1[3]==s2[3])):
					if(hammingDistance(ans[i],ans[j])<3):
						brk=1
						break
			if(brk == 1):
				break
		if(brk==0):
# 			print(ans)
			break

def tett():
    for i in range(128-16+1,128) :
        for j in range(0,8) :
            print( str(i - 16*j) + ",", end =" " )
        print("")

def pc3():
    PC_32 = [114, 98, 82, 66, 50, 34, 18, 2, 
        116, 100, 84, 68, 52, 36, 20, 4,  
        118, 102, 86, 70, 54, 38, 22, 6, 
        120, 104, 88, 72, 56, 40, 24, 8, 
        122, 106, 90, 74, 58, 42, 26, 10, 
        124, 108, 92, 76, 60, 44, 28, 12, 
        126, 118, 110, 102, 94, 86, 78, 70,
        126, 110, 94, 78, 62, 46, 30, 14,
        113, 97, 81, 65, 49, 33, 17, 1, 
        115, 99, 83, 67, 51, 35, 19, 3, 
        117, 101, 85, 69, 53, 37, 21, 5,
        119, 103, 87, 71, 55, 39, 23, 7, 
        121, 105, 89, 73, 57, 41, 25, 9,
        123, 107, 91, 75, 59, 43, 27, 11, 
        125, 109, 93, 77, 61, 45, 29, 13, 
        127, 111, 95, 79, 63, 47, 31, 15
    ]
    I_PC_32 = PC_32
    cnt = 1
    for i in PC_32:
        I_PC_32[i-1] = cnt
        cnt+=1

def util2():
    cnt = 1
    for i in I_PC_32 :
        print(str(i)+",",end =" ")
        cnt+=1
        if cnt == 9 :
            print("")
            cnt=1

def shuffle():
    import random 
  
    # initializing list  
    test_list = ary
    
    # Printing original list  
    print ("The original list is : " + str(test_list)) 
    
    # using Fisher–Yates shuffle Algorithm 
    # to shuffle a list 
    for i in range(len(test_list)-1, 0, -1): 
        
        # Pick a random index from 0 to i  
        j = random.randint(0, i + 1)  
        
        # Swap arr[i] with the element at random index  
        test_list[i], test_list[j] = test_list[j], test_list[i]  
        
    # Printing shuffled list  
    print ("The shuffled list is : " +  str(test_list)) 


while(len(s)) :
#     print(s)
    s = Cloning(temp_s)
    vis = []
    temp = []
    for i in range(16) :
        temp = []
        for j in range(16):
            temp.append(0)
        vis.append(temp)
    res = []
#     print(s)
    for j in s :
#         print(j)
        flag = 1
        removed = []
        for k in range(len(j)) :
#             print(k)
#             print(j[k])
            if vis[k][j[k]] :
                flag = 0
                break
            else :
                vis[k][j[k]] = 1
                removed.append([k,j[k]])
        if flag == 0 :
            for lst in removed :
                vis[lst[0]][lst[1]] = 0
        elif flag == 1 :
            res.append(j)
            temp_s.remove(j)
#             print(s)
        elif len(res) == 4 :
            break
#         print(res)
    if len(res) == 4 :
        fres.append(res)

print(len(fres))
# print(fres)

for temp in range(50) :
#     print(s)
    s = Cloning(temp_s)
    vis = []
    temp = []
    for i in range(16) :
        temp = []
        for j in range(16):
            temp.append(0)
        vis.append(temp)
    res = []
#     print(s)
    for j in s :
#         print(j)
        flag = 1
        removed = []
        for k in range(len(j)) :
#             print(k)
#             print(j[k])
            if vis[k][j[k]] :
                flag = 0
                break
            else :
                vis[k][j[k]] = 1
                removed.append([k,j[k]])
        if flag == 0 :
            for lst in removed :
                vis[lst[0]][lst[1]] = 0
        elif flag == 1 :
            res.append(j)
            temp_s.remove(j)
#             print(s)
        elif len(res) == 4 :
            break
#         print(res)
    if len(res) == 4 :
        fres.append(res)

print(len(fres))
