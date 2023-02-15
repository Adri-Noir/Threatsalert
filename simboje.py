import random
l=[13,15,17]
while not((l[0]==45 and l[1]==0 and l[2]==0) or (l[0]==0 and l[1]==45 and l[2]==0) or (l[0]==0 and l[1]==0 and l[2]==45)):
    boja1=random.randint(0, 2)
    boja2=random.randint(0, 2)
    if(boja1==0 and boja2==1):
        if(l[boja1]>=l[boja2] and l[boja1]!=0 and l[boja2]!=0):
            brpr=random.randint(1,l[boja2])
            l[0]-=brpr
            l[1]-=brpr
            l[2]+=brpr*2
        elif(l[boja1]<l[boja2] and l[boja1]!=0 and l[boja2]!=0):
            brpr=random.randint(1,l[boja1])
            l[0]-=brpr
            l[1]-=brpr
            l[2]+=brpr*2
    elif(boja1==0 and boja2==2):
        if(l[boja1]>=l[boja2] and l[boja1]!=0 and l[boja2]!=0):
            brpr=random.randint(1,l[boja2])
            l[0]-=brpr
            l[2]-=brpr
            l[1]+=brpr*2
        elif(l[boja1]<l[boja2] and l[boja1]!=0 and l[boja2]!=0):
            brpr=random.randint(1,l[boja1])
            l[0]-=brpr
            l[2]-=brpr
            l[1]+=brpr*2
    elif(boja1==1 and boja2==2):
        if(l[boja1]>=l[boja2] and l[boja1]!=0 and l[boja2]!=0):
            brpr=random.randint(1,l[boja2])
            l[1]-=brpr
            l[2]-=brpr
            l[0]+=brpr*2
        elif(l[boja1]<l[boja2] and l[boja1]!=0 and l[boja2]!=0):
            brpr=random.randint(1,l[boja1])
            l[1]-=brpr
            l[2]-=brpr
            l[0]+=brpr*2

print 'moguce'
