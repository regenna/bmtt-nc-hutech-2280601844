input_str= input("nhap x,y:")
dismensions=[int(x) for x in input_str.split(',')]
rowNum= dismensions[0]
colNum= dismensions[1]
multilist=[[0 for col in range(colNum)] for row in range(rowNum)]
for row in range(rowNum):
    for col in range(colNum):
        multilist[row][col]=row*col
print(multilist)