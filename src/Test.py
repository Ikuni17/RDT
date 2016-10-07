pos_ack = bytes([00000000])
#pos = bin(0)
#data = bin(128)
#neg = bin(64)
pos = (0).to_bytes(2, byteorder='big')
neg = (1).to_bytes(2, byteorder='big')
data = (128).to_bytes(2, byteorder='big')


#neg_ack = bytes([01000000])

#data = bytes([10000000])

def get_bit(byteval,idx):
    return ((byteval&(1<<idx))!=0)

#print(get_bit(data, 6))
#print("Pos: "+ str(len(str(pos))))
print(len(pos))
print(pos)
print(len(neg))
#print("Neg: "+ str(len(str(neg))))
print(neg)
#print("Data: "+ str(len(str(data))))
print(len(data))
print(data)
#print(pos_ack)
#print(data)


