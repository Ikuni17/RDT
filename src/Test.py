class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

class AckPack(Packet):
    global data
    flag_length = 7

    def __init__(self, seq_num, msg_S, flag):
        Packet.__init__(self, seq_num, msg_S)
        self.flag = flag


msg_S = 'The use of COBOL cripples the mind; its teaching should, therefore, be regarded as a criminal offense. -- Edsgar Dijkstra'
seq_num = 0
pos_ack = bytes([00000000])
#pos = bin(0)
#data = bin(128)
#neg = bin(64)
pos = (1).to_bytes(2, byteorder='big')
neg = (0).to_bytes(2, byteorder='big')
data = (128).to_bytes(2, byteorder='big')
p = AckPack(seq_num, msg_S, data)
#print(type(p.flag))

#neg_ack = bytes([01000000])

#data = bytes([10000000])

def get_bit(byteval,idx):
    return ((byteval&(1<<idx))!=0)

#print(get_bit(data, 6))
#print("Pos: "+ str(len(str(pos))))
#print(len(pos))
print(pos)
#print(len(neg))
#print("Neg: "+ str(len(str(neg))))
print(neg)
#print("Data: "+ str(len(str(data))))
#print(len(data))
print(data)
#print(pos_ack)
#print(data)

print(get_bit(int.from_bytes(pos, byteorder='big'), 0))
print(get_bit(int.from_bytes(neg, byteorder='big'), 0))
print(get_bit(int.from_bytes(data, byteorder='big'), 7))
print(get_bit(int.from_bytes(p.flag, byteorder='big'), 7))


def test(flag):
    if flag is "data":
        print("data")
    else:
        print("wrong")
