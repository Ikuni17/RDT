pos_ack = 0b00000000

neg_ack = 0b01000000

data = 0b10000000

def get_bit(byteval,idx):
    return ((byteval&(1<<idx))!=0)

print(get_bit(data, 6))