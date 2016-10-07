import Network
import argparse
from time import sleep
import hashlib

global pos_ack  # The format for a packet's introductory byte that denotes it as a positive acknowledgement.
pos_ack = (1).to_bytes(2, byteorder='big')

global neg_ack  # The format for a packet's introductory byte that denotes it as a negative acknowledgement.
neg_ack = (0).to_bytes(2, byteorder='big')

global data  # The format for a packet's introductory byte that denotes it as a data packet.
data = (128).to_bytes(1, byteorder='big')


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        # extract the fields
        seq_num = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        return self(seq_num, msg_S)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S

    @staticmethod
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length: Packet.seq_num_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[
                     Packet.seq_num_S_length + Packet.seq_num_S_length: Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length:]

        # compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        # and check if the same
        return checksum_S != computed_checksum_S


class AckPack(Packet):
    flag_length = 7

    def __init__(self, seq_num, msg_S, flag):
        Packet.__init__(self, seq_num, msg_S)
        self.flag = flag
        # self.flag_length = len(str(flag))
        # print(flag)
        # print("construct flag: " + str(self.flag))
        # print("construct flag length: " + str(self.flag_length))

    @classmethod
    def from_byte_S(self, byte_S):
        if AckPack.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        # extract the fields
        seq_num = int(byte_S[AckPack.length_S_length: AckPack.length_S_length + AckPack.seq_num_S_length])
        msg_S = byte_S[
                AckPack.length_S_length + AckPack.seq_num_S_length + AckPack.flag_length + AckPack.checksum_length:]
        flag = byte_S[
               AckPack.length_S_length + AckPack.seq_num_S_length: AckPack.length_S_length + AckPack.seq_num_S_length + AckPack.flag_length]
        # print("from flag")
        # print(flag)
        return self(seq_num, flag, msg_S)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # print("getSeqnum: " + seq_num_S)
        flag_S = str(self.flag).zfill(self.flag_length)
        # print("getFlag: " + flag_S)
        # convert length to a byte field of length_S_length bytes
        length_S = str(
            self.length_S_length + len(seq_num_S) + len(flag_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # print("getLength_S: " + length_S)
        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + flag_S + self.msg_S).encode('utf-8'))
        # print(checksum)
        checksum_S = checksum.hexdigest()
        # print("getchecksum: " + checksum_S)
        # compile into a string
        return length_S + seq_num_S + flag_S + checksum_S + self.msg_S

    #
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0:AckPack.length_S_length]
        # print("length_S: " + length_S)
        seq_num_S = byte_S[AckPack.length_S_length: AckPack.length_S_length + AckPack.seq_num_S_length]
        # print("seq_num: " + seq_num_S)
        # print(AckPack.flag_length)
        flag_S = byte_S[
                 AckPack.length_S_length + AckPack.seq_num_S_length: AckPack.flag_length + AckPack.seq_num_S_length + AckPack.length_S_length]
        # print(flag_S)
        checksum_S = byte_S[
                     AckPack.length_S_length + AckPack.seq_num_S_length + AckPack.flag_length: AckPack.seq_num_S_length + AckPack.length_S_length + AckPack.flag_length + AckPack.checksum_length]
        # print("checksum: " + checksum_S)
        msg_S = byte_S[
                AckPack.length_S_length + AckPack.seq_num_S_length + AckPack.flag_length + AckPack.checksum_length:]
        # print("msg_S: " + msg_S)

        # compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + flag_S + msg_S).encode('utf-8'))
        # print("checksum: " + str(checksum))
        computed_checksum_S = checksum.hexdigest()
        # print("computed checksum: " + computed_checksum_S)
        # and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        # keep extracting packets - if reordered, could get more than one
        while True:
            # check if we have received enough bytes
            if (len(self.byte_buffer) < Packet.length_S_length):
                return ret_S  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S  # not enough bytes to read the whole packet
            # create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            # remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            # if this was the last packet, will return on the next iteration
            # print("flag: " + p.flag)

    def rdt_2_1_send(self, msg_S):
        global data
        global pos_ack
        global neg_ack
        p = AckPack(self.seq_num, msg_S, data)
        self.seq_num += 1
        success = False
        while success is False:
            self.network.udt_send(p.get_byte_S())

    def rdt_2_1_receive(self):
        pass

    def rdt_3_0_send(self, msg_S):
        pass

    def rdt_3_0_receive(self):
        pass

    def check_format(self, flag):
        # Return true if 7th index is 1, which is flag for data packet. Otherwise false which is ACK packet
        return (int.from_bytes(flag, byteorder='big') & (1 << 7)) != 0

    def check_ack(self, flag):
        # Return true if 0th index is 1, which is flag for positive ACK. Otherwise false which is negative ACK
        return (int.from_bytes(flag, byteorder='big') & (1 << 0)) != 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
