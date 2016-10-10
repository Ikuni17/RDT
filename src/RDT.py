import Network
import argparse
from time import sleep
import hashlib

# Global variables used to differentiate between packets, converted to bytes later
# ACK flag is the least significant digit, data flag is the most significant digit
global pos_ack
pos_ack = 1

global neg_ack
neg_ack = 0

global data
data = 128


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
    flag_length = 3

    def __init__(self, seq_num, msg_S, flag):
        Packet.__init__(self, seq_num, msg_S)
        self.flag = flag

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
        # convert flag to bytes
        flag = (int(flag)).to_bytes(2, byteorder='big')
        return self(seq_num, msg_S, flag)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        flag_S = str(self.flag).zfill(self.flag_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(
            self.length_S_length + len(seq_num_S) + len(flag_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + flag_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + flag_S + checksum_S + self.msg_S

    #
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0:AckPack.length_S_length]
        seq_num_S = byte_S[AckPack.length_S_length: AckPack.length_S_length + AckPack.seq_num_S_length]
        flag_S = byte_S[
                 AckPack.length_S_length + AckPack.seq_num_S_length: AckPack.flag_length + AckPack.seq_num_S_length + AckPack.length_S_length]
        checksum_S = byte_S[
                     AckPack.length_S_length + AckPack.seq_num_S_length + AckPack.flag_length: AckPack.seq_num_S_length + AckPack.length_S_length + AckPack.flag_length + AckPack.checksum_length]
        msg_S = byte_S[
                AckPack.length_S_length + AckPack.seq_num_S_length + AckPack.flag_length + AckPack.checksum_length:]
        # compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + flag_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
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

    def rdt_2_1_send(self, msg_S, flag):
        global data
        global pos_ack
        global neg_ack

        # Create an ACK packet or data packet depending on the flag, then it
        if flag is "data":
            p = AckPack(self.seq_num, msg_S, data)
        elif flag is "pos":
            p = AckPack(self.seq_num, msg_S, pos_ack)
        elif flag is "neg":
            p = AckPack(self.seq_num, msg_S, neg_ack)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_2_1_receive(self):
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S

        # Make sure we have enough bytes
        if (len(self.byte_buffer) > AckPack.length_S_length):
            # Extract the length of the packet
            length = int(self.byte_buffer[:AckPack.length_S_length])
            # If the packet is not corrupt extract the fields and return the packet
            if not AckPack.corrupt(self.byte_buffer[0:length]):
                p = AckPack.from_byte_S(self.byte_buffer[0:length])
                self.byte_buffer = self.byte_buffer[length:]
                return p
            # Otherwise return nothing.
            else:
                return None

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