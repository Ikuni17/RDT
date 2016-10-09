import argparse
import RDT
import time


def makePigLatin(word):
    m = len(word)
    vowels = "a", "e", "i", "o", "u", "y"
    if m < 3 or word == "the":
        return word
    else:
        for i in vowels:
            if word.find(i) < m and word.find(i) != -1:
                m = word.find(i)
        if m == 0:
            return word + "way"
        else:
            return word[m:] + word[:m] + "ay"


def piglatinize(message):
    essagemay = ""
    message = message.strip(".")
    for word in message.split(' '):
        essagemay += " " + makePigLatin(word)
    return essagemay.strip() + "."


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pig Latin conversion server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    timeout = 5  # close connection if no new data within 5 seconds
    time_of_last_data = time.time()

    rdt = RDT.RDT('server', None, args.port)

    rdt_version = 2

    if rdt_version is 1:
        while (True):
            # try to receiver message before timeout
            msg_S = rdt.rdt_1_0_receive()
            if msg_S is None:
                if time_of_last_data + timeout < time.time():
                    break
                else:
                    continue
            time_of_last_data = time.time()

            # convert and reply
            rep_msg_S = piglatinize(msg_S)
            print('Converted %s \nto %s\n' % (msg_S, rep_msg_S))
            rdt.rdt_1_0_send(rep_msg_S)

    elif rdt_version is 2:
        filler_msg = 'stuff'
        while (True):
            success = False
            # Loop until we receive a valid data packet
            while success is False:
                # try to receive message before timeout
                rcv_pkt = rdt.rdt_2_1_receive()

                # If corrupt send NACK, otherwise check for data packet
                if rcv_pkt is not None:
                    print(rcv_pkt.flag)
                    # Will be true if we have a data packet, and break loop
                    # print(type(rcv_pkt.flag.encode('utf-8')))
                    success = rdt.check_format(rcv_pkt.flag.encode('utf-8'))

                else:
                    rdt.rdt_2_1_send(filler_msg, "neg")

            # Once we have a valid data packet, send ACK and extract the message
            rdt.rdt_2_1_send(filler_msg, "pos")
            msg_S = rcv_pkt.msg_S
            '''if msg_S is None:
                if time_of_last_data + timeout < time.time():
                    break
                else:
                    continue
                time_of_last_data = time.time()'''

            # convert and reply
            rep_msg_S = piglatinize(msg_S)
            print('Converted %s \nto %s\n' % (msg_S, rep_msg_S))

            success = False
            while success is False:
                # Make the packet and attempt to send it
                rdt.rdt_2_1_send(rep_msg_S, "data")
                # Wait to receive a response from the receiver
                response = rdt.rdt_2_1_receive()

                # If the response was corrupt, start the loop over, otherwise enter logic below
                if response is not None:
                    # Check the type of packet
                    type = rdt.check_format(response.flag.encode('utf-8'))

                    # False means we have an ACK packet
                    if type is False:
                        # Success is set to true if the packet is a positive acknowledgement
                        # If a NACK the while loop will iterate again from the beginning
                        success = rdt.check_ack(response.flag.encode('utf-8'))

    elif rdt_version is 3:
        while (True):
            # try to receive message before timeout
            msg_S = rdt.rdt_3_0_receive()
            if msg_S is None:
                if time_of_last_data + timeout < time.time():
                    break
                else:
                    continue
                time_of_last_data = time.time()

            # convert and reply
            rep_msg_S = piglatinize(msg_S)
            print('Converted %s \nto %s\n' % (msg_S, rep_msg_S))
            rdt.rdt_3_0_send(rep_msg_S)

    rdt.disconnect()

    rdt.disconnect()
