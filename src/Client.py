import argparse
import RDT
import time

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Quotation client talking to a Pig Latin server.')
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    msg_L = [
        'The use of COBOL cripples the mind; its teaching should, therefore, be regarded as a criminal offense. -- Edsgar Dijkstra',
        'C makes it easy to shoot yourself in the foot; C++ makes it harder, but when you do, it blows away your whole leg. -- Bjarne Stroustrup',
        'A mathematician is a device for turning coffee into theorems. -- Paul Erdos',
        'Grove giveth and Gates taketh away. -- Bob Metcalfe (inventor of Ethernet) on the trend of hardware speedups not being able to keep up with software demands',
        'Wise men make proverbs, but fools repeat them. -- Samuel Palmer (1805-80)']

    timeout = 2  # send the next message if not response
    time_of_last_data = time.time()

    rdt = RDT.RDT('client', args.server, args.port)
    rdt_version = 2

    if rdt_version is 1:
        for msg_S in msg_L:
            print('Converting: ' + msg_S)
            rdt.rdt_1_0_send(msg_S)
            # try to receive message before timeout 
            msg_S = None
            while msg_S == None:
                msg_S = rdt.rdt_1_0_receive()
                if msg_S is None:
                    if time_of_last_data + timeout < time.time():
                        break
                    else:
                        continue
            time_of_last_data = time.time()

            # print the result
            if msg_S:
                print('to: ' + msg_S + '\n')


    elif rdt_version is 2:
        # Loop through all the messages, sending each in their own packet
        for msg_S in msg_L:
            print('Converting: ' + msg_S)
            success = False
            #data_get = False

            # Loop until a positive ack is received for this packet
            while success is False:
                # Make the packet and attempt to send it
                rdt.rdt_2_1_send(msg_S, "data")
                # Wait to receive a response from the receiver
                response = rdt.rdt_2_1_receive()
                print(response)

                # If the response was corrupt, start the loop over, otherwise enter logic below
                if response is not None:
                    # Check the type of packet
                    type = rdt.check_format(response.flag.encode('utf-8'))

                    # False means we have an ACK packet
                    if type is False:
                        # Success is set to true if the packet is a positive acknowledgement
                        # If a NACK the while loop will iterate again from the beginning
                        success = rdt.check_ack(response.flag.encode('utf-8'))

            # If we reach this point, the packet was received by the server, and we received a postive ACK
            success = False
            # Loop until we receive a valid data packet with the response message
            while success is False:
                rcv_pkt = rdt.rdt_2_1_receive()

                # If corrupt send NACK, otherwise check for data packet
                if rcv_pkt is not None:
                    # Will be true if we have a data packet, and break loop
                    success = rdt.check_format(rcv_pkt.flag.encode('utf-8'))

                else:
                    rdt.rdt_2_1_send(msg_S, "neg")

            # Once we have the valid packet, extract the message and print it
            print("to: " + rcv_pkt.msg_S + "\n")
            # Send positive ACK
            rdt.rdt_2_1_send(msg_S, "pos")

    elif rdt_version is 3:
         for msg_S in msg_L:
            print('Converting: '+msg_S)
            success = False
            data_get = False

            #TODO Implement RDT3.0 protocol


    rdt.disconnect()
