#!/usr/bin/python
"""""
@File:           ServerApp.py
@Description:    Server Application running Go-Back-N protocol
                 for reliable data transfer.
@Author:         Chetan Borse
@EMail:          chetanborse2106@gmail.com
@Created_on:     03/23/2017
@License         GNU General Public License
@python_version: 2.7
===============================================================================
"""

import os
import argparse

from GoBackN.server import Receiver
from GoBackN.server import SocketError
from GoBackN.server import FileIOError


def ServerApp(**args):
    # Arguments
    filename = args["filename"]
    senderIP = args["sender_ip"]
    senderPort = args["sender_port"]
    receiverIP = args["receiver_ip"]
    receiverPort = args["receiver_port"]
    sequenceNumberBits = args["sequence_number_bits"]
    timeout = args["timeout"]
    www = args["www"]

    # Create 'Receiver' object
    receiver = Receiver(receiverIP,
                        receiverPort,
                        sequenceNumberBits,
                        www)

    try:
        # Create receiver UDP socket
        receiver.open()

        # Receive file to sender
        receiver.receive(filename,
                         senderIP,
                         senderPort,
                         timeout)

        # Close receiver UDP socket
        receiver.close()
    except SocketError as e:
        print("Unexpected exception in receiver UDP socket!!")
        print(e)
    except FileIOError as e:
        print("Unexpected exception in file to be received!!")
        print(e)
    except Exception as e:
        print("Unexpected exception!")
        print(e)
    finally:
        receiver.close()


if __name__ == "__main__":
    # Argument parser
    parser = argparse.ArgumentParser(description='Go-Back-N Protocol Server Application',
                                     prog='python \
                                           ServerApp.py \
                                           -f <filename> \
                                           -a <sender_ip> \
                                           -b <sender_port> \
                                           -x <receiver_ip> \
                                           -y <receiver_port> \
                                           -m <sequence_number_bits> \
                                           -t <timeout> \
                                           -w <www>')

    parser.add_argument("-f", "--filename", type=str, default="index.html",
                        help="File to be received, default: index.html")
    parser.add_argument("-a", "--sender_ip", type=str, default="127.0.0.1",
                        help="Sender IP, default: 127.0.0.1")
    parser.add_argument("-b", "--sender_port", type=int, default=8081,
                        help="Sender Port, default: 8081")
    parser.add_argument("-x", "--receiver_ip", type=str, default="127.0.0.1",
                        help="Receiver IP, default: 127.0.0.1")
    parser.add_argument("-y", "--receiver_port", type=int, default=8080,
                        help="Receiver Port, default: 8080")
    parser.add_argument("-m", "--sequence_number_bits", type=int, default=2,
                        help="Total number of bits used in sequence numbers, default: 2")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Timeout, default: 10")
    parser.add_argument("-w", "--www", type=str, default=os.path.join(os.getcwd(), "data", "receiver"),
                        help="Destination folder for receipt, default: /<Current Working Directory>/data/receiver/")

    # Read user inputs
    args = vars(parser.parse_args())

    # Run Server Application
    ServerApp(**args)
