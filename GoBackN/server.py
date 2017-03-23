#!/usr/bin/python
"""""
@File:           server.py
@Description:    This is a receiver running Go-Back-N protocol
                 for reliable data transfer.
@Author:         Chetan Borse
@EMail:          chetanborse2106@gmail.com
@Created_on:     03/23/2017
@License         GNU General Public License
@python_version: 2.7
===============================================================================
"""

import os
import logging
import random
import socket
import struct
import select
import hashlib
from collections import namedtuple
from threading import Thread


# Set logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s RECEIVER [%(levelname)s] %(message)s',)
log = logging.getLogger()


class SocketError(Exception):
    pass


class FileIOError(Exception):
    pass


class Receiver(object):
    """
    Receiver running Go-Back-N protocol for reliable data transfer.
    """

    def __init__(self,
                 receiverIP="127.0.0.1",
                 receiverPort=8080,
                 www=os.path.join(os.getcwd(), "data", "receiver")):
        self.receiverIP = receiverIP
        self.receiverPort = receiverPort
        self.www = www

    def open(self):
        """
        Create UDP socket for communication with the client.
        """
        log.info("Creating UDP socket %s:%d for communication with the client",
                 self.receiverIP, self.receiverPort)

        try:
            self.receiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.receiverSocket.bind((self.receiverIP, self.receiverPort))
            self.receiverSocket.setblocking(0)
        except Exception as e:
            log.error("Could not create UDP socket for communication with the client!")
            log.debug(e)
            raise SocketError("Creating UDP socket %s:%d for communication with the client failed!"
                              % (self.receiverIP, self.receiverPort))

    def receive(self,
                filename,
                senderIP="127.0.0.1",
                senderPort=8081,
                timeout=10):
        """
        Receive packets transmitted from sender and
        write payload data to the specified file.
        """
        log.info("Started to receive packets transmitted from sender")
        filename = os.path.join(self.www, filename)

        # Create a file handler for writing data received from sender
        try:
            log.info("Writing payload data to '%s'", filename)
            self.fileHandle = open(filename, "wb")
        except IOError as e:
            log.error("Could not create a file handle!")
            log.debug(e)
            raise FileIOError("Creating a file handle failed!\nFilename: %s"
                              % filename)

        # Create an object of 'Window', which handles packet receipt
        window = Window()

        # Create a thread named 'PacketHandler' to monitor packet receipt
        log.info("Creating a thread to monitor packet receipt")
        packetHandler = PacketHandler(self.fileHandle,
                                      self.receiverSocket,
                                      senderIP,
                                      senderPort,
                                      self.receiverIP,
                                      self.receiverPort,
                                      window,
                                      timeout)

        # Start thread execution
        log.info("Starting thread execution")
        packetHandler.start()

        # Wait for a thread to finish its execution
        packetHandler.join()

    def close(self):
        """
        Close a file handle and UDP socket.
        """
        # Close file handle
        try:
            if self.fileHandle:
                self.fileHandle.close()
        except IOError as e:
            log.error("Could not close a file handle!")
            log.debug(e)
            raise FileIOError("Closing a file handle failed!")

        # Close receiver's socket
        try:
            if self.receiverSocket:
                self.receiverSocket.close()
        except Exception as e:
            log.error("Could not close UDP socket!")
            log.debug(e)
            raise SocketError("Closing UDP socket %s:%d failed!"
                              % (self.receiverIP, self.receiverPort))


class Window(object):
    """
    Class for assisting packet receipt.
    """

    def __init__(self):
        self.expectedPkt = 0
        self.maxSize = 1

    def expectedPacket(self):
        return self.expectedPkt

    def slide(self):
        self.expectedPkt += 1


class PacketHandler(Thread):
    """
    Thread for monitoring packet receipt.
    """

    PACKET = namedtuple("Packet", ["SequenceNumber", "Checksum", "Data"])

    def __init__(self,
                 fileHandle,
                 receiverSocket,
                 senderIP,
                 senderPort,
                 receiverIP,
                 receiverPort,
                 window,
                 timeout=10,
                 packetLossProbability=0.1,
                 bufferSize=2048):
        Thread.__init__(self)
        self.fileHandle = fileHandle
        self.receiverSocket = receiverSocket
        self.senderIP = senderIP
        self.senderPort = senderPort
        self.receiverIP = receiverIP
        self.receiverPort = receiverPort
        self.window = window
        self.timeout = timeout
        self.packetLossProbability = packetLossProbability
        self.bufferSize = bufferSize

    def run(self):
        """
        Start monitoring packet receipt.
        """
        log.info("Started to monitor packet receipt")

        # Monitor receiver
        # untill all packets are successfully received from sender
        chance = 0
        while True:
            # Listen for incoming packets on receiver's socket
            # with the provided timeout
            ready = select.select([self.receiverSocket], [], [], self.timeout)

            # If no packet is received within timeout;
            if not ready[0]:
                # Wait, if no packets are yet transmitted by sender
                if self.window.expectedPacket() == 0:
                    continue
                # Stop receiving packets from sender,
                # if there are more than 5 consecutive timeouts
                else:
                    if chance == 5:
                        log.warning("Timeout!!")
                        log.info("Gracefully terminating the receiver process, as client stopped transmission!!")
                        break
                    else:
                        chance += 1
                        continue
            else:
                chance = 0

            # Receive packet
            try:
                receivedPacket, _ = self.receiverSocket.recvfrom(self.bufferSize)
            except Exception as e:
                log.error("Could not receive UDP packet!")
                log.debug(e)
                raise SocketError("Receiving UDP packet failed!")

            # Parse header fields and payload data from the received packet
            receivedPacket = self.parse(receivedPacket)

            # Check whether the received packet is not corrupt
            if self.corrupt(receivedPacket):
                log.warning("Received corrupt packet!!")
                log.warning("Discarding packet with sequence number: %d",
                            receivedPacket.SequenceNumber)
                continue

            # Check whether the received packet's sequence number matches
            # with the expected packet
            if receivedPacket.SequenceNumber != self.window.expectedPacket():
                log.warning("Received out of order packet!!")
                log.warning("Discarding packet with sequence number: %d",
                            receivedPacket.SequenceNumber)

                # Reliable acknowledgement transfer
                log.info("Transmitting an acknowledgement with ack number: %d",
                         self.window.expectedPacket())
                self.rdt_send()

                continue

            # Simulate artificial packet loss
            if self.simulate_packet_loss():
                log.error("Simulating artificial packet loss!!")
                log.error("Lost a packet with sequence number: %d",
                          receivedPacket.SequenceNumber)
                continue

            # Deliver data to Application Layer
            log.info("Received packet with sequence number: %d",
                     receivedPacket.SequenceNumber)
            self.deliver(receivedPacket.Data)

            # Slide receiver's window by 1
            self.window.slide()

            # Reliable acknowledgement transfer
            log.info("Transmitting an acknowledgement with ack number: %d",
                     self.window.expectedPacket())
            self.rdt_send()

    def parse(self, receivedPacket):
        """
        Parse header fields and payload data from the received packet.
        """
        header = receivedPacket[0:6]
        data = receivedPacket[6:]

        sequenceNumber = struct.unpack('=I', header[0:4])[0]
        checksum = struct.unpack('=H', header[4:])[0]

        packet = PacketHandler.PACKET(SequenceNumber=sequenceNumber,
                                      Checksum=checksum,
                                      Data=data)

        return packet

    def corrupt(self, receivedPacket):
        """
        Check whether the received packet is corrupt or not.
        """
        # Compute checksum for the received packet
        computedChecksum = self.checksum(receivedPacket.Data)

        # Compare computed checksum with the checksum of received packet
        if computedChecksum != receivedPacket.Checksum:
            return True
        else:
            return False

    def checksum(self, data):
        """
        Compute and return a checksum of the given payload data
        """
        # Force payload data into 16 bit chunks
        if (len(data) % 2) != 0:
            data += "0"

        sum = 0
        for i in range(0, len(data), 2):
            data16 = ord(data[i]) + (ord(data[i+1]) << 8)
            sum = self.carry_around_add(sum, data16)

        return ~sum & 0xffff

    def carry_around_add(self, sum, data16):
        """
        Helper function for carry around add.
        """
        sum = sum + data16
        return (sum & 0xffff) + (sum >> 16)

    def simulate_packet_loss(self):
        """
        Simulate artificial packet loss.
        """
        r = random.random()

        if r <= self.packetLossProbability:
            return True
        else:
            return False

    def deliver(self, data):
        """
        Deliver data to Application Layer.
        """
        try:
            self.fileHandle.write(data)
        except IOError as e:
            log.error("Could not write to file handle!")
            log.debug(e)
            raise FileIOError("Writing to file handle failed!")

    def rdt_send(self):
        """
        Reliable acknowledgement transfer.
        """
        # Create a raw acknowledgement
        rawAck = self.make_pkt()

        # Transmit an acknowledgement using underlying UDP protocol
        self.udt_send(rawAck)

    def make_pkt(self):
        """
        Create a raw acknowledgement.
        """
        ackNumber = struct.pack('=I', self.window.expectedPacket())
        checksum = struct.pack('=16s', self.get_ack_hashcode())
        rawAck = ackNumber + checksum
        return rawAck

    def get_ack_hashcode(self):
        """
        Compute the hash code for acknowledgement to be transmitted.
        """
        hashcode = hashlib.md5()
        hashcode.update(str(self.window.expectedPacket()))
        return hashcode.digest()

    def udt_send(self, ack):
        """
        Transmit an acknowledgement using underlying UDP protocol.
        """
        try:
            self.receiverSocket.sendto(ack, (self.senderIP, self.senderPort))
        except Exception as e:
            log.error("Could not send UDP packet!")
            log.debug(e)
            raise SocketError("Sending UDP packet to %s:%d failed!"
                              % (self.senderIP, self.senderPort))
