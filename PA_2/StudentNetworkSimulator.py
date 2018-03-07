from NetworkSimulator import NetworkSimulator
import queue
import random
from Event import Event
from Packet import Packet
from message import Message
from EventListImpl import EventListImpl
import math


class StudentNetworkSimulator(NetworkSimulator, object):

    """
    * Predefined Constants (static member variables):
     *
     *   int MAXDATASIZE : the maximum size of the Message data and
     *                     Packet payload
     *
     *   int A           : a predefined integer that represents entity A
     *   int B           : a predefined integer that represents entity B
     *
     *
     * Predefined Member Methods:
     *
     *  stopTimer(int entity): 
     *       Stops the timer running at "entity" [A or B]
     *  startTimer(int entity, double increment): 
     *       Starts a timer running at "entity" [A or B], which will expire in
     *       "increment" time units, causing the interrupt handler to be
     *       called.  You should only call this with A.
     *  toLayer3(int callingEntity, Packet p)
     *       Puts the packet "p" into the network from "callingEntity" [A or B]
     *  toLayer5(int entity, String dataSent)
     *       Passes "dataSent" up to layer 5 from "entity" [A or B]
     *  getTime()
     *       Returns the current time in the simulator.  Might be useful for
     *       debugging.
     *  printEventList()
     *       Prints the current event list to stdout.  Might be useful for
     *       debugging, but probably not.
     *
     *
     *  Predefined Classes:
     *
     *  Message: Used to encapsulate a message coming from layer 5
     *    Constructor:
     *      Message(String inputData): 
     *          creates a new Message containing "inputData"
     *    Methods:
     *      boolean setData(String inputData):
     *          sets an existing Message's data to "inputData"
     *          returns true on success, false otherwise
     *      String getData():
     *          returns the data contained in the message
     *  Packet: Used to encapsulate a packet
     *    Constructors:
     *      Packet (Packet p):
     *          creates a new Packet that is a copy of "p"
     *      Packet (int seq, int ack, int check, String newPayload)
     *          creates a new Packet with a sequence field of "seq", an
     *          ack field of "ack", a checksum field of "check", and a
     *          payload of "newPayload"
     *      Packet (int seq, int ack, int check)
     *          create a new Packet with a sequence field of "seq", an
     *          ack field of "ack", a checksum field of "check", and
     *          an empty payload
     *    Methods:
     *      boolean setSeqnum(int n)
     *          sets the Packet's sequence field to "n"
     *          returns true on success, false otherwise
     *      boolean setAcknum(int n)
     *          sets the Packet's ack field to "n"
     *          returns true on success, false otherwise
     *      boolean setChecksum(int n)
     *          sets the Packet's checksum to "n"
     *          returns true on success, false otherwise
     *      boolean setPayload(String newPayload)
     *          sets the Packet's payload to "newPayload"
     *          returns true on success, false otherwise
     *      int getSeqnum()
     *          returns the contents of the Packet's sequence field
     *      int getAcknum()
     *          returns the contents of the Packet's ack field
     *      int getChecksum()
     *          returns the checksum of the Packet
     *      int getPayload()
     *          returns the Packet's payload
     *

    """




    # Add any necessary class/static variables here.  Remember, you cannot use
    # these variables to send messages error free!  They can only hold
    # state information for A or B.
    # Also add any necessary methods (e.g. checksum of a String)
    waitA = 0
    waitB = 0
    alternating_bitA = 0
    alternating_bitB = 0
    global_messageA = ""
    global_messageB = ""
    timeout = False
    ack = 0
    corruptPkt = 0
    lostPkt = 0
    resentPkt = 0
    sentPkt = 0
    rcvPkt = 0

    def corrupt(self, packet):
        check = 0
        for char in packet.get_payload():
            check += ord(char)
        if check == packet.get_checksum():
            return True
        else:
            return False

    
    # This is the constructor.  Don't touch!
    def __init__(self, num_messages, loss, corrupt, avg_delay, trace, seed):
        super(StudentNetworkSimulator, self).__init__(num_messages, loss, corrupt, avg_delay, trace, seed)

    # This routine will be called whenever the upper layer at the sender [A]
    # has a message to send.  It is the job of your protocol to insure that
    # the data in such a message is delivered in-order, and correctly, to
    # the receiving upper layer.
    def a_output(self, message):
        # msg = message.get_data()
        if self.timeout:
            if self.waitA == 1:
                checksum = 0
                for char in message.get_data():
                    checksum += ord(char)

                self.global_messageA = message

                sndpkt = Packet(0, 0, checksum, message.get_data())
                self.to_layer3(0, sndpkt)
                self.start_timer(0, 1000)
                self.timeout = False
                self.resentPkt += 1
                print(" TIMEOUT SUCCESSFULLY RESENT FOR BIT 0")

            elif self.waitA == 3:
                checksum = 0
                for char in message.get_data():
                    checksum += ord(char)

                self.global_messageA = message

                sndpkt = Packet(1, 1, checksum, message.get_data())
                self.to_layer3(0, sndpkt)
                self.start_timer(0, 1000)
                self.timeout = False
                self.resentPkt += 1
                print(" TIMEOUT SUCCESSFULLY RESENT FOR BIT 1")
        else:
            self.rcvPkt += 1
            if self.waitA == 0:
                checksum = 0
                for char in message.get_data():
                    checksum += ord(char)

                self.global_messageA = message

                sndpkt = Packet(0, 0, checksum, message.get_data())
                self.to_layer3(0, sndpkt)
                self.start_timer(0, 1000)
                self.waitA += 1
                self.sentPkt += 1
            elif self.waitA == 2:
                checksum = 0
                for char in message.get_data():
                    checksum += ord(char)

                self.global_messageA = message

                sndpkt = Packet(1, 1, checksum, message.get_data())
                self.to_layer3(0, sndpkt)
                self.start_timer(0, 1000)
                self.waitA += 1
                self.sentPkt += 1

    # This routine will be called whenever a packet sent from the B-side
    # (i.e. as a result of a toLayer3() being done by a B-side procedure)
    # arrives at the A-side.  "packet" is the (possibly corrupted) packet
    # sent from the B-side.

    def a_input(self, packet):
        if self.waitA == 1 or self.waitA == 3:
            if self.waitA == 1:
                if packet.get_acknum() is 0 and packet.get_checksum() is 0:
                    self.ack += 1
                    print(" SUCCESSFUL ACK: ", self.ack)
                    self.stop_timer(0)
                    self.waitA += 1
                else:
                    print(" UNSUCCESSFUL ACK")
            if self.waitA == 3:
                if packet.get_acknum() is 1 or packet.get_checksum() is 0:
                    self.ack += 1
                    print(" SUCCESSFUL ACK: ", self.ack)
                    self.stop_timer(0)
                    self.waitA = 0
                else:
                    print(" UNSUCCESSFUL ACK")

    # This routine will be called when A's timer expires (thus generating a
    # timer interrupt). You'll probably want to use this routine to control 
    # the retransmission of packets. See startTimer() and stopTimer(), above,
    # for how the timer is started and stopped. 

    def a_timer_interrupt(self):
        print(" TIMEOUT DETECTED")
        self.timeout = True
        self.lostPkt += 1
        self.a_output(self.global_messageA)

    # This routine will be called once, before any of your other A-side
    # routines are called. It can be used to do any required
    # initialization (e.g. of member variables you add to control the state
    # of entity A).	

    def a_init(self):
        self.alternating_bitA = 0
        self.global_messageA = ""
        self.waitA = 0

    # This routine will be called whenever a packet sent from the B-side
    # (i.e. as a result of a toLayer3() being done by an A-side procedure)
    # arrives at the B-side.  "packet" is the (possibly corrupted) packet
    # sent from the A-side.

    def b_input(self, packet):
        not_cor = self.corrupt(packet)
        if self.waitB is 0:
            if packet.get_acknum() is 0 and not_cor:
                self.to_layer5(1, packet.get_payload())
                self.to_layer3(1, Packet(0, 0, 0, ""))
                self.waitB += 1
            elif not_cor:
                print(" ACK LOST IN TRANSIT")
                # self.lostPkt += 1
                self.to_layer3(1, Packet(1, 1, 0, ""))
            else:
                print(" PACKET CORRUPT")
                self.corruptPkt += 1
                self.lostPkt -= 1
                self.to_layer3(1, Packet(1, 1, 1, ""))
        elif self.waitB is 1:
            if packet.get_acknum() is 1 and not_cor:
                self.to_layer5(1, packet.get_payload())
                self.to_layer3(1, Packet(1, 1, 0, ""))
                self.waitB = 0
            elif not_cor:
                print(" ACK LOST IN TRANSIT")
                # self.lostPkt += 1
                self.to_layer3(1, Packet(0, 0, 0, ""))
            else:
                print(" PACKET CORRUPT")
                self.corruptPkt += 1
                self.lostPkt -= 1
                self.to_layer3(1, Packet(0, 0, 1, ""))

    # This routine will be called once, before any of your other B-side
    # routines are called. It can be used to do any required
    # initialization (e.g. of member variables you add to control the state
    # of entity B).
    def b_init(self):
        self.alternating_bitB = 0
        self.global_messageB = ""
        self.waitB = 0
