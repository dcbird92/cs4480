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
    base = 1
    waitTime = 20
    seq_num = 1
    expected_seq = 1
    buffer = []
    extra = []
    window_size = 8
    ack = 0
    corruptPktB = 0
    lostPktA = 0
    lostPktB = 0
    timeouts = 0
    resentPkt = 0
    sentPkt = 0
    rcvPkt = 0
    layer5B = 0
    droppedMessages = 0
    x = False

    def not_corrupt(self, packet):
        check = 0
        for char in packet.get_payload():
            check += ord(char)
        check += packet.get_acknum()
        check += packet.get_seqnum()
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
        self.rcvPkt += 1
        if self.seq_num < self.base + self.window_size:
            checksum = 0
            # create a checksum to pass in the message
            # the checksum is the ascii total of the message plus the sequence number
            for char in message.get_data():
                checksum += ord(char)
            checksum += self.seq_num

            sndpkt = Packet(self.seq_num, 0, checksum, message.get_data())
            # add the packet to the buffer
            self.buffer.append(sndpkt)
            self.to_layer3(0, sndpkt)
            if self.base == self.seq_num:
                self.start_timer(0, self.waitTime)
            # new message being sent increment sequence number
            self.seq_num += 1
            self.sentPkt += 1
        else:
            # if the extra buffer is greater than 50, disregard new messages
            if len(self.extra) < 50:
                self.extra.append(message)
            else:
                self.droppedMessages += 1


    # This routine will be called whenever a packet sent from the B-side
    # (i.e. as a result of a toLayer3() being done by a B-side procedure)
    # arrives at the A-side.  "packet" is the (possibly corrupted) packet
    # sent from the B-side.

    def a_input(self, packet):
        if self.not_corrupt(packet):
            # check to not increment on repeated ack
            if self.base < packet.get_acknum()+1:
                self.ack += 1
            # set the base to the the next ACK number
            count = packet.get_acknum() + 1 - self.base
            self.base = packet.get_acknum()+1
            self.waitTime = 20
            if self.base + 3 == self.seq_num:
                self.waitTime = 25
            elif self.base + 4 < self.seq_num:
                self.waitTime = 30
            if self.base == self.seq_num:
                self.stop_timer(0)
            else:
                # reset timers to prevent excess timeouts
                self.stop_timer(0)
                self.start_timer(0, self.waitTime)
            if len(self.extra) > 0:
                # if the buffer is full and messages were saved to the extra buffer
                while count > 0 and len(self.extra) > 0:
                    self.a_output(self.extra.pop(0))
                    self.rcvPkt -= 1
                    count -= 1
        else:
            print(" CORRUPT PACKET")

    # This routine will be called when A's timer expires (thus generating a
    # timer interrupt). You'll probably want to use this routine to control 
    # the retransmission of packets. See startTimer() and stopTimer(), above,
    # for how the timer is started and stopped. 

    def a_timer_interrupt(self):
        print(" TIMEOUT DETECTED")
        self.timeouts += 1
        self.waitTime *= 2
        self.start_timer(0, self.waitTime)
        new_base = self.base
        # start at the base and resend all messages in the window
        while new_base < self.seq_num:
            self.to_layer3(0, self.buffer[new_base])
            new_base += 1
            self.resentPkt += 1

    # This routine will be called once, before any of your other A-side
    # routines are called. It can be used to do any required
    # initialization (e.g. of member variables you add to control the state
    # of entity A).	

    def a_init(self):
        self.base = 0
        self.seq_num = 0

    # This routine will be called whenever a packet sent from the B-side
    # (i.e. as a result of a toLayer3() being done by an A-side procedure)
    # arrives at the B-side.  "packet" is the (possibly corrupted) packet
    # sent from the A-side.

    def b_input(self, packet):
        not_cor = self.not_corrupt(packet)
        if not_cor and packet.get_seqnum() == self.expected_seq:
            # send data to the upper layer
            self.to_layer5(1, packet.get_payload())
            self.layer5B += 1
            # send ack message to A with the seq number being the ACK
            self.to_layer3(1, Packet(0, self.expected_seq, self.expected_seq, ""))
            # increment the next seq expected
            self.expected_seq += 1
            self.x = False
        else:
            if not not_cor:
                self.corruptPktB += 1
            elif not self.x:
                self.lostPktA += 1
                self.x = True
            # send an ACK to A with the last accepted sequence number
            self.to_layer3(1, Packet(self.expected_seq-1, self.expected_seq-1, self.expected_seq-1, ""))

    # This routine will be called once, before any of your other B-side
    # routines are called. It can be used to do any required
    # initialization (e.g. of member variables you add to control the state
    # of entity B).
    def b_init(self):
        self.expected_seq = 0
