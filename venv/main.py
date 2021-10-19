from scapy.all import *
from binascii import hexlify
import os
import time
import sys

FILE = None # .pcap file to be analyzed
PRINT_FILE = 'consolePrint.txt' # static file for stroing console print
DEFAULT_STDOUT = sys.stdout

framesArr = [] # for storing packets as objects
ethernetProt = {} # ETHERNET II Protocols
ieeeProt = {} # IEEE 802.3 Protocols
ipProt = {} # IPv4 Protocols
wnProt = {} # WELL-KNOWN protocols
icmpTypes = {} # ICMP Types

ipList = {} # list of all unique IP addresses

http_packets = [] # TCP communication
https_packets = []
telnet_packets = []
ssh_packets = []
ftpC_packets = []
ftpD_packets = []
tcp_packet_list = []

tftp_packets = [] # TFTP communication
tftp_packet_list = []
icmp_packets = [] # ICMP communication
icmp_packet_list = []
arp_packets = [] # ARP communication
arp_packet_list = []

class pcapFrame():
    def __init__(self, num, buffer):
        self.num = num
        self.buffer = buffer
        self.frameLength = len(buffer)
        self.frameType = None


class TCPComm():
    def __init__(self, srcIp, destIp, srcPort, destPort, frame, flags):
        self.srcIP = srcIp
        self.destIP = destIp
        self.srcPort = srcPort
        self.destPort = destPort
        self.flags = flags
        self.isComplete = False
        self.relatedFrame = frame
        self.comm = [] # related communication packets

    def append_comm(self, packet):
        self.comm.append(packet)


class ARPComm():
    def __init__(self, op, sendIP, sendMAC, tarIP, tarMAC, frame):
        self.op = op
        self.sendIP = sendIP
        self.sendMAC = sendMAC
        self.tarIP = tarIP
        self.tarMAC = tarMAC
        self.relatedFrame = frame
        self.pair = None
        self.comm = []

    def append_comm(self, packet):
        self.comm.append(packet)


class ICMPComm():
    def __init__(self, srcIP, destIP, type, frame):
        self.srcIP = srcIP
        self.destIP = destIP
        self.icmpMess = self.getICMP(type)
        self.relatedFrame = frame
        self.comm = []

    def append_packet(self, packet):
        self.comm.append(packet)

    def getICMP(self, type):
        if icmpTypes is not None and icmpTypes.get(type) is not None:
            return icmpTypes[type]
        return None


def save_frames(frames):
    global framesArr

    i = 1
    for frame in frames:
        newFrame = pcapFrame(i, raw(frame))
        framesArr.append(newFrame)
        i += 1


def printBytes(frame: pcapFrame, useSep = True):
    try:
        rawFrame = frame.buffer
        i = 0
        for index in range(frame.frameLength):
            if i % 16 == 0:
                print()
            elif i % 8 == 0:
                print(" ", end="")

            i += 1
            print(str(hexlify(rawFrame[index:index+1]))[2: -1], end="")
            print(" ", end="")

        print()
        if useSep:
            print('=' * 100)
            print('=' * 100)
        else:
            print('\n')

    except FileNotFoundError:
        print('File was not found')


def composeMAC(hexBytes):
    byteStream = str(hexlify(hexBytes))[2:-1]
    address = ':'.join(byteStream[i:i+2] for i in range(0, len(byteStream), 2))
    return address


def composeIP(buffer):
    result = ''
    for i in range(len(buffer)):
        result += str(int(str(hexlify(buffer[i:i+1]))[2:-1], 16))
        result += '.' if i != (len(buffer) - 1) else ''

    return result


def countIPs(address):
    if address in ipList:
        value = ipList[address]
        ipList[address] = value + 1
    else:
        ipList[address] = 1


def findFrameType(frame: pcapFrame):
    rawFrame = frame.buffer
    protocol_val = int(str(hexlify(rawFrame[12:14]))[2:-1], 16) # protocol decimal value

    if protocol_val > 1500:
        return 'Ethernet II'
    else:
        if str(hexlify(rawFrame[14:15]))[2:-1] == 'ff':
            return 'IEEE 802.3 - Raw'
        elif str(hexlify(rawFrame[14:15]))[2:-1] == 'aa':
            return 'IEEE 802.3 - LLC & SNAP'
        else:
            return 'IEEE 802.3 - LLC'


def initFrame(frame: pcapFrame):
    frame.frameType = findFrameType(frame)
    return frame


def emptyArrays():
    global http_packets, https_packets, telnet_packets, ssh_packets, ftpC_packets, ftpD_packets, tcp_packet_list
    global tftp_packets, tftp_packet_list, icmp_packets, icmp_packet_list, arp_packets, arp_packet_list

    http_packets = []  # TCP communication
    https_packets = []
    telnet_packets = []
    ssh_packets = []
    ftpC_packets = []
    ftpD_packets = []
    tcp_packet_list = []

    tftp_packets = []  # TFTP communication
    tftp_packet_list = []
    icmp_packets = []  # ICMP communication
    icmp_packet_list = []
    arp_packets = []  # ARP communication
    arp_packet_list = []


def loadPackets(frames):
    emptyArrays()

    if frames is not None:
        for frame in frames:
            frame = initFrame(frame)
            rawPacket = frame.buffer

            # ----------------- ETHERNET ---------------------
            if frame.frameType == 'Ethernet II':
                protocol_dec = int(str(hexlify(rawPacket[12:14]))[2:-1], 16)

                if ethernetProt.get(protocol_dec) is not None:
                    if protocol_dec == 2048:  # IPv4 protocol
                        offsetIhl = protocol_dec = int(str(hexlify(rawPacket[14:15]))[3:-1], 16) * 4 + 14
                        ipProtocol = ipProt.get(int(str(hexlify(rawPacket[23:24]))[2:-1], 16))

                        sourceIP = composeIP(rawPacket[26:30])
                        destIP = composeIP(rawPacket[30:34])

                        if ipProtocol is not None:
                            if ipProtocol == 'TCP':  # TCP protocol
                                sourcePort = int(str(hexlify(rawPacket[offsetIhl:offsetIhl + 2]))[2:-1], 16)
                                destPort = int(str(hexlify(rawPacket[offsetIhl + 2:offsetIhl + 4]))[2:-1], 16)
                                wnProtocol = None
                                if sourcePort > destPort:  # nested protocol
                                    wnProtocol = wnProt[destPort] if wnProt.get(destPort) is not None else 'Unknown protocol'
                                else:
                                    wnProtocol = wnProt[sourcePort] if wnProt.get(sourcePort) is not None else 'Unknown protocol'

                                tcpFrame = TCPComm(sourceIP, destIP, sourcePort, destPort, frame, int(str(hexlify(rawPacket[offsetIhl + 13:offsetIhl + 14]))[2:-1], 16))  # partial initialization of TCP communication

                                if wnProtocol == 'HTTP':
                                    http_packets.append(tcpFrame)
                                elif wnProtocol == 'HTTPS (SS1)':
                                    https_packets.append(tcpFrame)
                                elif wnProtocol == 'TELNET':
                                    telnet_packets.append(tcpFrame)
                                elif wnProtocol == 'SSH':
                                    ssh_packets.append(tcpFrame)
                                elif wnProtocol == 'FTP-DATA':
                                    ftpD_packets.append(tcpFrame)
                                elif wnProtocol == 'FTP-CONTROL':
                                    ftpC_packets.append(tcpFrame)

                            elif ipProtocol == 'UDP':  # UDP protocol
                                sourcePort = int(str(hexlify(rawPacket[offsetIhl:offsetIhl + 2]))[2:-1], 16)
                                destPort = int(str(hexlify(rawPacket[offsetIhl + 2:offsetIhl + 4]))[2:-1], 16)
                                wnProtocol = None

                                wnProtocol = wnProt[destPort] if wnProt.get(destPort) is not None else 'Unknown protocol'  # edit so it can analyse nested communications

                                if wnProtocol == 'TFTP':  # edit!
                                    tftp_packets.append(frame)

                            elif ipProtocol == 'ICMP':
                                icmpType = int(str(hexlify(rawPacket[offsetIhl:offsetIhl + 1]))[2:-1], 16)

                                icmpPacket = ICMPComm(sourceIP, destIP, icmpType, frame)
                                icmp_packets.append(icmpPacket)

                        else:
                            print("Unknown protocol")

                    elif protocol_dec == 2054:
                        operation = int(str(hexlify(rawPacket[20:22]))[2:-1], 16)  # request/ reply
                        senderMAC = composeMAC(rawPacket[22:28])
                        senderIP = composeIP(rawPacket[28:32])
                        targetMAC = composeMAC(rawPacket[32:38])
                        targetIP = composeIP(rawPacket[38:42])

                        arpPacket = ARPComm(operation, senderIP, senderMAC, targetIP, targetMAC, frame)
                        arp_packets.append(arpPacket)


def nestedProtocols(frame: pcapFrame):
    if frame is not None:
        rawPacket = frame.buffer

        # ----------------- ETHERNET ---------------------
        if frame.frameType == 'Ethernet II':
            protocol_dec = int(str(hexlify(rawPacket[12:14]))[2:-1], 16)

            if ethernetProt.get(protocol_dec) is not None:
                print(ethernetProt[protocol_dec])

                if protocol_dec == 2048: # IPv4 protocol
                    offsetIhl = protocol_dec = int(str(hexlify(rawPacket[14:15]))[3:-1], 16) * 4 + 14
                    ipProtocol = ipProt.get(int(str(hexlify(rawPacket[23:24]))[2:-1], 16))

                    sourceIP = composeIP(rawPacket[26:30])
                    destIP = composeIP(rawPacket[30:34])
                    print(f'Source IP: {sourceIP}')
                    print(f'Destination IP: {destIP}')

                    countIPs(sourceIP) # count all the source IPs

                    if ipProtocol is not None:
                        print(ipProtocol)

                        if ipProtocol == 'TCP': # TCP protocol
                            sourcePort = int(str(hexlify(rawPacket[offsetIhl:offsetIhl+2]))[2:-1], 16)
                            destPort = int(str(hexlify(rawPacket[offsetIhl+2:offsetIhl+4]))[2:-1], 16)
                            wnProtocol = None
                            print(f'Source port: {sourcePort}')
                            print(f'Destination port: {destPort}')
                            if sourcePort > destPort: # nested protocol
                                wnProtocol = wnProt[destPort] if wnProt.get(destPort) is not None else 'Unknown protocol'
                            else:
                                wnProtocol = wnProt[sourcePort] if wnProt.get(sourcePort) is not None else 'Unknown protocol'
                            print(wnProtocol)

                            tcpFrame = TCPComm(sourceIP, destIP, sourcePort, destPort,\
                                               frame, int(str(hexlify(rawPacket[offsetIhl+13:offsetIhl+14]))[2:-1], 16)) # partial initialization of TCP communication

                            if wnProtocol == 'HTTP':
                                http_packets.append(tcpFrame)
                            elif wnProtocol == 'HTTPS (SS1)':
                                https_packets.append(tcpFrame)
                            elif wnProtocol == 'TELNET':
                                telnet_packets.append(tcpFrame)
                            elif wnProtocol == 'SSH':
                                ssh_packets.append(tcpFrame)
                            elif wnProtocol == 'FTP-DATA':
                                ftpD_packets.append(tcpFrame)
                            elif wnProtocol == 'FTP-CONTROL':
                                ftpC_packets.append(tcpFrame)

                        elif ipProtocol == 'UDP': # UDP protocol
                            sourcePort =  int(str(hexlify(rawPacket[offsetIhl:offsetIhl+2]))[2:-1], 16)
                            destPort = int(str(hexlify(rawPacket[offsetIhl+2:offsetIhl+4]))[2:-1], 16)
                            wnProtocol = None
                            print(f'Source port: {sourcePort}')
                            print(f'Destination port: {destPort}')

                            wnProtocol = wnProt[destPort] if wnProt.get(destPort) is not None else 'Unknown protocol' # edit so it can analyse nested communications
                            print(wnProtocol) # nested protocol

                            if wnProtocol == 'TFTP': # edit!
                                tftp_packets.append(frame)

                        elif ipProtocol == 'ICMP':
                            icmpType = int(str(hexlify(rawPacket[offsetIhl:offsetIhl+1]))[2:-1], 16)

                            icmpPacket = ICMPComm(sourceIP, destIP, icmpType, frame)
                            icmp_packets.append(icmpPacket)

                    else:
                        print("Unknown protocol")

                elif protocol_dec == 2054:
                    operation = int(str(hexlify(rawPacket[20:22]))[2:-1], 16) # request/ reply
                    senderMAC = composeMAC(rawPacket[22:28])
                    senderIP = composeIP(rawPacket[28:32])
                    targetMAC = composeMAC(rawPacket[32:38])
                    targetIP = composeIP(rawPacket[38:42])

                    print('Request' if operation == 1 else 'Response')
                    print(f'Sender MAC: {senderMAC}', end = '\t')
                    print(f'Sender IP: {senderIP}')
                    print(f'Target MAC: {targetMAC}', end = '\t')
                    print(f'Target IP: {targetIP}')

                    arpPacket = ARPComm(operation, senderIP, senderMAC, targetIP, targetMAC, frame)
                    arp_packets.append(arpPacket)
            else:
                print('Unknown protocol')

        # ----------------- IEEE - RAW ---------------------
        elif frame.frameType == 'IEEE 802.3 - Raw':
            print('IPX')

        # ----------------- IEEE - LLC & SNAP ---------------------
        elif frame.frameType == 'IEEE 802.3 - LLC & SNAP':
            protocolDSAP_dec = int(str(hexlify(rawPacket[14:15]))[2:-1], 16)
            protocolSSAP_dec = int(str(hexlify(rawPacket[15:16]))[2:-1], 16)
            print(f'DSAP: {ieeeProt[protocolDSAP_dec] if ieeeProt.get(protocolDSAP_dec) is not None else "Unknown"}', end = '\t')
            print(f'SSAP: {ieeeProt[protocolSSAP_dec] if ieeeProt.get(protocolSSAP_dec) is not None else "Unknown"}')

            print(ieeeProt[protocolDSAP_dec] if ieeeProt.get(protocolDSAP_dec) is not None else 'Unknown protocol')  # nested protocol
            etherType = int(str(hexlify(rawPacket[20:22]))[2:-1], 16)
            print(ethernetProt[etherType] if ethernetProt.get(etherType) is not None else 'Unknown EtherType')

        elif frame.frameType == 'IEEE 802.3 - LLC':
            protocolDSAP_dec = int(str(hexlify(rawPacket[14:15]))[2:-1], 16)
            protocolSSAP_dec = int(str(hexlify(rawPacket[15:16]))[2:-1], 16)
            print(f'DSAP: {ieeeProt[protocolDSAP_dec] if ieeeProt.get(protocolDSAP_dec) is not None else "Unknown"}', end = '\t')
            print(f'SSAP: {ieeeProt[protocolSSAP_dec] if ieeeProt.get(protocolSSAP_dec) is not None else "Unknown"}')
            print(ieeeProt[protocolDSAP_dec] if ieeeProt.get(protocolDSAP_dec) is not None else 'Unknown protocol') # nested protocol


def initTCP(communication):
    temp_comm = communication

    # --------------------------- GROUP RELATED PACKETS ---------------------------
    for packet in range(len(temp_comm)):
        actPacket: TCPComm = temp_comm[packet]

        if actPacket is not None:
            for i in range(packet+1, len(temp_comm)):
                if temp_comm[i] is None:
                    continue
                elif (actPacket.srcIP == temp_comm[i].srcIP and actPacket.destIP == temp_comm[i].destIP and actPacket.srcPort == temp_comm[i].srcPort and actPacket.destPort == temp_comm[i].destPort)\
                    or (actPacket.srcIP == temp_comm[i].destIP and actPacket.destIP == temp_comm[i].srcIP and actPacket.srcPort == temp_comm[i].destPort and actPacket.destPort == temp_comm[i].srcPort):
                    actPacket.append_comm(temp_comm[i])
                    temp_comm[i] = None
        else:
            continue

        tcp_packet_list.append(actPacket)
        temp_comm[packet] = None # empty the list

    # --------------------------- ANALYSIS ---------------------------
    if len(tcp_packet_list) > 0:
        for commun in tcp_packet_list:
            if len(commun.comm) >= 3:
               if (commun.flags == 2 and commun.comm[0].flags == 18 and commun.comm[1].flags == 16):
                   end1, end2, end3, end4 = commun.comm[-1].flags, commun.comm[-2].flags, commun.comm[-3].flags, commun.comm[-4].flags

                   if (end1 == 4 or end1 == 20 or (end1 == 16 and end2 == 17 and end3 == 17) or (end4 == 17 and end3 == 16 and end2 == 17 and end1 == 16)):
                       commun.isComplete = True
               else:
                   commun = None

    # --------------------------- OUTPUT ---------------------------
    printComplete = 0
    printIncomplete = 0

    # COMPLETE COMMUNICATION
    for commun in tcp_packet_list:
        if commun is None:
            continue

        if commun.isComplete == 1 and printComplete == 0:
            printComplete = 1

            print('\n================= KOMPLETNA TCP KOMUNIKACIA =================')
            print(f'Frame number: {commun.relatedFrame.num}')

            # PACKET LENGTH
            print(f'Frame pcapAPI length: {commun.relatedFrame.frameLength}B')
            print(f'Length of the frame transferred via media: {64 if commun.relatedFrame.frameLength < 60 else commun.relatedFrame.frameLength + 4}B')

            # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
            print(commun.relatedFrame.frameType)
            print(f'Source MAC address: {composeMAC(commun.relatedFrame.buffer[6:12])}')
            print(f'Destination MAC address: {composeMAC(commun.relatedFrame.buffer[:6])}')


            protocol_dec = int(str(hexlify(commun.relatedFrame.buffer[12:14]))[2:-1], 16)
            print(ethernetProt[protocol_dec] if ethernetProt.get(protocol_dec) is not None else 'Unknown protocol')

            if protocol_dec == 2048:
                ipProtocol = ipProt.get(int(str(hexlify(commun.relatedFrame.buffer[23:24]))[2:-1], 16))
                print(f'Source IP: {commun.srcIP}')
                print(f'Destination IP: {commun.destIP}')

                if ipProtocol is not None:
                    print(ipProtocol)

                    if ipProtocol == 'TCP':
                        if commun.srcPort < commun.destPort:
                            print(wnProt[commun.srcPort] if wnProt.get(commun.srcPort) is not None else '')
                        else:
                            print(wnProt[commun.destPort] if wnProt.get(commun.destPort) is not None else '')

                        print(f'Source port: {commun.srcPort}')
                        print(f'Destiantion port: {commun.destPort}')

            # FRAME TYPE & BYTE STREAM
            printBytes(commun.relatedFrame)

            # set the number of packets to be printed
            if len(commun.comm) > 19:
                temparr = commun.comm[:9] + commun.comm[-10:]
            else:
                temparr = commun.comm

            for member in temparr:
                print(f'Frame number: {member.relatedFrame.num}')

                # PACKET LENGTH
                print(f'Frame pcapAPI length: {member.relatedFrame.frameLength}B')
                print(f'Length of the frame transferred via media: {64 if member.relatedFrame.frameLength < 60 else member.relatedFrame.frameLength + 4}B')

                # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
                print(member.relatedFrame.frameType)
                print(f'Source MAC address: {composeMAC(member.relatedFrame.buffer[6:12])}')
                print(f'Destination MAC address: {composeMAC(member.relatedFrame.buffer[:6])}')

                protocol_dec = int(str(hexlify(member.relatedFrame.buffer[12:14]))[2:-1], 16)
                print(ethernetProt[protocol_dec] if ethernetProt.get(protocol_dec) is not None else 'Unknown protocol')

                if protocol_dec == 2048:
                    ipProtocol = ipProt.get(int(str(hexlify(member.relatedFrame.buffer[23:24]))[2:-1], 16))
                    print(f'Source IP: {member.srcIP}')
                    print(f'Destination IP: {member.destIP}')

                    if ipProtocol is not None:
                        print(ipProtocol)

                        if ipProtocol == 'TCP':
                            if member.srcPort < member.destPort:
                                print(wnProt[member.srcPort] if wnProt.get(member.srcPort) is not None else '')
                            else:
                                print(wnProt[member.destPort] if wnProt.get(member.destPort) is not None else '')

                            print(f'Source port: {member.srcPort}')
                            print(f'Destiantion port: {member.destPort}')

                # FRAME TYPE & BYTE STREAM
                printBytes(commun.relatedFrame)
            temparr = None

    # INCOMPLETE COMMUNICATION
    for commun in tcp_packet_list:
        if commun is None:
            continue

        if commun.isComplete == False and printIncomplete == 0:
            printIncomplete = 1

            print('\n================= NEUPLNA TCP KOMUNIKACIA =================')
            print(f'Frame number: {commun.relatedFrame.num}')

            # PACKET LENGTH
            print(f'Frame pcapAPI length: {commun.relatedFrame.frameLength}B')
            print(f'Length of the frame transferred via media: {64 if commun.relatedFrame.frameLength < 60 else commun.relatedFrame.frameLength + 4}B')

            # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
            print(commun.relatedFrame.frameType)
            print(f'Source MAC address: {composeMAC(commun.relatedFrame.buffer[6:12])}')
            print(f'Destination MAC address: {composeMAC(commun.relatedFrame.buffer[:6])}')

            protocol_dec = int(str(hexlify(commun.relatedFrame.buffer[12:14]))[2:-1], 16)
            print(ethernetProt[protocol_dec] if ethernetProt.get(protocol_dec) is not None else 'Unknown protocol')

            if protocol_dec == 2048:
                ipProtocol = ipProt.get(int(str(hexlify(commun.relatedFrame.buffer[23:24]))[2:-1], 16))
                print(f'Source IP: {commun.srcIP}')
                print(f'Destination IP: {commun.destIP}')

                if ipProtocol is not None:
                    print(ipProtocol)

                    if ipProtocol == 'TCP':
                        if commun.srcPort < commun.destPort:
                            print(wnProt[commun.srcPort] if wnProt.get(commun.srcPort) is not None else '')
                        else:
                            print(wnProt[commun.destPort] if wnProt.get(commun.destPort) is not None else '')

                        print(f'Source port: {commun.srcPort}')
                        print(f'Destiantion port: {commun.destPort}')

            # FRAME TYPE & BYTE STREAM
            printBytes(commun.relatedFrame)

            # set the number of packets to be printed
            if len(commun.comm) > 19:
                temparr = commun.comm[:9] + commun.comm[-10:]
            else:
                temparr = commun.comm

            for member in temparr:
                print(f'Frame number: {member.relatedFrame.num}')

                # PACKET LENGTH
                print(f'Frame pcapAPI length: {member.relatedFrame.frameLength}B')
                print(
                    f'Length of the frame transferred via media: {64 if member.relatedFrame.frameLength < 60 else member.relatedFrame.frameLength + 4}B')

                # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
                print(member.relatedFrame.frameType)
                print(f'Source MAC address: {composeMAC(member.relatedFrame.buffer[6:12])}')
                print(f'Destination MAC address: {composeMAC(member.relatedFrame.buffer[:6])}')

                protocol_dec = int(str(hexlify(member.relatedFrame.buffer[12:14]))[2:-1], 16)
                print(ethernetProt[protocol_dec] if ethernetProt.get(
                    protocol_dec) is not None else 'Unknown protocol')

                if protocol_dec == 2048:
                    ipProtocol = ipProt.get(int(str(hexlify(member.relatedFrame.buffer[23:24]))[2:-1], 16))
                    print(f'Source IP: {member.srcIP}')
                    print(f'Destination IP: {member.destIP}')

                    if ipProtocol is not None:
                        print(ipProtocol)

                        if ipProtocol == 'TCP':
                            if member.srcPort < member.destPort:
                                print(wnProt[member.srcPort] if wnProt.get(member.srcPort) is not None else '')
                            else:
                                print(wnProt[member.destPort] if wnProt.get(member.destPort) is not None else '')

                            print(f'Source port: {member.srcPort}')
                            print(f'Destiantion port: {member.destPort}')

                # FRAME TYPE & BYTE STREAM
                printBytes(commun.relatedFrame)
            temparr = None

    if printComplete == 0:
        print('Could not find any complete TCP communication')

    if printIncomplete == 0:
        print('Could not find any incomplete TCP communication')


def initARP(communication):
    temp_array = communication

    # --------------------------- GROUP RELATED PACKETS ---------------------------
    for packet in range(len(temp_array)):
        actPacket: ARPComm = temp_array[packet]

        if actPacket is None:
            continue

        for i in range(packet+1, len(temp_array)):
            if temp_array[i] is None:
                continue
            else:
                # if (actPacket.sendIP == temp_array[i].sendIP and actPacket.tarIP == temp_array[i].tarIP and actPacket.sendMAC == temp_array[i].sendMAC and actPacket.tarMAC == temp_array[i].tarMAC and actPacket.op == temp_array[i].op):
                #     actPacket.append_comm(temp_array[i])
                #     temp_array[i] = None
                if actPacket.sendIP == temp_array[i].tarIP and actPacket.tarIP == temp_array[i].sendIP and (actPacket.sendMAC == temp_array[i].tarMAC or actPacket.tarMAC == temp_array[i].sendMAC) and temp_array[i].op != actPacket.op:
                    actPacket.pair = temp_array[i]
                    temp_array[i] = None
                    break

        arp_packet_list.append(actPacket)
        temp_array[packet] = None

    # --------------------------- OUTPUT ---------------------------
    cnt = 1
    for commu in arp_packet_list:
        frame = commu.relatedFrame

        print(f'\n================= COMMUNICATION {cnt} =================')
        if commu.op == 1 and commu.pair is not None:
            print(f'IP address: {commu.tarIP}\t MAC address: {commu.tarMAC}')
            print()


        print(f'Frame number: {frame.num}')

        # PACKET LENGTH
        print(f'Frame pcapAPI length: {frame.frameLength}B')
        print(f'Length of the frame transferred via media: {64 if frame.frameLength < 60 else frame.frameLength + 4}B')

        # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
        print(frame.frameType)

        protocol_dec = int(str(hexlify(frame.buffer[12:14]))[2:-1], 16)
        print(ethernetProt[protocol_dec] if ethernetProt.get(protocol_dec) is not None else 'Unknown protocol', end='')

        if protocol_dec == 2054:
            if(commu.op == 1):
                print(' - Request')
            else:
                print(' - Reply')
        else:
            print()

        print(f'Source IP: {commu.sendIP}')
        print(f'Destination IP: {commu.tarIP}')
        print(f'Source MAC address: {commu.sendMAC}')
        print(f'Destination MAC address: {commu.tarMAC}')

        printBytes(frame, useSep = False)

        if commu.pair is not None: # pair print
            pair = commu.pair
            pairFrame = pair.relatedFrame
            print(f'IP address: {commu.tarIP}\t MAC address: {pair.sendMAC}')
            print()

            print(f'Frame number: {pairFrame.num}')

            # PACKET LENGTH
            print(f'Frame pcapAPI length: {pairFrame.frameLength}B')
            print(f'Length of the frame transferred via media: {64 if pairFrame.frameLength < 60 else pairFrame.frameLength + 4}B')

            # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
            print(pairFrame.frameType)

            pair_protocol_dec = int(str(hexlify(pairFrame.buffer[12:14]))[2:-1], 16)
            print(ethernetProt[pair_protocol_dec] if ethernetProt.get(pair_protocol_dec) is not None else 'Unknown protocol',
                  end='')

            if protocol_dec == 2054:
                if (pair.op == 2):
                    print(' - Reply')
            else:
                print()

            print(f'Source IP: {pair.sendIP}')
            print(f'Destination IP: {pair.tarIP}')
            print(f'Source MAC address: {pair.sendMAC}')
            print(f'Destination MAC address: {pair.tarMAC}')

            printBytes(pairFrame)

        cnt += 1


def initICMP(communication):
    temp_array = communication

    # --------------------------- GROUP RELATED PACKETS ---------------------------
    for packet in range(len(temp_array)):
        actPacket: ICMPComm = temp_array[packet]

        if actPacket is None:
            continue
        else:
            for i in range(packet+1, len(temp_array)):
                if temp_array[i] is None:
                    continue
                else:
                    if (actPacket.srcIP == temp_array[i].srcIP and actPacket.destIP == temp_array[i].destIP) or (actPacket.srcIP == temp_array[i].destIP and actPacket.destIP == temp_array[i].srcIP):
                        actPacket.append_packet(temp_array[i])
                        temp_array[i] = None

        icmp_packet_list.append(actPacket)
        temp_array[packet] = None

    # --------------------------- OUTPUT ---------------------------
    cnt = 1
    for commu in icmp_packet_list:
        actFrame = commu.relatedFrame
        rawFrame = actFrame.buffer

        print(f'\n================= COMMUNICATION {cnt} =================')

        print('Frame number:', actFrame.num)  # row number of a frame

        # PACKET LENGTH
        print(f'Frame pcapAPI length: {actFrame.frameLength}B')
        print(f'Length of the frame transferred via media: {64 if actFrame.frameLength < 60 else actFrame.frameLength + 4}B')

        # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
        print(actFrame.frameType)
        print(f'Source MAC address: {composeMAC(rawFrame[6:12])}')
        print(f'Destination MAC address: {composeMAC(rawFrame[:6])}')

        if actFrame.frameType == 'Ethernet II':
            protocol_dec = int(str(hexlify(actFrame.buffer[12:14]))[2:-1], 16)
            print(ethernetProt[protocol_dec] if ethernetProt.get(protocol_dec) is not None else 'Unknown protocol')

            if protocol_dec == 2048:
                ipProtocol = ipProt.get(int(str(hexlify(rawFrame[23:24]))[2:-1], 16))

                print(f'Source IP: {commu.srcIP}')
                print(f'Destination IP: {commu.destIP}')

                if ipProtocol is not None:
                    print(ipProtocol)

                    if ipProtocol == 'ICMP':
                        print(f'Message: {commu.icmpMess}')

        # FRAME TYPE & BYTE STREAM
        printBytes(actFrame, useSep = False)

        for member in commu.comm:
            memberFrame = member.relatedFrame
            rawMemberPacket = memberFrame.buffer

            print('Frame number:', memberFrame.num)  # row number of a frame

            # PACKET LENGTH
            print(f'Frame pcapAPI length: {memberFrame.frameLength}B')
            print(
                f'Length of the frame transferred via media: {64 if memberFrame.frameLength < 60 else memberFrame.frameLength + 4}B')

            # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
            print(memberFrame.frameType)
            print(f'Source MAC address: {composeMAC(rawMemberPacket[6:12])}')
            print(f'Destination MAC address: {composeMAC(rawMemberPacket[:6])}')

            if memberFrame.frameType == 'Ethernet II':
                protocol_dec = int(str(hexlify(memberFrame.buffer[12:14]))[2:-1], 16)
                print(ethernetProt[protocol_dec] if ethernetProt.get(protocol_dec) is not None else 'Unknown protocol')

                if protocol_dec == 2048:
                    ipProtocol = ipProt.get(int(str(hexlify(memberFrame.buffer[23:24]))[2:-1], 16))

                    print(f'Source IP: {member.srcIP}')
                    print(f'Destination IP: {member.destIP}')

                    if ipProtocol is not None:
                        print(ipProtocol)

                        if ipProtocol == 'ICMP':
                            print(f'Message: {member.icmpMess}')

            # FRAME TYPE & BYTE STREAM
            printBytes(memberFrame, useSep = False)

        cnt += 1


def printIPList():
    highestNumber = 0
    highestIP = None

    print('IP adresy odosielajucich uzlov')
    for i in ipList.keys():
        print(i)
        if ipList.get(i) > highestNumber:
            highestNumber = ipList.get(i)
            highestIP = i

    print(f'\nAdresa uzla s najvacsim poctom odoslanych packetov: {highestIP}\t {highestNumber} packetov')


def fillProtocols(path, protocols): # TODO: make it refresh lists while program runs
    try:
        file = open(path, 'r')
        for line in file:
            index = int(line[line.find(';')+1:line.rfind(';')])
            val = line[line.rfind(';')+1:-1]
            protocols[index] = val

    except FileNotFoundError:
        print('Error opening file with protocols')
        exit(1)


def comprehensivePrint(frame: pcapFrame):
    actFrame = initFrame(frame)
    rawFrame = actFrame.buffer

    print('Frame number:', actFrame.num) # row number of a frame

    # PACKET LENGTH
    print(f'Frame pcapAPI length: {actFrame.frameLength}B')
    print(f'Length of the frame transferred via media: {64 if actFrame.frameLength < 60 else actFrame.frameLength + 4 }B')

    # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
    print(actFrame.frameType)
    print(f'Source MAC address: {composeMAC(rawFrame[6:12])}')
    print(f'Destination MAC address: {composeMAC(rawFrame[:6])}')

    # FRAME TYPE & BYTE STREAM
    nestedProtocols(actFrame)
    printBytes(actFrame)


def clearFile(path):
    file = open(path, 'w')
    file.close()


def loadFile():
    testFiles = None
    file = None

    try:
        testFiles = os.listdir('.\\test-files')
    except NotADirectoryError:
        pass

    try:
        # FILE LOAD
        while (not file):
            file = input('The name of file you wish to open (include .pcap filename extension): ')
            if not file in testFiles:
                print('File does not exist')
                file = None
        print('=' * 100)
    except FileNotFoundError:
        print('File does not exist or is corrupted')
        exit(1)

    return file


def menu():
    print(
        '0 | Choose another file to analyse\n' +
        '1 | Parts 1-3\n' +
        '2 | Part 4a\n' +
        '3 | Part 4b\n' +
        '4 | Part 4c\n' +
        '5 | Part 4d\n' +
        '6 | Part 4e\n' +
        '7 | Part 4f\n' +
        '8 | Part 4g\n' +
        '9 | Part 4h\n' +
        '10 | Part 4i\n' +
        'q | Terminate the application\n'
    )


def main():
    fillProtocols('.\\protocols\\ETHERNET_protocols.txt', ethernetProt) # ETHERNET PROTOCOLS
    fillProtocols('.\\protocols\\IEEE_protocols.txt', ieeeProt) # IEEE PROTOCOLS
    fillProtocols('.\\protocols\\IP_protocols.txt', ipProt) # IP PROTOCOLS
    fillProtocols('.\\protocols\\WN_protocols.txt', wnProt) # TCP PROTOCOLS
    fillProtocols('.\\protocols\\ICMP_types.txt', icmpTypes) # ICMP TYPES

    # USER INTERFACE
    try:
        global FILE

        # load initial .pcap file
        FILE = loadFile()
        frames = rdpcap(f'.\\test-files\\{FILE}')
        save_frames(frames)

        # USER-MENU
        while True:
            menu()
            operation = input('Select operation: ')
            print()

            if operation == '0':
                FILE = None
                FILE = loadFile()
                frames = rdpcap(f'.\\test-files\\{FILE}')
                save_frames(frames)
                clearFile(f'\\{PRINT_FILE}')

            elif operation == '1':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile
                emptyArrays()

                for x in framesArr:
                    comprehensivePrint(x)
                printIPList()

                printFile.close()
            elif operation == '2':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                loadPackets(framesArr)
                initTCP(http_packets)

                printFile.close()
            elif operation == '3':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                loadPackets(framesArr)
                initTCP(http_packets)

                printFile.close()
            elif operation == '4':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                loadPackets(framesArr)
                initTCP(http_packets)

                printFile.close()
            elif operation == '5':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                loadPackets(framesArr)
                initTCP(http_packets)

                printFile.close()
            elif operation == '6':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                loadPackets(framesArr)
                initTCP(http_packets)

                printFile.close()
            elif operation == '7':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                loadPackets(framesArr)
                initTCP(http_packets)

                printFile.close()
            elif operation == '8':
                # printFile = open(f'.\\{PRINT_FILE}', 'w')
                # sys.stdout = printFile

                # loadPackets(frames)
                # TFTP

                # printFile.close()
                pass
            elif operation == '9':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                loadPackets(framesArr)
                initICMP(icmp_packets)

                printFile.close()
            elif operation == '10':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                loadPackets(framesArr)
                initARP(arp_packets)

                printFile.close()
            elif operation == 'q':
                break

            if operation != '0':
                sys.stdout = DEFAULT_STDOUT

                # Open print FILE
                print('Opening file...')
                os.startfile(f'.\\{PRINT_FILE}')  # opens file with printed frames
                time.sleep(3)

            operation = None

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()