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

ipList = {} # list of all unique IP addresses

http_packets = []
https_packets = []
telnet_packets = []
ssh_packets = []
ftpC_packets = []
ftpD_packets = []
tcp_packet_list = []

tftp_packets = []
icmp_packets = []
arp_packets = []


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

    def append_packet(self, packet):
        self.comm.append(packet)


def save_frames(frames):
    global framesArr

    i = 1
    for frame in frames:
        newFrame = pcapFrame(i, raw(frame))
        framesArr.append(newFrame)
        i += 1


def printBytes(frame: pcapFrame):
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
        print('=' * 100)
        print('=' * 100)

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

                            wnProtocol = wnProt[destPort] if wnProt.get(destPort) is not None else 'Unknown protocol'
                            print(wnProtocol) # nested protocol

                            if wnProtocol == 'TFTP':
                                tftp_packets.append(frame)

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

                    arp_packets.append(frame)

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

    # group related packets
    for packet in range(len(temp_comm)):
        actPacket: TCPComm = temp_comm[packet]

        if actPacket is not None:
            for i in range(packet+1, len(temp_comm)):
                if temp_comm[i] is None:
                    continue
                elif (actPacket.srcIP == temp_comm[i].srcIP and actPacket.destIP == temp_comm[i].destIP and actPacket.srcPort == temp_comm[i].srcPort and actPacket.destPort == temp_comm[i].destPort)\
                    or (actPacket.srcIP == temp_comm[i].destIP and actPacket.destIP == temp_comm[i].srcIP and actPacket.srcPort == temp_comm[i].destPort and actPacket.destPort == temp_comm[i].srcPort):
                    actPacket.append_packet(temp_comm[i])
                    temp_comm[i] = None
        else:
            continue

        tcp_packet_list.append(actPacket)
        temp_comm[packet] = None # empty the list

        # ANALYSIS
        if len(tcp_packet_list) > 0:
            for commun in tcp_packet_list:
                if len(commun.comm) >= 3:
                   if (commun.flags == 2 and commun.comm[0].flags == 18 and commun.comm[1].flags == 16):
                       end1, end2, end3, end4 = commun.comm[-1].flags, commun.comm[-2].flags, commun.comm[-3].flags, commun.comm[-4].flags

                       if (end1 == 4 or end1 == 20 or (end1 == 16 and end2 == 17 and end3 == 17) or (end4 == 17 and end3 == 16 and end2 == 17 and end1 == 16)):
                           commun.isComplete = True
                   else:
                       commun = None

        # OUTPUT
        printComplete = 0
        printIncomplete = 0
        for commun in tcp_packet_list:
            if commun is None:
                continue

            if commun.isComplete == 1 and printComplete == 0:
                printComplete = 1

                print('================= KOMPLETNA TCP KOMUNIKACIA =================')

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

                if len(commun.comm) > 19:
                    break



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


def menu():
    print(
        '1 | Print all frames with information\n' +
        'q | Terminate the application\n'
    )


def main():
    global FILE
    testFiles = None

    try:
       testFiles = os.listdir('.\\test-files')
    except NotADirectoryError:
        pass

    fillProtocols('.\\protocols\\ETHERNET_protocols.txt', ethernetProt) # ETHERNET PROTOCOLS
    fillProtocols('.\\protocols\\IEEE_protocols.txt', ieeeProt) # IEEE PROTOCOLS
    fillProtocols('.\\protocols\\IP_protocols.txt', ipProt) # IP PROTOCOLS
    fillProtocols('.\\protocols\\WN_protocols.txt', wnProt) # TCP PROTOCOLS

    # USER INTERFACE
    try:
        # FILE LOAD
        while(not FILE):
            FILE = input('The name of file you wish to open (include .pcap filename extension): ')
            if not FILE in testFiles:
                print('File does not exist')
                FILE = None
        print('=' * 100)

        frames = rdpcap(f'.\\test-files\\{FILE}')
        save_frames(frames)

        # USER-MENU
        while True:
            menu()
            operation = input('Select operation: ')
            print()

            if operation == '1':
                printFile = open(f'.\\{PRINT_FILE}', 'w')
                sys.stdout = printFile

                for x in framesArr:
                    comprehensivePrint(x)
                printIPList()

                # Open print FILE
                print('Opening file...')
                os.startfile(f'.\\{PRINT_FILE}')  # opens file with printed frames
                time.sleep(2)

                initTCP(http_packets)
                printFile.close()
                sys.stdout = DEFAULT_STDOUT

            elif operation == 'q':
                break

            operation = None

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()