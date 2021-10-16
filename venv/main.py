from scapy.all import *
from binascii import hexlify
import os
import time

FILE = None # .pcap file to be analyzed
PRINT_FILE = 'consolePrint.txt' # static file for stroing console print

framesArr = [] # for storing packets as objects
ethernetProt = {} # ETHERNET II Protocols
ieeeProt = {} # IEEE 802.3 Protocols
ipProt = {} # IPv4 Protocols
tcpProt = {} # TCP protocols
udpProt = {} # UDP protocols


class pcapFrame():
    num = None # row number of the frame
    buffer = None # binary packet data
    frameLength = None # frame length
    frameType = None # frame type

    def __init__(self, num, buffer):
        self.num = num
        self.buffer = buffer
        self.frameLength = len(buffer)


def save_frames(frames):
    global framesArr

    i = 1
    for frame in frames:
        newFrame = pcapFrame(i, raw(frame))
        framesArr.append(newFrame)
        i += 1


def printBytes(frame: pcapFrame, printFile):
    try:
        rawFrame = frame.buffer
        i = 0
        for index in range(frame.frameLength):
            if i % 16 == 0:
                print(file = printFile)
            elif i % 8 == 0:
                print(" ", end="", file = printFile)

            i += 1
            print(str(hexlify(rawFrame[index:index+1]))[2: -1], end="", file = printFile)
            print(" ", end="", file = printFile)

        print(file = printFile)
        print('=' * 100, file = printFile)
        print('=' * 100, file = printFile)

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


def nestedProtocols(frame: pcapFrame, printFile):
    if frame is not None:
        rawPacket = frame.buffer
        protocolFlow = None

        # ----------------- ETHERNET ---------------------
        if frame.frameType == 'Ethernet II':
            protocol_dec = int(str(hexlify(rawPacket[12:14]))[2:-1], 16)

            if ethernetProt.get(protocol_dec) is not None:
                print(ethernetProt[protocol_dec], file = printFile)

                if protocol_dec == 2048: # IPv4 protocol
                    offsetIhl = protocol_dec = int(str(hexlify(rawPacket[14:15]))[3:-1], 16) * 4 + 14
                    ipProtocol = ipProt.get(int(str(hexlify(rawPacket[23:24]))[2:-1], 16))

                    sourceIP = composeIP(rawPacket[26:30])
                    destIP = composeIP(rawPacket[30:34])
                    print(f'Source IP: {sourceIP}', file = printFile)
                    print(f'Destination IP: {destIP}', file = printFile)

                    if ipProtocol is not None:
                        print(ipProtocol, file = printFile)

                        if ipProtocol == 'TCP': # TCP protocol
                            sourcePort = int(str(hexlify(rawPacket[offsetIhl:offsetIhl+2]))[2:-1], 16)
                            destPort = int(str(hexlify(rawPacket[offsetIhl+2:offsetIhl+4]))[2:-1], 16)
                            print(f'Source port: {sourcePort}', file = printFile)
                            print(f'Destination port: {destPort}', file = printFile)
                            if sourcePort > destPort: # nested protocol
                                print(tcpProt[destPort] if tcpProt.get(destPort) is not None else 'Unknown protocol', file = printFile)
                            else:
                                print(tcpProt[sourcePort] if tcpProt.get(sourcePort) is not None else 'Unknown protocol', file = printFile)

                        elif ipProtocol == 'UDP': # UDP protocol
                            sourcePort =  int(str(hexlify(rawPacket[offsetIhl:offsetIhl+2]))[2:-1], 16)
                            destPort = int(str(hexlify(rawPacket[offsetIhl+2:offsetIhl+4]))[2:-1], 16)
                            print(f'Source port: {sourcePort}', file = printFile)
                            print(f'Destination port: {destPort}', file = printFile)
                            print(udpProt[destPort] if udpProt.get(destPort) is not None else 'Unknown protocol', file = printFile) # nested protocol
                    else:
                        print("Unknown protocol", file = printFile)

                elif protocol_dec == 2054:
                    operation = int(str(hexlify(rawPacket[20:22]))[2:-1], 16) # request/ reply
                    senderMAC = composeMAC(rawPacket[22:28])
                    senderIP = composeIP(rawPacket[28:32])
                    targetMAC = composeMAC(rawPacket[32:38])
                    targetIP = composeIP(rawPacket[38:42])

                    print('Request' if operation == 1 else 'Response', file = printFile)
                    print(f'Sender MAC: {senderMAC}', file = printFile, end = '\t')
                    print(f'Sender IP: {senderIP}', file = printFile)
                    print(f'Target MAC: {targetMAC}', file = printFile, end = '\t')
                    print(f'Target IP: {targetIP}', file = printFile)

            else:
                print('Unknown protocol', file = printFile)

        # ----------------- IEEE - RAW ---------------------
        elif frame.frameType == 'IEEE 802.3 - Raw':
            print('IPX', file = printFile)

        # ----------------- IEEE - LLC & SNAP ---------------------
        elif frame.frameType == 'IEEE 802.3 - LLC & SNAP':
            protocolDSAP_dec = int(str(hexlify(rawPacket[14:15]))[2:-1], 16)
            protocolSSAP_dec = int(str(hexlify(rawPacket[15:16]))[2:-1], 16)
            print(f'DSAP: {ieeeProt[protocolDSAP_dec] if ieeeProt.get(protocolDSAP_dec) is not None else "Unknown"}', end = '\t', file = printFile)
            print(f'SSAP: {ieeeProt[protocolSSAP_dec] if ieeeProt.get(protocolSSAP_dec) is not None else "Unknown"}', file = printFile)

            print(ieeeProt[protocolDSAP_dec] if ieeeProt.get(protocolDSAP_dec) is not None else 'Unknown protocol', file = printFile)  # nested protocol
            # analyse also nested SSAP protocol (EtherType)

        elif frame.frameType == 'IEEE 802.3 - LLC':
            protocolDSAP_dec = int(str(hexlify(rawPacket[14:15]))[2:-1], 16)
            protocolSSAP_dec = int(str(hexlify(rawPacket[15:16]))[2:-1], 16)
            print(f'DSAP: {ieeeProt[protocolDSAP_dec] if ieeeProt.get(protocolDSAP_dec) is not None else "Unknown"}', end = '\t', file = printFile)
            print(f'SSAP: {ieeeProt[protocolSSAP_dec] if ieeeProt.get(protocolSSAP_dec) is not None else "Unknown"}', file = printFile)

            print(ieeeProt[protocolDSAP_dec] if ieeeProt.get(protocolDSAP_dec) is not None else 'Unknown protocol', file = printFile) # nested protocol


def fillProtocols(path, protocols):
    try:
        file = open(path, 'r')
        for line in file:
            index = int(line[line.find(';')+1:line.rfind(';')])
            val = line[line.rfind(';')+1:-1]
            protocols[index] = val

    except FileNotFoundError:
        print('Error opening file with protocols')
        exit(1)


def comprehensivePrint(frame: pcapFrame, printFile):
    actFrame = initFrame(frame)
    rawFrame = actFrame.buffer

    print('Frame number:', actFrame.num, file = printFile) # row number of a frame

    # PACKET LENGTH
    print(f'Frame pcapAPI length: {actFrame.frameLength}B', file = printFile)
    print(f'Length of the frame transferred via media: {64 if actFrame.frameLength < 60 else actFrame.frameLength + 4 }B', file = printFile)

    # FRAME TYPE & (SRC && DEST MAC ADDRESSES)
    print(actFrame.frameType, file=printFile)
    print(f'Source MAC address: {composeMAC(rawFrame[6:12])}', file = printFile)
    print(f'Destination MAC address: {composeMAC(rawFrame[:6])}', file = printFile)

    # FRAME TYPE & BYTE STREAM
    nestedProtocols(actFrame, printFile)
    printBytes(actFrame, printFile)

    # nestedProtocols(actFrame)


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
    fillProtocols('.\\protocols\\TCP_protocols.txt', tcpProt) # TCP PROTOCOLS
    fillProtocols('.\\protocols\\UDP_protocols.txt', udpProt) # UDP PROTOCOLS

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
                clearFile(f'.\\{PRINT_FILE}')
                printFile = open(f'.\\{PRINT_FILE}', 'a')

                for x in framesArr:
                    comprehensivePrint(x, printFile)

                printFile.close()

                print('Opening output file...\n')
                time.sleep(3)
                os.startfile(f'.\\{PRINT_FILE}') # opens file with printed frames

            elif operation == 'q':
                break

            operation = None

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()