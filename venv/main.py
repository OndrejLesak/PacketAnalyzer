from scapy.all import *
from binascii import hexlify
import os
import time

FILE = None # .pcap file to be analyzed
PRINT_FILE = 'consolePrint.txt' # static file for stroing console print

framesArr = [] # for storing packets as objects
ethernetProt = {} # ETHERNET II Protocols
ieeeProt = {} # IEEE 802.3 Protocols
ipProt = {}


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
    pass


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
        protocolFlow = None

        if frame.frameType == 'Ethernet II':
            protocol_dec = int(str(hexlify(rawPacket[12:14]))[2:-1], 16)

            if ethernetProt.get(protocol_dec) is not None:
                protocolFlow = ethernetProt[protocol_dec]

                if protocol_dec == 2048:
                    if ipProt.get(int(str(hexlify(rawPacket[23:24]))[2:-1], 16)) is not None:
                        protocolFlow += " -> " + ipProt[int(str(hexlify(rawPacket[23:24]))[2:-1], 16)]

            else:
                protocolFlow = 'Unknown protocol'

        elif frame.frameType == 'IEEE 802.3 - Raw':
            protocolFlow = 'IPX'

        elif frame.frameType == 'IEEE 802.3 - LLC & SNAP':
            protocolDSAP_dec = int(str(hexlify(rawPacket[14:15]))[2:-1], 16)
            protocolSSAP_dec = int(str(hexlify(rawPacket[15:16]))[2:-1], 16)

            if ieeeProt.get(protocolDSAP_dec) is not None:
                protocolFlow = 'DSAP: ' + ieeeProt[protocolDSAP_dec] + '\n'
            else:
                protocolFlow = 'DSAP: Unknown\n'

            if ieeeProt.get(protocolSSAP_dec) is not None:
                protocolFlow += 'SSAP: ' + ieeeProt[protocolSSAP_dec] + '\n'
            else:
                protocolFlow += 'SSAP: Unknown\n'

        return protocolFlow


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

    # FRAME TYPE & SRC & DEST MAC ADDRESSES
    print(actFrame.frameType, file=printFile)
    print(f'Source MAC address: {composeMAC(rawFrame[6:12])}', file = printFile)
    print(f'Destination MAC address: {composeMAC(rawFrame[:6])}', file = printFile)

    # FRAME TYPE & BYTE STREAM
    # print(nestedProtocols(actFrame), file = printFile)
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

    # fillProtocols('.\\protocols\\ETHERNET_protocols.txt', ethernetProt)
    # fillProtocols('.\\protocols\\IEEE_protocols.txt', ieeeProt)
    # fillProtocols('.\\protocols\\IP_protocols.txt', ipProt)

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