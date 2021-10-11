from scapy.all import *
from binascii import hexlify
import os
import time

FILE = 'trace-27.pcap' # .pcap file to be analyzed

framesArr = [] # for storing packets as objects
ethernetProt = {} # ETHERNET II Protocols
ieeeProt = {} # IEEE 802.3 Protocols


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
    pass


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

    # SRC & DEST MAC ADDRESSES
    print(f'Source MAC address: {composeMAC(rawFrame[6:12])}', file = printFile)
    print(f'Destination MAC address: {composeMAC(rawFrame[:6])}', file = printFile)

    # FRAME TYPE & BYTE STREAM
    print(actFrame.frameType, file = printFile)
    printBytes(actFrame, printFile)


def clearFile(path):
    file = open(path, 'w')
    file.close()


def menu():
    print(
        '1 | Print all frames with information\n' +
        'q | Terminate the application\n'
    )


def main():
    frames = rdpcap(f'.\\test-files\\{FILE}')

    save_frames(frames)
    fillProtocols('.\\protocols\ETHERNET_protocols.txt', ethernetProt)
    fillProtocols('.\\protocols\IEEE_protocols.txt', ieeeProt)

    # USER INTERFACE
    try:
        while True:
            menu()
            operation = input('Select operation: ')
            print()

            if operation == '1':
                clearFile('.\\consolePrint.txt')
                printFile = open('.\\consolePrint.txt', 'a')

                for x in framesArr:
                    comprehensivePrint(x, printFile)

                printFile.close()

                print('Opening output file...')
                time.sleep(3)
                os.startfile('.\\consolePrint.txt') # opens file with printed frames

            elif operation == 'q':
                break

            operation = None

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()