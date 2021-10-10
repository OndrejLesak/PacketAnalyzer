from scapy.all import *
from binascii import hexlify

FILE = 'trace-27.pcap' # .pcap file to be analyzed
framesArr = [] # for storing packets as objects
ethernetProt = {} # ETHERNET II Protocols
ieeeProt = {} # IEEE 802.3 Protocols


class pcapFrame():
    destMAC = None # destination MAC address
    srcMAC = None # source MAC address
    protocol = None # internet protocol type
    srcAddr = None # source IP address
    destAddr = None # destination IP address
    buffer = None # binary packet data
    num = None # row number of the frame
    byteStream = None # byte stream of the frame
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


def printBytes(frame: pcapFrame):
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


def composeMAC(hexBytes):
    byteStream = str(hexlify(hexBytes))[2:-1]
    address = ':'.join(byteStream[i:i+2] for i in range(0, len(byteStream), 2))
    return address


def printFrameType(frame: pcapFrame):
    rawFrame = frame.buffer
    protocol_val = int(str(hexlify(rawFrame[12:14]))[2:-1], 16) # protocol decimal value

    if protocol_val > 1500:
        frame.frameType = 'Ethernet II'
    else:
        if str(hexlify(rawFrame[14:15]))[2:-1] == 'ff':
           frame.frameType = 'IEEE 802.3 - Raw'
        elif str(hexlify(rawFrame[14:15]))[2:-1] == 'aa':
            frame.frameType = 'IEEE 802.3 - LLC & SNAP'
        else:
            frame.frameType = 'IEEE 802.3 - LLC'


def initFrame(frame: pcapFrame):
    pass


def nestedProtocols(frame: pcapFrame):
    rawFrame = frame.buffer

    if frame.frameType == 'Ethernet II':
        print(ethernetProt[int(str(hexlify(rawFrame[12:14]))[2:-1], 16)])
        # 23rd byte (IPv4 nested protocol)
    elif frame.frameType == 'IEEE 802.3 - Raw':
        print('IPX')
    elif frame.frameType == 'IEEE 802.3 - LLS & SNAP':
        # print(ieeeProt)
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
        exit(-1)


def comprehensivePrint(frame: pcapFrame):
    rawFrame = frame.buffer

    print('Frame number:', frame.num) # row number of a frame

    # PACKET LENGTH
    print(f'Frame pcapAPI length: {frame.frameLength}B')
    print(f'Length of the frame transferred via media: {64 if frame.frameLength < 60 else frame.frameLength + 4 }B')

    # SRC & DEST MAC ADDRESSES
    print(f'Source MAC address: {composeMAC(frame.buffer[6:12])}')
    print(f'Destination MAC address: {composeMAC(frame.buffer[:6])}')
    printFrameType(frame)
    print(frame.frameType)
    nestedProtocols(frame)
    printBytes(frame)


def menu():
    print(
        '1 | Print all frames with information\n' +
        '2 | Print frame\'s nested protocols\n' +
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
                # for x in framesArr:
                #     comprehensivePrint(x)
                comprehensivePrint(framesArr[5])

            elif operation == 'q':
                break

            operation = None

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()