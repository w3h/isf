#!/usr/bin/env python
# coding=utf-8

#import sys
#ISF_DIR = "/Users/W.HHH/code/isf"
#sys.path.append(ISF_DIR)
#sys.path.append(ISF_DIR + "/lib/protocols")
#sys.path.append(ISF_DIR + "/lib/thirdparty")

from core.exploit import *
from lib.protocols.pn_dcp import *
import threading
from tabulate import tabulate


class MyScript(BaseExploit):
    register_info = {
        'ID' : 'ICF-2017-F0010001',
        'Name' : '利用Profinet协议发现工控设备',
        'Author' : ['wenzhe zhu','w3h'],
        'License': ISF_LICENSE,
        'Create_Date' : '2017-11-09',
        'Description' : '''发送一个Profinet协议报文，扫描所有支持此协议的设备，包括主机和控制器等设备。''',
    }

    register_options = [
        mkopt("--Interface", help="Interface Name e.g eth0, en0.", type="string", default="eth0"),
        mkopt("--NetworkTimeout", help="Timeout for blocking network calls (in seconds).", type="string", default="5"),
    ]

    PROFINET_BROADCAST_ADDRESS_1 = '01:0e:cf:00:00:00'
    PROFINET_BROADCAST_ADDRESS_2 = "28:63:36:5a:18:f1"
    sniff_mac_address = None
    sniff_finished = threading.Event()
    result = []

    def sniff_answer(self):
        self.sniff_finished.clear()
        response = sniff(iface=self.nic, filter="ether dst host %s" % self.sniff_mac_address, timeout=self.timeout)
        self.result = []
        for i in range(len(response)):
            pkt = response[i]
            if pkt[Ether].dst == self.sniff_mac_address:
                Device_Name = ''
                Device_Type = ''
                MAC_Address = pkt[Ether].src
                IP_Address = ''
                Netmask = ''
                GateWay = ''
                if pkt.haslayer(PNDCPIdentDeviceNameOfStationResponseBlock):
                    Device_Name = pkt[PNDCPIdentDeviceNameOfStationResponseBlock].NameOfStation
                if pkt.haslayer(PNDCPIdentDeviceManufacturerSpecificResponseBlock):
                    Device_Type = pkt[PNDCPIdentDeviceManufacturerSpecificResponseBlock].DeviceVendorValue
                if pkt.haslayer(PNDCPIdentIPParameterResponseBlock):
                    IP_Address = pkt[PNDCPIdentIPParameterResponseBlock].IPaddress
                    Netmask = pkt[PNDCPIdentIPParameterResponseBlock].Subnetmask
                    GateWay = pkt[PNDCPIdentIPParameterResponseBlock].StandardGateway
                self.result.append([Device_Name, Device_Type, MAC_Address, IP_Address, Netmask, GateWay])
        self.sniff_finished.set()

    def SendPacketToMac(self, target_mac):
        packet = Ether(src=self.sniff_mac_address, dst=target_mac, type=0x8892) / ProfinetIO(frameID=0xFEFE) / \
                 PNDCPHeader(ServiceID=5, ServiceType=0, DCPBlocks=[PNDCPIdentRequest()])
        sendp(packet, iface=self.nic)

    def run(self, target_mac):
        packet = Ether(src=self.sniff_mac_address, dst=target_mac, type=0x8892) / ProfinetIO(frameID=0xFEFE) / \
                 PNDCPHeader(ServiceID=5, ServiceType=0, DCPBlocks=[PNDCPIdentRequest()])
        sendp(packet, iface=self.nic)

    def exploit(self, *args, **kwargs):
        self.nic = self.getParam("Interface")
        self.timeout = int(self.getParam("NetworkTimeout"))
        self.sniff_mac_address = get_if_hwaddr(self.nic)
        p = threading.Thread(target=self.sniff_answer)
        p.setDaemon(True)
        p.start()
        self.run(target_mac=self.PROFINET_BROADCAST_ADDRESS_1)
        self.run(target_mac=self.PROFINET_BROADCAST_ADDRESS_2)
        self.sniff_finished.wait(self.timeout + 1)
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        TABLE_HEADER = ['Device Name', 'Device Type', "MAC Address", "IP Address", "Netmask", "GateWay"]
        print(tabulate(unique_device, headers=TABLE_HEADER))


MainEntry(MyScript, __name__)
