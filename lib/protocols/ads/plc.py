#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2014-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""

import socket
from scapy.all import *
from utils import *

from adsudp import *
from adstcp import *


class PLCClient:
    def __init__(self, ip, port = 48898, timeout=10):
        self.ip = ip
        self.port = port

    def getPLCInfo(self):
        pkt = AdsBroadcast()
        s = SendPacket(pkt, self.ip, 48899, 'udp')
        data, addr = s.recvfrom(2048)
        info = AdsBroadcastResponse(data)
        return info

    def getNetId(self):
        info = self.getPLCInfo()
        return info.getfieldval('netid')

    def reboot(self):
        pkt = AdsControlRequest()
        pkt.target_netid = self.getNetId()
        SendPacket(pkt, self.ip, self.port, 'tcp')

    def auth(self, username, password):
        netid = ""
        pkt = AdsAuth(username = username, password = password)
        SendPacket(pkt, self.ip, 48899, 'udp')


if __name__ == '__main__':
    t = PLCClient("192.168.1.8")
    print t.reboot()
