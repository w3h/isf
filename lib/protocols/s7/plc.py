#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2014-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""

import socket
from scapy.all import *
from s7 import *
import time


class PLCClient:
    def __init__(self, ip, port = 102, slot = 3, rack = 0):
        self.ip = ip
        self.port = port
        self.slot = slot
        self.rack = rack
        self.s = None
        self.conn = None
        self.sequence = 0

    def __del__(self):
        self.closeSocket()

    def createSocket(self):
        self.s = socket.socket()
        self.s.connect((self.ip, int(self.port)))
        self.conn = StreamSocket(self.s, Raw)

    def closeSocket(self):
        try:
            self.conn.close()
            self.s.close()
        except:
            pass

    def createConn(self):
        if not self.s: self.createSocket()
        dsttsap = 0x0100 + self.slot
        s7 =  TPTK() / COTPConn(dsttsap = dsttsap)
        self.conn.send(s7)
        self.conn.recv()
        #return S7_Conn(response.load)

    def setupCommunication(self):
        s7 =  TPTK() / COTP() / S7Comm_SetupComm()
        self.conn.send(s7)
        self.conn.recv()

    def stop(self):
        s7 =  TPTK() / COTP() / S7Comm_StopCpu()
        self.conn.send(s7)

    def hotReboot(self):
        s7 =  TPTK() / COTP() / S7Comm_HotReboot()
        self.conn.send(s7)

    def coldReboot(self):
        s7 =  TPTK() / COTP() / S7Comm_ColdReboot()
        self.conn.send(s7)

    def upload(self):
        response = self.conn.send(S7_StartUpload())
        time.sleep(0.1)
        response = self.conn.send(S7_Upload())
        time.sleep(0.1)
        response = self.conn.send(S7_EndUpload())
        time.sleep(0.1)
