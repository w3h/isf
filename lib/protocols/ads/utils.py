#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2015-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""

import socket
from scapy.all import *
#from xtype import *


def CreateTcpSocket(ip, port, timeout=10):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((ip, port))  # encapsulate into try/catch
    return s

def CreateUdpSocket(ip, port, timeout=10):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    return s

def CreateTcpRawSocket(ip, port, timeout=10):
    s = CreateTcpSocket(ip, port, timeout)
    connection = StreamSocket(s, Raw)
    return connection

def SendPacket(pks, ip=None, port=None, stype=None, timeout=10, verbose=None):
    if stype == None:
        send(pks, verbose = verbose)
    elif stype == 'tcpraw':
        connection = CreateTcpRawSocket(ip, port, timeout)
        if isinstance(pks, basestring): pks = Raw(pks)
        response = connection.sr1(pks)
        return response, connection
    elif stype == 'tcp':
        s = CreateTcpSocket(ip, port, timeout)
        if not isinstance(pks, basestring): pks = str(pks)
        s.send(pks)
        return s
    elif stype == 'udp':
        s = CreateUdpSocket(ip, port, timeout)
        if not isinstance(pks, basestring): pks = str(pks)
        s.sendto(pks, (ip, port))
        return s
    else:
        raise
