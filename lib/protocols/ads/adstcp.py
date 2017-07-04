#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2014-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""

from basefield import *


class AdsReadState(Packet):
    name = "AdsReadState"
    fields_desc = [
        StrField('unknown', '\x00\x00\x02\x00\x00\x00'),
        DotHexField("target_netid", '255.255.0.0.0.0'),
        ShortField("target_port", 10000),
        DotHexField("sender_netid", '255.255.0.0.0.0'),
        ShortField("sender_port", 32769),
        LEShortField('cmdid', 0x04),
        LEShortField('stateflag', 0x04),
        LEIntField('cndata', 0x00),
        LEIntField('errorcode', 0x04),
        LEIntField('invakeid', 0x22),
    ]

class AdsReadStateResponse(Packet):
    name = "AdsReadStateResponse"
    fields_desc = [
        StrField('unknown', '\x00\x00\x28\x00\x00\x00'),
        DotHexField("target_netid", '255.255.0.0.0.0'),
        LEShortField("target_port", 10000),
        DotHexField("sender_netid", '255.255.0.0.0.0'),
        LEShortField("sender_port", 32769),
        LEShortField('cmdid', 0x04),
        LEShortField('stateflag', 0x04),
        LEIntField('cndata', 0x00),
        LEIntField('errorcode', 0x04),
        LEIntField('invakeid', 0x22),
        LEIntField('result', 0x0),
        LEShortField('adsstate', 0xf),
        LEShortField('devicestate', 0x2),
    ]

class AdsControlRequest(Packet):
    name = "AdsControlRequest"
    fields_desc = [
        StrField('unknown', '\x00\x00\x28\x00\x00\x00'),
        DotHexField("target_netid", '255.255.0.0.0.0'),
        LEShortField("target_port", 10000),
        DotHexField("sender_netid", '255.255.0.0.0.0'),
        LEShortField("sender_port", 32769),
        LEShortField('cmdid', 0x05),
        LEShortField('stateflag', 0x04),
        LEIntField('cndata', 0x08),
        LEIntField('errorcode', 0x00),
        LEIntField('invakeid', 0xc6),
        LEShortField('adsstate', 0x0C),
        LEShortField('devicestate', 0x00),
        LEIntField("cblength", 0x00),
        StrLenField("data", "", length_from = lambda pkt: pkt.cblength),
    ]

bind_layers(TCP, AdsReadState, port=48898)
bind_layers(TCP, AdsReadStateResponse)
bind_layers(TCP, AdsControlRequest, port=48898)
