#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2014-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""

from basefield import *


class AdsBroadcast(Packet):
    name = "AdsBroadcast"
    fields_desc = [
        StrFixedLenField('sequence', '\x03\x66\x14\x71', 4),
        StrFixedLenField("group", '\x00\x00\x00\x00\x01\x00\x00\x00\x00', 8),
        DotHexField("netid", '255.255.0.0.0.0'),
        ShortField("port", 10000),
        IntField('res', 0)
    ]

class AdsBroadcastResponse(Packet):
    name = "AdsBroadcastResponse"
    fields_desc = [
        StrFixedLenField('sequence', '\x03\x66\x14\x71', 4),
        StrFixedLenField("group", '\x00\x00\x00\x00\x01\x00\x00\x08', 8),
        DotHexField("netid", '255.1.1.1.1.255'),
        LEShortField("port", 10000),
        StrField('unknown1', '\x03\x00\x00\x00'),
        LEShortField('type1', 0x05),
        FieldLenField("length1", 0x0a, length_of="data1", fmt="<H"),
        StrLenField("data1", None, length_from = lambda pkt: pkt.length1),
        LEShortField('type2', 0x04),
        FieldLenField("length2", 0x114, length_of="data2", fmt="<H"),
        StrLenField("data2", None, length_from = lambda pkt: pkt.length2),
        LEShortField('type3', 0x03),
        LEShortField('length3', 0x04),
        TwinCATVersionField('TwinCATVersion', '2.0.255'),
    ]

class AdsAuth(Packet):
    name = "AdsAuth"
    fields_desc = [
        StrFixedLenField('sequence', '\x03\x66\x14\x71', 4),
        StrFixedLenField("group", '\x00\x00\x00\x00\x06\x00\x00\x00', 8),
        DotHexField("netid", '5.13.117.96.1.1'),
        LEShortField("port", 10000),
        StrField('unknown1', '\x05\x00\x00\x00'),

        LEShortField('type1', 0x0c),
        FieldLenField("hostnamelen", None, length_of="hostname",
            fmt="<H", adjust=lambda pkt,x: x+1),
        StrLenField("hostname", 'HACK-PC', length_from = lambda pkt: pkt.hostnamelen - 1),
        ByteField('r1', 0),

        LEShortField('type2', 0x07),
        FieldLenField("length2", None, length_of="data2",
            fmt="<H", adjust=lambda pkt,x: x+1),
        StrLenField("data2", '11', length_from = lambda pkt: pkt.length2 - 1),
        ByteField('r2', 0),

        LEShortField('type3', 0x0d),
        FieldLenField("usernamelen", None, length_of="username",
            fmt="<H", adjust=lambda pkt,x: x+1),
        StrLenField("username", None,
            length_from = lambda pkt: pkt.usernamelen - 1),
        ByteField('r3', 0),

        LEShortField('type4', 0x02),
        FieldLenField("passwordlen", None, length_of="password",
            fmt="<H", adjust=lambda pkt,x: x+1),
        StrLenField("password", None,
            length_from = lambda pkt: pkt.passwordlen - 1),
        ByteField('r4', 0),

        LEShortField('type5', 0x05),
        FieldLenField("localiplen", None, length_of="localip",
            fmt="<H", adjust=lambda pkt,x: x+1),
        StrLenField("localip", "192.168.1.88",
            length_from = lambda pkt: pkt.localiplen - 1),
        ByteField('r5', 0),
    ]

class AdsAuthResponse(Packet):
    name = "AdsAuthResponse"
    fields_desc = [
        StrFixedLenField('sequence', '\x03\x66\x14\x71', 4),
        StrFixedLenField("group", '\x00\x00\x00\x00\x06\x00\x00\x00', 8),
        DotHexField("netid", '255.1.1.1.1.255'),
        LEShortField("port", 10000),
        StrFixedLenField('unknown1', '\x01\x00\x00\x00', 4),

        LEShortField('type1', 0x01),
        FieldLenField("errcodelen", 4, length_of="hostname", fmt="<H"),
        StrLenField("errcode", '\x00\x00\x00\x00',
            length_from = lambda pkt: pkt.errcodelen),
    ]


bind_layers(UDP, AdsBroadcast, port=48899)
bind_layers(UDP, AdsBroadcastResponse)
bind_layers(UDP, AdsAuth, port=48899)
bind_layers(UDP, AdsAuthResponse)


if __name__ == "__main__":
    t = AdsBroadcast()
    print t.netid
