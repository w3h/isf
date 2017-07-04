#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2014-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""


from tptk import *


class COTP(Packet):
    name = "COTP"
    fields_desc = [
        ByteField("length", 0x2),
        XByteField("pdutype", 0xf0),
        XByteField("lastunit", 0x80),
    ]

class COTPConn(COTP):
    name = "COTPConn"
    fields_desc = [
        ByteField("length", 17),
        XByteField("pdutype", 0xe0),
        XShortField("dstcaddr", 0x0000),
        XShortField("srcaddr", 0x0001),
        XByteField("tpc", 0x00),
        XByteField("paracode1", 0xc1),
        ByteField("paralen1", 0x02),
        XShortField("srctsap", 0x0100),
        XByteField("paracode2", 0xc2),
        ByteField("paralen2", 0x02),
        XShortField("dsttsap", 0x0103),  # slot 102/103
        XByteField("paracode0", 0xc0),
        ByteField("paralen0", 0x01),
        XByteField("tpdusize", 0x0a),
    ]

class COTPConnResponse(COTP):
    name = "COTPConnResponse"
    fields_desc = [
        ByteField("length", None),
        XByteField("pdutype", None),
        XShortField("dstcarefer", None),
        XShortField("srcrefer", None),
        XByteField("tpc", None),
        XByteField("paracode0", None),
        ByteField("paralen0", None),
        XByteField("tpdusize", None),
        XByteField("paracode1", None),
        ByteField("paralen1", None),
        XShortField("srctsap", None),
        XByteField("paracode2", None),
        ByteField("paralen2", None),
        XShortField("dsttsap", None),
    ]



#bind_layers(TPTK, COTP, pdutype = 0xf0)
#bind_layers(TPTK, COTPConn, pdutype = 0xe0)
#bind_layers(TPTK, COTPConnResponse, pdutype = 0xd0)
