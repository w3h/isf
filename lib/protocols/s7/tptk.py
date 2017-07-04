#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2014-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""


from scapy.all import *


class TPTK(Packet):
    name = "tptk"
    fields_desc = [
        ByteField("version", 3),
        ByteField("res", 0),
        ShortField("length", 4)
    ]

    def post_build(self, p, pay):
        if pay:
            l = struct.pack(">H", len(pay)+4)
            p = p[:2] + l + p[4:]
            return p + pay
        else:
            return p

bind_layers(TCP, TPTK, dport = 102)
