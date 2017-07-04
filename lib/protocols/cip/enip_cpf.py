#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 David I. Urbina, david.urbina@utdallas.edu
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Ethernet/IP Common Packet Format Scapy dissector."""
import struct

from scapy import all as scapy_all

import utils


class CPF_SequencedAddressItem(scapy_all.Packet):
    name = "CPF_SequencedAddressItem"
    fields_desc = [
        scapy_all.LEIntField("connection_id", 0),
        scapy_all.LEIntField("sequence_number", 0),
    ]


class CPF_AddressDataItem(scapy_all.Packet):
    name = "CPF_AddressDataItem"
    fields_desc = [
        scapy_all.LEShortEnumField('type_id', 0, {
            0x0000: "Null Address",
            0x00a1: "Connection-based Address",
            0x00b1: "Connected Transport Packet",
            0x00b2: "Unconnected Message",
            0x0100: "ListServices response",
            0x8002: 'Sequenced Address Item',
        }),
        scapy_all.LEShortField("length", None),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay


class ENIP_CPF(scapy_all.Packet):
    name = "ENIP_CPF"
    fields_desc = [
        utils.LEShortLenField("count", 2, count_of="items"),
        scapy_all.PacketListField("items", [CPF_AddressDataItem('', 0, 0), CPF_AddressDataItem('', 0, 0)],
                                  CPF_AddressDataItem, count_from=lambda p: p.count),
    ]

    def extract_padding(self, p):
        return '', p


scapy_all.bind_layers(CPF_AddressDataItem, CPF_SequencedAddressItem, type_id=0x8002)
