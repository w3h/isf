#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Nicolas Iooss, SUTD
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
"""Ethernet/IP over UDP scapy dissector

This dissector only supports a "keep-alive" kind of packet which has been seen
in SUTD's secure water treatment testbed.
"""
import struct

from scapy import all as scapy_all

import utils

# Keep-alive sequences
ENIP_UDP_KEEPALIVE = (
    b'\x01\x00\xff\xff\xff\xff' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00' +
    b'\xff\xff\xff\xff\x00\x00\x00\x00')


class ENIP_UDP_SequencedAddress(scapy_all.Packet):
    name = "ENIP_UDP_SequencedAddress"
    fields_desc = [
        scapy_all.LEIntField("connection_id", 0),
        scapy_all.LEIntField("sequence", 0),
    ]


class ENIP_UDP_Item(scapy_all.Packet):
    name = "ENIP_UDP_Item"
    fields_desc = [
        scapy_all.LEShortEnumField("type_id", 0, {
            0x00b1: "Connected_Data_Item",
            0x8002: "Sequenced_Address",
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


class ENIP_UDP(scapy_all.Packet):
    """Ethernet/IP packet over UDP"""
    name = "ENIP_UDP"
    fields_desc = [
        utils.LEShortLenField("count", None, count_of="items"),
        scapy_all.PacketListField("items", [], ENIP_UDP_Item,
                                  count_from=lambda p: p.count),
    ]

    def extract_padding(self, p):
        return "", p


scapy_all.bind_layers(scapy_all.UDP, ENIP_UDP, sport=2222, dport=2222)
scapy_all.bind_layers(ENIP_UDP_Item, ENIP_UDP_SequencedAddress, type_id=0x8002)

if __name__ == '__main__':
    # Test building/dissecting packets
    # Build a keep-alive packet
    pkt = scapy_all.Ether(src='00:1d:9c:c8:13:37', dst='01:00:5e:40:12:34')
    pkt /= scapy_all.IP(src='192.168.1.42', dst='239.192.18.52')
    pkt /= scapy_all.UDP(sport=2222, dport=2222)
    pkt /= ENIP_UDP(items=[
        ENIP_UDP_Item() / ENIP_UDP_SequencedAddress(connection_id=1337, sequence=42),
        ENIP_UDP_Item(type_id=0x00b1) / scapy_all.Raw(load=ENIP_UDP_KEEPALIVE),
    ])

    # Build!
    data = str(pkt)
    pkt = scapy_all.Ether(data)
    pkt.show()

    # Test the value of some fields
    assert pkt[ENIP_UDP].count == 2
    assert pkt[ENIP_UDP].items[0].type_id == 0x8002
    assert pkt[ENIP_UDP].items[0].length == 8
    assert pkt[ENIP_UDP].items[0].payload == pkt[ENIP_UDP_SequencedAddress]
    assert pkt[ENIP_UDP_SequencedAddress].connection_id == 1337
    assert pkt[ENIP_UDP_SequencedAddress].sequence == 42
    assert pkt[ENIP_UDP].items[1].type_id == 0x00b1
    assert pkt[ENIP_UDP].items[1].length == 38
    assert pkt[ENIP_UDP].items[1].payload.load == ENIP_UDP_KEEPALIVE
