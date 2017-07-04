#!/usr/bin/env python
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
"""Useful routines and utilities which simplify code writing"""
from scapy import all as scapy_all


def hexdump(data, columns=16, indentlvl=""):
    """Return the hexadecimal representation of the data"""

    def do_line(line):
        return (
            indentlvl +
            " ".join("{:02x}".format(ord(b)) for b in line) +
            "   " * (columns - len(line)) +
            "  " +
            "".join(b if 32 <= ord(b) < 127 else "." for b in line))

    return "\n".join(do_line(data[i:i + columns]) for i in range(0, len(data), columns))


class LEShortLenField(scapy_all.FieldLenField):
    """A len field in a 2-byte integer"""

    def __init__(self, name, default, count_of=None, length_of=None):
        scapy_all.FieldLenField.__init__(self, name, default, fmt="<H",
                                         count_of=count_of, length_of=length_of)


class XBitEnumField(scapy_all.BitEnumField):
    """A BitEnumField with hexadecimal representation"""

    def __init__(self, name, default, size, enum):
        scapy_all.BitEnumField.__init__(self, name, default, size, enum)

    def i2repr_one(self, pkt, x):
        if x in self.i2s:
            return self.i2s[x]
        return scapy_all.lhex(x)
