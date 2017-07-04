#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2014-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""

import struct
from scapy.all import *


class DotHexField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")

    def id2str(self, id):
        return "".join(map(lambda x: struct.pack("B", int(x)), id.split(".")))

    def str2id(self, s):
        return ("%d."*6)[:-1] % tuple(map(ord, s))

    def i2m(self, pkt, x):
        if x is None:
            return "\0" * 6
        return self.id2str(x)

    def m2i(self, pkt, x):
        return self.str2id(x)

    def any2i(self, pkt, x):
        if type(x) is str and len(x) is 6:
            x = self.m2i(pkt, x)
        return x

    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        return x


'''
class DotHexField(StrFixedLenField):
    def __init__(self, name, default):
        default = [struct.pack('B', int(i)) for i in default.split('.')]
        length = len(default)
        default = ''.join(default)
        StrFixedLenField.__init__(self, name, default, length)

    def i2repr(self, pkt, v):
        if type(v) is str:
            v = [str(ord(i)) for i in v]
            v = '.'.join(v)
        return repr(v)
'''

class TwinCATVersionField(StrFixedLenField):
    def __init__(self, name, default):
        dotlist = default.split('.')
        default = struct.pack('B', int(dotlist[0]))
        default += struct.pack('B', int(dotlist[0]))
        default += struct.pack('i', int(dotlist[2]))
        StrFixedLenField.__init__(self, name, default, 4)

    def i2repr(self, pkt, v):
        if type(v) is str:
            t = str(ord(v[0])) + '.' + str(ord(v[1])) + '.'
            t += str(int((v[3]+v[2]).encode('hex'), 16))
            return repr(t)
