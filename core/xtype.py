#!/usr/bin/env python
# coding:utf-8

"""
Copyright (c) 2015-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""

import struct
from scapy.all import *


"""字符转换用全局变量"""
base = [str(x) for x in range(10)] + [
    chr(x) for x in range(ord('A'), ord('A') + 6)]


def binToDec(string_num):
    """将二进制转换为十进制"""
    return str(int(string_num, 2))


def hexToDec(string_num):
    """将十六进制转换为十进制"""
    return str(int(string_num.upper(), 16))

def decToBin(string_num):
    """将十进制转换为二进制"""
    num = int(string_num)
    mid = []
    bin_len = len(decToHex(num)) * 4    # 用于补全数据位
    while True:
        if num == 0:
            break
        num, rem = divmod(num, 2)
        mid.append(base[rem])
    while (len(mid) < bin_len):
        mid.append(0)
    return ''.join([str(x) for x in mid[::-1]])


def decToHex(string_num):
    """将十进制转换为十六进制"""
    num = int(string_num)
    mid = []
    while True:
        if num == 0:
            break
        num, rem = divmod(num, 16)
        mid.append(base[rem])
    return ''.join([str(x) for x in mid[::-1]])


def hexToBin(string_num):
    """将十六进制转换成二进制"""
    return decToBin(hexToDec(string_num.upper()))


def binToHex(string_num):
    """将二进制转换为十六进制"""
    return decToHex(binToDec(string_num))


def loadToFloat(my_load):
    """将load转换为浮点数"""
    try:
        return struct.unpack('>f', my_load)[0]
    except:
        return "Failure"


def floatToLoad(string_num):
    """将浮点转换为load"""
    try:
        return struct.pack('>f', string_num)
    except:
        return "Failure"


def listToStr(my_list):
    """将list转换为str"""
    try:
        return "".join(my_list)
    except:
        return "Failure"


def loadToHex(my_load):
    """将数据包load转换为16进制"""
    try:
        return my_load.encode('hex')
    except:
        return "Failure"


def hexToLoad(my_hex):
    """将16进制转换为数据包load"""
    try:
        return my_hex.decode('hex')
    except:
        return "Failure"


def packet_to_hex(packet):
    """用于将scapy_packet转换为16进制数据。

    Args：
        packet：需要转换的数据包
    """
    try:
        return str(packet)
    except:
        return False


def hex_to_packet(hex):
    """用于将16进制数据转换为scapy_packet。

    Args：
        hex：需要转换的16进制数据包
    """
    try:
        return Ether(packet)
    except:
        return False


def address_to_hex(address):
    """用于将IP地址转化为16进制字符串。

    Args：
        address：需要转换的IP地址
    """
    num = address.split('.')
    if not len(num) == 4:
        return False
    # Check each of the 4 numbers is between 0 and 255
    data = ''
    for n in num:
        data += struct.pack("!B", int(n)).encode('hex')
    return data

def hex_to_address(hex):
    """用于将16进制字符串转化为IP地址。

    Args：
        hex：需要转换的16进制字符串
    """
    data  = hexToDec(hex[0:2])
    data += '.' + hexToDec(hex[2:4])
    data += '.' + hexToDec(hex[4:6])
    data += '.' + hexToDec(hex[6:8])
    return data
