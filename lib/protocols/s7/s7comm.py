#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2014-2016 By W.HHH. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""


import struct
from scapy.all import *
from cotp import *


FUNC_TYPE  = {
    0x00: "CPU Services",
    0xF0: "Setup Communication",
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PLC Control",
    0x29: "PLC Stop",
}

class S7Comm_Header(Packet):
    name = "S7Comm_Header"
    fields_desc = [
        XByteField("proid", 0x32),
        ByteField("rosctr", 1),
        XShortField("res", 0x0000),
        ShortField("dataunitrefer", 512),
        ShortField("paralen", 0),
        ShortField("datalen", 0),
        ConditionalField(XByteField("errclass", 0),
            lambda pkt: True if pkt[S7Comm_Header].rosctr == 3 else False),
        ConditionalField(XByteField("errcode", 0),
            lambda pkt: True if pkt[S7Comm_Header].rosctr == 3 else False),
    ]

class S7Comm_Para(Packet):
    name = "S7Comm_Para"
    fields_desc = [
        ByteEnumField("function", 0xF0, FUNC_TYPE),
    ]

class S7Comm_Para_SetupComm(S7Comm_Para):
    name = "S7Comm_Para_SetupComm"
    fields_desc = [
        ByteEnumField("function", 0xF0, FUNC_TYPE),
        ByteField("res", 0),
        XShortField("callingamq", 0x1),
        XShortField("calledamq", 0x1),
        ShortField("pdulen", 480),
    ]

class S7Comm_Para_StopCpu(S7Comm_Para):
    name = "S7Comm_Para_StopCpu"
    fields_desc = [
        ByteEnumField("function", 0x29, FUNC_TYPE),
        StrField("unknown", "\0"*4),
        XShortField("length", 0x09),
        StrField("pi", "P_PROGRAM"),
    ]

class S7Comm_Para_HotReboot(S7Comm_Para):
    name = "S7Comm_Para_HotReboot"
    fields_desc = [
        ByteEnumField("function", 0x28, FUNC_TYPE),
        StrField("unknown", "\x00\x00\x00\x00\x00\x00\xfd"),
        ShortField("length1", 0),
        XByteField("length2", 0x09),
        StrField("pi", "P_PROGRAM"),
    ]

class S7Comm_Para_ColdReboot(S7Comm_Para):
    name = "S7Comm_Para_ColdReboot"
    fields_desc = [
        ByteEnumField("function", 0x28, FUNC_TYPE),
        StrField("unknown", "\x00\x00\x00\x00\x00\x00\xfd"),
        ShortField("length1", 2),
        StrField("Argument", '\x43\x20'),
        XByteField("length2", 0x09),
        StrField("pi", "P_PROGRAM"),
    ]

class S7Comm_Para_StartUpload(S7Comm_Para):
    name = "S7Comm_Para_StartUpload"
    fields_desc = [
        ByteEnumField("function", 0x1d, FUNC_TYPE),
        ByteField('unknown1', 0),
        XShortField('errorcode', 0x0000),
        StrField("unknown2", "\x00\x00\x00\x00"),
        ByteField("length1", 9),
        StrField("fileidentifier", '_'),
        StrField('unknown3', '0'),
        ByteField("blocktype", 66),
        StrField("blocknumber", '00001'),
        StrField("desfilesystem", 'A'),
    ]

class S7Comm_Para_Upload(S7Comm_Para):
    name = "S7Comm_Para_Upload"
    fields_desc = [
        ByteEnumField("function", 0x1e, FUNC_TYPE),
        ByteField('unknown1', 0),
        XShortField('errorcode', 0x0000),
        StrField("unknown2", "\x00\x00\x00\x00"),
    ]

class S7Comm_Para_EndUpload(S7Comm_Para):
    name = "S7Comm_Para_EndUpload"
    fields_desc = [
        ByteEnumField("function", 0x1f, FUNC_TYPE),
        ByteField('unknown1', 0),
        XShortField('errorcode', 0x0000),
        StrField("unknown2", "\x00\x00\x00\x00"),
    ]


class S7Comm_Para_RequestDownload(S7Comm_Para):
    name = "S7Comm_Para_RequestDownload"
    fields_desc = [
        ByteEnumField("function", 0x1a, FUNC_TYPE),
        ByteField('unknown1', 0),
        XShortField('errorcode', 0x0100),
        StrField("unknown2", "\x00\x00\x00\x00"),
        ByteField("length1", 9),
        StrField("file_identifer", "_"),
        StrField("unknown3", "0"),
        ByteField('block_type', 56),
        StrField('block_number', '00001'),
        StrField('destination_filesystem', 'P'),
        ByteField("length2", 13),
        StrField("unknown4", "1"),
        StrField("length_memory", "000132"),
        StrField("length_mc7", "000022"),
    ]

class S7Comm_Para_StartDownload(S7Comm_Para):
    name = "S7Comm_Para_StartDownload"
    fields_desc = [
        ByteEnumField("function", 0x1b, FUNC_TYPE),
        ByteField('unknown1', 0),
        XShortField('errorcode', 0x0000),
        StrField("unknown2", "\x00\x00\x00\x00"),
        ByteField("length1", 9),
        StrField("file_identifer", "_"),
        StrField("unknown3", "0"),
        ByteField('block_type', 56),
        StrField('block_number', '00001'),
        StrField('destination_filesystem', 'P'),
    ]

class S7Comm_Data(Packet):
    name = "S7Comm_Data"
    fields_desc = [
        StrField('data', ''),
    ]

class S7Comm_Para_Download(S7Comm_Para):
    name = "S7Comm_Para_Download"
    fields_desc = [
        ByteEnumField("function", 0x1b, FUNC_TYPE),
        ByteField('unknown1', 0),
    ]

class S7Comm_Para_EndDownload(S7Comm_Para):
    name = "S7Comm_Para_StartDownload"
    fields_desc = [
        ByteEnumField("function", 0x1c, FUNC_TYPE),
        ByteField('unknown1', 0),
        XShortField('errorcode', 0x0000),
        StrField("unknown2", "\x00\x00\x00\x00"),
        ByteField("length1", 9),
        StrField("file_identifer", "_"),
        StrField("unknown3", "0"),
        ByteField('block_type', 56),
        StrField('block_number', '00001'),
        StrField('destination_filesystem', 'P'),
    ]

class S7Comm(Packet):
    name = "S7Comm"
    fields_desc = [
        PacketField("header", None, None),
        PacketField("parameter", None, None),
        PacketField("data", None, None),
    ]

    def post_build(self, pkt, pay):
        if len(self.fields_desc) == 2:
            l = struct.pack(">H", len(self.fields_desc[1].default))
            pkt = pkt[:6] + l + pkt[8:]
            return pkt + pay
        elif len(self.fields_desc) == 3:
            l = struct.pack(">H", len(self.fields_desc[1].default))
            d = struct.pack(">H", len(self.fields_desc[2].default))
            pkt = pkt[:6] + l + d + pkt[10:]
            return pkt + pay
        else:
            return pkt + pay


class S7Comm_SetupComm(S7Comm):
    name = "S7Comm_SetupComm"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_SetupComm(), S7Comm_Para_SetupComm),
    ]

class S7Comm_HotReboot(S7Comm):
    name = "S7Comm_HotReboot"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_HotReboot(), S7Comm_Para_HotReboot),
    ]

class S7Comm_ColdReboot(S7Comm):
    name = "S7Comm_ColdReboot"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_ColdReboot(), S7Comm_Para_ColdReboot),
    ]

class S7Comm_StopCpu(S7Comm):
    name = "S7Comm_StopCpu"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_StopCpu(), S7Comm_Para_StopCpu),
    ]

class S7Comm_StartUpload(S7Comm):
    name = "S7Comm_Cpu"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_StartUpload(), S7Comm_Para_StartUpload),
    ]

class S7Comm_Upload(S7Comm):
    name = "S7Comm_Cpu"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_Upload(), S7Comm_Para_Upload),
    ]

class S7Comm_Upload_Response(S7Comm):
    name = "S7Comm_Upload_Response"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_Upload(), S7Comm_Para_Upload),
        PacketField("data", S7Comm_Data(), S7Comm_Data),
    ]

class S7Comm_EndUpload(S7Comm):
    name = "S7Comm_EndUpload"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_EndUpload(), S7Comm_Para_EndUpload),
    ]


class S7Comm_RequestDownload(S7Comm):
    name = "S7Comm_RequestDownload"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_RequestDownload(), S7Comm_Para_RequestDownload),
    ]

class S7Comm_StartDownload(S7Comm):
    name = "S7Comm_RequestDownload"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_StartDownload(), S7Comm_Para_StartDownload),
    ]

class S7Comm_Download(S7Comm):
    name = "S7Comm_Download"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para_Download(), S7Comm_Para_Download),
        PacketField("data", S7Comm_Data(), S7Comm_Data),
    ]

class S7Comm_EndDownload(S7Comm):
    name = "S7Comm_EndDownload"
    fields_desc = [
        PacketField("header", S7Comm_Header(), S7Comm_Header),
        PacketField("parameter", S7Comm_Para(function=0x1c), S7Comm_Para),
    ]


bind_layers(TPTK, S7Comm_SetupComm)
