#! /usr/bin/env python
# coding:utf-8
from scapy.all import *
from .utils import *


class TPKT(Packet):
    name = "TPKT"
    fields_desc = [XByteField("Version", 0x03),
                   XByteField("Reserved", 0x00),
                   XShortField("Length", None)]

    def post_build(self, p, pay):
        if self.Length is None and pay:
            l = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p + pay

    def guess_payload_class(self, payload):
        if payload.encode('hex')[2:4] == 'e0':
            return COTP_CR_TPDU
        elif payload.encode('hex')[2:4] == 'd0':
            return COTP_CC_TPDU
        elif payload.encode('hex')[2:4] == 'f0':
            return COTP_DT_TPDU
        else:
            return None

class COTP_OPTION_Field(Packet):
    name = "COTP_OPTION_Field"
    fields_desc = [
        ByteEnumField(
            "ParameterCode", 0xc0, {0xc0: "tpdu-size", 0xc1: "src-tsap", 0xc2: "dst-tsap"}),
        FieldLenField("ParameterLength", None, fmt="B",
                      length_of="Parameter", adjust=lambda pkt, x: (x + 1) / 2),
        StrLenField
        ("Parameter", None, length_from=lambda p: p.ParameterLength)]

    def extract_padding(self, p):
        return "", p

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            if self.Parameter is None:
                l = 0
            else:
                l = len(self.Parameter)
            p = p[:1] + struct.pack("!B", l) + p[2:]
        return p + pay


class COTP_CR_TPDU(Packet):
    name = "COTP_CR_TPDU"
    fields_desc = [XByteField("COTPLength", None),
                   ByteEnumField(
                       "PDUType", 0xe0, {0xe0: "CR", 0xd0: "CC"}),
                   XShortField("Dref", 0x0000),
                   XShortField("Sref", 0x0012),
                   # XShortField("Sref", 0x01a1),
                   XByteField("ClassOption", 0x00),
                   PacketListField(
                       "Parameters", [], COTP_OPTION_Field, length_from=lambda p:p.COTPLength - 6)
                   ]

    def post_build(self, p, pay):
        if self.COTPLength is None:
            l = len(p) + len(pay) - 1
            p = struct.pack("!B", l) + p[1:]
        return p + pay


class COTP_CC_TPDU(Packet):
    name = "COTP_CC_TPDU"
    fields_desc = [XByteField("COTPLength", None),
                   ByteEnumField(
                       "PDUType", 0xd0, {0xe0: "CR", 0xd0: "CC"}),
                   XShortField("Dref", 0x0000),
                   XShortField("Sref", 0x0012),
                   # XShortField("Sref", 0x01a1),
                   XByteField("ClassOption", 0x00),
                   PacketListField(
                       "Parameters", [], COTP_OPTION_Field, length_from=lambda p:p.COTPLength - 6)
                   ]

    def post_build(self, p, pay):
        if self.COTPLength is None:
            l = len(p) + len(pay) - 1
            p = struct.pack("!B", l) + p[1:]
        return p + pay


class COTP_DT_TPDU(Packet):
    name = "COTP_DT_TPDU"
    fields_desc = [XByteField("COTPLength", None),
                   ByteEnumField("PDUType", 0xf0, {0xf0: "DT"}),
                   FlagsField("EOT", 0, 1, ["End", "Not end"]),
                   BitField("TPDUNR", 0, 7)
                   ]

    def post_build(self, p, pay):
        if self.COTPLength is None:
            l = len(p) - 1
            p = struct.pack("!B", l) + p[1:]
        return p + pay

    def guess_payload_class(self, payload):
        # print payload.encode('hex')
        if payload.encode('hex')[:2] == '32':
            if payload.encode('hex')[2:4] == '01':  # ROSCTR: Job (1)
                # Function: Setup communication (0xf0)
                if payload.encode('hex')[20:22] == 'f0':
                    return S7_SetCon_TPDU_Req
                # Function: Read Var (0x04)
                if payload.encode('hex')[20:22] == '04':
                    return S7_ReadVar_TPDU
                # Function: Write Var (0x05)
                if payload.encode('hex')[20:22] == '05':
                    return S7_WriteVar_TPDU
                # Function: Start upload (0x1d)
                if payload.encode('hex')[20:22] == '1d':
                    return S7_RequestUploadBlock_TPDU_Req
                # Function: Upload (0x1e)
                if payload.encode('hex')[20:22] == '1e':
                    return S7_UploadBlock_TPDU_Req
                # Function: End upload (0x1f)
                if payload.encode('hex')[20:22] == '1f':
                    return S7_UploadBlockEnd_TPDU_Req

            if payload.encode('hex')[2:4] == '03':  # ROSCTR: Ack_Data (3)
                # Function: Read Var (0x04)
                if payload.encode('hex')[24:26] == '04':
                    return S7_ReadVar_Response_TPDU
                # Function: Write Var (0x05)
                if payload.encode('hex')[24:26] == '05':
                    return S7_WriteVar_TPDU
                # Function: Start upload (0x1d)
                if payload.encode('hex')[20:22] == '1d':
                    return S7_RequestUploadBlock_TPDU_Rsp
                # Function: Upload (0x1e)
                if payload.encode('hex')[20:22] == '1e':
                    return S7_UploadBlock_TPDU_Rsp
                # Function: End upload (0x1f)
                if payload.encode('hex')[20:22] == '1f':
                    return S7_UploadBlockEnd_TPDU_Rsp

            if payload.encode('hex')[2:4] == '07':  # ROSCTR: Userdata (7)
                if payload.encode('hex')[20:26] == '000112':
                    # Subfunction: Read SZL (1)
                    if payload.encode('hex')[30:34] == '4401':
                        return S7_ReadSZL_TPDU
                    if payload.encode('hex')[30:34] == '8401':
                        return S7_ReadSZL_Response_TPDU
                    # Subfunction: List Block (1)
                    if payload.encode('hex')[30:34] == '4301':
                        return S7_ListBlock_TPDU_Req
                    if payload.encode('hex')[30:34] == '8301':
                        return S7_ListBlock_TPDU_Rsp
                    if payload.encode('hex')[30:34] == '4302':
                        return S7_ListBlock_of_Type_TPDU_Req
                    if payload.encode('hex')[30:34] == '8302':
                        return S7_ListBlock_of_Type_TPDU_Rsp
                    if payload.encode('hex')[30:34] == '4303':
                        return S7_GetBlock_Info_TPDU_Req
                    if payload.encode('hex')[30:34] == '8303':
                        return S7_GetBlock_Info_TPDU_Rsp
        else:
            return None

###########SetCon#####################


class S7_SetCon_Parameter_TPDU(Packet):
    name = "S7_SetCon_Parameter_TPDU"
    fields_desc = [XByteField("Function", 0xf0),
                   XByteField("Reserved", 0x00),
                   XShortField("MaxAmQcalling", 0x0001),
                   XShortField("MaxAmQcalled", 0x0001),
                   XShortField("PDULength", 0x01e0)
                   ]


class S7_SetCon_TPDU_Req(Packet):
    name = "S7_SetCon_TPDU_Req"
    fields_desc = [XByteField("ProtocolId", 0x32),
                   ByteEnumField(
                       "ROSCTR", 0x01, {0x01: "JOB", 0x03: "Ack_Data", 0x07: "Userdata"}),
                   XShortField("RedundancyId", 0x0000),
                   LEShortField("PDUR", 0x0000),
                   XShortField("ParameterLength", None),
                   XShortField("DataLength", 0x0000),
                   PacketField("Parameters", None, S7_SetCon_Parameter_TPDU)
                   ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l1 = len(str(self.Parameters))
            p = p[:6] + struct.pack("!H", l1) + p[8:]
        return p + pay


class S7_SetCon_TPDU_Rsp(Packet):
    name = "S7_SetCon_TPDU_Rsp"
    fields_desc = [XByteField("ProtocolId", 0x32),
                   ByteEnumField(
                       "ROSCTR", 0x03, {0x01: "JOB", 0x03: "Ack_Data", 0x07: "Userdata"}),
                   XShortField("RedundancyId", 0x0000),
                   LEShortField("PDUR", 0x0000),
                   XShortField("ParameterLength", None),
                   XShortField("DataLength", 0x0000),
                   ByteEnumField(
        "ErrorClass", 0x00, {0x01: "No Error"}),
        XByteField("ErrorCode", 0x00),
        PacketField("Parameters", None, S7_SetCon_Parameter_TPDU)
    ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l1 = len(str(self.Parameters))
            p = p[:6] + struct.pack("!H", l1) + p[8:]
        return p + pay


###########Read-SZL-request################
class S7_ReadSZL_Parameter_TPDU(Packet):
    name = "S7_ReadSZL_Parameter_TPDU"
    fields_desc = [X3BytesField("Parameterhead", 0x000112),
                   XByteField("ParameterLength", None),
                   XByteField("Code", 0x11),
                   BitField("Type", 4, 4),
                   BitField("FunctionGroup", 4, 4),
                   ByteEnumField("Subfunction", 0x01, {0x01: "Read SZL"}),
                   XByteField("seq", 0x00)
                   ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l = len(p) - 4
            p = p[:3] + struct.pack("!B", l) + p[4:]
        return p + pay


class S7_ReadSZL_Data_TPDU(Packet):
    name = "S7_ReadSZL_Data_TPDU"
    fields_desc = [XByteField("ReturnCode", 0xff),
                   XByteField("TransportSize", 0x09),
                   XShortField("Length", None),
                   XShortField("SZLID", 0x001c),
                   XShortField("SZLINDEX", 0x0000)
                   ]

    def post_build(self, p, pay):
        if self.Length is None:
            l = len(p) - 4
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p + pay


class S7_ReadSZL_TPDU(Packet):
    name = "S7_ReadSZL_TPDU"
    fields_desc = [XByteField("ProtocolId", 0x32),
                   ByteEnumField(
                       "ROSCTR", 0x07, {0x01: "JOB", 0x03: "Ack_Data", 0x07: "Userdata"}),
                   XShortField("RedundancyId", 0x0000),
                   LEShortField("PDUR", 0x0100),
                   XShortField("ParameterLength", None),
                   XShortField("DataLength", None),
                   PacketLenField(
                       "Parameters", None, S7_ReadSZL_Parameter_TPDU, length_from=lambda x: x.ParameterLength),
                   PacketField("Data", None, S7_ReadSZL_Data_TPDU)
                   ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l1 = len(str(self.Parameters))
            p = p[:6] + struct.pack("!H", l1) + p[8:]
        if self.DataLength is None:
            l2 = len(str(self.Data))
            p = p[:8] + struct.pack("!H", l2) + p[10:]
        return p + pay


###########Read-SZL-Response################

class S7_ReadSZL_Parameter_Response_TPDU(Packet):
    name = "S7_ReadSZL_Parameter_Response_TPDU"
    fields_desc = [X3BytesField("Parameterhead", 0x000112),
                   XByteField("ParameterLength", None),
                   XByteField("Code", 0x11),
                   BitField("Type", 8, 4),
                   BitField("FunctionGroup", 4, 4),
                   ByteEnumField("Subfunction", 0x01, {0x01: "Read SZL"}),
                   XByteField("seq", 0x00),
                   XByteField("DURN", 0x00),
                   XByteField("LastUnit", 0x00),
                   XShortEnumField("ErrorCode", 0x0000, {0x0000: "No Error"})
                   ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l = len(p) - 4
            p = p[:3] + struct.pack("!B", l) + p[4:]
        return p + pay


class S7_ReadSZL_Data_Tree_TPDU(Packet):
    name = "S7_ReadSZL_Data_Tree_TPDU"
    fields_desc = [
        # XShortField("Index", 0x0001),
        StrField("Data", "\x00", fmt="H")
        # StrFixedLenField("Data", "\x00",10)
        # StrLenField("Data", "\x00", length_from=20)
    ]

    def extract_padding(self, p):
        return "", p


class S7_ReadSZL_Data_Response_TPDU(Packet):
    name = "S7_ReadSZL_Data_Response_TPDU"
    fields_desc = [XByteField("ReturnCode", 0xff),
                   XByteField("TransportSize", 0x09),
                   XShortField("Length", None),
                   XShortField("SZLID", 0x001c),
                   XShortField("SZLINDEX", 0x0000),
                   #    XShortField("SZLLength", 0x0028),
                   FieldLenField(
        "SZLLength", None, length_of="SZLDataTree", fmt="H", adjust=lambda pkt, x:x),
        FieldLenField(
                       "SZLListCount", None, count_of="SZLDataTree", fmt="H", adjust=lambda pkt, x:x),
        PacketListField(
                       "SZLDataTree", [], S7_ReadSZL_Data_Tree_TPDU, length_from=lambda x: x.SZLLength * x.SZLListCount)
    ]

    def post_build(self, p, pay):
        if self.Length is None:
            l = len(p) - 4
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p + pay


class S7_ReadSZL_Response_TPDU(Packet):
    name = "S7_ReadSZL_Response_TPDU"
    fields_desc = [XByteField("ProtocolId", 0x32),
                   ByteEnumField(
                       "ROSCTR", 0x07, {0x01: "JOB", 0x03: "Ack_Data", 0x07: "Userdata"}),
                   XShortField("RedundancyId", 0x0000),
                   LEShortField("PDUR", 0x0100),
                   XShortField("ParameterLength", None),
                   XShortField("DataLength", None),
                   PacketLenField(
                       "Parameters", None, S7_ReadSZL_Parameter_Response_TPDU, length_from=lambda x: x.ParameterLength),
                   PacketField("Data", None, S7_ReadSZL_Data_Response_TPDU)
                   ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l1 = len(str(self.Parameters))
            p = p[:6] + struct.pack("!H", l1) + p[8:]
        if self.DataLength is None:
            l2 = len(str(self.Data))
            p = p[:8] + struct.pack("!H", l2) + p[10:]
        return p + pay


###########Create-connect-start###########
def create_s7_connect(connection, src_tsap, dst_tsap, pdur):
    # COTP_CR
    packet1 = TPKT() / COTP_CR_TPDU()
    packet1.Parameters = [
        COTP_OPTION_Field(), COTP_OPTION_Field(), COTP_OPTION_Field()]
    packet1.PDUType = "CR"
    packet1.Parameters[0].ParameterCode = "tpdu-size"
    packet1.Parameters[0].Parameter = "0a".decode('hex')
    packet1.Parameters[1].ParameterCode = "src-tsap"
    packet1.Parameters[2].ParameterCode = "dst-tsap"
    packet1.Parameters[1].Parameter = src_tsap.decode('hex')
    packet1.Parameters[2].Parameter = dst_tsap.decode('hex')
    connection.sr1(packet1)
    # SetupComm
    packet2 = TPKT() / COTP_DT_TPDU(EOT=1) / S7_SetCon_TPDU_Req(Parameters=S7_SetCon_Parameter_TPDU())
    packet2.PDUR = pdur
    connection.sr1(packet2,)
    return pdur




def get_cpu_protect_level(connection, pdur):
    packet1 = TPKT() / COTP_DT_TPDU(EOT=1) / S7_ReadSZL_TPDU(Parameters=S7_ReadSZL_Parameter_TPDU(), Data=S7_ReadSZL_Data_TPDU())
    packet1[S7_ReadSZL_Data_TPDU].SZLID = 0x0232
    packet1[S7_ReadSZL_Data_TPDU].SZLINDEX = 0x0004
    rsp = connection.sr1(packet1)
    cpu_protect_level = int(str(rsp)[48].encode('hex'))
    return cpu_protect_level, pdur
