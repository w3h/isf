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
"""Establish all what is needed to communicate with a PLC"""
import logging
import socket
import struct

from scapy import all as scapy_all

from cip import CIP, CIP_Path, CIP_ReqConnectionManager, \
    CIP_MultipleServicePacket, CIP_ReqForwardOpen, CIP_RespForwardOpen, \
    CIP_ReqForwardClose, CIP_ReqGetAttributeList, CIP_ReqReadOtherTag
from enip_tcp import ENIP_TCP, ENIP_SendUnitData, ENIP_SendUnitData_Item, \
    ENIP_ConnectionAddress, ENIP_ConnectionPacket, ENIP_RegisterSession, ENIP_SendRRData

# Global switch to make it easy to test without sending anything
NO_NETWORK = False

logger = logging.getLogger(__name__)


class PLCClient(object):
    """Handle all the state of an Ethernet/IP session with a PLC"""

    def __init__(self, plc_addr, plc_port=44818):
        if not NO_NETWORK:
            try:
                self.sock = socket.create_connection((plc_addr, plc_port))
            except socket.error as exc:
                logger.warn("socket error: %s", exc)
                logger.warn("Continuing without sending anything")
                self.sock = None
        else:
            self.sock = None
        self.session_id = 0
        self.enip_connid = 0
        self.sequence = 1

        # Open an Ethernet/IP session
        sessionpkt = ENIP_TCP() / ENIP_RegisterSession()
        if self.sock is not None:
            self.sock.send(str(sessionpkt))
            reply_pkt = self.recv_enippkt()
            self.session_id = reply_pkt.session

    @property
    def connected(self):
        return True if self.sock else False

    def send_rr_cip(self, cippkt):
        """Send a CIP packet over the TCP connection as an ENIP Req/Rep Data"""
        enippkt = ENIP_TCP(session=self.session_id)
        enippkt /= ENIP_SendRRData(items=[
            ENIP_SendUnitData_Item(type_id=0),
            ENIP_SendUnitData_Item() / cippkt
        ])
        if self.sock is not None:
            self.sock.send(str(enippkt))

    def send_rr_cm_cip(self, cippkt):
        """Encapsulate the CIP packet into a ConnectionManager packet"""
        cipcm_msg = [cippkt]
        cippkt = CIP(path=CIP_Path.make(class_id=6, instance_id=1))
        cippkt /= CIP_ReqConnectionManager(message=cipcm_msg)
        self.send_rr_cip(cippkt)

    def send_rr_mr_cip(self, cippkt):
        """Encapsulate the CIP packet into a MultipleServicePacket to MessageRouter"""
        cipcm_msg = [cippkt]
        cippkt = CIP(path=CIP_Path(wordsize=2, path=b'\x20\x02\x24\x01'))
        cippkt /= CIP_MultipleServicePacket(packets=cipcm_msg)
        self.send_rr_cip(cippkt)

    def send_unit_cip(self, cippkt):
        """Send a CIP packet over the TCP connection as an ENIP Unit Data"""
        enippkt = ENIP_TCP(session=self.session_id)
        enippkt /= ENIP_SendUnitData(items=[
            ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=self.enip_connid),
            ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=self.sequence) / cippkt
        ])
        self.sequence += 1
        if self.sock is not None:
            self.sock.send(str(enippkt))

    def send_crash_cip(self, cippkt):
        """Send a CIP packet over the TCP connection as an ENIP Unit Data"""
        enippkt = ENIP_TCP(session=self.session_id)
        enippkt /= ENIP_SendUnitData(items=[
            ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=self.enip_connid),
            ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=self.sequence) / cippkt
        ])
        self.sequence += 1
        if self.sock is not None:
            self.sock.send(str(enippkt) + 'A'*65535)

    def recv_enippkt(self):
        """Receive an ENIP packet from the TCP socket"""
        if self.sock is None:
            return
        pktbytes = self.sock.recv(2000)
        pkt = ENIP_TCP(pktbytes)
        return pkt

    def forward_open(self):
        """Send a forward open request"""
        cippkt = CIP(service=0x54, path=CIP_Path(wordsize=2, path=b'\x20\x06\x24\x01'))
        cippkt /= CIP_ReqForwardOpen(path_wordsize=2, path=b"\x20\x02\x24\x01")
        self.send_rr_cip(cippkt)
        resppkt = self.recv_enippkt()
        if self.sock is None:
            return
        cippkt = resppkt[CIP]
        if cippkt.status[0].status != 0:
            logger.error("Failed to Forward Open CIP connection: %r", cippkt.status[0])
            return False
        assert isinstance(cippkt.payload, CIP_RespForwardOpen)
        self.enip_connid = cippkt.payload.OT_network_connection_id
        return True

    def forward_close(self):
        """Send a forward close request"""
        cippkt = CIP(service=0x4e, path=CIP_Path(wordsize=2, path=b'\x20\x06\x24\x01'))
        cippkt /= CIP_ReqForwardClose(path_wordsize=3, path=b"\x01\x00\x20\x02\x24\x01")
        self.send_rr_cip(cippkt)
        if self.sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        if cippkt.status[0].status != 0:
            logger.error("Failed to Forward Close CIP connection: %r", cippkt.status[0])
            return False
        return True

    def get_attribute(self, class_id, instance, attr):
        """Get an attribute for the specified class/instance/attr path"""
        # Get_Attribute_Single does not seem to work properly
        # path = CIP_Path.make(class_id=class_id, instance_id=instance, attribute_id=attr)
        # cippkt = CIP(service=0x0e, path=path)  # Get_Attribute_Single
        path = CIP_Path.make(class_id=class_id, instance_id=instance)
        cippkt = CIP(path=path) / CIP_ReqGetAttributeList(attrs=[attr])
        self.send_rr_cm_cip(cippkt)
        if self.sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        if cippkt.status[0].status != 0:
            logger.error("CIP get attribute error: %r", cippkt.status[0])
            return
        resp_getattrlist = str(cippkt.payload)
        assert resp_getattrlist[:2] == b'\x01\x00'  # Attribute count must be 1
        assert struct.unpack('<H', resp_getattrlist[2:4])[0] == attr  # First attribute
        assert resp_getattrlist[4:6] == b'\x00\x00'  # Status
        return resp_getattrlist[6:]

    def set_attribute(self, class_id, instance, attr, value):
        """Set the value of attribute class/instance/attr"""
        path = CIP_Path.make(class_id=class_id, instance_id=instance)
        # User CIP service 4: Set_Attribute_List
        cippkt = CIP(service=4, path=path) / scapy_all.Raw(load=struct.pack('<HH', 1, attr) + value)
        self.send_rr_cm_cip(cippkt)
        if self.sock is None:
            return
        resppkt = self.recv_enippkt()
        cippkt = resppkt[CIP]
        if cippkt.status[0].status != 0:
            logger.error("CIP set attribute error: %r", cippkt.status[0])
            return False
        return True

    def get_list_of_instances(self, class_id):
        """Use CIP service 0x4b to get a list of instances of the specified class"""
        start_instance = 0
        inst_list = []
        while True:
            cippkt = CIP(service=0x4b, path=CIP_Path.make(class_id=class_id, instance_id=start_instance))
            self.send_rr_cm_cip(cippkt)
            if self.sock is None:
                return
            resppkt = self.recv_enippkt()

            # Decode a list of 32-bit integers
            data = str(resppkt[CIP].payload)
            for i in range(0, len(data), 4):
                inst_list.append(struct.unpack('<I', data[i:i + 4])[0])

            cipstatus = resppkt[CIP].status[0].status
            if cipstatus == 0:
                return inst_list
            elif cipstatus == 6:
                # Partial response, query again from the next instance
                start_instance = inst_list[-1] + 1
            else:
                logger.error("Error in Get Instance List response: %r", resppkt[CIP].status[0])
                return

    def read_full_tag(self, class_id, instance_id, total_size):
        """Read the content of a tag which can be quite big"""
        data_chunks = []
        offset = 0
        remaining_size = total_size

        while remaining_size > 0:
            cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=class_id, instance_id=instance_id))
            cippkt /= CIP_ReqReadOtherTag(start=offset, length=remaining_size)
            self.send_rr_cm_cip(cippkt)
            if self.sock is None:
                return
            resppkt = self.recv_enippkt()

            cipstatus = resppkt[CIP].status[0].status
            received_data = str(resppkt[CIP].payload)
            if cipstatus == 0:
                # Success
                assert len(received_data) == remaining_size
            elif cipstatus == 6 and len(received_data) > 0:
                # Partial response (size too big)
                pass
            else:
                logger.error("Error in Read Tag response: %r", resppkt[CIP].status[0])
                return

            # Remember the chunk and continue
            data_chunks.append(received_data)
            offset += len(received_data)
            remaining_size -= len(received_data)
        return b''.join(data_chunks)

    @staticmethod
    def attr_format(attrval):
        """Format an attribute value to be displayed to a human"""
        if len(attrval) == 1:
            # 1-byte integer
            return hex(struct.unpack('B', attrval)[0])
        elif len(attrval) == 2:
            # 2-byte integer
            return hex(struct.unpack('<H', attrval)[0])
        elif len(attrval) == 4:
            # 4-byte integer
            return hex(struct.unpack('<I', attrval)[0])
        elif all(x == b'\0' for x in attrval):
            # a series of zeros
            return '[{} zeros]'.format(len(attrval))
        # format in hexadecimal the content of attrval
        return ''.join('{:2x}'.format(ord(x)) for x in attrval)
