# Copyright (C) 2016 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# This file is part of Katnip.
#
# Katnip is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Katnip is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Katnip.  If not, see <http://www.gnu.org/licenses/>.

import socket
from scapy.all import Ether, IP, UDP, Raw
from udp import UdpTarget


class RawUdpTarget(UdpTarget):
    '''
    RawUdpTarget is implementation of a UDP target using a raw socket
    '''

    def __init__(self, name, interface, host, port, timeout=None, logger=None):
        '''
        :param name: name of the target
        :param interface: interface name
        :param host: host ip (to send data to) currently unused
        :param port: port to send to
        :param timeout: socket timeout (default: None)
        :param logger: logger for the object (default: None)
        '''
        super(RawUdpTarget, self).__init__(name, host, port, timeout, logger)
        self._interface = interface

    def _prepare_socket(self):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket.bind((self._interface, 0))

    def _send_to_target(self, data):
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        ip = IP(src=self.host, dst='255.255.255.255')
        udp = UDP(sport=68, dport=self.port)
        payload = Raw(load=data)
        packet = str(ether / ip / udp / payload)
        self.logger.debug('Sending header+data to host: %s:%d' % (self.host, self.port))
        self.socket.send(packet)
        self.logger.debug('Header+data sent to host')

    def _receive_from_target(self):
        return self.socket.recvfrom(1024)
