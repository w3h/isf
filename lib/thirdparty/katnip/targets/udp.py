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
from kitty.targets.server import ServerTarget


class UdpTarget(ServerTarget):
    '''
    UdpTarget is implementation of a UDP target
    '''

    def __init__(self, name, host, port, timeout=None, logger=None):
        '''
        :param name: name of the target
        :param host: host ip (to send data to) currently unused
        :param port: port to send to
        :param timeout: socket timeout (default: None)
        :param logger: logger for the object (default: None)
        '''
        super(UdpTarget, self).__init__(name, logger)
        self.host = host
        self.port = port
        if (host is None) or (port is None):
            raise ValueError('host and port may not be None')
        self.timeout = timeout
        self.socket = None
        self.bind_host = None
        self.bind_port = None
        self.expect_response = False

    def set_binding(self, host, port, expect_response=False):
        '''
        enable binding of socket to given ip/address
        '''
        self.bind_host = host
        self.bind_port = port
        self.expect_response = expect_response
        self._do_bind()

    def _do_bind(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.bind((self.bind_host, self.bind_port))

    def _prepare_socket(self):
        if self.bind_host is None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self._do_bind()

    def pre_test(self, test_num):
        super(UdpTarget, self).pre_test(test_num)
        if self.socket is None:
            self._prepare_socket()
            if self.timeout is not None:
                self.socket.settimeout(self.timeout)

    def post_test(self, test_num):
        super(UdpTarget, self).post_test(test_num)
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def _send_to_target(self, data):
        self.logger.debug('Sending data to host: %s:%d' % (self.host, self.port))
        self.socket.sendto(data, (self.host, self.port))

    def _receive_from_target(self):
        return self.socket.recvfrom(1024)
