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
import time
import traceback
from kitty.targets import ServerTarget
from kitty.core import KittyException


class TcpTarget(ServerTarget):
    '''
    TcpTarget is implementation of a TCP target for the ServerFuzzer
    '''

    def __init__(self, name, host, port, max_retries=10, timeout=None, logger=None):
        '''
        :param name: name of the target
        :param host: host ip (to send data to) currently unused
        :param port: port to send to
        :param max_retries: maximum connection retries (default: 10)
        :param timeout: socket timeout (default: None)
        :param logger: logger for the object (default: None)
        '''
        super(TcpTarget, self).__init__(name, logger)
        self.host = host
        self.port = port
        if (host is None) or (port is None):
            raise ValueError('host and port may not be None')
        self.timeout = timeout
        self.socket = None
        self.max_retries = max_retries

    def pre_test(self, test_num):
        super(TcpTarget, self).pre_test(test_num)
        retry_count = 0
        while self.socket is None and retry_count < self.max_retries:
            sock = self._get_socket()
            if self.timeout is not None:
                sock.settimeout(self.timeout)
            try:
                retry_count += 1
                sock.connect((self.host, self.port))
                self.socket = sock
            except Exception:
                sock.close()
                self.logger.error('Error: %s' % traceback.format_exc())
                self.logger.error('Failed to connect to target server, retrying...')
                time.sleep(1)
        if self.socket is None:
            raise(KittyException('TCPTarget: (pre_test) cannot connect to server (retries = %d' % retry_count))

    def _get_socket(self):
        '''
        get a socket object
        '''
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def post_test(self, test_num):
        '''
        Called after a test is completed, perform cleanup etc.
        '''
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        super(TcpTarget, self).post_test(test_num)

    def _send_to_target(self, data):
        self.socket.send(data)

    def _receive_from_target(self):
        return self.socket.recv(10000)
