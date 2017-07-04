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
import ssl
from katnip.targets.tcp import TcpTarget


class SslTarget(TcpTarget):
    '''
    SslTarget is an implementation of SSL target,
    used for testing HTTPs etc.
    '''

    def __init__(self, name, host, port, timeout=None, logger=None):
        '''
        :param name: name of the target
        :param host: host ip (to send data to) currently unused
        :param port: port to send to
        :param timeout: socket timeout (default: None)
        :param logger: logger for the object (default: None)
        '''
        super(SslTarget, self).__init__(name, host, port, timeout, logger=None)

    def _get_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return ssl.wrap_socket(sock)
