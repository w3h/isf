# Copyright (C) 2016 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# This file is part of Kitty.
#
# Kitty is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Kitty is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Kitty.  If not, see <http://www.gnu.org/licenses/>.
'''
.. warning:: This module is not tested yet.
'''
from __future__ import absolute_import
import serial
from kitty.core import KittyException
from kitty.targets.server import ServerTarget


class SerialTarget(ServerTarget):
    '''
    Fuzzing over serial (uart) line.

    You can tell the target whether to reconnect each test ('pre_test'),
    or only at the beginning of the entire fuzzing session ('setup'),
    by specifying the matching string as the open_at parameter to ``__init__``
    '''

    def __init__(self, name, device, baudrate=115200, timeout=0.5,
                 open_at='setup', logger=None, expect_response=False):
        '''
        :param name: name of the target
        :param device: serial device name/path
        :param baudrate: baud rate of the serial channel (default: 115200)
        :param timeout: receive timeout on the channel in seconds (default: 0.5)
        :type open_at: str
        :param open_at:
            at what stage should the port be opened.
            Either 'setup' or 'pre_test' (default: 'setup')
        :param logger: logger for this object (default: None)
        :param expect_response:
            should wait for response from the victim (default: False)

        :examples:

            >>> SerialTarget('SomeTarget', '/dev/ttyUSB0', 57600)
            >>> SerialTarget('ToTarget', '/dev/ttyUSB0', timeout=5)
        '''
        super(SerialTarget, self).__init__(name, logger, expect_response)
        self.device = device
        self.baudrate = baudrate
        self.timeout = timeout
        self.open_at = open_at
        if self.open_at not in ['setup', 'pre_test']:
            raise KittyException('open_at must be either "setup" or "pre_test"')

    def _send_to_target(self, payload):
        self.serial.write(payload)

    def _receive_from_target(self):
        return self.serial.read(10000)

    def setup(self):
        super(SerialTarget, self).setup()
        self._conn_open('setup')

    def teardown(self):
        self._conn_close('setup')
        super(SerialTarget, self).teardown()

    def pre_test(self, test_num):
        '''
        Called before each test

        :param test_num: the test number
        '''
        self._conn_open('pre_test')
        super(SerialTarget, self).pre_test(test_num)

    def post_test(self, test_num):
        '''
        Called after each test

        :param test_num: the test number
        '''
        self._conn_close('pre_test')
        super(SerialTarget, self).post_test(test_num)

    def _conn_open(self, stage):
        if self.open_at == stage:
            self._conn_close(stage)
            self.serial = serial.Serial(self.device, self.baudrate)
            self.serial.timeout = self.timeout

    def _conn_close(self, stage):
        if self.open_at == stage:
            if self.serial:
                self.serial.close()
                self.serial = None

