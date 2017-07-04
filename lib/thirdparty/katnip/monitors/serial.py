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
from __future__ import absolute_import
import re
import os
import time
import serial
from threading import Lock
from kitty.monitors.base import BaseMonitor


class SerialMonitor(BaseMonitor):
    '''
    SerialMonitor monitors the output of a serial connection by looking for a
    pattern in the serial output.

    This monitor captures all the received data from the serial,
    but it is also able to detect successful/failed tests
    by looking for specific patterns in the serial output.

    .. note::

        The monitor can work either with a success pattern
        (failure if pattern was not found)
        or with a failure pattern
        (success if pattern was not found)

    :examples:

        Setting a monitor that will fail a test if a line that contains
        "stack smashing detected" appears in the serial

        ::

            monitor = SerialMonitor('detect smash monitor', '/dev/ttyUSB0', capture_dir='serial_caps')
            monitor.set_failure_pattern('stack smashing detected')

        Setting a monitor that will fail a test if a line that contains either
        "reboot" or "restart" appears on the serial (utilizing regex)

        ::

            monitor = SerialMonitor('detect reboot monitor', '/dev/ttyUSB0', capture_dir='serial_caps')
            monitor.set_failure_pattern('(reboot)|(restart)')
    '''

    def __init__(self, name, dev_name=None, baudrate=115200,
                 capture_dir='.', logger=None):
        '''
        :param name: name of the monitor object
        :param dev_name: serial device
        :param baudrate: serial baudrate
        :param capture_dir: where to store the captured serial output
        :param logger: logger for the monitor object
        '''
        super(SerialMonitor, self).__init__(name, logger)
        self.pattern_cbs = []
        self.dev_name = dev_name
        self.baudrate = baudrate
        self.serial = None
        self.fd = None
        self.fdlock = Lock()
        file_template = 'test_%(test_num)d_%(timestamp)s_serial.txt'
        self.name_pattern = os.path.join(capture_dir, file_template)
        self.current_file_name = None

    def setup(self):
        self.serial = serial.Serial(self.dev_name, self.baudrate)
        super(SerialMonitor, self).setup()

    def teardown(self):
        super(SerialMonitor, self).teardown()
        if self.serial is not None:
            self.serial.close()
        if self.fd is not None:
            self.fd.close()

    def add_pattern_callback(self, pattern, cb):
        '''
        Add a pattern to search for on the serial output, and the callback that
        will be called when the pattern is found.

        :type pattern: str
        :param pattern: regular expression pattern to be searched for in the serial output
        :type cb: callable
        :param cb: the callback to be called when pattern is found; must accept 3 params:
                   (1) a SerialMonitor instance
                   (2) the matching line
                   (3) the re match object of the found match
        '''
        self.pattern_cbs.append((re.compile(pattern), cb))

    def add_success_pattern(self, success_pattern):
        '''
        Set a pattern that declares the test successful if received

        :type success_pattern: str
        :param success_pattern: regular expression pattern of output that signifies success (e.g. no bug there)
        '''
        def success_cb(self, line, match):
            self.report.success()
        self.add_pattern_callback(success_pattern, success_cb)

    def set_success_pattern(self, success_pattern):
        return self.add_success_pattern(success_pattern)

    def add_failure_pattern(self, failure_pattern):
        '''
        Set a pattern that declares the test as failed if received

        :type failure_pattern: str
        :param failure_pattern: regular expression pattern of output that signifies failure (e.g. potential bug there)
        '''
        def failure_cb(self, line, match):
            self.report.failed('failure pattern [%s] matched line [%s]' % (match.re.pattern, line))
        self.add_pattern_callback(failure_pattern, failure_cb)

    def set_failure_pattern(self, failure_pattern):
        return self.add_failure_pattern(failure_pattern)

    def close_fd(self):
        if self.fd is not None:
            self.fdlock.acquire()
            self.fd.close()
            self.fd = None
            self.fdlock.release()

    def post_test(self):
        self.report.add('capture_file_name', self.current_file_name)
        if self.fd is not None:
            self.close_fd()
            self.current_file_name = None
        super(SerialMonitor, self).post_test()

    def pre_test(self, test_number):
        super(SerialMonitor, self).pre_test(test_number)
        newfilename = self.name_pattern % {
            'test_num': self.test_number,
            'timestamp': str(int(time.time()))
        }
        dirname = os.path.dirname(newfilename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        newfd = open(newfilename, 'wb')
        self.fdlock.acquire()
        oldfd = self.fd
        self.fd = newfd
        self.fdlock.release()
        self.current_file_name = newfilename
        if oldfd is not None:
            oldfd.close()

    def _monitor_func(self):
        '''
        Called in a loop.
        '''
        line = self.serial.readline()
        if line:
            for pattern, cb in self.pattern_cbs:
                match = pattern.search(line)
                if match:
                    cb(self, line, match)
            self.fdlock.acquire()
            if self.fd is not None:
                self.fd.write(line)
            self.fdlock.release()

