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

'''
TelnetMonitor monitors the output of a telnet connection by looking for a
pattern in the command output
'''
import re
import os
import time
import telnetlib
from kitty.monitors.base import BaseMonitor


class TelnetMonitor(BaseMonitor):
    def __init__(self, name, username, password, host, port=23,
                 cmd_timeout=3, capture_dir='.', logger=None):
        '''
        :param name: name of the monitor
        :param username: remote username
        :param password: remote password
        :param host: telnet host
        :param port: telnet port (default: 23)
        :param cmd_timeout: timtout for running the command (default: 3)
        :param capture_dir: where to store the telnet output (default: ='.')
        :param logger: logger for the object (default: None)
        '''
        super(TelnetMonitor, self).__init__(name, logger)
        self.success_pattern = None
        self.success_pattern_str = None
        self.failure_pattern = None
        self.failure_pattern_str = None
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.cmd_timeout = cmd_timeout
        self.tn = None
        self.tn_mon = None
        self.fd = None
        file_template = 'test_%(test_num)d_%(timestamp)s_telnet.txt'
        self.name_pattern = os.path.join(capture_dir, file_template)
        self.current_file_name = None
        self._pre_test_cmds = []
        self._post_test_cmds = []
        self._monitor_cmds = []

    def _read_until(self, tn, expected):
        resp = tn.read_until(expected, self.cmd_timeout)
        if expected in resp:
            return resp
        else:
            raise Exception('%s: timeout while waiting for expected: "%s"'
                            % (self.name, expected))

    def _login(self, tn):
        '''
        .. todo:: need to make it more robust
        '''
        self._read_until(tn, 'login:')
        tn.write(self.username + '\n')
        self._read_until(tn, 'Password:')
        tn.write(self.password + '\n')
        self._read_until(tn, 'Using network console')

    def _do_cmd(self, tn, cmd, expected_output):
        tn.write(cmd + '\n')
        if expected_output is not None:
            output = tn.read_until(expected_output, self.cmd_timeout)
            if expected_output in output:
                return (True, output)
            else:
                return (False, output)
        else:
            output = tn.read_some()
            return (True, output)

    def setup(self):
        self.tn = telnetlib.Telnet(self.host, self.port)
        self.tn_mon = telnetlib.Telnet(self.host, self.port)
        self._login(self.tn)
        self._login(self.tn_mon)
        for cmd, expected_output in self._monitor_cmds:
            self._do_cmd(self.tn_mon, cmd, expected_output)
        super(TelnetMonitor, self).setup()

    def teardown(self):
        super(TelnetMonitor, self).teardown()
        if self.tn is not None:
            self.tn.close()
        if self.tn_mon is not None:
            self.tn_mon.close()
        if self.fd is not None:
            self.fd.close()

    def set_monitor_command(self, cmd):
        self.monitor_command = cmd

    def set_success_pattern(self, success_pattern):
        '''set a pattern that declares the test successful if received'''
        self.success_pattern = re.compile(success_pattern)
        self.success_pattern_str = success_pattern

    def set_failure_pattern(self, failure_pattern):
        '''set a pattern that declares the test a failure if received'''
        self.failure_pattern = re.compile(failure_pattern)
        self.failure_pattern_str = failure_pattern

    def add_pre_test_cmd(self, cmd, expected_output=None):
        self._pre_test_cmds.append((cmd, expected_output))

    def add_post_test_cmd(self, cmd, expected_output=None):
        self._post_test_cmds.append((cmd, expected_output))

    def add_monitor_cmd(self, cmd, expected_output=None):
        self._monitor_cmds.append((cmd, expected_output))

    def post_test(self):
        cmd_results = []
        for cmd, expected_output in self._post_test_cmds:
            success, output = self._do_cmd(self.tn, cmd, expected_output)
            result = (cmd, output, expected_output, success)
            if not success:
                self.logger.debug('MONITOR MARKED REPORT FAILED AS TRUE !')
                self.report.failed('post test command failed')
                self.report.add('cmd', cmd)
                self.report.add('expected_output', expected_output)
                self.report.add('actual output', output)
            cmd_results.append(result)
        self.report.add('post test commands', cmd_results)

        self.report.add('capture_file_name', self.current_file_name)
        if self.fd is not None:
            fd = self.fd
            self.fd = None
            fd.close()
            self.current_file_name = None

        super(TelnetMonitor, self).post_test()

    def pre_test(self, test_number):
        super(TelnetMonitor, self).pre_test(test_number)
        newfilename = self.name_pattern % {
            'test_num': self.test_number,
            'timestamp': str(int(time.time()))
        }
        dirname = os.path.dirname(newfilename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        newfd = open(newfilename, 'wb')
        oldfd = self.fd
        self.fd = newfd
        self.current_file_name = newfilename
        if oldfd is not None:
            oldfd.close()

        for cmd, expected_output in self._pre_test_cmds:
            success, output = self._do_cmd(self.tn, cmd, expected_output)
            if not success:
                self.report.failed('pre test command failed')
                self.report.add('cmd', cmd)
                self.report.add('expected_output', expected_output)
                self.report.add('actual output', output)

    def _monitor_func(self):
        '''
        Nothing is done here, so we use a sleep for now.
        '''
        time.sleep(0.1)
