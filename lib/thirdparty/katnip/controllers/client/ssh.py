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

import paramiko
from kitty.controllers.client import ClientController


class ClientSshController(ClientController):
    '''
    ClientSshController controlls a remote process by
    starting it on each trigger using ssh.
    '''

    def __init__(self, name, username, password, hostname, port, command, process_name, logger=None):
        '''
        :param name: name of the object
        :param username: ssh login username
        :param password: ssh login password
        :param hostname: ssh server ip
        :param port: ssh server port
        :param command: client trigger command
        :param process_name: command process name
        :param logger: logger for this object (default: None)
        '''
        super(ClientSshController, self).__init__(name, logger)

        self._username = username
        self._password = password
        self._hostname = hostname
        self._port = port
        self._command = command
        self._process_name = process_name
        self._ssh = None

    def teardown(self):
        '''
        Closes the SSH connection and calls super's teardown.
        '''
        if self._ssh:
            self._ssh.close()
        self._ssh = None
        super(ClientSshController, self).teardown()

    def pre_test(self, num):
        '''
        Creates an SSH connection
        '''
        super(ClientSshController, self).pre_test(num)
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect(self._hostname, self._port, self._username, self._password)

    def post_test(self):
        '''
        Log output of process, check if crashed
        '''
        self._stdout.channel.settimeout(3)
        self._stderr.channel.settimeout(3)
        self.logger.debug('reading stdout...')
        try:
            self.report.add('stdout', self._stdout.read())
            self.logger.debug('getting process return code...')
            return_code = self._stdout.channel.recv_exit_status()
            self.logger.debug('return code: %d', return_code)
            self.report.add('return_code', return_code)
        except socket.timeout:
            self.report.add('stdout', 'Timeout reading stdout.)')
            return_code = -2
            self.report.add('return_code', return_code)
        self.logger.debug('return code: %d', return_code)
        self.logger.debug('reading stderr...')
        try:
            self.report.add('stderr', self._stderr.read())
        except socket.timeout:
            self.report.add('stderr', 'Timeout reading stderr.)')
        self.report.add('failed', return_code < 0)
        self._stop_process()
        self._ssh.close()
        super(ClientSshController, self).post_test()

    def trigger(self):
        '''
        Trigger the target communication with the server stack.
        '''
        self.report.add('command', self._command)
        (self._stdin, self._stdout, self._stderr) = self._ssh.exec_command(self._command)

    def _stop_process(self):
        '''
        Kills the target process.
        '''
        kill_cmd = 'killall %s' % self._process_name
        self._ssh.exec_command(kill_cmd)

    def _is_victim_alive(self):
        # return self._process and (self._process.poll() is None)
        return True
