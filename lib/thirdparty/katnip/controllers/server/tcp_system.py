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
from kitty.controllers.base import BaseController


class ServerTcpSystemController(BaseController):
    '''
    This controller controls a process on a remote machine
    by sending tcp commands over the network to a local agent
    on the remote machine to execute the target using popen.

    .. note::

        The implementation of the agent is not part of the code
        it might be added someday, but currently it is not...
    '''

    def __init__(self, name, logger, proc_name, host, port):
        '''
        :param name: name of the object
        :param logger: logger for the object
        :param proc_name: trigger's process name
        :param host: hostname of the agent
        :param port: port of the agent
        '''
        super(ServerTcpSystemController, self).__init__(name, logger)
        self._proc_name = proc_name
        self._host = host
        self._port = port
        self._agent_socket = None

    def setup(self):
        super(ServerTcpSystemController, self).setup()
        if not self._is_victim_alive():
            msg = 'ServerTcpSystemController cannot start victim'
            self.logger.error(msg)
            raise Exception(msg)

    def teardown(self):
        super(ServerTcpSystemController, self).teardown()
        if not self.is_victim_alive():
            msg = 'victim is already down'
            self.logger.error(msg)
            raise Exception(msg)
        else:
            msg = 'ServerTcpSystemController does not actually stop the process'
            self.logger.info(msg)

    def pre_test(self, test_number):
        super(ServerTcpSystemController, self).pre_test(test_number)
        if not self._is_victim_alive():
            self._restart()
        self.report.add('pre_test_pid', self._get_pid())

    def post_test(self):
        super(ServerTcpSystemController, self).post_test()
        self.report.add('post_test_pid', self._get_pid())

    def _restart(self):
        self.logger.info('restart called')
        self._do_remote_command('reboot', True)
        self.setup()

    def _get_pid(self):
        data = self._do_remote_command("pgrep %s" % self._proc_name, False)
        curr_pid = int(data)
        return curr_pid

    def _is_victim_alive(self):
        active = False
        try:
            self._get_pid()
            active = True
        except Exception:
            pass

        return active

    def _connect_to_agent(self, retry):
        while True:
            try:
                self._agent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._agent_socket.settimeout(2)
                self._agent_socket.connect((self._host, self._port))
                break
            except Exception:
                if retry:
                    self.logger.warning("Failed to connect to agent")
                    self.logger.warning("Sleep 5 seconds and retry")
                    time.sleep(5)
            if not retry:
                break

    def _do_remote_command(self, command, retry=True):
        self.logger.info('do remote command: %s' % command)
        self._connect_to_agent(retry)
        self._agent_socket.send(command)
        data = self._agent_socket.recv(1024)
        self.logger.info('response: %s' % data)
        self._agent_socket.close()
        self._agent_socket = None
        return data
