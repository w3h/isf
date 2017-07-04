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

import time
import os
import signal
from subprocess import Popen, PIPE
from kitty.controllers.client import ClientController


class ClientProcessController(ClientController):
    '''
    ClientProcessController controls a process
    by starting it on each trigger.
    It uses subprocess.Popen and logs the process output (stdout, stderr)
    '''
    sig_dict = {
        k: v for v, k in reversed(sorted(signal.__dict__.items())) if v.startswith('SIG') and not v.startswith('SIG_')
     }

    def __init__(self, name, process_path, process_args, process_env=None, logger=None):
        '''
        :param name: name of the object
        :param process_path: path to the target executable
        :param process_args: arguments to pass to the process
        :param process_env: the process environment (default: None)
        :param logger: logger for this object (default: None)
        '''
        super(ClientProcessController, self).__init__(name, logger)
        assert(process_path)
        assert(os.path.exists(process_path))
        if process_env is None:
            process_env = os.environ.copy()
        self._process_path = process_path
        self._process_name = os.path.basename(process_path)
        self._process_args = process_args
        self._process = None
        self._process_env = process_env

    def teardown(self):
        '''
        Stops the process and calls super's teardown.
        '''
        self._stop_process()
        self._process = None
        super(ClientProcessController, self).teardown()

    def post_test(self):
        '''
        Logs stdout, stderr amd return code of the target process.
        '''
        killed = self._stop_process()
        assert(self._process)
        self.report.add('stdout', self._process.stdout.read())
        self.report.add('stderr', self._process.stderr.read())
        self.logger.debug('return code: %d', self._process.returncode)
        self.logger.debug('killed: %s', killed)
        self.report.add('return_code', self._process.returncode)
        signame = self.sig_dict.get(-self._process.returncode, None)
        if signame:
            self.report.add('signal_name', signame)
        self.report.add('killed', killed)
        if not killed:
            if self._process.returncode < 0:
                if signame:
                    self.report.failed('got signal %s' % signame)
                else:
                    self.report.failed('negative return code')
        self._process = None
        super(ClientProcessController, self).post_test()

    def trigger(self):
        '''
        Starts the target in a subprocess
        '''
        assert(self._process is None)
        cmd = [self._process_path] + self._process_args
        self._process = Popen(cmd, stdout=PIPE, stderr=PIPE, env=self._process_env)
        self.report.add('process_name', self._process_name)
        self.report.add('process_path', self._process_path)
        self.report.add('process_args', self._process_args)
        self.report.add('process_id', self._process.pid)

    def _stop_process(self):
        '''
        Tries to stop the process
        :return: True if process was killed, False otherwise
        '''
        if self._is_victim_alive():
            self._process.terminate()
            time.sleep(0.5)
            if self._is_victim_alive():
                self._process.kill()
                time.sleep(0.5)
                if self._is_victim_alive():
                    raise Exception('Failed to kill client process')
            return True
        else:
            return False

    def _is_victim_alive(self):
        return self._process and (self._process.poll() is None)
