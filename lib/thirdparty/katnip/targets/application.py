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

import os
import time
import select
from subprocess import Popen, PIPE
from kitty.targets.server import ServerTarget


class ApplicationTarget(ServerTarget):
    '''
    ApplicationTarget will run an application for each fuzzed payloads
    '''

    def __init__(self, name, path, args, env=None, tempfile=None, timeout=2, logger=None):
        '''
        :param name: name of the object
        :param path: path to the target executable
        :param args: arguments to pass to the process
        :param env: the process environment (default: None)
        :param tempfile: temp filename to be created with the mutated data as contents (default: None)
        :param timeout: seconds to wait for the process stdout and stderr output before kill (default: 2)
        :param logger: logger for this object (default: None)

        :example:

            ::

                ApplicationTarget(
                    name='ApplicationTarget',
                    path='/tmp/myApp',
                    args=['-a', '-b', '-c tempdata.bin'],
                    env=None,
                    tempfile='/tmp/tempdata.bin',
                    timeout=1.5)

            Will run ``/tmp/myApp -a -b -c /tmp/tempdata.bin`` for evey mutation with timout of 1.5 seconds

        '''
        super(ApplicationTarget, self).__init__(name, logger)
        self.path = path
        self.args = args
        self.env = env
        self.tempfile = tempfile
        self.timeout = timeout
        self.set_expect_response(False)
        self._process = None

    def pre_test(self, test_num):
        super(ApplicationTarget, self).pre_test(test_num)
        if self.tempfile:
            filename = self.tempfile
            if os.path.exists(filename):
                self.logger.debug('deleting %s', filename)
                os.unlink(filename)

    def _is_victim_alive(self):
        '''
        :return: True if process is still running
        '''
        return self._process and (self._process.poll() is None)

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

    def _send_to_target(self, data):
        self.logger.info('send called')
        if self.tempfile:
            self.logger.info('tempfile path is %s', self.tempfile)
        if data:
            self.logger.info('data length: %#x' % len(data))
            end = min(len(data) - 1, 100)
            self.logger.info('data (start): %s', data[:end].encode('hex'))
        cmd = [self.path] + self.args
        if self.tempfile:
            nfile = open(self.tempfile, 'wb')
            nfile.write(data)
            nfile.close()
            self.logger.debug('tempfile written successfully')
            self.logger.debug('starting cmd: "%s"' % cmd)
            self._process = Popen(cmd, stdout=PIPE, stderr=PIPE, env=self.env)
            self.logger.debug('cmd done')
        else:  # pipe mode
            self._process = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=self.env)
            self._process.stdin.write(data)
        self.report.add('path', self.path)
        self.report.add('args', str(self.args))
        self.report.add('process_id', self._process.pid)

    def _read(self, fd):
        resp = ''
        poll_obj = select.poll()
        poll_obj.register(fd, select.POLLIN)
        start = time.time()
        while(time.time()-start) < self.timeout:
            poll_result = poll_obj.poll(self.timeout)
            if poll_result:
                resp += fd.read(1)
        return resp

    def post_test(self, test_num):
        self.report.add('stdout', self._read(self._process.stdout))
        self.report.add('stderr', self._read(self._process.stderr))
        if self._process.returncode is None:
            self.logger.info('process is running, lets kill it!')
            self._stop_process()
        else:
            self.logger.debug('return code: %d', self._process.returncode)
            self.report.add('return_code', self._process.returncode)
            if self._process.returncode != 0:
                self.report.failed('Application failed. Return Code: %d' % self._process.returncode)
        self._process = None
        super(ApplicationTarget, self).post_test(test_num)
