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
`Frida <http://www.frida.re>`_ based controllers for server fuzzing.
'''
from __future__ import absolute_import
import frida
from kitty.controllers.base import BaseController


class FridaLaunchServerController(BaseController):
    '''
    This controller uses frida to launch an application.
    You can pass JS script so kitty will be able to detect failures
    using Frida's capabilities.

    :example:

        ::

            js_code = """
            Interceptor.attach(ptr(failure_func_addr), {
                onEnter: function(args) {
                    send('[kitty:failed] this function should never be called!');
                }
            });

            """
            ctl = FridaLaunchServerController('fritty', None, 'local', ['someproc'], js_code)
    '''

    def __init__(self, name, logger, device_path, argv, js_script=None):
        '''
        :param name: name of the object
        :param logger: logger for the object
        :param device_path: frida target device path
        :type argv: list of str
        :param argv: arguments to launch the application
        :type js_script: str
        :param js_script: JS script to run on the target.
            in this script you can perform hooks and detect "failures" on the device.
            if a failure is detected, call `send('[kitty:failed] (reason)');` from JS.
            if somehow a pass is detected, call `send('[kitty:passed]  (reason)');` from JS.
            (default: None)
        '''
        super(FridaLaunchServerController, self).__init__(name, logger)
        self._frida_device_path = device_path
        self._frida_argv = argv
        self._frida_js_script = js_script
        self._frida_session = None
        self._frida_pid = None
        self._frida_device = None
        self._frida_script = None

    def _frida_reset(self):
        self._frida_session = None
        self._frida_pid = None
        self._frida_device = None
        self._frida_script = None

    def _frida_session_on_detached(self):
        self.logger.error('detached callback called')
        self._frida_reset()

    def _frida_script_on_message(self, message, data):
        '''
        This function is called when the JS script calls "send"
        if the message payload starts with '[kitty:passed]' the test will be marked as passed
        if the message payload starts with '[kitty:failed]' the test will be marked as failed
        if the message payload starts with '[kitty:log]' the rest of the payload with go to log
        '''
        payload = message['payload']
        parts = payload.split(' ', 1)
        if len(parts) == 1:
            parts.append(None)
        if parts[0].lower() == '[kitty:failed]':
            self.report.failed(parts[1])
        elif parts[0].lower() == '[kitty:passed]':
            self.report.passed()
        elif parts[0].lower() == '[kitty:log]':
            self.logger.info('Message from JS script: %s' % payload)

    def setup(self):
        super(FridaLaunchServerController, self).setup()
        if not self._is_victim_alive():
            self._frida_device = frida.get_device(self._frida_device_path)
            self._frida_pid = self._frida_device.spawn(self._frida_argv)
            self._frida_session = self._frida_device.attach(self._frida_pid)
            self._frida_session.on('detached', self._frida_session_on_detached)
            if self._frida_js_script is not None:
                self._frida_script = self._frida_session.create_script(self._frida_js_script)
                self._frida_script.on('message', self._frida_script_on_message)
                self._frida_script.load()
            self._frida_device.resume(self._frida_pid)

    def teardown(self):
        if not self._is_victim_alive():
            msg = 'victim is already down'
            self.logger.error(msg)
            raise Exception(msg)
        else:
            if self._frida_script is not None:
                self._frida_script.unload()
            self._frida_session.off('detached', self._frida_session_on_detached)
            self._frida_session.detach()
            self._frida_device.kill(self._frida_pid)
            self._frida_reset()
        super(FridaLaunchServerController, self).teardown()

    def pre_test(self, test_number):
        super(FridaLaunchServerController, self).pre_test(test_number)
        if not self._is_victim_alive():
            self._restart()
        self.report.add('pre_test_pid', self._get_pid())

    def post_test(self):
        super(FridaLaunchServerController, self).post_test()

    def _restart(self):
        self.logger.info('restart called')
        self.teardown()
        self.setup()

    def _get_pid(self):
        return self._frida_pid

    def _is_victim_alive(self):
        if self._frida_pid:
            return True
        else:
            return False
