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
PingController connect host by icmp
'''
from kitty.controllers.base import BaseController
from icmp_ping import Pinger


class PingController(BaseController):
    def __init__(self, name, host, max_retries=3, timeout=None, logger=None):
        '''
        :param name: name of the target
        :param host: host ip (to send data to) currently unused
        :param max_retries: maximum connection retries (default: 3)
        :param timeout: socket timeout (default: None)
        :param logger: logger for the object (default: None)
        '''
        super(BaseController, self).__init__(name, logger)
        self.host = host
        if (host is None):
            raise ValueError('host and port may not be None')
        self.timeout = timeout
        self.max_retries = max_retries

    def setup(self):
        super(BaseController, self).setup()
        ret = self.ping_test()
        if not ret:
            msg = 'ping cannot connect target'
            self.logger.error(msg)
            raise Exception(msg)

    def post_test(self):
        super(BaseController, self).post_test()
        ret = self.ping_test()
        if not ret:
            self.logger.error("Target does not respond")
            self.report.failed('Target does not respond')

    def ping_test(self):
        pinger = Pinger(target_host=self.host, count=self.max_retries)
        ret = pinger.ping()
        return ret
