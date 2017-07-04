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
from kitty.targets.server import ServerTarget


class FileTarget(ServerTarget):
    '''
    FileTarget will create files with the fuzzed payloads
    '''

    def __init__(self, name, file_path, base_name, postfix=None, logger=None):
        '''
        :param name: name of the target
        :param file_path: path to stores files at
        :param base_name: base file name, it will be appended by the test number
        :param postfix: filename postfix (default: None)
        :param logger: logger for the object (default: None)

        :example:

            ::

                FileTarget('FileTarget', '/tmp', 'fuzzed', '.bin')

            Will generate the followinf files:

            ::

                /tmp/fuzzed_0.bin
                /tmp/fuzzed_1.bin
                /tmp/fuzzed_2.bin
                ...
        '''
        super(FileTarget, self).__init__(name, logger)
        self.path = file_path
        self.base_name = base_name
        self.postfix = postfix
        self.full_path = None
        self.set_expect_response(False)

    def pre_test(self, test_num):
        super(FileTarget, self).pre_test(test_num)
        filename = '%s_%d' % (self.base_name, self.test_number)
        if self.postfix:
            filename = '%s.%s' % (filename, self.postfix)
        self.full_path = os.path.join(self.path, filename)
        if os.path.exists(self.full_path):
            self.logger.debug('deleting %s', self.full_path)
            os.unlink(self.full_path)
        self.report.add('fuzzed_file_path', self.full_path)

    def _send_to_target(self, data):
        self.logger.debug('file path is %s', self.full_path)
        if data:
            self.logger.debug('data length: %#x' % len(data))
            end = min(len(data) - 1, 100)
            self.logger.debug('data (start): %s', data[:end].encode('hex'))
        if self.full_path:
            self.logger.debug('opening file')
            nfile = open(self.full_path, 'wb')
            nfile.write(data)
            nfile.close()
            self.logger.debug('file written successfully')
        else:
            self.logger.error(
                'send called without setting path (in pre_transmit)'
            )
            raise ValueError(
                'send called without setting path (in pre_transmit)'
            )
