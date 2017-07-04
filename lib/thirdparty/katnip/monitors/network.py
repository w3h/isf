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
Network monitor
'''
import os
from scapy.all import wrpcap, conf

from kitty.monitors import BaseMonitor


class NetworkMonitor(BaseMonitor):
    '''
    NetworkMonitor is a monitor for network activity on a specific interface.
    It runs on a separate thread, and currently requires root permissions
    or CAP_NET_RAW capabilities on Linux.
    '''

    def __init__(self, interface, dir_path, name, logger=None):
        '''
        :param interface: name of interface to listen to
        :param dir_path: path to store captured pcaps
        :param name: name of the monitor
        :param logger: logger for the monitor instance
        '''
        super(NetworkMonitor, self).__init__(name, logger)
        self._iface = interface
        self._path = dir_path
        self._packets = None
        self._sock = None

    def setup(self):
        '''
        Open the L2socket.
        '''
        self._packets = None
        self._sock = conf.L2socket(iface=self._iface)
        super(NetworkMonitor, self).setup()

    def pre_test(self, test_number):
        '''
        Clean the packet list.
        '''
        super(NetworkMonitor, self).pre_test(test_number)
        self._packets = []

    def post_test(self):
        '''
        Store the pcap.
        '''
        filename = os.path.join(self._path, 'test_%s.pcap' % self.test_number)
        packets = self._packets[:]
        if len(packets):
            wrpcap(filename, packets)
        else:
            self.logger.debug('No packets to write')
        self._packets = None
        self.report.add('pcap file', filename)
        super(NetworkMonitor, self).post_test()

    def teardown(self):
        '''
        Close the L2socket.
        '''
        self.logger.debug('closing socket')
        self._sock.close()
        super(NetworkMonitor, self).teardown()

    def _monitor_func(self):
        '''
        Called in a loop.
        '''
        self.logger.debug('in _monitor_func')
        if self._sock:
            packet = self._sock.recv(1600)
            if packet and (self._packets is not None):
                self._packets.append(packet)


if __name__ == '__main__':
    import time
    print('creating monitor')
    mon = NetworkMonitor('lo', '/tmp/', 'Dummy Monitor')
    print('calling mon.setup')
    mon.setup()
    print('calling mon.pre_test')
    mon.pre_test(1)
    print('calling time.sleep(5)')
    time.sleep(5)
    print('calling mon.post_test')
    mon.post_test()
    print('calling mon.teardown')
    mon.teardown()
    print('---- done ----')
