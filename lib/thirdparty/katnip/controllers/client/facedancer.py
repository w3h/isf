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
This controller is used to signal the SAS version of the Facedancer stack
to perform a USB reset.
'''
from kitty.controllers.client import ClientController


class ClientFacedancerController(ClientController):
    '''
    ClientFacedancerController is a controller that uses files in /tmp
    to communicate with the facedancer stack.
    .. note:: This requires a modified version of the facedancer stack.
    '''

    RESTART_FILE = '/tmp/restart_facedancer'

    def __init__(self, name, restart_file=RESTART_FILE, logger=None):
        '''
        :param name: name of the object
        :param controller_port: the device controller port (i.e. '/dev/ttyACM0')
        :param connect_delay:
        :param logger: logger for the object (default: None)
        '''
        super(ClientFacedancerController, self).__init__(name, logger)
        self._restart_file = restart_file

    def trigger(self):
        '''
        Trigger a data exchange from the tested client
        '''
        f = open(self._restart_file, 'w')
        f.close()
