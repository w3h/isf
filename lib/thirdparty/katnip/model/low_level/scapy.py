# Copyright (C) 2016 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# This module was authored and contributed by dark-lbp <jtrkid@gmail.com>
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
from __future__ import absolute_import
from kitty.model import BaseField
from kitty.model.low_level.encoder import ENC_STR_DEFAULT, StrEncoder
import random
from scapy.all import *
import sys
import StringIO


class ScapyField(BaseField):
    '''
    Wrap a fuzzed scapy.packet.Packet object as a kitty field.
    Since the fuzzing parameters can be configured by the fuzz function of Scapy,
    this field assumes that the fuzz function was already called on the given field

    :example:

        ::

            from scapy.all import *
            tcp_packet = IP()/TCP()
            field = ScapyField(value=fuzz(tcp_packet), name='tcp packet', fuzz_count=50, seed=1000)

    '''

    _encoder_type_ = StrEncoder

    def __init__(self, value, encoder=ENC_STR_DEFAULT, fuzzable=True, name=None, fuzz_count=1000, seed=1024):
        '''
        :param value: scapy_packet_class
        :type encoder: :class:`~kitty.model.low_levele.encoder.ENC_STR_DEFAULT`
        :param encoder: encoder for the field
        :param fuzzable: is field fuzzable (default: True)
        :param name: name of the object (default: None)
        :param fuzz_count: fuzz count (default: 1000)
        :param seed: random seed (default: 1024)
        '''
        self._seed = seed
        # set the random seed
        random.seed(self._seed)
        # set the fuzz count
        self._fuzz_count = fuzz_count
        # keep reference to the field for the _mutate method
        self._fuzz_packet = value
        super(ScapyField, self).__init__(value=str(value), encoder=encoder, fuzzable=fuzzable, name=name)
        # reset random count
        random.seed(self._seed)

    def num_mutations(self):
        '''
        :return: number of mutations this field will perform
        '''
        if self._fuzzable:
            return self._fuzz_count
        else:
            return 0

    def _mutate(self):
        # during mutation, all we really do is call str(self.fuzz_packet)
        # as scapy performs mutation each time str() is called...
        self._current_value = str(self._fuzz_packet)

    def reset(self):
        super(ScapyField, self).reset()
        # reset fuzz_packet to default status
        random.seed(self._seed)


    def get_info(self):
        info = super(ScapyField, self).get_info()
        # add seed to report
        info['seed'] = self._seed
        if isinstance(self._fuzz_packet, Packet):
            info['scapy/command'] = self._fuzz_packet.command()
        return info
