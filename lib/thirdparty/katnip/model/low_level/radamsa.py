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
Radamsa wrapper to generate mutations using radamsa.

You can get radamsa at https://github.com/aoh/radamsa
'''
from random import Random
import subprocess
from kitty.model import BaseField
from kitty.model import StrEncoder, ENC_STR_DEFAULT
from kitty.core import KittyException


class RadamsaField(BaseField):
    '''
    This class uses radamsa to generate payload based on a given input.
    Since radamsa can run infinitly, it is limited by the user,
    by specifying the amount of payloads to generate (fuzz_count).
    To provide repeatablity, the user provides a seed that is used to
    generate seeds for radamsa.
    If radamsa is not installed in the system path, the user can provide
    the path (bin_path).
    If bin_path not specified, it will be assumed that the radamsa binary
    is in the path already.

    :example:

        ::

            from katnip.model.low_level.radamsa import RadamsaField
            RadamsaField(name='ip address', value='127.0.0.1', fuzz_count=20, bin_path='/path/to/radamsa')
    '''

    _encoder_type_ = StrEncoder

    def __init__(self, value, encoder=ENC_STR_DEFAULT, fuzzable=True, name=None, fuzz_count=1000, seed=123456, bin_path=None):
        '''
        :param value: default value
        :type encoder: :class:`~kitty.model.low_levele.encoder.ENC_STR_DEFAULT`
        :param encoder: encoder for the field
        :param fuzzable: is field fuzzable (default: True)
        :param name: name of the object (default: None)
        :param fuzz_count: fuzz count (default: 1000)
        :param seed: random seed for generating radamsa seeds (default: 123456)
        :param bin_path: path to the radamsa binary (default: None)
        '''
        self._random = Random()
        self._seed = seed
        self._current_seed = None
        self._random.seed(self._seed)
        self._fuzz_count = fuzz_count
        self._bin_path = bin_path if bin_path else 'radamsa'
        self._radamsa_err = None
        self._radamsa_out = None
        super(RadamsaField, self).__init__(value=value, encoder=encoder, fuzzable=fuzzable, name=name)
        self._check_radamsa_available()

    def num_mutations(self):
        '''
        :return: number of mutations this field will perform
        '''
        if self._fuzzable:
            return self._fuzz_count
        else:
            return 0

    def _check_radamsa_available(self):
        '''
        Check whether we can run radamsa.
        '''
        try:
            sp = subprocess.Popen(self._bin_path)
            sp.terminate()
        except Exception as ex:
            raise KittyException('Can\'t run %s. error: %s' % (self._bin_path, ex))

    def _run_radamsa(self):
        command = self._get_command()
        sp = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._radamsa_out, self._radamsa_err = sp.communicate(self._default_value)
        return self._radamsa_out

    def _get_command(self):
        return [self._bin_path, '-s', str(self._current_seed)]

    def _mutate(self):
        self._current_seed = self._random.randint(-100000000000, 100000000000)
        self._current_value = self._run_radamsa()

    def reset(self):
        super(RadamsaField, self).reset()
        self._random.seed(self._seed)
        self._random._current_seed = None
        self._radamsa_err = None
        self._radamsa_out = None

    def get_info(self):
        info = super(RadamsaField, self).get_info()
        info['base_seed'] = self._seed
        if self._current_seed is not None:
            info['radamsa'] = {
                'seed': self._current_seed,
                'command': ' '.join(str(x) for x in self._get_command()),
            }
            if self._radamsa_err:
                info['radamsa']['stderr'] = self._radamsa_err
        return info
