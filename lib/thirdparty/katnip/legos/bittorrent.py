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
Bittorent file (.torrent) protocol lego.
Those legos impelent the bencoding format:
https://wiki.theory.org/BitTorrentSpecification#Bencoding
'''
from kitty.model import Container, TakeFrom
from kitty.model import Delimiter, String, SizeInBytes, SInt64
from kitty.model import ENC_INT_DEC


_unique_ids = {}


def _merge(*args):
    return '-'.join(args)


def _unique_name(name):
    if name not in _unique_ids:
        _unique_ids[name] = 0
    _unique_ids[name] += 1
    return _merge(name, str(_unique_ids[name]))


class TString(Container):
    '''
    Bencoded String.
    Format: ``<string length encoded in base ten ASCII>:<string data>``
    '''

    def __init__(self, value, fuzz_value=True, fuzz_length=True, fuzz_delim=True, name=None):
        '''
        :param value: str, will be enclosed in String
        :param fuzz_value: bool (default: True)
        :param fuzz_length: bool (default: True)
        :param fuzz_delim: bool (default: True)
        :param name: name of container (default: None)
        '''
        name = name if name is not None else _unique_name(type(self).__name__)
        if isinstance(value, str):
            fvalue = String(value=value, fuzzable=fuzz_value, name=_merge(name, 'value'))
        else:
            fvalue = value
        fvalue_name = fvalue.get_name()
        super(TString, self).__init__(name=name, fields=[
            SizeInBytes(sized_field=fvalue_name, length=32, encoder=ENC_INT_DEC, fuzzable=fuzz_length, name=_merge(name, 'length')),
            Delimiter(value=':', fuzzable=fuzz_delim, name=_merge(name, 'delim')),
            fvalue
        ])


class TInteger(Container):
    '''
    Bencoded integer.
    Format: `` i<integer encoded in base ten ASCII>e``
    '''

    def __init__(self, value, fuzz_value=True, fuzz_delims=True, name=None):
        '''
        :param value: int, will be enclosed in a Int32
        :fuzz_value: bool (default: True)
        :fuzz_delims: bool (default: True)
        :param name: name of container (default: None)
        '''
        name = name if name is not None else _unique_name(type(self).__name__)
        super(TInteger, self).__init__(name=name, fields=[
            String(value='i', max_size=1, fuzzable=fuzz_delims, name=_merge(name, 'start')),
            SInt64(value=value, encoder=ENC_INT_DEC, fuzzable=fuzz_value, name=_merge(name, 'value')),
            String(value='e', max_size=1, fuzzable=fuzz_delims, name=_merge(name, 'end')),
        ])


class TList(Container):
    '''
    Bencoded list.
    Format: ``l<bencoded values>e``
    '''
    def __init__(self, fields=[], fuzz_delims=True, name=None):
        '''
        :param fields: content of the list, Fields...
        :fuzz_delims: bool (default: True)
        :param name: name of container (default: None)
        '''
        name = name if name is not None else _unique_name(type(self).__name__)
        super(TList, self).__init__(name=name, fields=[
            String(value='l', max_size=1, fuzzable=fuzz_delims, name=_merge(name, 'start')),
            TakeFrom(fields=fields, name=_merge(name, 'fields'), min_elements=len(fields)/2),
            String(value='e', max_size=1, fuzzable=fuzz_delims, name=_merge(name, 'end'))
        ])


class TDict(Container):
    '''
    Bencoded dictionary.
    Format: ``d<bencoded string><bencoded element>e``
    '''

    def __init__(self, fields={}, fuzz_keys=True, fuzz_delims=True, name=None):
        '''
        :param fields: dictionary of strings and torrent fields
        :fuzz_delims: bool (default: True)
        :param name: name of container (default: None)
        '''
        name = name if name is not None else _unique_name(type(self).__name__)
        dictionary_fields = []
        for k, v in fields.items():
            dictionary_fields.append(Container(name=_merge(name, 'container', k), fields=[
                TString(value=k, fuzz_value=fuzz_keys, fuzz_length=fuzz_keys, fuzz_delim=fuzz_delims, name=_merge(name, 'key', k)),
                v
            ]))
        super(TDict, self).__init__(name=name, fields=[
            String(value='d', max_size=1, fuzzable=fuzz_delims, name=_merge(name, 'start')),
            TakeFrom(name=_merge(name, 'fields'), fields=dictionary_fields, min_elements=len(dictionary_fields)/2),
            String(value='e', max_size=1, fuzzable=fuzz_delims, name=_merge(name, 'end'))
        ])
