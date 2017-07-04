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
TLV (tag/type-length-value) legos.
Simplify fuzzing of TLV-based protocol.
'''
from kitty.model import BitField
from kitty.model import SizeInBytes
from kitty.model import ENC_INT_BE, ENC_BITS_DEFAULT
from kitty.model import Container


class TLV(Container):
    '''
    A container for fuzzing TLV elements,
    it represents a full binary TLV element.
    '''

    def __init__(self, name, tag, fields=None, tag_size=32, length_size=32, encoder=ENC_INT_BE, fuzzable=True, fuzz_tag=False, fuzz_length=True):
        '''
        :param name: name of the tlv element
        :param tag: tag of element
        :param fields: element fields, e.g. value (default: None)
        :param tag_size: size of tag field in bits (default: 32)
        :param length_size: size of length field in bits (default: 32)
        :param encoder: encoder for tag and length fields (default: ENC_INT_BE)
        :param fuzzable: should fuzz the element (default: True)
        :param fuzz_tag: should fuzz the tag value (default: False)
        :param fuzz_length: should fuzz the element length (default: True)
        '''
        tag_name = '%s-tag' % name
        len_name = '%s-length' % name
        val_name = '%s-value' % name
        if fields is None:
            fields = []
        _fields = [
            BitField(name=tag_name, value=tag, length=tag_size, signed=False, encoder=encoder, fuzzable=fuzz_tag),
            SizeInBytes(name=len_name, sized_field=val_name, length=length_size, encoder=encoder, fuzzable=fuzz_length),
            Container(name=val_name, fields=fields)
        ]
        super(TLV, self).__init__(fields=_fields, encoder=ENC_BITS_DEFAULT, fuzzable=fuzzable, name=name)


class TLVFactory(object):
    '''
    Factory class for TLV elements, which allows configuration for all TLV blocks, including:

    - Size of the tag/type field in bits
    - Size of the length field in bits
    - Encoder for tag and length fields
    '''

    def __init__(self, tag_size=32, length_size=32, encoder=ENC_INT_BE):
        '''
        :param tag_size: size of tag field in bits (default: 32)
        :param length_size: size of length field in bits (default: 32)
        :param encoder: encoder for tag and length (default: ENC_INT_BE)
        '''
        self._tag_size = tag_size
        self._len_size = length_size
        self._encoder = encoder

    def element(self, name, tag, fields=None, fuzzable=True, fuzz_tag=False, fuzz_length=True):
        '''
        Generate a TLV element.

        :param name: name of the element
        :param tag: value of the element tag
        :param fields: fields of the element may be a field or list of fields - e.g. value (default: None)
        :param fuzzable: should fuzz the element (default: True)
        :param fuzz_tag: should fuzz the tag value (default: False)
        :param fuzz_length: should fuzz the element length (default: True)
        '''
        return TLV(
            name=name, tag=tag, value=fields, tag_size=self._tag_size, length_size=self._len_size,
            encoder=self._encoder, fuzzable=fuzzable, fuzz_tag=fuzz_tag, fuzz_length=fuzz_length)


if __name__ == '__main__':
    from kitty.model import String
    tlv = TLVFactory()
    elem = tlv.element('version', 0x1, value=String(name='version-string', value='1.2.3'))
    print elem.num_mutations()
    print elem.render().bytes.encode('hex')
    while elem.mutate():
        print elem.render().bytes.encode('hex')
