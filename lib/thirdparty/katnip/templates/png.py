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
PNG Templates - There's still work to be done
'''
from kitty.model import *
import zlib


def compression_func(s):
    compressor = zlib.compressobj()
    compressed = compressor.compress(s)
    compressed += compressor.flush()
    return compressed

ZLIB_COMPRESS = StrFuncEncoder(compression_func)


class Chunk(Container):
    '''
    PNG Chunk
    '''

    def __init__(self, chunk_type, data_fields=None, fuzzable=True, name=None):
        '''
        :param chunk_type: four-char string (e.g. IHDR, iTXt, etc.)
        :type data_fields: field or list of fields
        :param data_fields: chunk data(default: None)
        :param fuzzable: is the field fuzzable(default: True)
        :param name: name of the field(default: None)
        '''
        if data_fields is None:
            data_fields = []
        if name is None:
            name = chunk_type
        length_name = '%s_length' % name
        type_name = '%s_type' % name
        data_name = '%s_data' % name
        crc_name = '%s_crc' % name
        crc_part_name = '%s_crced' % name
        fields = [
            Size(data_name, length=32, name=length_name),
            Container(name=crc_part_name, fields=[
                Static(chunk_type, name=type_name),
                Container(fields=data_fields, name=data_name),
            ]),
            Checksum(crc_part_name, 32, 'crc32', name=crc_name)
        ]
        super(Chunk, self).__init__(fields=fields, fuzzable=fuzzable, name=name)


class zTXt(Chunk):
    '''
    zTXt chunk.
    '''

    def __init__(self, keyword, data, fuzzable=True, name='zTXt'):
        '''
        :param keyword: chunk keyword
        :type data: str
        :param data: chunk data
        :param fuzzable: is the field fuzzable (default: True)
        :param name: name of the field (default: 'zTXt')
        '''
        data_fields = [
            # Pad(80, '\x00', String(name='%s_key' % keyword, value=keyword)),
            String(name='%s_key' % keyword, value=keyword),
            Static('\x00'),
            U8(name='%s compression method' % keyword, value=0),
            String(name='%s data' % keyword, value=data, encoder=ZLIB_COMPRESS)
        ]
        super(zTXt, self).__init__('zTXt', data_fields=data_fields, fuzzable=fuzzable, name='%s_%s' % (name, keyword))


class tEXt(Chunk):
    '''
    tEXt chunk.
    '''

    def __init__(self, keyword, data, fuzzable=True, name='tEXt'):
        '''
        :param keyword: chunk keyword
        :type data: str
        :param data: chunk data
        :param fuzzable: is the field fuzzable (default: True)
        :param name: name of the field (default: 'tEXt')
        '''
        data_fields = [
            # Pad(80, '\x00', String(name='%s_key' % keyword, value=keyword)),
            String(name='%s_key' % keyword, value=keyword),
            Static('\x00'),
            String(name='%s data' % keyword, value=data)
        ]
        super(tEXt, self).__init__('tEXt', data_fields=data_fields, fuzzable=fuzzable, name='%s_%s' % (name, keyword))


class iTXt(Chunk):
    '''
    iTXt chunk.
    '''
    def __init__(self, keyword, data, fuzzable=True, name='iTXt', compressed=False):
        '''
        :param keyword: chunk keyword
        :type data: str
        :param data: chunk data
        :param fuzzable: is the field fuzzable (default: True)
        :param name: name of the field (default: 'tEXt')
        :param compressed: is data compressed (default: False)
        '''
        data_fields = [
            # Pad(80, '\x00', String(name='%s_key' % keyword, value=keyword)),
            String(name='%s_key' % keyword, value=keyword),
            Static('\x00'),
            U8(name='%s compression flag' % keyword, value=1 if compressed else 0),
            U8(name='%s compression method' % keyword, value=0),
            # Pad(80, '\x00', String(name='%s language tag' % keyword, value='')),
            # Pad(80, '\x00', String(name='%s translated keyword' % keyword, value='')),
            String(name='%s language tag' % keyword, value=''),
            Static('\x00'),
            String(name='%s translated keyword' % keyword, value='s'),
            Static('\x00'),
        ]
        if compressed:
            Container(fields=String(name='%s txt' % keyword, value=data, encoder=ENC_STR_UTF8),
                      encoder=BitsFuncEncoder(lambda x: Bits(bytes=compression_func(x.tobytes()))))
        else:
            String(name='%s txt' % keyword, value=data, encoder=ENC_STR_UTF8)
        super(iTXt, self).__init__('iTXt', data_fields=data_fields, fuzzable=fuzzable, name='%s_%s' % (name, keyword))


_defaults = {
    'height': 3,
    'width': 3,
    'idat data size': 12,
    'profile name': 'my profile name',
    'profile': 'the profile'
}


png_template = Template(name='png', fields=[
    Static(name='magic', value='\x89PNG\r\n\x1a\n'),
    Chunk('IHDR', [
        U32(name='width', value=_defaults['width']),
        U32(name='height', value=_defaults['height']),
        U8(name='bit depth', value=8),
        U8(name='color type', value=2),
        U8(name='compression method', value=0),
        U8(name='filter method', value=0),
        U8(name='interlace method', value=0)
    ]),
    TakeFrom(name='optional chunks', fields=[
        # Chunk('PLTE', RandomBytes(name='pallete', value='\xff\xff\xff', min_length=3, max_length=1000)),
        Chunk('tRNS', RandomBytes(name='transperancy', value='\x05', min_length=1, max_length=1000)),
        Chunk('gAMA', U32(name='gama', value=45455)),
        # Chunk('cHRM', [
        #     U32(name='White Point x', value=0),
        #     U32(name='White Point y', value=0),
        #     U32(name='Red x', value=0),
        #     U32(name='Red y', value=0),
        #     U32(name='Green x', value=0),
        #     U32(name='Green y', value=0),
        #     U32(name='Blue x', value=0),
        #     U32(name='Blue y', value=0),
        # ]),
        # Chunk('sRGB', U8(name='rendering intent', value=0)),
        Chunk('iCCP', [
            # Pad(80, '\x00', String(name='profile name', value=_defaults['profile name'])),
            String(name='profile name', value=_defaults['profile name']),
            Static('\x00'),
            U8(name='compression method', value=0),
            RandomBytes(name='data', value=_defaults['profile'], min_length=len(_defaults['profile']),
                        max_length=50000, encoder=ZLIB_COMPRESS)
        ]),
        OneOf(name='textual data', fields=[
            TakeFrom(name='zTXtFields', fields=[
                zTXt('Title', 'kitty title'),
                zTXt('Author', 'kitty author'),
                zTXt('Description', 'kitty description'),
                zTXt('Copyright', 'kitty copyright'),
                zTXt('Creation', 'kitty creation'),
                zTXt('Software', 'kitty software'),
                zTXt('Disclaimer', 'kitty disclaimer'),
                zTXt('Warning', 'kitty warning'),
                zTXt('Source', 'kitty source'),
                zTXt('Comment', 'kitty comment'),
            ], max_elements=1),
            TakeFrom(name='tEXtFields', fields=[
                tEXt('Title', 'kitty title'),
                tEXt('Author', 'kitty author'),
                tEXt('Description', 'kitty description'),
                tEXt('Copyright', 'kitty copyright'),
                tEXt('Creation', 'kitty creation'),
                tEXt('Software', 'kitty software'),
                tEXt('Disclaimer', 'kitty disclaimer'),
                tEXt('Warning', 'kitty warning'),
                tEXt('Source', 'kitty source'),
                tEXt('Comment', 'kitty comment'),
            ], max_elements=1),
            TakeFrom(name='iTXtFields', fields=[
                iTXt('Title', 'kitty title'),
                iTXt('Author', 'kitty author'),
                iTXt('Description', 'kitty description'),
                iTXt('Copyright', 'kitty copyright'),
                iTXt('Creation', 'kitty creation'),
                iTXt('Software', 'kitty software'),
                iTXt('Disclaimer', 'kitty disclaimer'),
                iTXt('Warning', 'kitty warning'),
                iTXt('Source', 'kitty source'),
                iTXt('Comment', 'kitty comment'),
            ], max_elements=1),
        ]),
        # Chunk('', []),
        # Chunk('', []),
        # Chunk('', []),
        # Chunk('', []),
        # Chunk('', []),
        # Chunk('', []),
    ], max_elements=3),
    Chunk('IDAT', name='last idat', data_fields=[
        RandomBytes(name='data', value='000000000000000000000000000000000000'.decode('hex'), min_length=5,
                    max_length=10000, encoder=ZLIB_COMPRESS)
    ]),
    Chunk('IEND')
])
