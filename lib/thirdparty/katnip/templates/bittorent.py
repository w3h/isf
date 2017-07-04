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
Tempalte of a bittorent file.

Use it directly, or copy and modify it,
as it generates many ( > 1M ) payloads.

This template is based on the MetaInfo file structure:
https://wiki.theory.org/BitTorrentSpecification#Metainfo_File_Structure
'''
from katnip.legos.bittorrent import *
from kitty.model import *


bittorent_base_template = Template(name='metainfo', fields=[
    TDict(fuzz_delims=False, fields={
        'info': Container(name='info', fields=[
            OneOf(name='info_multi', fields=[
                TDict(name='info_single', fuzz_delims=False, fields={
                    # common fields
                    'piece-length': TInteger(value=20),
                    'pieces': TString(value=RandomBytes(value='\x00'*20*20, min_length=0, max_length=1000, step=20, name='pieces value')),
                    'private': TInteger(value=0),
                    # single file fields
                    'name': TString(value='the file name', name='name value'),
                    'length': TInteger(value=400),
                    'md5sum': TString(value=RandomBytes(value='AA' * 16, min_length=0, max_length=1000, name='md5sum value')),
                }),
                TDict(name='info_multi', fuzz_delims=False, fields={
                    # common fields
                    'piece-length': TInteger(value=20),
                    'pieces': TString(value=RandomBytes(value='\x00'*20*20, min_length=0, max_length=1000, step=20, name='pieces value')),
                    'private': TInteger(value=0),
                    # multi file fields
                    'name': TString(value='kitty', name='directory path'),
                    'files': TList(name='files', fuzz_delims=False, fields=[
                        TDict(name='file1', fuzz_delims=False, fields={
                            'name': TString(value='the file name', name='file1 name value'),
                            'length': TInteger(value=400),
                            'md5sum': TString(value=RandomBytes(value='AA' * 16, min_length=0, max_length=1000, name='file1 md5sum value')),
                        }),
                        TDict(name='file2', fuzz_delims=False, fields={
                            'name': TString(value='the file name', name='file2 name value'),
                            'length': TInteger(value=400),
                            'md5sum': TString(value=RandomBytes(value='AA' * 16, min_length=0, max_length=1000, name='file2 md5sum value')),
                        }),
                        TDict(name='file3', fuzz_delims=False, fields={
                            'name': TString(value='the file name', name='file3 name value'),
                            'length': TInteger(value=400),
                            'md5sum': TString(value=RandomBytes(value='AA' * 16, min_length=0, max_length=1000, name='file3 md5sum value')),
                        })
                    ])
                })
            ])
        ]),
        'announce': TString('http://anounce.url'),  # TODO
        'announce-list': TList(),  # TODO
        'creation-date': TInteger(1),  # TODO
        'comment': TString(value='my comment'),
        'created-by': TString(value='kitty'),
        'encoding': TString('utf-8')
    }, name='topmost')
])