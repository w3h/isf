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
bootp basic Template
'''

from kitty.model import *


test_bootp_template = Template(name='test bootp', fields=[
    # 1 is Request 2 is reply
    Byte(1, encoder=ENC_INT_LE, name='Op'),
    # Hardware type
    Byte(1, encoder=ENC_INT_LE, name='HType'),
    # Hardware Address Length
    Byte(6, encoder=ENC_INT_LE, name='HLen'),
    # Hops
    Byte(0, encoder=ENC_INT_LE, name='Hops'),
    # Transaction ID
    RandomBytes('\xaa\xbb\xcc\xdd', min_length=4, max_length=4, name='XID'),
    # Seconds elapsed
    Word(0, encoder=ENC_INT_LE, name='Secs'),
    # Unicast flag
    Word(0, encoder=ENC_INT_LE, name='Flags'),
    # Client IP Address
    Dword(0, encoder=ENC_INT_LE, name='CIAddr'),
    # Your IP Address
    Dword(0, encoder=ENC_INT_LE, name='YIAddr'),
    # Server IP Address
    Dword(0, encoder=ENC_INT_LE, name='SIAddr'),
    # Gateway IP Address
    Dword(0, encoder=ENC_INT_LE, name='GIAddr'),
    Pad(
        pad_length=16 * 8,
        # Client Hardware Address
        fields=String('\xaa\xbb\xcc\xdd\xee\xff', max_size=16, name='CHAddr')
    ),
    Pad(
        pad_length=64 * 8,
        # Server Host Name
        fields=String('\x00' * 64, max_size=64, name='SName')
    ),
    Pad(
        pad_length=128 * 8,
        # Boot filename
        fields=String('\x00' * 128, max_size=128, name='SName')
    ),
    Dword(0x63538263, encoder=ENC_INT_LE, name='Magic_Cookie'),
    Pad(
        pad_length=60 * 8,
        # Server Host Name
        fields=String('\x00' * 60, max_size=60, name='Vend')
    ),
    Repeat(
        min_times=0,
        max_times=160,
        fields=[
            RandomBytes('\x00' * 8, min_length=8, max_length=9, name='TLV Type'),
            SizeInBytes('TLV Value', length=8, encoder=ENC_INT_LE, fuzzable=True, name='TLV Length'),
            String('\x00', max_size=255, name='TLV Value'),
        ],
        name='Random TLV'
    )
])
