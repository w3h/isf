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
Extensions to Kitty's encoders.

This module contain encoders that were excluded from Kitty
because they are too esoteric or because they require external
dependencies that might be harder to install on some platforms.

External dependencies that are not installed by default:
pycrypto
'''

from Crypto.Cipher import AES, DES, DES3
from bitstring import Bits
from kitty.model.low_level.encoder import StrEncoder
from kitty.core import KittyException


class BlockCipherEncoder(StrEncoder):
    '''
    Generic block cipher encoder.
    '''
    _key_sizes_ = None
    _iv_size_ = None
    _block_size_ = None
    _default_key_size_ = None
    _default_mode_ = None

    def __init__(self, key=None, iv=None, mode=None, key_size=None, key_provider=None, padder=None):
        '''
        All fields default to None.
        :type key: str
        :param key: encryption key, must be 8 bytes
        :param iv: iv, must be 8 bytes long, if None - use zeros
        :param mode: encrytion mode
        :param key_size: size of key, should be provided only when using key provider
        :type key_provider: function(key_size) -> str
        :param key_provider: function that returns key
        :type padder: function(str, block_size) -> str
        :param padder: function that pads the data, if None - will pad with zeros
        '''
        self.key = key
        self.iv = iv
        self.mode = mode
        self.key_size = key_size
        self.key_provider = key_provider
        self.padder = padder
        self._check_args()

    def _check_args(self):
        '''
        This is a massive check. argh...
        '''
        if self.key:
            if len(self.key) not in self._key_sizes_:
                raise KittyException('provided key size (%d) not in %s' % (len(self.key), self._key_sizes_))
            if self.key_provider:
                raise KittyException('You should not provide both key and key_provider.')
        elif self.key_provider:
            if not callable(self.key_provider):
                raise KittyException('key_provider must be callable')
            if not self.key_size:
                if self._default_key_size_:
                    self.key_size = self._default_key_size_
                else:
                    raise KittyException('key_size should be specified when using key_provider')
            if self.key_size not in self._key_sizes_:
                raise KittyException('key size (%d) not a valid one (use %s)' % (self.key_size, self._key_sizes_))
        else:
            raise KittyException('You need to provide either key or key_provider')
        if not self.iv:
            self.iv = '\x00' * self._iv_size_
        if len(self.iv) != self._iv_size_:
            raise KittyException('Invalid iv size: %#x. Expected: %#x')
        if not self.padder:
            self.padder = self._zero_padder
        if self.mode is None:
            self.mode = self._default_mode_

    def _zero_padder(self, data, blocksize):
        remainder = len(data) % self._block_size_
        if remainder:
            data += '\x00' * (self._block_size_ - remainder)
        return data


class BlockEncryptEncoder(BlockCipherEncoder):
    '''
    Generic block cipher encryption encoder.
    '''

    def encode(self, data):
        self.current_key = self.key
        if self.key_provider:
            self.current_key = self.key_provider(self.key_size)
        cipher = self._cipher_class_.new(key=self.current_key, mode=self.mode, IV=self.iv)
        encrypted = cipher.encrypt(self.padder(data, 16))
        return Bits(bytes=encrypted)


class AesEncryptEncoder(BlockEncryptEncoder):
    '''
    AES encryption encoder.
    See :class:`~katnip.model.low_level.encoders.BlockCipherEncoder` for parameters.
    '''
    _key_sizes_ = [16, 24, 32]
    _iv_size_ = 16
    _block_size_ = 16
    _default_key_size_ = 16
    _default_mode_ = AES.MODE_CBC
    _cipher_class_ = AES


class DesEncryptEncoder(BlockEncryptEncoder):
    '''
    DES encryption encoder.
    See :class:`~katnip.model.low_level.encoders.BlockCipherEncoder` for parameters.
    '''
    _key_sizes_ = [8]
    _iv_size_ = 8
    _block_size_ = 8
    _default_key_size_ = 8
    _default_mode_ = DES.MODE_CBC
    _cipher_class_ = DES


class Des3EncryptEncoder(BlockEncryptEncoder):
    '''
    3DES encryption encoder.
    See :class:`~katnip.model.low_level.encoders.BlockCipherEncoder` for parameters.
    '''
    _key_sizes_ = [16, 24]
    _iv_size_ = 8
    _block_size_ = 8
    _default_key_size_ = 8
    _default_mode_ = DES3.MODE_CBC
    _cipher_class_ = DES3


class BlockDecryptEncoder(BlockCipherEncoder):
    '''
    Generic block cipher decryption encoder.
    See :class:`~katnip.model.low_level.encoders.BlockCipherEncoder` for parameters.
    '''

    def encode(self, data):
        if len(data) % self._block_size_:
            raise KittyException('data must be %d-bytse aligned' % self._block_size_)
        self.current_key = self.key
        if self.key_provider:
            self.current_key = self.key_provider(self.key_size)
        cipher = self._cipher_class_.new(key=self.current_key, mode=self.mode, IV=self.iv)
        decrypted = cipher.decrypt(data)
        # print 'data', data.encode('hex')
        # print 'decrypted', decrypted.encode('hex')
        # print 'current key', self.current_key.encode('hex')
        # print 'IV', self.iv.encode('hex')
        # print 'mode', self.mode
        return Bits(bytes=decrypted)


class AesDecryptEncoder(BlockDecryptEncoder):
    '''
    AES decryption encoder.
    See :class:`~katnip.model.low_level.encoders.BlockCipherEncoder` for parameters.
    '''
    _key_sizes_ = [16, 24, 32]
    _iv_size_ = 16
    _block_size_ = 16
    _default_key_size_ = 16
    _default_mode_ = AES.MODE_CBC
    _cipher_class_ = AES


class DesDecryptEncoder(BlockDecryptEncoder):
    '''
    DES decryption encoder.
    See :class:`~katnip.model.low_level.encoders.BlockCipherEncoder` for parameters.
    '''
    _key_sizes_ = [8]
    _iv_size_ = 8
    _block_size_ = 8
    _default_key_size_ = 8
    _default_mode_ = DES.MODE_CBC
    _cipher_class_ = DES


class Des3DecryptEncoder(BlockDecryptEncoder):
    '''
    3DES decryption encoder.
    See :class:`~katnip.model.low_level.encoders.BlockCipherEncoder` for parameters.
    '''
    _key_sizes_ = [16, 24]
    _iv_size_ = 8
    _block_size_ = 8
    _default_key_size_ = 8
    _default_mode_ = DES3.MODE_CBC
    _cipher_class_ = DES3


def AesCbcEncryptEncoder(key=None, iv=None, key_size=16, key_provider=None, padder=None):
    '''
    AES CBC Encrypt encoder.
    See :class:`~katnip.model.low_level.encoder.AesEncryptEncoder` for parameter description.
    '''
    return AesEncryptEncoder(key, iv, AES.MODE_CBC, key_size, key_provider, padder)


def AesEcbEncryptEncoder(key=None, iv=None, key_size=16, key_provider=None, padder=None):
    '''
    AES ECB Encrypt encoder.
    See :class:`~katnip.model.low_level.encoder.AesEncryptEncoder` for parameter description.
    '''
    return AesEncryptEncoder(key, iv, AES.MODE_ECB, key_size, key_provider, padder)


def AesCbcDecryptEncoder(key=None, iv=None, key_size=16, key_provider=None):
    '''
    AES CBC Decrypt encoder.
    See :class:`~katnip.model.low_level.encoder.AesDecryptEncoder` for parameter description.
    '''
    return AesDecryptEncoder(key, iv, AES.MODE_CBC, key_size, key_provider)


def AesEcbDecryptEncoder(key=None, iv=None, key_size=16, key_provider=None):
    '''
    AES ECB Decrypt encoder.
    See :class:`~katnip.model.low_level.encoder.AesDecryptEncoder` for parameter description.
    '''
    return AesDecryptEncoder(key, iv, AES.MODE_ECB, key_size, key_provider)
