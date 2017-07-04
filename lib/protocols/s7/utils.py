#!/usr/bin/env python
# -*- coding: utf-8 -*-


def hash_password(password):
    password_hash_new = ''
    # Password = '\x01\x02\x03\x04\x05\x06\x07\x08'
    if len(password) < 1 or len(password) > 8:
        pass
    else:
        password_hash = password + '20'.decode('hex') * (8 - len(password))
        for i in range(8):
            if i < 2:
                temp_data = ord(password_hash[i])
                temp_data = temp_data ^ 0x55
                password_hash_new = password_hash_new + str(chr(temp_data))
            else:
                temp_data1 = ord(password_hash[i])
                temp_data2 = ord(password_hash_new[i - 2])
                temp_data1 = temp_data1 ^ 0x55 ^ temp_data2
                password_hash_new = password_hash_new + str(chr(temp_data1))
        return password_hash_new


def dehash_password(Hash):
    password = ''
    password_hash = Hash
    for i in range(8):
        if i < 2:
            temp_data = ord(password_hash[i])
            temp_data = temp_data ^ 0x55
            password = password + str(unichr(temp_data))
        else:
            temp_data1 = ord(password_hash[i])
            temp_data2 = ord(Hash[i - 2])
            temp_data1 = temp_data1 ^ temp_data2 ^ 0x55
            password = password + str(unichr(temp_data1))
    for i in range(8):
        if password[-1] == ' ':
            password = password[: -1]
    return password
