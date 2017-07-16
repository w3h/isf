#!/usr/bin/env python
# coding=utf-8

from core.exploit import *
from main import scan_new


class MyScript(BaseExploit):
    register_info = {
        'ID' : 'ICF-2017-F0010001',
        'Name' : '控制器扫描工具',
        'Author' : 'w3h',
        'License': ISF_LICENSE,
        'Create_Date' : '2015-04-09',
        'Description' : '''控制器扫描工具，目前支持S7和Modbus。''',
    }

    register_options = [
        mkopt('--TargetIp', action='store', dest='TargetIp', type='string',
                    default="", help='The Target is ip address or list or file'),
        mkopt('--Ports', action='store', dest='Ports', type='string',
                    default="", help='The Target Ports [102,502]'),
    ]

    def exploit(self, *args, **kwargs):
        targetip = self.getParam("TargetIp")
        ports = self.getParam("Ports")

        if os.path.isfile(targetip):
            scan_new(targetip, None, ports)
        else:
            scan_new({}, targetip, ports)


MainEntry(MyScript, __name__)
