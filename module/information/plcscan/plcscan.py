#!/usr/bin/env python
# coding=utf-8

from core.exploit import *
from main import scan_new


class MyPoc(BaseExploit):
    pocinfo = {
        'ID' : 'ICF-2017-F0010001',
        'Name' : '控制器扫描工具',
        'Author' : 'w3h',
        'Create_Date' : '2015-04-09',
        'Description' : '''控制器扫描工具，目前支持S7和Modbus。''',
    }

    register_options = [
        make_option('--TargetIp', action='store', dest='TargetIp', type='string',
                    default="", help='The Target is ip address'),
        make_option('--TargetIpList', action='store', dest='TargetIpList', type='string',
                    default="", help='The Target is ip address list'),
        make_option('--TargetIpFile', action='store', dest='TargetIpFile', type='string',
                    default="", help='The Target is local file of ip address'),
        make_option('--Ports', action='store', dest='Ports', type='string',
                    default="", help='The Target Ports [102,502]'),
    ]

    def exploit(self, *args, **kwargs):
        targetip = self.getParam("TargetIp")
        targetiplist = self.getParam("TargetIpList")
        targetipfile = self.getParam("TargetIpFile")
        ports = self.getParam("Ports")

        if targetip:
            scan_new({}, targetip, ports)
        elif targetiplist:
            scan_new({}, targetiplist, ports)
        elif targetipfile:
            scan_new(targetipfile, None, ports)
        else:
            raise


MainEntry(MyPoc, __name__)
