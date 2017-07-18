#!/usr/bin/env python
# coding=utf-8

from core.exploit import *
from main import scan_new


class NewOptions:
    def __int__(self):
        self.src_tsap = ''
        self.dst_tsap = ''


class MyScript(BaseExploit):
    register_info = {
        'ID' : 'ICF-2017-F0010001',
        'Name' : '控制器扫描工具',
        'Author' : 'w3h',
        'License': ISF_LICENSE,
        'Create_Date' : '2017-04-09',
        'Description' : '''控制器扫描工具，目前支持S7和Modbus。''',
    }

    register_options = [
        mkopt_rport(102),
        mkopt("--STsap", help="Try this src-tsap (list) (default: 0x100,0x200)", type="string",
                    default="0x100,0x200", metavar="LIST"),
        mkopt("--DTsap", help="Try this dst-tsap (list) (default: 0x102,0x200,0x201)", type="string",
                    default="0x102,0x200,0x201", metavar="LIST"),
    ]

    def exploit(self, *args, **kwargs):
        stsap = self.getParam("STsap")
        dtsap = self.getParam("DTsap")
        opt = NewOptions()
        opt.src_tsap = stsap
        opt.dst_tsap = dtsap
        scan_new({}, self.TargetIp, self.TargetPort, opt)


MainEntry(MyScript, __name__)
