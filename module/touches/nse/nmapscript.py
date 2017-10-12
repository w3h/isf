#!/usr/bin/env python
# coding=utf-8

from core.exploit import *
from nmap import nmap


class MyScript(BaseExploit):
    register_info = {
        'ID' : 'ICF-2017-F0010003',
        'Name' : 'NMAP工控扫描工具',
        'Author' : 'w3h',
        'License': ISF_LICENSE,
        'Create_Date' : '2015-04-09',
        'Description' : '''NMAP工控扫描工具。''',
    }

    register_options = [
        mkopt('--TargetIp', action='store', dest='TargetIp', type='string',
                    default="", help='The Target is ip address or list or file'),
        mkopt('--TargetPort', action='store', dest='TargetPort', type='string',
                    default="", help='The Target Port'),
        mkopt('--Script', action='store', dest='Script', type='string',
                    default="", help='The Namp Script Name'),
        mkopt('--HPARA', action='store', dest='HPARA', type='string',
              default="", help='The hide parameter'),
    ]

    def exploit(self, *args, **kwargs):
        nm = nmap.PortScanner()
        scriptname = self.getParam("Script")
        p = os.path.realpath(__file__)
        p = os.path.dirname(p)
        p = os.path.join(p, scriptname)
        p = p.replace('\\', "/")
        ments = "-p %s --script=%s" % (str(self.TargetPort), p)
        ret = nm.scan(self.TargetIp, arguments=ments)
        if not ret:
            return ret

        UniPrinter().pprint(ret['scan'][self.TargetIp])
        return ret['scan'][self.TargetIp]

MainEntry(MyScript, __name__)
