#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""
Copyright (c) 2015-2016 By W3H. All rights reserved.
See the file 'docs/COPYING' for copying permission
"""

class POC_ERRCODE:
    SUCCESS = 1
    FAILED = 0

class VULTYPE(object):
    DOS = {'en': "dos", 'zh': "拒绝服务"}
    INFO_DISC = {'en': "Information Disclosure", 'zh': "信息泄露"}
    XSS = {"en": 'Cross Site Scripting', 'zh': '跨站'}
    WP = {'en': "Weak Password", 'zh': '弱口令'}
    DP = {'en': "Default Password", 'zh': '默认口令'}
    REP = {'en': "Replay Attacks", 'zh': '重放攻击'}
    BRUTE = {'en': "Brute", 'zh': '暴力破解'}
    BACKDOOR = {'en': "Backdoor", 'zh': '后门'}
    OF = {'en': "Overflow", 'zh': '缓充区溢出'}
    DT = {'en': "Directory Traversal", 'zh': '目录遍历'}
    OTHER = {'en': "Other", 'zh': '其它'}

class VENDOR(object):
    AB = {'en': 'Rockwell', 'zh': '罗克韦尔'}
    ABB = {'en': 'ABB', 'zh': '贝利'}
    SI = {'en': 'Siemens', 'zh': '西门子'}
    HSM = {'en': 'Hirschmann', 'zh': '赫思曼'}
    BF = {'en': 'Bechoff', 'zh': '倍福'}
    SID = {'en': 'Schneider', 'zh': '施耐德'}
    HYS = {'en': 'HollySys', 'zh': '和利时'}
    HYW = {'en': 'Honeywell', 'zh': '霍尼韦尔'}
    GE = {'en': 'General Electric', 'zh': '通用电气'}
    MX = {'en': 'Moxa', 'zh': '摩莎'}
    ES = {'en': 'Ericsson', 'zh': '爱立信'}
    AD = {'en': 'Advantech', 'zh': '研华'}
    OMN = {'en': 'Omron', 'zh': '欧姆龙'}
    MSH = {'en': 'Mitsubish', 'zh': '三菱'}
    BHM = {'en': 'Bachmann', 'zh': '巴赫曼'}
    KV = {'en': 'KingView', 'zh': '组态王'}
    ALL = {'en': 'All', 'zh': '全部'}

class RISK(object):
    H = {'en': 'Hight Risk', 'zh': '高风险'}
    M = {'en': 'Middle Risk', 'zh': '中风险'}
    L = {'en': 'Low Risk', 'zh': '低风险'}