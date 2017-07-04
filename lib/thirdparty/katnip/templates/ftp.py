# Copyright (C) 2016 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# This file is part of Katnip.
#
# Katnip is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Katnip is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Katnip.  If not, see <http://www.gnu.org/licenses/>.

'''
FTP Protocol command templates.
Based on RFC 959 (https://www.ietf.org/rfc/rfc959.txt)

Nice presentation about FTP can be found here:
http://www.csun.edu/~jeffw/Semesters/2006Fall/COMP429/Presentations/Ch25-FTP.pdf
'''

from kitty.model import *


class TelnetString(Template):
    '''
    represents: [Command]<SP>[Parameter]<CRLF>
    '''
    def __init__(self, command, optional=False, parameter=None, name=None):
        '''
        :param command: command string
        :param optional: has optional parameter (default: False)
        :param parameter: optional parameter string(default: None)
        :param name: name of the field (default: None)
        '''
        if name is None:
            name = 'CMD_%s' % command
        fields = []
        fields.append(String(value=command, name='string_COMMAND_%s' % command))
        if parameter is not None:
            if optional:
                optional_fields = []
                optional_fields.append(Delimiter(value=' ', name='delim_space'))
                optional_fields.append(String(value=parameter, name='string_%s_PARAM_' % command))
                fields.append(Repeat(optional_fields, min_times=0, max_times=2))
            else:
                fields.append(Delimiter(value=' ', name='delim_space'))
                fields.append(String(value=parameter, name='string_%s_PARAM_' % command))
        fields.append(Delimiter(value='\r\n', name='delim_CRLF', fuzzable=False))
        super(TelnetString, self).__init__(name=name, fields=fields)

# 4.1.1.  ACCESS CONTROL COMMANDS (page 25)
# USER <SP> <username> <CRLF>
user_command = TelnetString(command='USER', parameter='user')

# PASS <SP> <password> <CRLF>
pass_command = TelnetString(command='PASS', parameter='user')

# ACCT <SP> <account-information> <CRLF>
acct_command = TelnetString(command='ACCT', parameter='anonymous')

# CWD  <SP> <pathname> <CRLF>
cwd_command = TelnetString(command='CWD', parameter='/')

# CHANGE TO PARENT DIRECTORY (CDUP)
# CDUP <CRLF>
cdup_command = TelnetString(command='CDUP')

# more commands ...
# SMNT <SP> <pathname> <CRLF>
smnt_command = TelnetString(command='SMNT', parameter='/etc/passwd')

# LOGOUT (QUIT)
# QUIT <CRLF>
quit_command = TelnetString(command='QUIT')

# REIN <CRLF>
rein_command = TelnetString(command='REIN')
# PORT <SP> <host-port> <CRLF>
port_command = TelnetString(command='PORT', parameter='1234')
# PASV <CRLF>
pasv_command = TelnetString(command='PASV')
# TYPE <SP> <type-code> <CRLF>
type_command = TelnetString(command='TYPE', parameter='1234')
# STRU <SP> <structure-code> <CRLF>
stru_command = TelnetString(command='STRU', parameter='1234')
# MODE <SP> <mode-code> <CRLF>
mode_command = TelnetString(command='MODE', parameter='KittyDir')
# RETR <SP> <pathname> <CRLF>
retr_command = TelnetString(command='RETR', parameter='KittyDir')
# STOR <SP> <pathname> <CRLF>
stor_command = TelnetString(command='STOR', parameter='KittyDir')
# STOU <CRLF>
stou_command = TelnetString(command='STOU')
# APPE <SP> <pathname> <CRLF>
appe_command = TelnetString(command='APPE', parameter='KittyDir')
# ALLO <SP> <decimal-integer>
#     [<SP> R <SP> <decimal-integer>] <CRLF>
allo_command = Template(name='CMD_ALLO', fields=[
    String(value='ALLO', name='string_COMMAND_ALLO'),
    Repeat( [
                Delimiter(value=' ', name='delim_space1'),
                UInt8(value=17, name='decimal_ALLO_PARAM_1', encoder=ENC_INT_DEC),
                Delimiter(value=' ', name='delim_space2'),
                String(value='R', name='string_ALLO_PARAM_2'),
                Delimiter(value=' ', name='delim_space3'),
                UInt8(value=17, name='decimal_ALLO_PARAM_3', encoder=ENC_INT_DEC)
            ],
            min_times=0, max_times=2),
    Delimiter(value='\r\n', name='delim_CRLF', fuzzable=False)
    ])
# REST <SP> <marker> <CRLF>
rest_command = TelnetString(command='REST', parameter='HelloKitty')
# RNFR <SP> <pathname> <CRLF>
rnfr_command = TelnetString(command='RNFR', parameter='KittyDir')
# RNTO <SP> <pathname> <CRLF>
rnto_command = TelnetString(command='RNTO', parameter='KittyDir')
# ABOR <CRLF>
abor_command = TelnetString(command='ABOR')
# DELE <SP> <pathname> <CRLF>
dele_command = TelnetString(command='DELE', parameter='KittyDir')
# RMD  <SP> <pathname> <CRLF>
rmd_command = TelnetString(command='RMD', parameter='KittyDir')
# MKD  <SP> <pathname> <CRLF>
mkd_command = TelnetString(command='MKD', parameter='KittyDir')
# PWD  <CRLF>
pwd_command = TelnetString(command='PWD')
# LIST [<SP> <pathname>] <CRLF>
list_command = TelnetString(command='LIST', parameter='/')
# NLST [<SP> <pathname>] <CRLF>
nlst_command = TelnetString(command='NLST', parameter='KittyDir')
# SITE <SP> <string> <CRLF>
site_command = TelnetString(command='SITE', parameter='HelloKitty')
# SYST <CRLF>
syst_command = TelnetString(command='SYST')
# STAT [<SP> <pathname>] <CRLF>
stat_command = TelnetString(command='STAT', parameter='KittyDir', optional=True)
# HELP [<SP> <string>] <CRLF>
help_command = TelnetString(command='HELP', parameter='HelloKitty', optional=True)
# NOOP <CRLF>
noop_command = TelnetString(command='SYST')

