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
import paramiko
try:
    import scp
    scp_imported = True
except ImportError:
    scp_imported = False


class ReconnectingSSHConnection(object):
    """
    A wrapper around paramiko's SSHClient which handles connection dropouts gracefully.
    """
    def __init__(self, hostname, port, username, password, use_scp=False, scp_sanitize=None):
        """
        :param hostname: ssh server hostname or ip
        :param port: ssh server port
        :param username: ssh login username
        :param password: ssh login password
        :param use_scp: use the SCP protocol for transferring files instead of SFTP (default: False)
        :param scp_sanitize: sanitization function used on filenames passed to the scp module, if used. (defaut: no sanitization)
        """
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        self._use_scp = use_scp
        self._scp_sanitize = scp_sanitize if callable(scp_sanitize) else lambda s:s

        if self._use_scp and not scp_imported:
            raise Exception("The scp package needs to be installed in order to copy files with scp")

        self._paramiko = paramiko.SSHClient()
        self._paramiko.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def _ensure_connected(self):
        if self._paramiko.get_transport() is None or not self._paramiko.get_transport().isAlive():
            self._paramiko.connect(self._hostname, self._port, self._username, self._password)

    def _sftp(self):
        return self._paramiko.open_sftp()

    def _scp(self):
        return scp.SCPClient(self._paramiko.get_transport(), sanitize=self._scp_sanitize)
            
    def exec_command(self, command):
        """
        Execute a command on the ssh server.

        :param command: the command string to execute
        :returns: a tuple of the return_code from the command, the stdout output and the stderr output
        """
        self._ensure_connected()
        stdin, stdout, stderr = self._paramiko.exec_command(command)
        return_code = stdout.channel.recv_exit_status()
        return return_code, stdout.read(), stderr.read()

    def close(self):
        """
        Close the connection
        """
        self._paramiko.close()

    def put(self, localpath, remotepath):
        """
        Put a file on the ssh server using sftp or scp.

        :param localpath: the local path to the file to copy
        :param remotepath: the remote path to which the file should be copied
        :raises: OSException or IOException if file not found
        """
        self._ensure_connected()
        if not self._use_scp:
            self._sftp().put(localpath, remotepath)
        else:
            self._scp().put(localpath, remotepath)

    def get(self, remotepath, localpath):
        """
        Get a file from the ssh server using sftp or scp.

        :param remotepath: the remote path of the file to be copied
        :param localpath: the local path to which the file should be copied
        :raises: OSException or IOException if file not found
        """
        self._ensure_connected()
        if not self._use_scp:
            self._sftp().get(remotepath, localpath)
        else:
            self._scp().get(remotepath, localpath)

    def remove(self, remotepath):
        """
        Remove a file from the ssh server using sftp or scp.

        :param remotepath: the remote path of the file to be removed
        :raises: OSException or IOException if file not found
        """
        self._ensure_connected()
        if not self._use_scp:
            self._sftp().remove(remotepath)
        else:
            res, stdout, stderr =  self.exec_command("/bin/rm %s" % remotepath)
            if res != 0:                
                raise IOError(stderr)


