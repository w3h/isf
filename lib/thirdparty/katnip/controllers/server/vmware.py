# Copyright (C) 2016 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# This module was authored and contributed by dark-lbp <jtrkid@gmail.com>
# and yformaggio <Github.com/yformaggio>
#
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

from kitty.controllers.base import BaseController
import time
import subprocess
import glob


class VMWareController (BaseController):
    '''
    This is a Base vmware Controler.To use this VMWareController you should reference this class
    and implement is_victim_alive function.

    :example:

        ::

            class MyVMWareController(VMWareController):
                def __init__(self, name, vmrun, vmx, host, port, background=True, logger=None, snap_name=None):
                    super(MyVMWareController, self).__init__(name, vmrun, vmx, background=background, logger=logger, snap_name=snap_name)
                    self._host = host
                    self._port = port

                def is_victim_alive(self):
                    # SYN check
                    self.active = False
                    try:
                        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.s.settimeout(1)
                        self.s.connect((self._host, self._port))
                        self.s.close()
                        self.active = True
                    except Exception:
                        return self.active
                    return self.active

            controller = MyVMWareController('VMWare Controller', vmrun='/path/to/vmrun', vmx='/path/to/vmx',
                 host='Target_IP' ,port=Target_port, background=True, snap_name='Snapshot name')

    '''

    def __init__(self, name, vmrun, vmx, background=True, logger=None, snap_name=None):
        '''
        :param name: name of the object (default: None)
        :param vmrun: path of vmrun
        :param vmx: path of the vmx file or vm machine folder
        :param background: runing vm at background (default: True)
        :param logger: logger for the controller (default: None)
        :param snap_name: Snapshot name to revert to on restart (default: None)
        :example:

            ::
                controller = VMWareController('VMWare Controller', vmrun='/path/to/vmrun', vmx='/path/to/vmx',
                 background=True, snap_name='Snapshot name')
        '''

        super(VMWareController, self).__init__(name, logger)
        # Get vmrun path
        self._vmrun = vmrun
        # Get vmx file name
        self._vmx = self._get_vmx_path(vmx)
        self._snap_name = snap_name
        self.background = background

    def setup(self):
        super(VMWareController, self).setup()
        self._restart_target()
        if not self.is_victim_alive():
            msg = 'Controller cannot start target'
            raise Exception(msg)

    def teardown(self):
        super(VMWareController, self).teardown()
        if not self.is_victim_alive():
            msg = 'Target is already down'
            self.logger.error(msg)
        else:
            msg = 'Test Finish'
            self.logger.info(msg)

    def post_test(self):
        super(VMWareController, self).post_test()
        if not self.is_victim_alive():
            self.logger.error("Target does not respond")
            self.report.failed('Target does not respond')

    def pre_test(self, test_number):
        # catch crash which last test case missed
        if not self.is_victim_alive():
            self.logger.error("VM is not running or last test crash the target")
            self.logger.error("Tring to reset VM")
            self.report.failed("VM is not running or last test crash the target")
            self._restart_target()
        super(VMWareController, self).pre_test(test_number)

    def _get_vmx_path(self, vmx):
        """
        Get vmx file path
        :param vmx: path of the vmx file or vm machine folder
        :return: real vmx path
        """
        if vmx[-4:] != '.vmx':
            vmx = glob.glob(vmx + '//*.vmx')
            if len(vmx) == 1:
                vmx = vmx[0]
            else:
                vmx = None
                self.logger.error("didn't find vmx file, exit.")
                raise Exception("Cannot find vmx file please check input")
        return vmx

    def _vmcommand(self, command, log_message=None):
        """
        Wrapper for used vmrun commands.
        :param command: vmrun command to execute
        :log_message: log message
        """
        if self.logger and log_message:
            self.logger.debug(log_message)
        return subprocess.check_call(command)

    ###
    # VMRUN COMMAND WRAPPERS
    ###

    def _delete_snapshot(self, snap_name=None):
        """
        Delete specific snapshots of VMWare VM
        :param Snapshot name to delete (default: None)
        """
        if not snap_name:
            snap_name = self._snap_name
        log_message = "Deleting snapshot: %s" % snap_name
        command = [self._vmrun, "deleteSnapshot", snap_name]
        return self._vmcommand(command, log_message)

    def _list(self):
        """
        List all VMWare VMs
        """
        log_message = "listing running virtual machine"
        command = [self._vmrun, "list"]
        return self._vmcommand(command, log_message)

    def _list_snapshots(self):
        """
        List all snapshots of specific VMWare VM
        """
        log_message = "listing snapshots"
        command = [self._vmrun, "listSnapshots", self._vmx]
        return self._vmcommand(command, log_message)

    def _reset(self):
        """
        Reset the VMWare VM
        """
        log_message = "Resetting virtual machine"
        command = [self._vmrun, "reset", self._vmx]
        return self._vmcommand(command, log_message)

    def _revert_to_snapshot(self, snap_name=None):
        """
        Revert snapshot
        """
        if not snap_name:
            snap_name = self._snap_name
        log_message = "reverting to snapshot: %s" % snap_name
        command = [self._vmrun, "revertToSnapshot", self._vmx, snap_name]
        return self._vmcommand(command, log_message)

    def _snapshot(self, snap_name=None):
        """
        Take a snapshot of the  VMWare VM
        """
        if not snap_name:
            snap_name = self._snap_name
        log_message = ("taking snapshot: %s" % snap_name)
        command = [self._vmrun, "snapshot", self._vmx, snap_name]
        return self._vmcommand(command, log_message)

    def _start_vm(self):
        """
        Start the VMWare VM
        """
        log_message = "Starting the virtual machine {}".format(self._vmx)
        if self.background:
            command = [self._vmrun, "start", self._vmx, "nogui"]
        else:
            command = [self._vmrun, "start", self._vmx]
        return self._vmcommand(command, log_message)

    def _stop_vm(self):
        """
        Stops the VM
        """
        log_message = "Stopping the virtual machine {}".format(self._vmx)
        command = [self._vmrun, "stop", self._vmx]
        return self._vmcommand(command, log_message)

    def _suspend(self):
        """
        Suspend VM execution
        """
        log_message = "Suspending the virtual machine {}".format(self._vmx)
        command = [self._vmrun, "suspend", self._vmx]
        return self._vmcommand(command, log_message)

    ###
    # EXTENDED COMMANDS
    ###

    def _restart_target(self):
        """
        Revert to the specified snapshot and start the virtual machine.
        """
        self._revert_to_snapshot()
        self._start_vm()
        # Wait for the snapshot to come alive.
        self._wait()

    def _wait(self):
        """
        Adding some time for the VM to come up
        """
        while not self.is_victim_alive():
            time.sleep(0.5)
