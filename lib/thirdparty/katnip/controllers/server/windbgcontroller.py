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

import time
import os
import threading
import traceback
from winappdbg import win32, Debug, Crash

try:
    from winappdbg import CrashDAO
except ImportError:
    raise ImportError("Error: SQLAlchemy is not installed!")

from kitty.core.threading_utils import FuncThread
from kitty.controllers import BaseController


def _my_event_handler(self, event):
    '''
    handle debugger events
    '''

    code = event.get_event_code()

    if code == win32.EXCEPTION_DEBUG_EVENT and event.is_last_chance():
        self._crash_event_complete.clear()
        self.logger.warning("Crash detected, storing crash dump in database...")
        self.report.failed('crash detected')
        self.report.add('event name', event.get_event_name())
        self.report.add('event code', code)

        # Generate a minimal crash dump.
        crash = Crash(event)

        # You can turn it into a full crash dump (recommended).
        # crash.fetch_extra_data( event, takeMemorySnapshot = 0 ) # no memory dump
        # crash.fetch_extra_data( event, takeMemorySnapshot = 1 ) # small memory dump
        crash.fetch_extra_data(event, takeMemorySnapshot=2)  # full memory dump

        self.report.add('crash_isExploitable', crash.isExploitable())

        self.report.add('crash_briefReport', crash.briefReport())
        self.report.add('crash_fullReport', crash.fullReport())
        self.report.add('crash_timestamp', crash.timeStamp)
        self.report.add('crash_signature', crash.signature)

        # Connect to the database. You can use any URL supported by SQLAlchemy.
        # For more details see the reference documentation.
        dao = CrashDAO(self._sql_crash_db)

        # If you do this instead, heuristics are used to detect duplicated
        # crashes so they aren't added to the database.
        dao.add(crash, allow_duplicates=False)

        # Kill the process.
        self._process.kill()

    # DO WE NEED THIS ???
    if 'Process termination event' == event.get_event_name():
        self.logger.debug('detected process termination event code=%d' % code)
        self.logger.debug('debugee count=%s' % self._debug.get_debugee_count())
        self.logger.debug('debugee pids=%s' % self._debug.get_debugee_pids())
        # event.get_process().kill()
        # self._debug.stop()
        # self._process = None


class WinAppDbgController(BaseController):
    '''
    WinAppDbgController controls a server process
    by starting it on setup making sure it stays up.
    It uses winappdbg to attach to the target processes.
    '''

    def __init__(self, name, process_path, process_args=[], sql_crash_db='sqlite:///crashes.sqlite', logger=None):
        '''
        :param name: name of the object
        :param process_path: path to the target executable
        :param process_args: arguments to pass to the process
        :param attach: try to attach if process path
        :param sql_crash_db: sql alchemy connection string to crash db (default:sqlite:///crashes.sqlite)
        :param logger: logger for this object (default: None)
        '''
        super(WinAppDbgController, self).__init__(name, logger)
        assert(process_path)
        assert(os.path.exists(process_path))
        self._process_path = process_path
        self._process_name = os.path.basename(process_path)
        self._process_args = process_args
        self._process = None
        self._sql_crash_db = sql_crash_db
        self._crash_event_complete = threading.Event()
        self._server_is_up = threading.Event()
        self._crash_event_complete.set()
        self._debug = Debug(lambda x: _my_event_handler(self, x), bKillOnExit=True)

    def _debug_server(self):
        '''
        debugger thread
        '''
        try:
            self._process = None
            # Start a new process for debugging.
            argv = [self._process_path] + self._process_args
            self.logger.debug('debugger starting server: %s' % argv)
            try:
                self._process = self._debug.execv(argv, bFollow=True)
            except WindowsError:
                self.logger.error('debug_server received exception', traceback.fmt_exc())
            self._pid = self._process.get_pid()
            self.logger.info('process started. pid=%d' % self._pid)

            # Wait for the debugee to finish.
            self._server_is_up.set()
            self._debug.loop()
        except:
            self.logger.error('Got an exception in _debug_server')
            self.logger.error(traceback.format_exc())
        # Stop the debugger.
        finally:
            self._debug.stop()
            self._process = None
            self._pid = -1
            self._crash_event_complete.set()

    def _start_server_thread(self):
        '''
        start the server thread
        '''
        self._server_is_up.clear()
        self.server_thread = FuncThread(self._debug_server)
        self.server_thread.start()
        self.logger.info('waiting for server to be up')
        self._server_is_up.wait()
        self.logger.info('server should be up')

    def _kill_all_processes(self):
        '''
        kill all processes with the same name
        :return: True if all matching processes were killed properly, False otherwise
        '''
        res = True
        # Lookup the currently running processes.
        self._debug.system.scan_processes()
        # For all processes that match the requested filename...
        for (process, name) in self._debug.system.find_processes_by_filename(self._process_name):
            process_pid = process.get_pid()
            self.logger.info('found process %s (%d) - trying to kill it' % (name, process_pid))
            try:
                process.kill()
                self.logger.info('successfully killed %s (%d)' % (name, process_pid))
            except:
                self.logger.error('failed to kill %s (%d) [%s]' % (name, process_pid, traceback.format_exc()))
                res = False
        return res

    def setup(self):
        '''
        Called at the beginning of a fuzzing session.
        Will start the server up.
        '''
        self._stop_process()
        self._start_server_thread()

    def teardown(self):
        self._stop_process()
        self._process = None
        super(WinAppDbgController, self).teardown()

    def pre_test(self, test_number):
        super(WinAppDbgController, self).pre_test(test_number)
        if not self._is_victim_alive():
            self.logger.error('victim is dead, restarting...')
            # self.report.failed('server is down during pre_test - failure it probably from previous test (%d)' % (test_number-1))
            self._restart()
            self._crash_event_complete.set()
        else:
            self.logger.debug('victim is alive (pid=%d)' % self._pid)

    def post_test(self):
        self.logger.debug('in')
        time.sleep(1)
        self.logger.debug('after sleep')
        res = self._crash_event_complete.wait()
        self.logger.debug('after wait')
        if not res:
            self.report.failed('incomplete crash detected')
        super(WinAppDbgController, self).post_test()
        self.logger.debug('out')

    def _stop_process(self):
        '''
        Stop the process (if running)
        '''
        return self._kill_all_processes()

    def _stop_process_old(self):
        '''
        :return: True if process was killed, False otherwise
        '''
        if self._is_victim_alive():
            self._process.kill()
            time.sleep(0.5)
            if self._is_victim_alive():
                self._process.kill()
                time.sleep(0.5)
                if self._is_victim_alive():
                    raise Exception('Failed to kill client process')
            self._debug.stop()
            return True
        else:
            self._debug.stop()
            return False

    def _restart(self):
        '''
        restart the process
        '''
        self._stop_process()
        self.server_thread.join(1)
        time.sleep(3)
        self._server_is_up.clear()
        self._start_server_thread()

    def _is_victim_alive(self):
        '''
        check if process running
        '''
        if self._process:
            self.logger.debug('process pid: %d' % self._pid)
            is_alive = self._process.is_alive()
            is_debugee_started = self._debug.is_debugee_started(self._pid)
            self.logger.debug('is_alive = %s' % is_alive)
            self.logger.debug('is_debugee_started = %s' % is_debugee_started)
            return (is_alive and is_debugee_started)
        else:
            self.logger.debug('_process is None')
        return False
