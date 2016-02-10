################################################################################
#
#  Copyright 2014-2015 Eric Lacombe <eric.lacombe@security-labs.org>
#
################################################################################
#
#  This file is part of fuddly.
#
#  fuddly is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  fuddly is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with fuddly. If not, see <http://www.gnu.org/licenses/>
#
################################################################################

import os
import threading
import datetime
import time
import traceback

from libs.external_modules import *
import data_models
from fuzzfmk.global_resources import *
import fuzzfmk.error_handling as eh

class MonitorCondition(object):
    def __init__(self):
        self.lck = threading.Lock()
        self.resume_fuzzing_event = threading.Event()
        self.data_emitted_event = threading.Event()
        self.arm_event = threading.Event()

    def wait_until_data_is_emitted(self):
        while not self.data_emitted_event.is_set():
            self.data_emitted_event.wait(1)

    def wait_until_data_can_be_emitted(self):
        while not self.resume_fuzzing_event.is_set():
            self.resume_fuzzing_event.wait(1)

    def wait_for_data_ready(self):
        while not self.arm_event.is_set():
            self.arm_event.wait(1)

    def notify_data_ready(self):
        self.arm_event.set()

    def notify_data_emission(self):
        with self.lck:
            self.data_emitted_event.set()
            self.resume_fuzzing_event.clear()

    def lets_fuzz_continue(self):
        with self.lck:
            self.resume_fuzzing_event.set()
            self.data_emitted_event.clear()
            self.arm_event.clear()


class Monitor(object):
    def __init__(self, st, fmk_ops):
        self._prj = st
        self.probes = self._prj.get_probes()
        self.fmk_ops = fmk_ops
        self._logger = None
        self._target_status = None

    def set_logger(self, logger):
        self._logger = logger

    def set_strategy(self, strategy):
        self._logger.print_console('*** Monitor refresh in progress... ***\n', nl_before=False, rgb=Color.COMPONENT_INFO)
        self.stop_all_probes()
        self._prj = strategy
        self.probes = self._prj.get_probes()

    def start(self):
        self.__enable = True
        self._target_status = None
        self.monitor_conditions = {}
        self._logger.print_console('*** Monitor is started ***\n', nl_before=False, rgb=Color.COMPONENT_START)
        
    def stop(self):
        self._logger.print_console('*** Monitor stopping in progress... ***\n', nl_before=False, rgb=Color.COMPONENT_INFO)
        self.stop_all_probes()
        self._logger.print_console('*** Monitor is stopped ***\n', nl_before=False, rgb=Color.COMPONENT_STOP)

    def enable_hooks(self):
        self.__enable = True

    def disable_hooks(self):
        self.__enable = False

    def quick_reset_probe(self, name, *args):
        return self._prj.quick_reset_probe(name, *args)

    def start_probe(self, name):
        return self._prj.launch_probe(name)

    def is_probe_launched(self, pname):
        return self._prj.is_probe_launched(pname)

    def stop_probe(self, name):
        ok = self._prj.stop_probe(name)
        if not ok:
            self.fmk_ops.set_error("Probe '%s' does not exist" % name,
                                   code=Error.CommandError)
            return

        if name in self.monitor_conditions:
            self.monitor_conditions[name].notify_data_ready()
            self.monitor_conditions[name].notify_data_emission()
            self.monitor_conditions.pop(name)

        try:
            self._wait_for_probe_termination(name)
        except eh.Timeout:
            self.fmk_ops.set_error("Timeout! Probe '%s' seems to be stuck in its 'main()' method." % name,
                                   code=Error.OperationCancelled)
            return


    def get_evts(self, name):
        '''
        This method is called by the project each time a probe is launched.
        '''
        if name in self.monitor_conditions:
            # this branch is a priori useless
            ret = self.monitor_conditions[name]
        else:
            self.monitor_conditions[name] = MonitorCondition()
            ret = self.monitor_conditions[name]

        return ret

    def stop_all_probes(self):
        for p in self._prj.get_probes():
            self._prj.stop_probe(p)
            if p in self.monitor_conditions:
                self.monitor_conditions[p].notify_data_ready()
                self.monitor_conditions[p].notify_data_emission()
        self.monitor_conditions = {}

        try:
            self._wait_for_probe_termination()
        except eh.Timeout:
            self.fmk_ops.set_error("Timeout! At least one probe seems to be stuck in its 'main()' method.",
                                   code=Error.OperationCancelled)


    def _wait_for_probe_termination(self, p=None):
        if p is None:
            plist = self._prj.get_probes()
        else:
            plist = [p]

        t0 = datetime.datetime.now()
        while True:
            for p in plist:
                if self._prj.is_probe_launched(p):
                    break
            else:
                break

            now = datetime.datetime.now()
            if (now - t0).total_seconds() > 10:
                raise eh.Timeout

            time.sleep(0.1)


    def get_probe_status(self, name):
        return self._prj.get_probe_status(name)

    def get_probe_delay(self, name):
        return self._prj.get_probe_delay(name)

    def set_probe_delay(self, name, delay):
        return self._prj.set_probe_delay(name, delay)

    def do_before_sending_data(self):
        self._target_status = None
        if self.monitor_conditions:
            for name, mobj in self.monitor_conditions.items():
                mobj.notify_data_ready()

    def do_after_sending_data(self):
        '''
        Return False to stop current operations
        '''
        if self.monitor_conditions:
            for name, mobj in self.monitor_conditions.items():
                mobj.notify_data_emission()


    def do_before_resuming_sending_data(self):
        if self.monitor_conditions:
            for name, mobj in self.monitor_conditions.items():
                mobj.wait_until_data_can_be_emitted()


    # Used only in interactive session
    # (not called during Operator execution)
    def do_after_sending_and_logging_data(self):
        if not self.__enable:
            return True

        return self.is_target_ok()

        # for n, p in self.probes.items():
        #     if self._prj.is_probe_launched(n):
        #         pstatus = self._prj.get_probe_status(n)
        #         if pstatus.get_status() < 0:
        #             return False
        #
        # return True

    @property
    def target_status(self):
        if self._target_status is None:
            for n, _ in self.probes.items():
                if self._prj.is_probe_launched(n):
                    pstatus = self._prj.get_probe_status(n)
                    if pstatus.get_status() < 0:
                        self._target_status = -1
                        break
            else:
                self._target_status = 1

        return self._target_status

    def is_target_ok(self):
        return False if self.target_status < 0 else True


class Probe(object):

    def __init__(self):
        pass

    def _start(self, target, logger):
        logger.print_console("__ probe '{:s}' is starting __".format(self.__class__.__name__), nl_before=True, nl_after=True)
        self.start(target, logger)

    def _stop(self, target, logger):
        logger.print_console("__ probe '{:s}' is stopping __".format(self.__class__.__name__), nl_before=True, nl_after=True)
        self.stop(target, logger)

    def start(self, target, logger):
        pass

    def stop(self, target, logger):
        pass

    def quick_reset(self, target, logger):
        pass

    def arm_probe(self, target, logger):
        pass

    def main(self, target, logger):
        pass


class ProbeStatus(object):

    def __init__(self, status=None):
        self.__status = status
        self.__private = None

    def set_status(self, status):
        '''
        @status shall be an integer
        '''
        self.__status = status

    def get_status(self):
        return self.__status

    def set_private_info(self, pv):
        self.__private = pv

    def get_private_info(self):
        return self.__private


class ProbePID_SSH(Probe):
    """
    This generic probe enables you to monitor a process PID through an
    SSH connection.

    Attributes:
        process_name (str): name of the process to monitor.
        sshd_ip (str): IP of the SSH server.
        sshd_port (int): port of the SSH server.
        username (str): username to connect with.
        password (str): password related to the username.
        max_attempts (int): maximum number of attempts for getting
          the process ID.
        delay_between_attempts (float): delay in seconds between
          each attempt.
        delay (float): delay before retrieving the process PID.
        ssh_command_pattern (str): format string for the ssh command. '{0:s}' refer
          to the process name.
    """
    process_name = None
    sshd_ip = None
    sshd_port = 22
    username = None
    password = None
    max_attempts = 10
    delay_between_attempts = 0.1
    delay = 0.5
    ssh_command_pattern = 'pgrep {0:s}'

    def __init__(self):
        assert(self.process_name != None)
        assert(self.sshd_ip != None)
        assert(self.username != None)
        assert(self.password != None)

        if not ssh_module:
            raise eh.UnavailablePythonModule('Python module for SSH is not available!')

    def _get_pid(self, logger):
        ssh_in, ssh_out, ssh_err = \
            self.client.exec_command(self.ssh_command_pattern.format(self.process_name))

        if ssh_err.read():
            # fallback method as previous command does not exist on the system
            fallback_cmd = 'ps a -opid,comm'
            ssh_in, ssh_out, ssh_err = self.client.exec_command(fallback_cmd)
            res = ssh_out.read()
            if sys.version_info[0] > 2:
                res = res.decode('latin_1')
            pid_list = res.split('\n')
            for entry in pid_list:
                if entry.find(self.process_name) >= 0:
                    pid = int(entry.split()[0])
                    break
            else:
                # process not found
                pid = -1
        else:
            res = ssh_out.read()
            if sys.version_info[0] > 2:
                res = res.decode('latin_1')
            l = res.split()
            if len(l) > 1:
                logger.print_console("*** ERROR: more than one PID detected for process name '{:s}'"
                                     " --> {!s}".format(self.process_name, l),
                                     rgb=Color.ERROR,
                                     nl_before=True)
                pid = -10
            elif len(l) == 1:
                pid = int(l[0])
            else:
                # process not found
                pid = -1

        return pid

    def start(self, target, logger):
        self.status = ProbeStatus(0)
        self.client = ssh.SSHClient()
        self.client.set_missing_host_key_policy(ssh.AutoAddPolicy())
        self.client.connect(self.sshd_ip, port=self.sshd_port,
                            username=self.username,
                            password=self.password)
        self._saved_pid = self._get_pid(logger)
        if self._saved_pid < 0:
            logger.print_console("*** ERROR: unable to retrieve process PID",
                                 rgb=Color.ERROR,
                                 nl_before=True)
        else:
            msg = "*** '{:s}' current PID: {:d}\n".format(self.process_name, self._saved_pid)
            self.status.set_private_info(msg)
            logger.print_console(msg, rgb=Color.FMKINFO, nl_before=True)

    def stop(self, target, logger):
        self.client.close()

    def main(self, target, logger):
        cpt = self.max_attempts
        current_pid = -1
        time.sleep(self.delay)
        while cpt > 0 and current_pid == -1:
            time.sleep(self.delay_between_attempts)
            current_pid = self._get_pid(logger)
            cpt -= 1

        if current_pid == -10:
            self.status.set_status(10)
            self.status.set_private_info("ERROR with the ssh command")
        elif current_pid == -1:
            self.status.set_status(-2)
            self.status.set_private_info("'{:s}' is not running anymore!".format(self.process_name))
        elif self._saved_pid != current_pid:
            self._saved_pid = current_pid
            self.status.set_status(-1)
            self.status.set_private_info("'{:s}' PID({:d}) has changed!".format(self.process_name,
                                                                              current_pid))
        else:
            self.status.set_status(0)
            self.status.set_private_info(None)

        return self.status


def _handle_probe_exception(context, prj, probe):
    pname = probe.__class__.__name__
    prj.reset_probe(pname)
    print("\nException in probe '{:s}' ({:s}):".format(pname, context))
    print('-'*60)
    traceback.print_exc(file=sys.stdout)
    print('-'*60)

def probe(prj):
    def internal_func(probe_cls):
        probe = probe_cls()

        def probe_func(stop_event, evts, *args, **kargs):
            try:
                probe._start(*args, **kargs)
            except:
                _handle_probe_exception('during start()', prj, probe)
                return
            while not stop_event.is_set():
                delay = prj.get_probe_delay(probe.__class__.__name__)
                try:
                    status = probe.main(*args, **kargs)
                except:
                    _handle_probe_exception('during main()', prj, probe)
                    return
                prj.set_probe_status(probe.__class__.__name__, status)
                stop_event.wait(delay)

            try:
                probe._stop(*args, **kargs)
            except:
                _handle_probe_exception('during stop()', prj, probe)
            else:
                prj.reset_probe(probe.__class__.__name__)

        prj.register_new_probe(probe.__class__.__name__, probe_func, obj=probe, blocking=False)

        return probe_cls

    return internal_func


def blocking_probe(prj):
    def internal_func(probe_cls):
        probe = probe_cls()

        def probe_func(stop_event, evts, *args, **kargs):
            try:
                probe._start(*args, **kargs)
            except:
                _handle_probe_exception('during start()', prj, probe)
                return

            while not stop_event.is_set():
                delay = prj.get_probe_delay(probe.__class__.__name__)
                
                evts.wait_for_data_ready()

                try:
                    probe.arm_probe(*args, **kargs)
                except:
                    _handle_probe_exception('during arm_probe()', prj, probe)
                    evts.wait_until_data_is_emitted()
                    evts.lets_fuzz_continue()
                    return

                evts.wait_until_data_is_emitted()

                try:
                    status = probe.main(*args, **kargs)
                except:
                    _handle_probe_exception('during main()', prj, probe)
                    evts.lets_fuzz_continue()
                    return

                prj.set_probe_status(probe.__class__.__name__, status)
                evts.lets_fuzz_continue()
                stop_event.wait(delay)

            try:
                probe._stop(*args, **kargs)
            except:
                _handle_probe_exception('during start()', prj, probe)
            else:
                prj.reset_probe(probe.__class__.__name__)

        prj.register_new_probe(probe.__class__.__name__, probe_func, obj=probe, blocking=True)

        return probe_cls

    return internal_func
