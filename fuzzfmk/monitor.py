################################################################################
#
#  Copyright 2014-2016 Eric Lacombe <eric.lacombe@security-labs.org>
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


import threading
import datetime
import time
import traceback

from libs.external_modules import *
from fuzzfmk.global_resources import *
import fuzzfmk.error_handling as eh


class ProbeUser(object):

    timeout = 10.0

    def __init__(self, probe):
        self._probe = probe
        self._thread = None
        self._stop_event = threading.Event()

    def go_on(self):
        return not self._stop_event.is_set()

    def _wait(self, delay):
        self._stop_event.wait(delay)

    def stop(self):
        self._stop_event.set()

    def _notify_stop(self):
        self._stop_event.clear()

    def _clear(self):
        """
        Clear all events
        """
        self._stop_event.clear()

    def start(self, *args, **kwargs):
        if self.is_alive():
            raise RuntimeError
        self._clear()
        self._thread = threading.Thread(target=self._run, name=self._probe.__class__.__name__,
                                        args=args, kwargs=kwargs)
        self._thread.start()

    def join(self, timeout):
        if self.is_alive():
            self._thread.join(ProbeUser.timeout if timeout is None else timeout)
            if self.is_alive():
                raise eh.Timeout

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()

    def _run(self, *args, **kwargs):
        try:
            status = self._probe._start(*args, **kwargs)
        except:
            self._handle_exception('during start()')
            return

        if status is not None:
            self._probe.status = status

        while self.go_on():
            try:
                self._probe.status = self._probe.main(*args, **kwargs)
            except:
                self._handle_exception('during main()')
                return
            self._wait(self._probe.delay)

        try:
            self._probe._stop(*args, **kwargs)
        except:
            self._handle_exception('during stop()')
        else:
            self._notify_stop()


    def get_probe_delay(self):
        return self._probe.delay

    def set_probe_delay(self, delay):
        self._probe.delay = delay

    def get_probe_status(self):
        return self._probe.status

    def _handle_exception(self, context):
        probe_name = self._probe.__class__.__name__
        self._notify_stop()
        print("\nException in probe '{:s}' ({:s}):".format(probe_name, context))
        print('-'*60)
        traceback.print_exc(file=sys.stdout)
        print('-'*60)



class BlockingProbeUser(ProbeUser):

    def __init__(self, probe):
        ProbeUser.__init__(self, probe)

        self._continue_event = threading.Event()

        self._arm_event = threading.Event()
        self._armed_event = threading.Event()
        self._blocking_event = threading.Event()


    def _clear(self):
        ProbeUser._clear(self)
        self._arm_event.clear()
        self._armed_event.clear()
        self._blocking_event.clear()
        self._continue_event.clear()


    def _wait_for_data_ready(self):
        while not self._arm_event.is_set():
            if not self.go_on():
                return False
            self._arm_event.wait(1)

        self._arm_event.clear()
        return True

    def _notify_armed(self):
        self._armed_event.set()

    def _wait_for_blocking(self):
        timeout_appended = True
        while not self._blocking_event.is_set():
            if self._continue_event.is_set() or not self.go_on():
                self._continue_event.clear()
                timeout_appended = False
                break
            self._blocking_event.wait(1)
        self._blocking_event.clear()
        return timeout_appended

    def notify_data_ready(self):
        self._arm_event.set()

    def wait_until_armed(self):
        while not self._armed_event.is_set():
            self._armed_event.wait(1)

        self._armed_event.clear()

    def notify_blocking(self):
        self._blocking_event.set()

    def reinitialize(self):
        self._continue_event.set()

    def stop(self):
        ProbeUser.stop(self)
        self.reinitialize()


    def _run(self, *args, **kwargs):
        try:
            status = self._probe._start(*args, **kwargs)
        except:
            self._handle_exception('during start()')
            return

        if status is not None:
            self._probe.status = status

        while self.go_on():

            if not self._wait_for_data_ready():
                continue

            try:
                self._probe.arm(*args, **kwargs)
            except:
                self._handle_exception('during arm()')
                self._notify_armed()
                return

            self._notify_armed()

            if not self._wait_for_blocking():
                continue

            try:
                self._probe.status = self._probe.main(*args, **kwargs)
            except:
                self._handle_exception('during main()')
                return

        try:
            self._probe._stop(*args, **kwargs)
        except:
            self._handle_exception('during stop()')
        else:
            self._notify_stop()



class Monitor(object):
    def __init__(self):
        self.fmk_ops = None
        self._logger = None
        self._target = None
        self._target_status = None
        self._dm = None

        self.probe_runners = {}

        self.__enable = True

    def set_fmk_ops(self, fmk_ops):
        self.fmk_ops = fmk_ops

    def set_logger(self, logger):
        self._logger = logger

    def set_target(self, target):
        self._target = target

    def set_data_model(self, dm):
        self._dm = dm

    def add_probe(self, probe, blocking=False):
        if probe.__class__.__name__ in self.probe_runners:
            raise AlreadyExistingProbeError(probe.__class_.__name__)

        self.probe_runners[probe.__class__.__name__] = BlockingProbeUser(probe) if blocking else ProbeUser(probe)

    def start(self):
        self._logger.print_console('*** Monitor is started ***\n', nl_before=False, rgb=Color.COMPONENT_START)
        
    def stop(self):
        self._logger.print_console('*** Monitor stopping in progress... ***\n', nl_before=False, rgb=Color.COMPONENT_INFO)
        self.stop_all_probes()
        self._logger.print_console('*** Monitor is stopped ***\n', nl_before=False, rgb=Color.COMPONENT_STOP)

    def enable_hooks(self):
        self.__enable = True

    def disable_hooks(self):
        self.__enable = False


    def start_probe(self, probe_name):
        if probe_name in self.probe_runners:
            try:
                self.probe_runners[probe_name].start(self._dm, self._target, self._logger)
                return True
            except: pass
        return False


    def stop_probe(self, probe_name):
        if probe_name in self.probe_runners:
            self.probe_runners[probe_name].stop()
        else:
            self.fmk_ops.set_error("Probe '%s' does not exist" % probe_name,
                                   code=Error.CommandError)
            return

        try:
            self.probe_runners[probe_name].join()
        except eh.Timeout:
            self.fmk_ops.set_error("Timeout! Probe '%s' seems to be stuck in its 'main()' method." % probe_name,
                                   code=Error.OperationCancelled)
            return
        except RuntimeError: # thread has never been started
            pass

    def stop_all_probes(self):
        for _, probe_runner in self.probe_runners.items():
                probe_runner.stop()

        try:
            timeout = datetime.timedelta(seconds=ProbeUser.timeout)
            start_date = datetime.datetime.now()
            for _, probe_runner in self.probe_runners.items():
                timeout -= start_date - datetime.datetime.now()
                probe_runner.join(timeout.total_seconds())
        except eh.Timeout:
            self.fmk_ops.set_error("Timeout! At least one probe seems to be stuck in its 'main()' method.",
                                   code=Error.OperationCancelled)


    def get_probe_status(self, probe_name):
        return self.probe_runners[probe_name].get_probe_status()

    def get_probe_delay(self, probe_name):
        return self.probe_runners[probe_name].get_probe_delay()

    def set_probe_delay(self, probe_name, delay):
        return self.probe_runners[probe_name].set_probe_delay(delay)

    def is_probe_launched(self, probe_name):
        return self.probe_runners[probe_name].is_alive()

    def get_probes_names(self):
        probes_names = []
        for probe_name, _ in self.probe_runners.items():
            probes_names.append(probe_name)
        return probes_names

    def do_before_sending_data(self):
        self._target_status = None

        for _, probe_runner in self.probe_runners.items():
            if isinstance(probe_runner, BlockingProbeUser):
                probe_runner.notify_data_ready()

        for _, probe_runner in self.probe_runners.items():
            if isinstance(probe_runner, BlockingProbeUser) and probe_runner.go_on() \
                    and probe_runner.is_alive():
                probe_runner.wait_until_armed()

    def do_after_sending_data(self):
        '''
        Return False to stop current operations
        '''
        # if self.probe_helper:
        #     for name, mobj in self.probe_helper.items():
        #         if self._prj.is_probe_blocking(name):
        #             mobj.notify_data_emission()
        pass


    # Used only in interactive session
    # (not called during Operator execution)
    def do_after_sending_and_logging_data(self):
        if not self.__enable:
            return True

        return self.is_target_ok()


    def do_after_timeout(self):
        for _, probe_runner in self.probe_runners.items():
            if isinstance(probe_runner, BlockingProbeUser):
                probe_runner.notify_blocking()


    def do_on_error(self):
        for _, probe_runner in self.probe_runners.items():
            if isinstance(probe_runner, BlockingProbeUser):
                probe_runner.reinitialize()


    @property
    def target_status(self):
        if self._target_status is None:
            for n, probe_runner in self.probe_runners.items():
                if probe_runner.is_alive():
                    probe_status = probe_runner.get_probe_status()
                    if probe_status.get_status() < 0:
                        self._target_status = -1
                        break
            else:
                self._target_status = 1

        return self._target_status

    def is_target_ok(self):
        return not self.target_status < 0



class Probe(object):

    def __init__(self, delay=1.0):
        self.status = ProbeStatus(0)
        self.delay = delay

    def _start(self, dm, target, logger):
        logger.print_console("__ probe '{:s}' is starting __".format(self.__class__.__name__), nl_before=True, nl_after=True)
        return self.start(dm, target, logger)

    def _stop(self, dm, target, logger):
        logger.print_console("__ probe '{:s}' is stopping __".format(self.__class__.__name__), nl_before=True, nl_after=True)
        self.stop(dm, target, logger)

    def start(self, dm, target, logger):
        """
        Probe initialization

        Returns:
            ProbeStatus: may return a status or None
        """
        return None

    def stop(self, dm, target, logger):
        pass

    def arm(self, dm, target, logger):
        """
        Only used by blocking probes.
        Called by the framework just before sending a data.

        Args:
            target: the current target
            logger: the current logger
        """
        pass

    def main(self, dm, target, logger):
        """
        To be overloaded by user-code

        In the case of a basic probe, this method will be called in loop following a
        period specified within the associated project file.

        In the case of a blocking probe, this method will be called by the framework
        just after having sent a data (or a batch of data).

        Args:
            dm: the current data model
            target: the current target
            logger: the current logger

        Returns:
            ProbeStatus: negative status if something is wrong
        """
        raise NotImplementedError

    def configure(self, *args):
        """
        (Optional method) To be overloaded with any signature that fits your needs
        Could be called by user code through :meth:`fuzzfmk.monitor.Monitor.configure_probe`
        Use case example is to call it from an :class:`fuzzfmk.operator_helpers.Operator`

        Args:
            *args: anything that fits your needs
        """
        pass

class ProbeStatus(object):

    def __init__(self, status=None, info=None):
        self._now = datetime.datetime.now()
        self.__status = status
        self.__private = info

    def set_status(self, status):
        """
        Args:
            status (int): negative status if something is wrong
        """
        self.__status = status

    def get_status(self):
        return self.__status

    def set_private_info(self, pv):
        self.__private = pv

    def get_private_info(self):
        return self.__private

    def get_timestamp(self):
        return self._now

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

    def start(self, dm, target, logger):
        self.client = ssh.SSHClient()
        self.client.set_missing_host_key_policy(ssh.AutoAddPolicy())
        self.client.connect(self.sshd_ip, port=self.sshd_port,
                            username=self.username,
                            password=self.password)
        self._saved_pid = self._get_pid(logger)
        if self._saved_pid < 0:
            msg = "*** INIT ERROR: unable to retrieve process PID ***\n"
            # logger.print_console(msg, rgb=Color.ERROR, nl_before=True)
        else:
            msg = "*** INIT: '{:s}' current PID: {:d} ***\n".format(self.process_name,
                                                                    self._saved_pid)
            # logger.print_console(msg, rgb=Color.FMKINFO, nl_before=True)

        return ProbeStatus(self._saved_pid, info=msg)

    def stop(self, dm, target, logger):
        self.client.close()

    def main(self, dm, target, logger):
        cpt = self.max_attempts
        current_pid = -1
        time.sleep(self.delay)
        while cpt > 0 and current_pid == -1:
            time.sleep(self.delay_between_attempts)
            current_pid = self._get_pid(logger)
            cpt -= 1

        status = ProbeStatus()

        if current_pid == -10:
            status.set_status(10)
            status.set_private_info("ERROR with the ssh command")
        elif current_pid == -1:
            status.set_status(-2)
            status.set_private_info("'{:s}' is not running anymore!".format(self.process_name))
        elif self._saved_pid != current_pid:
            self._saved_pid = current_pid
            status.set_status(-1)
            status.set_private_info("'{:s}' PID({:d}) has changed!".format(self.process_name,
                                                                           current_pid))
        else:
            status.set_status(0)
            status.set_private_info(None)

        return status


def probe(project):
    def internal_func(probe_cls):
        project.monitor.add_probe(probe_cls(), blocking=False)
        return probe_cls

    return internal_func


def blocking_probe(project):
    def internal_func(probe_cls):
        project.monitor.add_probe(probe_cls(), blocking=True)
        return probe_cls

    return internal_func


class AlreadyExistingProbeError(Exception):
    def __init__(self, probe_name):
        Exception.__init__(self)
        self._probe_name = probe_name
    def __str__(self):
        return repr(self._probe_name)