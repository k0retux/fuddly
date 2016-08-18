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
import re
import subprocess
import select

from libs.external_modules import *
from framework.global_resources import *
import framework.error_handling as eh


class ProbeUser(object):
    timeout = 10.0
    probe_init_timeout = 20.0

    def __init__(self, probe):
        self._probe = probe
        self._thread = None
        self._started_event = threading.Event()
        self._stop_event = threading.Event()

    def start(self, *args, **kwargs):
        if self.is_alive():
            raise RuntimeError
        self._clear()
        self._thread = threading.Thread(target=self._run, name=self._probe.__class__.__name__,
                                        args=args, kwargs=kwargs)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def join(self, timeout):
        if self.is_alive():
            self._thread.join(ProbeUser.timeout if timeout is None else timeout)

            if self.is_alive():
                raise ProbeTimeoutError(self.__class__.__name__, timeout, ["start()", "arm()", "main()", "stop()"])

            self._stop_event.clear()

    def wait_for_probe_init(self, timeout=None):
        try:
            self._wait_for_probe(self._started_event, timeout)
        except ProbeTimeoutError as e:
            e.blocking_methods = ["start()"]
            raise e

        # Once a probe has started we do not clear self._started_event to avoid blocking the framework
        # in the situation where this method will be called again while the probe won't have been
        # restarted (currently in launch_operator, after having started the operator).

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()

    def is_stuck(self):
        """
        Tells if the probe has to be considered stuck by the monitor:
        i.e. if it is really stuck or if its stop was not acknowledged
        """
        return self.is_alive() and not self._go_on()

    def get_probe_delay(self):
        return self._probe.delay

    def set_probe_delay(self, delay):
        self._probe.delay = delay

    def get_probe_status(self):
        try:
            self._probe.reset()
        except:
            self._handle_exception('during reset()')
        return self._probe.status

    def _notify_probe_started(self):
        self._started_event.set()

    def _go_on(self):
        return not self._stop_event.is_set()

    def _wait(self, delay):
        self._stop_event.wait(delay)

    def _wait_for_probe(self, event, timeout=None):
        """
        Wait for the probe to trigger a specific event
        """
        timeout = ProbeUser.timeout if timeout is None else timeout
        start = datetime.datetime.now()

        while not event.is_set():
            if (datetime.datetime.now() - start).total_seconds() >= timeout:
                self.stop()
                raise ProbeTimeoutError(self.__class__.__name__, timeout)
            if not self.is_alive() or not self._go_on():
                break
            event.wait(1)

    def _clear(self):
        """ Clear all events """
        self._started_event.clear()
        self._stop_event.clear()

    def _run(self, *args, **kwargs):
        try:
            status = self._probe._start(*args, **kwargs)
        except:
            self._handle_exception('during start()')
            return

        if status is not None:
            self._probe.status = status

        self._notify_probe_started()

        while self._go_on():
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

    def _handle_exception(self, context):
        probe_name = self._probe.__class__.__name__
        print("\nException in probe '{:s}' ({:s}):".format(probe_name, context))
        print('-'*60)
        traceback.print_exc(file=sys.stdout)
        print('-'*60)



class BlockingProbeUser(ProbeUser):

    def __init__(self, probe, after_target_feedback_retrieval):
        ProbeUser.__init__(self, probe)

        self._after_target_feedback_retrieval = after_target_feedback_retrieval

        self._continue_event = threading.Event()

        self._arm_event = threading.Event()
        self._armed_event = threading.Event()
        self._blocking_event = threading.Event()
        self._probe_status_event = threading.Event()

    @property
    def after_target_feedback_retrieval(self):
        return self._after_target_feedback_retrieval

    def stop(self):
        ProbeUser.stop(self)
        self._continue_event.set()

    def notify_data_ready(self):
        self._arm_event.set()


    def wait_until_armed(self, timeout=None):
        try:
            self._wait_for_probe(self._armed_event, timeout)
        except ProbeTimeoutError as e:
            e.blocking_methods = ["arm()"]
            raise
        finally:
            self._armed_event.clear()
            # if error before wait_until_ready, we need to clear its event
            self._probe_status_event.clear()

    def wait_until_ready(self, timeout=None):
        try:
            self._wait_for_probe(self._probe_status_event, timeout)
        except ProbeTimeoutError as e:
            e.blocking_methods = ["main()"]
            raise
        finally:
            self._probe_status_event.clear()

    def notify_blocking(self):
        self._blocking_event.set()

    def notify_error(self):
        """ Informs the probe of an error """
        self._continue_event.set()

    def _clear(self):
        ProbeUser._clear(self)
        self._arm_event.clear()
        self._armed_event.clear()
        self._blocking_event.clear()
        self._continue_event.clear()
        self._probe_status_event.clear()

    def _wait_for_data_ready(self):
        """
        Wait on a request to arm

        Returns:
            bool: True if the arm event happened, False if a stop was asked
              or an error was signaled
        """
        while not self._arm_event.is_set():
            if not self._go_on():
                return False
            self._arm_event.wait(1)

        self._arm_event.clear()
        self._continue_event.clear()
        return True

    def _notify_armed(self):
        self._armed_event.set()

    def _wait_for_fmk_sync(self):
        """
        Wait on a blocking event: data sent or timeout

        Returns:
            bool: True if the blocking event happened, False if a stop was
              asked or an error was signaled
        """
        timeout_appended = True
        while not self._blocking_event.is_set():
            if self._continue_event.is_set() or not self._go_on():
                self._notify_status_retrieved()
                timeout_appended = False
                break
            self._blocking_event.wait(1)
        self._blocking_event.clear()
        return timeout_appended

    def _notify_status_retrieved(self):
        self._probe_status_event.set()

    def _run(self, *args, **kwargs):
        try:
            status = self._probe._start(*args, **kwargs)
        except:
            self._handle_exception('during start()')
            return

        if status is not None:
            self._probe.status = status

        self._notify_probe_started()

        while self._go_on():

            if not self._wait_for_data_ready():
                continue

            try:
                self._probe.arm(*args, **kwargs)
            except:
                self._handle_exception('during arm()')
                return

            self._notify_armed()

            if not self._wait_for_fmk_sync():
                continue

            try:
                self._probe.status = self._probe.main(*args, **kwargs)
            except:
                self._handle_exception('during main()')
                return

            self._notify_status_retrieved()

        try:
            self._probe._stop(*args, **kwargs)
        except:
            self._handle_exception('during stop()')


class Monitor(object):
    def __init__(self):
        self.fmk_ops = None
        self._logger = None
        self._target = None
        self._target_status = None
        self._dm = None

        self.probe_users = {}

        self.__enable = True

    def set_fmk_ops(self, fmk_ops):
        self.fmk_ops = fmk_ops

    def set_logger(self, logger):
        self._logger = logger

    def set_target(self, target):
        self._target = target

    def set_data_model(self, dm):
        self._dm = dm

    def add_probe(self, probe, blocking=False, after_target_feedback_retrieval=False):
        if probe.__class__.__name__ in self.probe_users:
            raise AddExistingProbeToMonitorError(probe.__class__.__name__)

        if blocking:
            self.probe_users[probe.__class__.__name__] = BlockingProbeUser(probe, after_target_feedback_retrieval)
        else:
            self.probe_users[probe.__class__.__name__] = ProbeUser(probe)

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

    def _get_probe_ref(self, probe):
        if isinstance(probe, type) and issubclass(probe, Probe):
            return probe.__name__
        elif isinstance(probe, str):
            return probe
        else:
            raise TypeError

    def configure_probe(self, probe, *args):
        try:
            self.probe_users[self._get_probe_ref(probe)].configure(*args)
        except KeyError:
            return False
        return True

    def start_probe(self, probe):
        probe_name = self._get_probe_ref(probe)
        if probe_name in self.probe_users:
            try:
                self.probe_users[probe_name].start(self._dm, self._target, self._logger)
            except:
                return False
        return True

    def stop_probe(self, probe):
        probe_name = self._get_probe_ref(probe)
        if probe_name in self.probe_users:
            self.probe_users[probe_name].stop()
            self._wait_for_specific_probes(ProbeUser, ProbeUser.join, [probe])
        else:
            self.fmk_ops.set_error("Probe '{:s}' does not exist".format(probe_name),
                                   code=Error.CommandError)

    def stop_all_probes(self):
        for _, probe_user in self.probe_users.items():
            probe_user.stop()

        self._wait_for_specific_probes(ProbeUser, ProbeUser.join)


    def get_probe_status(self, probe):
        return self.probe_users[self._get_probe_ref(probe)].get_probe_status()

    def get_probe_delay(self, probe):
        return self.probe_users[self._get_probe_ref(probe)].get_probe_delay()

    def set_probe_delay(self, probe, delay):
        return self.probe_users[self._get_probe_ref(probe)].set_probe_delay(delay)

    def is_probe_launched(self, probe):
        return self.probe_users[self._get_probe_ref(probe)].is_alive()

    def is_probe_stuck(self, probe):
        return self.probe_users[self._get_probe_ref(probe)].is_stuck()

    def get_probes_names(self):
        probes_names = []
        for probe_name, _ in self.probe_users.items():
            probes_names.append(probe_name)
        return probes_names

    def _wait_for_specific_probes(self, probe_user_class, probe_user_wait_method, probes=None,
                                  timeout=None):
        """
        Wait for probes to trigger a specific event

        Args:
            probe_user_class (ProbeUser): probe_user class that defines the method.
            probe_user_wait_method (method): name of the probe_user's method that will be used to wait.
            probes (list of :class:`ProbeUser`): probes to wait for. If None all probes will be concerned.
            timeout (float): maximum time to wait for in seconds.
        """
        probes = self.probe_users.items() if probes is None else probes

        if timeout is None:
            timeout = ProbeUser.timeout
        timeout = datetime.timedelta(seconds=timeout)
        start = datetime.datetime.now()

        for _, probe_user in probes:
            if isinstance(probe_user, probe_user_class):
                timeout -= start - datetime.datetime.now()
                try:
                    probe_user_wait_method(probe_user, timeout.total_seconds())
                except ProbeTimeoutError as e:
                    self.fmk_ops.set_error("Timeout! Probe '{:s}' seems to be stuck in one of these methods: {:s}"
                                           .format(e.probe_name, e.blocking_methods),
                                           code=Error.OperationCancelled)

    def wait_for_probe_initialization(self):
        self._wait_for_specific_probes(ProbeUser, ProbeUser.wait_for_probe_init,
                                       timeout=ProbeUser.probe_init_timeout)

    def notify_imminent_data_sending(self):
        if not self.__enable:
            return
        self._target_status = None

        for _, probe_user in self.probe_users.items():
            if isinstance(probe_user, BlockingProbeUser):
                probe_user.notify_data_ready()

        self._wait_for_specific_probes(BlockingProbeUser, BlockingProbeUser.wait_until_armed)


    def notify_data_sending_event(self):
        if not self.__enable:
            return

        for _, probe_user in self.probe_users.items():
            if isinstance(probe_user, BlockingProbeUser) and not probe_user.after_target_feedback_retrieval:
                probe_user.notify_blocking()


    def notify_target_feedback_retrieval(self):
        if not self.__enable:
            return
        for _, probe_user in self.probe_users.items():
            if isinstance(probe_user, BlockingProbeUser) and probe_user.after_target_feedback_retrieval:
                probe_user.notify_blocking()


    def wait_for_probe_status_retrieval(self):
        if not self.__enable:
            return

        self._wait_for_specific_probes(BlockingProbeUser, BlockingProbeUser.wait_until_ready)


    def notify_error(self):
        # WARNING: do not use between BlockingProbeUser.notify_data_ready and
        # BlockingProbeUser.wait_until_armed
        if not self.__enable:
            return

        for _, probe_user in self.probe_users.items():
            if isinstance(probe_user, BlockingProbeUser):
                probe_user.notify_error()

    @property
    def target_status(self):
        if self._target_status is None:
            for n, probe_user in self.probe_users.items():
                if probe_user.is_alive():
                    probe_status = probe_user.get_probe_status()
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
        self._status = ProbeStatus(0)
        self._delay = delay

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, status):
        self._status = status
        self._status.set_timestamp()

    @property
    def delay(self):
        return self._delay

    @delay.setter
    def delay(self, delay):
        self._delay = delay

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
            dm: the current data model
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

    def reset(self):
        """
        To be overloaded by user-code (if needed).

        Called each time the probe status is retrieved by the framework
        (through :meth:`Monitor.get_probe_status`).
        Useful especially for periodic probe that may need to be reset after each
        data sending.

        Note: shall be stateless and reentrant.
        """
        pass

    def configure(self, *args):
        """
        (Optional method) To be overloaded with any signature that fits your needs
        Could be called by user code through :meth:`framework.monitor.Monitor.configure_probe`
        Use case example is to call it from an :class:`framework.operator_helpers.Operator`

        Args:
            *args: anything that fits your needs
        """
        pass


class ProbeStatus(object):

    def __init__(self, status=None, info=None):
        self._now = None
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

    def set_timestamp(self):
        self._now = datetime.datetime.now()

    def get_timestamp(self):
        return self._now


class Backend(object):

    def __init__(self, codec='latin_1'):
        """
        Args:
            codec (str): codec used by the monitored system to answer.
        """
        self._started = False
        self.codec = codec
        self._sync_lock = threading.Lock()

    def start(self):
        with self._sync_lock:
            if not self._started:
                self._started = True
                self._start()

    def stop(self):
        with self._sync_lock:
            if self._started:
                self._started = False
                self._stop()

    def exec_command(self, cmd):
        with self._sync_lock:
            return self._exec_command(cmd)

    def _exec_command(self, cmd):
        raise NotImplementedError

    def _start(self):
        pass

    def _stop(self):
        pass


class SSH_Backend(Backend):
    """
    Backend to execute command through a serial line.
    """
    def __init__(self, username, password, sshd_ip, sshd_port=22, codec='latin_1'):
        """
        Args:
            sshd_ip (str): IP of the SSH server.
            sshd_port (int): port of the SSH server.
            username (str): username to connect with.
            password (str): password related to the username.
            codec (str): codec used by the monitored system to answer.
        """
        Backend.__init__(self, codec=codec)
        if not ssh_module:
            raise eh.UnavailablePythonModule('Python module for SSH is not available!')
        self.sshd_ip = sshd_ip
        self.sshd_port = sshd_port
        self.username = username
        self.password = password
        self.client = None

    def _start(self):
        self.client = ssh.SSHClient()
        self.client.set_missing_host_key_policy(ssh.AutoAddPolicy())
        self.client.connect(self.sshd_ip, port=self.sshd_port,
                            username=self.username,
                            password=self.password)

    def _stop(self):
        self.client.close()

    def _exec_command(self, cmd):
        ssh_in, ssh_out, ssh_err = \
            self.client.exec_command(cmd)

        if ssh_err.read():
            # the command does not exist on the system
            raise BackendError('The command does not exist on the host')
        else:
            return ssh_out.read()


class Serial_Backend(Backend):
    """
    Backend to execute command through a serial line.
    """
    def __init__(self, serial_port, baudrate=115200, bytesize=8, parity='N', stopbits=1,
                 xonxoff=False, rtscts=False, dsrdtr=False,
                 username=None, password=None, slowness_factor=5,
                 cmd_notfound=b'command not found', codec='latin_1'):
        """
        Args:
            serial_port (str): path to the tty device file. (e.g., '/dev/ttyUSB0')
            baudrate (int): baud rate of the serial line.
            bytesize (int): number of data bits. (5, 6, 7, or 8)
            parity (str): parity checking. ('N', 'O, 'E', 'M', or 'S')
            stopbits (int): number of stop bits. (1, 1.5 or 2)
            xonxoff (bool): enable software flow control.
            rtscts (bool): enable hardware (RTS/CTS) flow control.
            dsrdtr (bool): enable hardware (DSR/DTR) flow control.
            username (str): username to connect with. If None, no authentication step will be attempted.
            password (str): password related to the username.
            slowness_factor (int): characterize the slowness of the monitored system. The scale goes from
              1 (fastest) to 10 (slowest). This factor is a base metric to compute the time to wait
              for the authentication step to terminate (if `username` and `password` parameter are provided)
              and other operations involving to wait for the monitored system.
            cmd_notfound (bytes): pattern used to detect if the command does not exist on the
              monitored system.
            codec (str): codec used to send/receive information through the serial line
        """
        Backend.__init__(self, codec=codec)
        if not serial_module:
            raise eh.UnavailablePythonModule('Python module for Serial is not available!')

        self.serial_port = serial_port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits= stopbits
        self.xonxoff = xonxoff
        self.rtscts = rtscts
        self.dsrdtr = dsrdtr
        self.slowness_factor = slowness_factor
        self.cmd_notfound = cmd_notfound
        if sys.version_info[0] > 2:
            self.username = bytes(username, self.codec)
            self.password = bytes(password, self.codec)
        else:
            self.username = username
            self.password = password

        self.client = None

    def _start(self):
        self.ser = serial.Serial(self.serial_port, self.baudrate, bytesize=self.bytesize,
                                 parity=self.parity, stopbits=self.stopbits,
                                 xonxoff=self.xonxoff, dsrdtr=self.dsrdtr, rtscts=self.rtscts,
                                 timeout=self.slowness_factor*0.1)
        if self.username is not None:
            assert self.password is not None
            self.ser.flushInput()
            self.ser.write(self.username+b'\r\n')
            time.sleep(0.1)
            self.ser.readline() # we read login echo
            pass_prompt = self.ser.readline()
            retry = 0
            eot_sent = False
            while pass_prompt.lower().find(b'password') == -1:
                retry += 1
                if retry > 3 and eot_sent:
                    self.stop()
                    raise BackendError('Unable to establish a connection with the serial line.')
                elif retry > 3:
                    # we send an EOT if ever the console was not in its initial state
                    # (already logged, or with the password prompt, ...) when we first write on
                    # the serial line.
                    self.ser.write(b'\x04\r\n')
                    time.sleep(self.slowness_factor*0.8)
                    self.ser.flushInput()
                    self.ser.write(self.username+b'\r\n')
                    time.sleep(0.1)
                    self.ser.readline() # we consume the login echo
                    pass_prompt = self.ser.readline()
                    retry = 0
                    eot_sent = True
                else:
                    chunks = self._read_serial(duration=self.slowness_factor*0.2)
                    pass_prompt = b''.join(chunks)
            time.sleep(0.1)
            self.ser.write(self.password+b'\r\n')
            time.sleep(self.slowness_factor*0.7)

    def _stop(self):
        self.ser.write(b'\x04\r\n') # we send an EOT (Ctrl+D)
        self.ser.close()

    def _exec_command(self, cmd):
        if not self.ser.is_open:
            raise BackendError('Serial port not open')

        if sys.version_info[0] > 2:
            cmd = bytes(cmd, self.codec)
        cmd += b'\r\n'
        self.ser.flushInput()
        self.ser.write(cmd)
        time.sleep(0.1)
        self.ser.readline() # we consume the 'writing echo' from the input
        try:
            result = self._read_serial(duration=self.slowness_factor*0.8)
        except serial.SerialException:
            raise BackendError('Exception while reading serial line')
        else:
            # We have to remove the new prompt line at the end.
            # But in our testing environment, the two last entries had to be removed, namely
            # 'prompt_line \r\n' and 'prompt_line ' !?
            # print('\n*** DBG: ', result)
            result = result[:-2]
            ret = b''.join(result)
            if ret.find(self.cmd_notfound) != -1:
                raise BackendError('The command does not exist on the host')
            else:
                return ret

    def _read_serial(self, duration):
        result = []
        t0 = datetime.datetime.now()
        delta = -1
        while delta < duration:
            now = datetime.datetime.now()
            delta = (now - t0).total_seconds()
            res = self.ser.readline()
            if res == b'':
                break
            result.append(res)
        return result


class Shell_Backend(Backend):
    """
    Backend to execute shell commands locally
    """
    def __init__(self, timeout=None, codec='latin_1'):
        """
        Args:
            timeout (float): timeout in seconds for reading the result of the command
            codec (str): codec used by the monitored system to answer.
        """
        Backend.__init__(self, codec=codec)
        self._timeout = timeout
        self._app = None

    def _start(self):
        pass

    def _stop(self):
        pass

    def _exec_command(self, cmd):
        self._app = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready_to_read, ready_to_write, in_error = \
            select.select([self._app.stdout, self._app.stderr], [], [], self._timeout)

        if in_error:
            # the command does not exist on the system
            raise BackendError('Issue with file descriptors')
        elif ready_to_read:
            if len(ready_to_read) == 2:
                err = ready_to_read[1].read()
                if err.strip():
                    raise BackendError('ERROR: {!s}'.format(ready_to_read[1].read()))
            if ready_to_read[0]:
                return ready_to_read[0].read()
            else:
                raise BackendError('BUG')
        else:
            return b''


class BackendError(Exception): pass

class ProbePID(Probe):
    """
    Generic probe that enables you to monitor a process PID.

    The monitoring can be done through different backend (e.g., :class:`SSH_Backend`,
    :class:`Serial_Backend`).

    Attributes:
        backend (Backend): backend to be used (e.g., :class:`SSH_Backend`).
        process_name (str): name of the process to monitor.
        max_attempts (int): maximum number of attempts for getting
          the process ID.
        delay_between_attempts (float): delay in seconds between
          each attempt.
        delay (float): delay before retrieving the process PID.
        command_pattern (str): format string for the ssh command. '{0:s}' refer
          to the process name.
    """
    backend = None
    process_name = None
    command_pattern = 'pgrep {0:s}'
    max_attempts = 10
    delay_between_attempts = 0.1
    delay = 0.5

    def __init__(self):
        assert self.process_name != None
        assert self.backend != None
        Probe.__init__(self)

    def _get_pid(self, logger):
        try:
            res = self.backend.exec_command(self.command_pattern.format(self.process_name))
        except BackendError:
            fallback_cmd = 'ps a -opid,comm | grep {0:s}'.format(self.process_name)
            res = self.backend.exec_command(fallback_cmd)
            if sys.version_info[0] > 2:
                res = res.decode(self.backend.codec)
            pid_list = res.split('\n')
            for entry in pid_list:
                if entry.find(self.process_name) >= 0:
                    try:
                        pid = int(entry.split()[0])
                    except ValueError:
                        pid = -10
                    break
            else:
                # process not found
                pid = -1
        else:
            if sys.version_info[0] > 2:
                res = res.decode(self.backend.codec)
            l = res.split()
            if len(l) > 1:
                logger.print_console("*** ERROR: more than one PID detected for process name '{:s}'"
                                     " --> {!s}".format(self.process_name, l),
                                     rgb=Color.ERROR,
                                     nl_before=True)
                pid = -10
            elif len(l) == 1:
                try:
                    pid = int(l[0])
                except ValueError:
                    pid = -10
            else:
                # process not found
                pid = -1

        return pid

    def start(self, dm, target, logger):
        self.backend.start()
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
        self.backend.stop()

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
            status.set_status(-10)
            status.set_private_info("ERROR with the command")
        elif current_pid == -1:
            status.set_status(-2)
            status.set_private_info("'{:s}' is not running anymore!".format(self.process_name))
        elif self._saved_pid != current_pid:
            self._saved_pid = current_pid
            status.set_status(-1)
            status.set_private_info("'{:s}' PID({:d}) has changed!".format(self.process_name,
                                                                           current_pid))
        else:
            status.set_status(current_pid)
            status.set_private_info(None)

        return status


class ProbeMem(Probe):
    """
    Generic probe that enables you to monitor the process memory (RSS...) consumption.
    It can be done by specifying a ``threshold`` and/or a ``tolerance`` ratio.

    The monitoring can be done through different backend (e.g., :class:`SSH_Backend`,
    :class:`Serial_Backend`).

    Attributes:
        backend (Backend): backend to be used (e.g., :class:`SSH_Backend`).
        process_name (str): name of the process to monitor.
        threshold (int): memory (RSS) threshold in bytes that the monitored process should not exceed.
        tolerance (int): tolerance expressed in percentage of the memory (RSS) the process was
          using at the beginning of the monitoring.
        command_pattern (str): format string for the ssh command. '{0:s}' refer
          to the process name.
    """
    backend = None
    process_name = None
    threshold = None
    tolerance = 2
    command_pattern = 'ps -e -orss,comm | grep {0:s}'

    def __init__(self):
        assert self.process_name != None
        assert self.backend != None
        self._saved_mem = None
        Probe.__init__(self)

    def _get_mem(self):
        res = self.backend.exec_command(self.command_pattern.format(self.process_name))

        if sys.version_info[0] > 2:
            res = res.decode(self.backend.codec)
        proc_list = res.split('\n')
        for entry in proc_list:
            if entry.find(self.process_name) >= 0:
                try:
                    rss = int(re.search('\d+', entry.split()[0]).group(0))
                except:
                    rss = -10
                break
        else:
            # process not found
            rss = -1

        return rss

    def start(self, dm, target, logger):
        self.backend.start()
        self._saved_mem = self._get_mem()
        self.reset()
        if self._saved_mem < 0:
            msg = "*** INIT ERROR: unable to retrieve process RSS ***\n"
        else:
            msg = "*** INIT: '{:s}' current RSS: {:d} ***\n".format(self.process_name,
                                                                    self._saved_mem)
        return ProbeStatus(self._saved_mem, info=msg)

    def stop(self, dm, target, logger):
        self.backend.stop()

    def main(self, dm, target, logger):
        current_mem = self._get_mem()

        status = ProbeStatus()

        if current_mem == -10:
            status.set_status(-10)
            status.set_private_info("ERROR with the command")
        elif current_mem == -1:
            status.set_status(-2)
            status.set_private_info("'{:s}' is not found!".format(self.process_name))
        else:
            if current_mem > self._max_mem:
                self._max_mem = current_mem

            ok = True
            info = "*** '{:s}' maximum RSS: {:d} ***\n".format(self.process_name, self._max_mem)
            err_msg = ''
            if self.threshold is not None and self._max_mem > self.threshold:
                ok = False
                err_msg += '\n*** Threshold exceeded ***'
            if self.tolerance is not None:
                delta = abs(self._max_mem - self._saved_mem)
                if (delta/float(self._saved_mem))*100 > self.tolerance:
                    ok = False
                    err_msg += '\n*** Tolerance exceeded ***'
            if not ok:
                status.set_status(-1)
                status.set_private_info(err_msg+'\n'+info)
            else:
                status.set_status(self._max_mem)
                status.set_private_info(info)
        return status

    def reset(self):
        self._max_mem = self._saved_mem


def probe(project):
    def internal_func(probe_cls):
        project.monitor.add_probe(probe_cls(), blocking=False)
        return probe_cls

    return internal_func


def blocking_probe(project, after_target_feedback_retrieval=False):
    def internal_func(probe_cls):
        project.monitor.add_probe(probe_cls(), blocking=True,
                                  after_target_feedback_retrieval=after_target_feedback_retrieval)
        return probe_cls

    return internal_func


class AddExistingProbeToMonitorError(Exception):
    """
    Raised when a probe is being added a second time in a monitor
    """
    def __init__(self, probe_name):
        self._probe_name = probe_name

    @property
    def probe_name(self):
        return self._probe_name

class ProbeTimeoutError(Exception):
    """
    Raised when a probe is considered stuck
    """
    def __init__(self, probe_name, timeout, blocking_methods=None):
        """
        Args:
            probe_name (str): name of the probe where the timeout occurred
            timeout (float): time the probe waited before its timeout
            blocking_methods (list of str): list of probe_methods where the timeout may have happened
        """
        self._probe_name = probe_name
        self._timeout = timeout
        self._blocking_methods = [] if blocking_methods is None else blocking_methods

    @property
    def probe_name(self):
        return self._probe_name

    @property
    def timeout(self):
        return self._timeout

    @property
    def blocking_methods(self):
        str = ""
        for i in range(0, len(self._blocking_methods)):
            str += self._blocking_methods[i]
            str += ", " if i != len(self._blocking_methods) - 1 else ""
        return str

    @blocking_methods.setter
    def blocking_methods(self, blocking_methods):
        self._blocking_methods = blocking_methods
