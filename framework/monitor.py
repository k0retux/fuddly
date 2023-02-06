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

from framework.comm_backends import BackendError
from libs.external_modules import *
from framework.global_resources import *


class ProbeUser(object):
    timeout = 5.0
    probe_init_timeout = 15.0

    def __init__(self, probe):
        self._probe = probe
        self._thread = None
        self._started_event = threading.Event()
        self._stop_event = threading.Event()
        self._args = None
        self._kwargs = None

    @property
    def probe(self):
        return self._probe

    def start(self, *args, **kwargs):
        if self.is_alive():
            raise RuntimeError
        self._clear()
        self._args = args
        self._kwargs = kwargs
        # print('\n*** DBG start:', self._args, self._kwargs)
        self._thread = threading.Thread(target=self._run, name=self._probe.__class__.__name__,
                                        args=args, kwargs=kwargs)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        try:
            self._probe._stop(*self._args, **self._kwargs)
        except:
            self._handle_exception('during stop()')
        finally:
            self._thread = None

    def join(self, timeout=None):
        if self.is_alive():
            self._thread.join(ProbeUser.timeout if timeout is None else timeout)

            if self.is_alive():
                raise ProbeTimeoutError(self._probe.__class__.__name__, timeout, ["start()", "arm()", "main()", "stop()"])

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
                raise ProbeTimeoutError(self._probe.__class__.__name__, timeout)
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
        self._targets = None
        self._target_status = None
        self._dm = None
        self.probe_users = {}
        self._tg_from_probe = {}

        self.__enable = True

    def set_fmk_ops(self, fmk_ops):
        self.fmk_ops = fmk_ops

    def set_logger(self, logger):
        self._logger = logger

    def set_targets(self, targets):
        self._targets = targets

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
        # TODO: provide unique ref for same probe class name
        if isinstance(probe, type) and issubclass(probe, Probe):
            return probe.__name__
        elif isinstance(probe, Probe):
            return probe.__class__.__name__
        elif isinstance(probe, str):
            return probe
        else:
            print(probe)
            raise TypeError

    def configure_probe(self, probe, *args):
        try:
            self.probe_users[self._get_probe_ref(probe)].configure(*args)
        except KeyError:
            return False
        return True

    def start_probe(self, probe, related_tg=None):
        probe_ref = self._get_probe_ref(probe)
        self._related_tg = related_tg
        if probe_ref in self.probe_users:
            try:
                tgs = self._targets if self._related_tg is None else self._related_tg
                self.probe_users[probe_ref].start(self._dm, tgs, self._logger)
            except:
                self.fmk_ops.set_error("Exception raised in probe '{:s}' start".format(probe_ref),
                                       code=Error.UserCodeError)
                return False
            else:
                self._tg_from_probe[probe_ref] = related_tg
        return True

    def stop_probe(self, probe):
        probe_name = self._get_probe_ref(probe)
        if probe_name in self.probe_users:
            self.probe_users[probe_name].stop()
            if probe_name in self._tg_from_probe:
                del self._tg_from_probe[probe_name]
            self._wait_for_specific_probes(ProbeUser, ProbeUser.join, [probe])
        else:
            self.fmk_ops.set_error("Probe '{:s}' does not exist".format(probe_name),
                                   code=Error.CommandError)

    def stop_all_probes(self):
        for _, probe_user in self.probe_users.items():
            if probe_user.is_alive():
                probe_user.stop()
        self._tg_from_probe = {}
        self._wait_for_specific_probes(ProbeUser, ProbeUser.join)


    def get_probe_related_tg(self, probe):
        return self._tg_from_probe[self._get_probe_ref(probe)]

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

    def iter_probes(self):
        for _, probeuser in self.probe_users.items():
            yield probeuser.probe

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
                    if probe_status.value < 0:
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
        self._started = False

    def __str__(self):
        return "Probe - {:s}".format(self.__class__.__name__)

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
        if self._started:
            return
        logger.print_console("__ probe '{:s}' is starting __".format(self.__class__.__name__), nl_before=True, nl_after=True)
        self._started = True # even if .start() fail, .stop() should be called to provide a chance for cleanup
        ret = self.start(dm, target, logger)
        return ret

    def _stop(self, dm, target, logger):
        if not self._started:
            return
        logger.print_console("__ probe '{:s}' is stopping __".format(self.__class__.__name__), nl_before=True, nl_after=True)
        self.stop(dm, target, logger)
        self._started = False

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
        self._status = status
        self._private = info

    @property
    def value(self):
        return self._status

    @value.setter
    def value(self, val):
        """
        Args:
            val (int): negative value if something is wrong
        """
        self._status = val

    def set_private_info(self, pv):
        self._private = pv

    def get_private_info(self):
        return self._private

    def set_timestamp(self):
        self._now = datetime.datetime.now()

    def get_timestamp(self):
        return self._now


class ProbePID(Probe):
    """
    Generic probe that enables you to monitor a process PID.

    The monitoring can be done through different backend (e.g., :class:`SSH_Backend`,
    :class:`Serial_Backend`).

    Attributes:
        backend (framework.comm_backends.Backend): backend to be used (e.g., :class:`SSH_Backend`).
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
            chan_desc = self.backend.exec_command(self.command_pattern.format(self.process_name))
            res = self.backend.read_output(chan_desc)
        except BackendError:
            fallback_cmd = 'ps a -opid,comm | grep {0:s}'.format(self.process_name)
            chan_desc = self.backend.exec_command(fallback_cmd)
            res = self.backend.read_output(chan_desc)
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
            status.value = -10
            status.set_private_info("ERROR with the command")
        elif current_pid == -1:
            status.value = -2
            status.set_private_info("'{:s}' is not running anymore!".format(self.process_name))
        elif self._saved_pid != current_pid:
            self._saved_pid = current_pid
            status.value = -1
            status.set_private_info("'{:s}' PID({:d}) has changed!".format(self.process_name,
                                                                           current_pid))
        else:
            status.value = current_pid
            status.set_private_info(None)

        return status


class ProbeMem(Probe):
    """
    Generic probe that enables you to monitor the process memory (RSS...) consumption.
    It can be done by specifying a ``threshold`` and/or a ``tolerance`` ratio.

    The monitoring can be done through different backend (e.g., :class:`SSH_Backend`,
    :class:`Serial_Backend`).

    Attributes:
        backend (framework.comm_backends.Backend): backend to be used (e.g., :class:`SSH_Backend`).
        process_name (str): name of the process to monitor.
        threshold (int): memory (RSS) threshold that the monitored process should not exceed.
          (dimension should be the same as what is provided by the `ps` command of the system
          under test)
        tolerance (int): tolerance expressed in percentage of the memory (RSS) the process was
          using at the beginning of the monitoring (or after each time the tolerance has been
          exceeded).
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
        self._max_mem = None
        self._last_status_ok = None
        Probe.__init__(self)

    def _get_mem(self):
        chan_desc = self.backend.exec_command(self.command_pattern.format(self.process_name))
        res = self.backend.read_output(chan_desc)

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
        self._max_mem = None
        self._saved_mem = self._get_mem()
        self._last_status_ok = True
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
            status.value = -10
            status.set_private_info("ERROR with the command")
        elif current_mem == -1:
            status.value = -2
            status.set_private_info("'{:s}' is not found!".format(self.process_name))
        else:
            if current_mem > self._max_mem:
                self._max_mem = current_mem

            ok = True
            info = "*** '{:s}' Max RSS recorded: {:d} / Original " \
                   "RSS: {:d} ***\n".format(self.process_name, self._max_mem, self._saved_mem)
            err_msg = ''
            if self.threshold is not None and self._max_mem > self.threshold:
                ok = False
                err_msg += '\n*** Threshold exceeded (original RSS: {:d}) ***'.format(self._saved_mem)
            if self.tolerance is not None:
                delta = abs(self._max_mem - self._saved_mem)
                if (delta/float(self._saved_mem))*100 > self.tolerance:
                    ok = False
                    err_msg += '\n*** Tolerance exceeded (original RSS: {:d}) ***'.format(self._saved_mem)
            if not ok:
                status.value = -1
                status.set_private_info(err_msg+'\n'+info)
                self._last_status_ok = False
            else:
                status.value = self._max_mem
                status.set_private_info(info)
                self._last_status_ok = True
        return status

    def reset(self):
        if self._max_mem is not None and not self._last_status_ok:
            # In this case, the memory consumption exceeds the `tolerance` ratio or the `threshold`.
            # We update saved_mem with what was witnessed to avoid triggering an issue
            # continuously when the tolerance ratio has been exceeded.
            # Thus, in order for the probe to trigger a new issue, the
            # `tolerance` ratio should be exceeded again with the new saved_mem.
            self._saved_mem = self._max_mem
        self._max_mem = self._saved_mem


class ProbeCmd(Probe):
    """
    Generic probe that enables you to execute shell commands and retrieve the output.

    The monitoring can be done through different backend (e.g., :class:`SSH_Backend`,
    :class:`Serial_Backend`).

    Attributes:
        backend (framework.comm_backends.Backend): backend to be used (e.g., :class:`SSH_Backend`).
        init_command (str): ssh command to execute at init
        recurrent_command (str): ssh command to execute at each probing
    """
    backend = None
    init_command = None
    recurrent_command = None

    def __init__(self):
        assert self.backend != None
        self.chan_desc = None
        Probe.__init__(self)

    def start(self, dm, target, logger):
        self.backend.start()
        if self.init_command is not None:
            try:
                self.chan_desc = self.backend.exec_command(self.init_command)
                data = self.backend.read_output(self.chan_desc)
            except BackendError as err:
                return ProbeStatus(-1, info=str(err))

            return ProbeStatus(0, info=data)

    def stop(self, dm, target, logger):
        self.backend.stop()

    def main(self, dm, target, logger):
        try:
            if self.recurrent_command is not None:
                self.chan_desc = self.backend.exec_command(self.recurrent_command)
            data = self.backend.read_output(self.chan_desc)
        except BackendError as err:
            return ProbeStatus(-1, info=str(err))

        return ProbeStatus(0, info=data)


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
