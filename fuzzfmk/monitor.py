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

from libs.external_modules import *
import data_models
from fuzzfmk.global_resources import *


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
        self._logger=None

    def set_logger(self, logger):
        self._logger = logger

    def set_strategy(self, strategy):
        self._logger.print_console('*** Monitor refresh in progress...\n', nl_before=False, rgb=Color.COMPONENT_INFO)
        self.stop_all_probes()
        self._prj = strategy
        self.probes = self._prj.get_probes()

    def start(self):
        self.__enable = True
        self.monitor_conditions = {}
        self._logger.print_console('*** Monitor is started\n', nl_before=False, rgb=Color.COMPONENT_START)
        
    def stop(self):
        self._logger.print_console('*** Monitor stopping in progress...\n', nl_before=False, rgb=Color.COMPONENT_INFO)
        self.stop_all_probes()
        self._logger.print_console('*** Monitor is stopped\n', nl_before=False, rgb=Color.COMPONENT_STOP)


    def enable_hooks(self):
        self.__enable = True

    def disable_hooks(self):
        self.__enable = False

    def quick_reset_probe(self, name, *args):
        return self._prj.quick_reset_probe(name, *args)

    def start_probe(self, name):
        return self._prj.launch_probe(name)

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

        for n, p in self.probes.items():
            if self._prj.is_probe_launched(n):
                if self._prj.get_probe_status(n).get_status() < 0:
                    return False

        return True


class Probe(object):

    def __init__(self):
        pass

    def _start(self, target, logger):
        logger.log_fmk_info("Probe is starting (%s)" % self.__class__.__name__, nl_before=True, nl_after=True)
        self.start(target, logger)

    def _stop(self, target, logger):
        logger.log_fmk_info("Probe is stopping (%s)" % self.__class__.__name__, nl_before=True, nl_after=True)
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


def probe(prj):
    def internal_func(probe_cls):
        probe = probe_cls()

        def probe_func(stop_event, evts, *args, **kargs):
            probe._start(*args, **kargs)
            while not stop_event.is_set():
                delay = prj.get_probe_delay(probe.__class__.__name__)
                status = probe.main(*args, **kargs)
                prj.set_probe_status(probe.__class__.__name__, status)

                stop_event.wait(delay)

            probe._stop(*args, **kargs)
            prj.reset_probe(probe.__class__.__name__)

        prj.register_new_probe(probe.__class__.__name__, probe_func, obj=probe, blocking=False)

        return probe_cls

    return internal_func



def blocking_probe(prj):
    def internal_func(probe_cls):
        probe = probe_cls()

        def probe_func(stop_event, evts, *args, **kargs):
            probe._start(*args, **kargs)
            while not stop_event.is_set():
                delay = prj.get_probe_delay(probe.__class__.__name__)
                
                evts.wait_for_data_ready()

                probe.arm_probe(*args, **kargs)

                evts.wait_until_data_is_emitted()

                status = probe.main(*args, **kargs)
                prj.set_probe_status(probe.__class__.__name__, status)

                evts.lets_fuzz_continue()

                stop_event.wait(delay)

            probe._stop(*args, **kargs)
            prj.reset_probe(probe.__class__.__name__)

        prj.register_new_probe(probe.__class__.__name__, probe_func, obj=probe, blocking=True)

        return probe_cls

    return internal_func
