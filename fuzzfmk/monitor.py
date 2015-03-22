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
import fuzzfmk
fuzzfmk_folder = os.path.dirname(fuzzfmk.__file__)
app_folder = os.path.dirname(os.path.dirname(fuzzfmk.__file__))


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
        self.__st = st
        self.probes = self.__st.get_probes()
        self.fmk_ops = fmk_ops
        self._logger=None

    def set_logger(self, logger):
        self._logger = logger

    def set_strategy(self, strategy):
        self._logger.print_console('*** Monitor refresh in progress...\n', nl_before=False, rgb=Color.COMPONENT_INFO)
        self.stop_all_probes()
        self.__st = strategy
        self.probes = self.__st.get_probes()

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
        return self.__st.quick_reset_probe(name, *args)

    def start_probe(self, name):
        return self.__st.launch_probe(name)

    def stop_probe(self, name):
        ok = self.__st.stop_probe(name)
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
        for p in self.__st.get_probes():
            self.__st.stop_probe(p)
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
            plist = self.__st.get_probes()
        else:
            plist = [p]

        t0 = datetime.datetime.now()
        while True:
            for p in plist:
                if self.__st.is_probe_launched(p):
                    break
            else:
                break

            now = datetime.datetime.now()
            if (now - t0).total_seconds() > 10:
                raise eh.Timeout

            time.sleep(0.1)


    def get_probe_status(self, name):
        return self.__st.get_probe_status(name)

    def get_probe_delay(self, name):
        return self.__st.get_probe_delay(name)

    def set_probe_delay(self, name, delay):
        return self.__st.set_probe_delay(name, delay)

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
            if self.__st.is_probe_launched(n):
                if self.__st.get_probe_status(n).get_status() < 0:
                    return False

        return True
