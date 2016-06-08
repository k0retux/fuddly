################################################################################
#
#  Copyright 2016 Eric Lacombe <eric.lacombe@security-labs.org>
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

import copy

from fuzzfmk.global_resources import *

class PeriodicData(object):
    def __init__(self, data, period=None):
        self.data = data
        self.period = period

class Step(object):

    def __init__(self, node_name=None, final=False, fbk_timeout=None,
                 cbk_before_sending=None, cbk_after_sending=None, cbk_after_fbk=None,
                 periodic_data=None):
        if not final:
            assert node_name is not None
        self._dm = None
        self._node_name = node_name
        self._node = None
        self.final = final
        self.feedback_timeout = fbk_timeout
        self._periodic_data = periodic_data
        self._callbacks = {}
        if cbk_before_sending:
            self._callbacks[HOOK.before_sending] = cbk_before_sending
        if cbk_after_sending:
            self._callbacks[HOOK.after_sending] = cbk_after_sending
        if cbk_after_fbk:
            self._callbacks[HOOK.after_fbk] = cbk_after_fbk

    def set_data_model(self, dm):
        self._dm = dm

    def register_callback(self, callback, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        self._callbacks[hook] = callback

    def run_callback(self, next_step, feedback=None, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        if hook not in self._callbacks:
            return None

        cbk = self._callbacks[hook]
        if hook == HOOK.after_fbk:
            go_on = cbk(self, next_step, feedback)
        else:
            go_on = cbk(self, next_step)

        return go_on

    @property
    def node(self):
        if self._node is None:
            self._node = self._dm.get_data(self._node_name)
        return self._node

    @property
    def periodic_data(self):
        if self._periodic_data is None:
            return
        else:
            for pdata in self._periodic_data:
                yield pdata

    def __copy__(self):
        new_cbks = copy.copy(self._callbacks)
        new_dm = self._dm
        new_step = type(self)(node_name=self._node_name, final=self.final,
                              fbk_timeout=self.feedback_timeout,
                              periodic_data=copy.copy(self._periodic_data))
        new_step.__dict__.update(self.__dict__)
        new_step._node = None
        new_step._callbacks = new_cbks
        new_step._dm = new_dm

        return new_step


class FinalStep(Step):
    def __init__(self, node_name=None, final=False, fbk_timeout=None,
                 cbk_before_sending=None, cbk_after_sending=None, cbk_after_fbk=None,
                 periodic_data=None):
        Step.__init__(self, final=True)


class Scenario(object):

    def __init__(self, name):
        self.name = name
        self._dm = None
        self._step_list = []
        self._current_step_idx = 0

    def set_data_model(self, dm):
        self._dm = dm
        for st in self._step_list:
            st.set_data_model(self._dm)

    def add_steps(self, *steps):
        for st in steps:
            self._step_list.append(copy.copy(st))

    def do_next_step(self):
        self._current_step_idx += 1
        if self._current_step_idx >= len(self._step_list):
            self._current_step_idx = 0

    def get_current_step(self):
        return self._step_list[self._current_step_idx]

    def get_next_step(self):
        next_idx = self._current_step_idx+1
        if next_idx >= len(self._step_list):
            return self._step_list[0]
        else:
            return self._step_list[next_idx]

    def __copy__(self):
        orig_dm = self._dm
        orig_step_list = self._step_list
        orig_curr_step_idx = self._current_step_idx
        new_sc = type(self)(self.name)
        new_sc.__dict__.update(self.__dict__)
        new_sc._dm = orig_dm
        new_sc._step_list = []
        new_sc._current_step_idx = orig_curr_step_idx
        for step in orig_step_list:
            new_sc._step_list.append(copy.copy(step))

        return new_sc
