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
from fuzzfmk.data_model import Data

class PeriodicData(object):
    def __init__(self, data, period=None):
        self.data = data
        self.period = period


class DataProcess(object):
    def __init__(self, process, seed=None):
        self.process = process
        self.seed = seed
        self.outcomes = None

    def __copy__(self):
        new_datap = type(self)(self.process, seed=copy.copy(self.seed))
        assert new_datap.outcomes is None
        return new_datap

class Step(object):

    def __init__(self, data_desc=None, final=False, fbk_timeout=None,
                 cbk_before_sending=None, cbk_after_sending=None, cbk_after_fbk=None,
                 set_periodic=None, clear_periodic=None):

        self.final = final
        self.feedback_timeout = fbk_timeout

        if not final:
            assert data_desc is not None
            self._data_desc = data_desc
            if isinstance(data_desc, str):
                self._node_name = data_desc
            else:
                self._node_name = None
        else:
            self._node_name = None
            self._data_desc = None

        self._dm = None
        self._scenario_env = None
        self._node = None
        self._periodic_data = set_periodic
        if clear_periodic:
            self._periodic_data_to_remove = []
            for p in clear_periodic:
                self._periodic_data_to_remove.append(id(p))
        else:
            self._periodic_data_to_remove = None

        self._callbacks = {}
        if cbk_before_sending:
            self._callbacks[HOOK.before_sending] = cbk_before_sending
        if cbk_after_sending:
            self._callbacks[HOOK.after_sending] = cbk_after_sending
        if cbk_after_fbk:
            self._callbacks[HOOK.after_fbk] = cbk_after_fbk

    def set_data_model(self, dm):
        self._dm = dm

    def set_scenario_env(self, env):
        self._scenario_env = env

    def register_callback(self, callback, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        self._callbacks[hook] = callback

    def run_callback(self, next_step, feedback=None, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        if hook not in self._callbacks:
            return None

        cbk = self._callbacks[hook]
        if hook == HOOK.after_fbk:
            go_on = cbk(self, self._scenario_env, next_step, feedback)
        else:
            go_on = cbk(self, self._scenario_env, next_step)

        return go_on

    @property
    def node(self):
        if isinstance(self._data_desc, DataProcess) and self._data_desc.outcomes is not None:
            # that means that a data creation process has been registered and it has been
            # carried out
            if self._data_desc.outcomes.node:
                return self._data_desc.outcomes.node
            else:
                return None
        elif self._node_name is None:
            # that means that a data creation process has been registered and will be
            # carried out by the framework through a callback
            return None
        else:
            if self._node is None:
                self._node = self._dm.get_data(self._node_name)
        return self._node

    @property
    def data_desc(self):
        return self._data_desc

    @property
    def periodic_to_set(self):
        if self._periodic_data is None:
            return
        else:
            for pdata in self._periodic_data:
                yield pdata

    @property
    def periodic_to_clear(self):
        if self._periodic_data_to_remove is None:
            return
        else:
            for pid in self._periodic_data_to_remove:
                yield pid

    def __copy__(self):
        # PeriodicData should not be copied, only the list that contains them.
        # Indeed their ids (memory addr) are used for registration and cancellation
        new_cbks = copy.copy(self._callbacks)
        new_dm = self._dm
        new_env = None
        new_periodic_to_rm = copy.copy(self._periodic_data_to_remove)
        new_step = type(self)(data_desc=copy.copy(self._data_desc), final=self.final,
                              fbk_timeout=self.feedback_timeout,
                              set_periodic=copy.copy(self._periodic_data))
        new_step._node = None
        new_step._periodic_data_to_remove = new_periodic_to_rm
        new_step._callbacks = new_cbks
        new_step._dm = new_dm
        new_step._scenario_env = new_env
        return new_step


class FinalStep(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None,
                 cbk_before_sending=None, cbk_after_sending=None, cbk_after_fbk=None,
                 set_periodic=None):
        Step.__init__(self, final=True)


class ScenarioEnv(object):

    def __init__(self):
        self._dm = None

    def set_data_model(self, dm):
        self._dm = dm

    @property
    def dm(self):
        return self._dm


class Scenario(object):

    def __init__(self, name):
        self.name = name
        self._dm = None
        self._step_list = []
        self._current_step_idx = 0
        self._env = ScenarioEnv()
        self._periodic_ids = []

    def set_data_model(self, dm):
        self._dm = dm
        self._env.set_data_model(dm)
        for st in self._step_list:
            st.set_data_model(self._dm)

    def add_steps(self, *steps):
        for st in steps:
            for periodic in st.periodic_to_set:
                self._periodic_ids.append(id(periodic))
            st_copy = copy.copy(st)
            st_copy.set_scenario_env(self._env)
            self._step_list.append(st_copy)

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

    @property
    def periodic_to_clear(self):
        for pid in self._periodic_ids:
            yield pid

    def __copy__(self):
        orig_dm = self._dm
        orig_step_list = self._step_list
        orig_curr_step_idx = self._current_step_idx
        orig_env = self._env
        orig_periodic_ids = copy.copy(self._periodic_ids)
        new_sc = type(self)(self.name)
        # new_sc.__dict__.update(self.__dict__)
        new_sc._env = copy.copy(orig_env)
        new_sc._dm = orig_dm
        new_sc._step_list = []
        new_sc._current_step_idx = orig_curr_step_idx
        new_sc._periodic_ids = orig_periodic_ids
        for step in orig_step_list:
            new_step = copy.copy(step)
            new_step.set_scenario_env(new_sc._env)
            new_sc._step_list.append(new_step)

        return new_sc
