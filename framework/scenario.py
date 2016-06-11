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

from framework.global_resources import *
from framework.data_model import Data

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
                 # cbk_before_sending=None, cbk_after_sending=None, cbk_after_fbk=None,
                 set_periodic=None, clear_periodic=None):

        self.final = final
        self.feedback_timeout = fbk_timeout
        self._transitions = []

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

        # self._callbacks = {}
        # if cbk_before_sending:
        #     self._callbacks[HOOK.before_sending] = cbk_before_sending
        # if cbk_after_sending:
        #     self._callbacks[HOOK.after_sending] = cbk_after_sending
        # if cbk_after_fbk:
        #     self._callbacks[HOOK.after_fbk] = cbk_after_fbk

    def set_data_model(self, dm):
        self._dm = dm

    def set_scenario_env(self, env):
        self._scenario_env = env

    def connect_to(self, step, cbk_before_sending=None, cbk_after_sending=None, cbk_after_fbk=None):
        tr = Transition(step, cbk_before_sending=cbk_before_sending,
                        cbk_after_sending=cbk_after_sending,
                        cbk_after_fbk=cbk_after_fbk)
        self._transitions.append(tr)

    # def register_callback(self, callback, hook=HOOK.after_fbk):
    #     assert isinstance(hook, HOOK)
    #     self._callbacks[hook] = callback
    #
    # def run_callback(self, next_step, feedback=None, hook=HOOK.after_fbk):
    #     assert isinstance(hook, HOOK)
    #     if hook not in self._callbacks:
    #         return None
    #
    #     cbk = self._callbacks[hook]
    #     if hook == HOOK.after_fbk:
    #         go_on = cbk(self, self._scenario_env, next_step, feedback)
    #     else:
    #         go_on = cbk(self, self._scenario_env, next_step)
    #
    #     return go_on

    @property
    def transitions(self):
        for tr in self._transitions:
            yield tr

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


    def set_transitions(self, transitions):
        self._transitions = transitions

    def __hash__(self):
        return id(self)

    def __copy__(self):
        # PeriodicData should not be copied, only the list that contains them.
        # Indeed their ids (memory addr) are used for registration and cancellation
        # new_cbks = copy.copy(self._callbacks)
        new_dm = self._dm
        # new_env = None
        new_periodic_to_rm = copy.copy(self._periodic_data_to_remove)
        new_transitions = copy.copy(self._transitions)
        new_step = type(self)(data_desc=copy.copy(self._data_desc), final=self.final,
                              fbk_timeout=self.feedback_timeout,
                              set_periodic=copy.copy(self._periodic_data))
        new_step._node = None
        new_step._periodic_data_to_remove = new_periodic_to_rm
        # new_step._callbacks = new_cbks
        new_step._dm = new_dm
        new_step._scenario_env = None  # we ignore the environment, a new one will be provided
        new_step._transitions = new_transitions
        return new_step


class FinalStep(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None,
                 # cbk_before_sending=None, cbk_after_sending=None, cbk_after_fbk=None,
                 set_periodic=None):
        Step.__init__(self, final=True)


class Transition(object):

    def __init__(self, step, cbk_before_sending=None, cbk_after_sending=None, cbk_after_fbk=None):
        self._scenario_env = None
        self._step = step
        self._callbacks = {}
        if cbk_before_sending:
            self._callbacks[HOOK.before_sending] = cbk_before_sending
        if cbk_after_sending:
            self._callbacks[HOOK.after_sending] = cbk_after_sending
        if cbk_after_fbk:
            self._callbacks[HOOK.after_fbk] = cbk_after_fbk

    def set_step(self, step):
        self._step = step

    @property
    def step(self):
        return self._step

    def set_scenario_env(self, env):
        self._scenario_env = env
        self._step.set_scenario_env(env)

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

    def __hash__(self):
        return id(self)

    def __copy__(self):
        new_cbks = copy.copy(self._callbacks)
        new_transition = type(self)(self._step)
        new_transition._callbacks = new_cbks
        new_transition._scenario_env = None
        return new_transition


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
        self._env = ScenarioEnv()
        self._periodic_ids = set()
        self._anchor = None

    def set_data_model(self, dm):
        self._dm = dm
        self._env.set_data_model(dm)

    def set_anchor(self, step):
        self._anchor = step

    @property
    def current_step(self):
        return self._anchor

    @property
    def periodic_to_clear(self):
        for pid in self._periodic_ids:
            yield pid

    def __copy__(self):

        def graph_copy(init_step, dico):
            new_transitions = [copy.copy(tr) for tr in init_step.transitions]
            init_step.set_transitions(new_transitions)
            for periodic in init_step.periodic_to_set:
                new_sc._periodic_ids.add(id(periodic))

            for tr in init_step.transitions:
                if tr.step in dico.values():
                    continue
                if tr.step in dico:
                    new_step = dico[tr.step]
                else:
                    new_step = copy.copy(tr.step)
                    dico[tr.step] = new_step
                new_step.set_data_model(self._dm)
                tr.set_step(new_step)
                tr.set_scenario_env(new_sc._env)
                graph_copy(new_step, dico)


        orig_dm = self._dm
        new_anchor = copy.copy(self._anchor)
        new_anchor.set_data_model(self._dm)
        dico = {self._anchor: new_anchor}
        orig_env = self._env
        new_sc = type(self)(self.name)
        new_sc._env = copy.copy(orig_env)
        new_sc._dm = orig_dm
        new_sc._periodic_ids = set()  # periodic ids are gathered only during graph_copy()
        new_sc._anchor = new_anchor

        graph_copy(new_sc._anchor, dico)

        return new_sc
