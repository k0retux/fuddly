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
import subprocess
import platform

from framework.global_resources import *
from framework.data import Data, DataProcess, EmptyDataProcess, DataAttr, NodeBackend
from framework.node import Node
from framework.target_helpers import Target
from libs.external_modules import *
from libs.utils import find_file, retrieve_app_handler, Task

if sys.version_info[0] > 2:
    data_graph_desc_fstr = "Data('{!a}'...)"
else:
    data_graph_desc_fstr = "Data('{!s}'...)"

class Periodic(object):
    def __init__(self, data, period=None, vtg_ids=None):
        self.data = data
        self.period = period
        if vtg_ids is None:
            self.vtg_ids_list = None
        elif isinstance(vtg_ids, list):
            self.vtg_ids_list = vtg_ids
        else:
            assert isinstance(vtg_ids, int)
            self.vtg_ids_list = [vtg_ids]

    def __str__(self):
        desc = 'period={}s \| '.format(self.period)
        d = self.data
        if isinstance(d, DataProcess):
            desc += 'DP({:s})'.format(d.formatted_str(oneliner=True))
        elif isinstance(d, Data):
            if isinstance(d.content, Node):
                desc += d.content.name.upper()
            else:
                desc += data_graph_desc_fstr.format(d.to_str()[:10]) if d.description is None else f'"{d.description}"'
        elif isinstance(d, str):
            desc += "{:s}".format(d.upper())
        else:
            assert d is None
            desc += '[' + self.__class__.__name__ + ']'
        if self.vtg_ids_list is not None:
            vtg_str = str(self.vtg_ids_list) if len(self.vtg_ids_list) > 1 else str(self.vtg_ids_list[0])
            desc += ' -(vtg)-\> {:s}\n'.format(vtg_str)
        else:
            desc += '\n'
        desc = desc[:-1]

        return desc


class Step(object):

    def __init__(self, data_desc=None, final=False,
                 fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 start_tasks=None, stop_tasks=None,
                 do_before_data_processing=None, do_before_sending=None,
                 valid=True, vtg_ids=None):
        """
        Step objects are the building blocks of Scenarios.

        Args:
            data_desc:
            final:
            fbk_timeout:
            fbk_mode:
            set_periodic:
            clear_periodic:
            step_desc:
            do_before_data_processing:
            do_before_sending:
            valid:
            vtg_ids (list, int): Virtual ID list of the targets to which the outcomes of this data process will be sent.
              If ``None``, the outcomes will be sent to the first target that has been enabled.
              If ``data_desc`` is a list, this parameter should be a list where each item is the ``vtg_ids``
              of the corresponding item in the ``data_desc`` list.
            transition_on_dp_complete (bool):
              this attribute is set
              to ``True`` by the framework.

        """

        self.final = final
        self.valid = valid

        self.data_attrs = DataAttr()

        # In the context of a step hosting a DataProcess, if the latter is completed, meaning that all
        # the registered processes are exhausted (data makers have yielded), then if a transition for this
        # condition has been defined (this attribute will be set to True), the scenario will walk through it.
        self.transition_on_dp_complete = False

        self._step_desc = step_desc
        self._transitions = []
        self._do_before_data_processing = do_before_data_processing
        self._do_before_sending = do_before_sending

        self._handle_data_desc(data_desc)
        if vtg_ids is not None:
            if isinstance(data_desc, list):
                assert isinstance(vtg_ids, list)
                assert len(vtg_ids) == len(data_desc)
                self.vtg_ids_list = vtg_ids
            else:
                self.vtg_ids_list = [vtg_ids]
        else:
            self.vtg_ids_list = None

        self.make_free()

        # need to be set after self._data_desc
        self.feedback_timeout = fbk_timeout
        self.feedback_mode = fbk_mode

        self._scenario_env = None
        self._periodic_data = list(set_periodic) if set_periodic else None
        if clear_periodic:
            self._periodic_data_to_remove = []
            for p in clear_periodic:
                self._periodic_data_to_remove.append(id(p))
        else:
            self._periodic_data_to_remove = None

        self._tasks = list(start_tasks) if start_tasks else None
        if stop_tasks:
            self._tasks_to_stop = []
            for t in stop_tasks:
                self._tasks_to_stop.append(id(t))
        else:
            self._tasks_to_stop = None

        self._stutter_cpt = None
        self._stutter_max = None

    def _handle_data_desc(self, data_desc):
        self._atom = None

        if self.final:
            self._node_name = [None]
            self._data_desc = [None]
            return

        assert data_desc is not None
        if isinstance(data_desc, list):
            self._data_desc = data_desc
        else:
            self._data_desc = [data_desc]

        for desc in self._data_desc:
            assert isinstance(desc, (str, Data, DataProcess, EmptyDataProcess)), '{!r}, class:{:s}'.format(desc, self.__class__.__name__)

        if isinstance(data_desc, str):
            self._node_name = [data_desc]
        elif isinstance(data_desc, list):
            self._node_name = []
            for d in data_desc:
                if isinstance(d, str):
                    self._node_name.append(d)
                else:
                    self._node_name.append(None)
        else:
            self._node_name = [None]

    def set_scenario_env(self, env):
        self._scenario_env = env

    def connect_to(self, obj, dp_completed_guard=False, cbk_after_sending=None, cbk_after_fbk=None, prepend=False):
        if isinstance(self, NoDataStep):
            assert cbk_after_sending is None

        if dp_completed_guard:
            assert cbk_after_sending is None and cbk_after_fbk is None
            self.transition_on_dp_complete = True
            self._transitions.insert(0, Transition(obj, dp_completed_guard=dp_completed_guard))

        else:
            tr = Transition(obj,
                            cbk_after_sending=cbk_after_sending,
                            cbk_after_fbk=cbk_after_fbk)
            if prepend:
                self._transitions.insert(0, tr)
            else:
                self._transitions.append(tr)

    def do_before_data_processing(self):
        if self._do_before_data_processing is not None:
            self._do_before_data_processing(self._scenario_env, self)

    def do_before_sending(self):
        if self._do_before_sending is not None:
            self._do_before_sending(self._scenario_env, self)
            return True
        else:
            return False

    def make_blocked(self):
        self._blocked = True
        for d in self._data_desc:
            if isinstance(d, (Data, DataProcess)):
                d.make_blocked()

    def make_free(self):
        self._blocked = False
        for d in self._data_desc:
            if isinstance(d, (Data, DataProcess)):
                d.make_free()

    def _stutter_cbk(self, env, current_step, next_step):
        self._stutter_cpt += 1
        if self._stutter_cpt > self._stutter_max:
            self._stutter_cpt = 1
            return False
        else:
            return True

    def make_stutter(self, count):
        self._stutter_cpt = 1
        self._stutter_max = count
        self.connect_to(self, cbk_after_sending=self._stutter_cbk)

    def is_blocked(self):
        return self._blocked

    def set_dmaker_reset(self):
        """
        Request the framework to reset the data makers involved
        in the step before processing them.
        Relevant only when DataProcess are in use.
        """
        self.data_attrs.set(DataAttr.Reset_DMakers)

    def clear_dmaker_reset(self):
        """
        Restore the state changed by .set_dmaker_reset()
        """
        self.data_attrs.clear(DataAttr.Reset_DMakers)

    def cleanup(self):
        for d in self._data_desc:
            if isinstance(d, DataProcess):
                d.outcomes = None

    def has_dataprocess(self):
        if len(self._data_desc) > 1:
            # In this case we have multiple data
            # Practically it means that the creation of these data need to be performed
            # by data framework callback (CallBackOps.Replace_Data) because
            # a generator (by which a scenario will be executed) can only provide one data.
            return True
        elif isinstance(self._data_desc[0], DataProcess):
            return True
        else:
            return False

    @property
    def feedback_timeout(self):
        return self._feedback_timeout

    @feedback_timeout.setter
    def feedback_timeout(self, fbk_timeout):
        self._feedback_timeout = fbk_timeout
        for d in self._data_desc:
            if isinstance(d, (Data, DataProcess)):
                d.feedback_timeout = fbk_timeout

    @property
    def feedback_mode(self):
        return self._feedback_mode

    @feedback_mode.setter
    def feedback_mode(self, fbk_mode):
        self._feedback_mode = fbk_mode
        for d in self._data_desc:
            if isinstance(d, (Data, DataProcess)):
                d.feedback_mode = fbk_mode

    @property
    def transitions(self):
        for tr in self._transitions:
            yield tr

    @property
    def content(self):
        """
        Provide the atom of the step if possible.
        In the case of a DataProcess, if it has been carried out, then the resulting atom is returned,
        otherwise the seed atom is returned if it exists.
        
        Provide an atom list if the step contain multiple atom
        """
        atom_list = []
        update_node = False
        for idx, d in enumerate(self._data_desc):
            if isinstance(d, DataProcess):
                if d.outcomes is not None and d.outcomes.content:
                    # that means that a data creation process has been registered and it has been
                    # carried out
                    atom_list.append(d.outcomes.content)
                elif d.seed is not None:
                    # We provide the seed in this case
                    if isinstance(d.seed, str):
                        seed_name = d.seed
                        atom = self._scenario_env.dm.get_atom(d.seed)
                        d.seed = Data(atom)
                        d.seed.generate_info_from_content(origin=self._scenario_env.scenario)
                        atom_list.append(atom)
                    elif isinstance(d.seed, Data):
                        atom_list.append(d.seed.content if isinstance(d.seed.content, Node) else None)
                    else:
                        atom_list.append(None)
                else:
                    atom_list.append(None)
            elif isinstance(d, Data):
                atom_list.append(d.content if isinstance(d.content, Node) else None)
            elif isinstance(d, Data) or self._node_name[idx] is None:
                # that means that a data creation process has been registered and will be
                # carried out by the framework through a callback
                atom_list.append(None)
            else:
                if self._atom is None:
                    update_node = True
                    self._atom = {}
                if update_node:
                    self._atom[idx] = self._scenario_env.dm.get_atom(self._node_name[idx])
                    self._data_desc[idx] = Data(self._atom[idx])
                    update_node = False
                atom_list.append(self._atom[idx])

        return atom_list[0] if len(atom_list) == 1 else atom_list

    @content.setter
    def content(self, atom_list):
        if isinstance(atom_list, list):
            self._data_desc = [Data(a) for a in atom_list]
        if isinstance(atom_list, Node):
            self._data_desc = [Data(atom_list)]
        else:
            raise ValueError

    def get_data(self):
        node_list = self.content
        if not isinstance(node_list, list):
            d_desc = self._data_desc[0]
            if isinstance(d_desc, Data):
                d = d_desc
            elif node_list is not None:
                d = Data(node_list)
            else:
                # in this case a data creation process is provided to the framework through the
                # callback HOOK.before_sending_step1
                d = Data('STEP:POISON_1')
        else:
            # In this case we have multiple data
            # Practically it means that the creation of these data need to be performed
            # by data framework callback (CallBackOps.Replace_Data) because
            # a generator (by which a scenario will be executed) can only provide one data.
            d = Data('STEP:POISON_2')

        if not d.has_info():
            if self._step_desc is not None:
                d.add_info(self._step_desc.replace('\n', ' '))

            for idx, d_desc in enumerate(self._data_desc):
                if isinstance(d_desc, DataProcess):
                    d.add_info('DP({:s})'.format(d_desc.formatted_str(oneliner=True)))
                elif isinstance(d_desc, Data) and not d_desc.has_node_content():
                    d.add_info('User-provided Data()')
                else:
                    d.add_info("Data Model: '{!s}'"
                               .format(self._scenario_env.dm.name))
                    d.add_info("Node Name: '{!s}'"
                               .format(self._node_name[idx]))

            if self._periodic_data is not None:
                p_sz = len(self._periodic_data)
                d.add_info("Set {:d} periodic{:s}".format(p_sz, 's' if p_sz > 1 else ''))
            if self._periodic_data_to_remove is not None:
                p_sz = len(self._periodic_data_to_remove)
                d.add_info("Clear {:d} periodic{:s}".format(p_sz, 's' if p_sz > 1 else ''))

        if self.is_blocked():
            d.make_blocked()
        else:
            d.make_free()
        if self._feedback_timeout is not None:
            d.feedback_timeout = self._feedback_timeout
        if self._feedback_mode is not None:
            d.feedback_mode = self._feedback_mode

        d.set_attributes_from(self.data_attrs)

        if self.vtg_ids_list:
            # Note in the case of self._data_desc contains multiple data, related
            # vtg_ids are retrieved directly from the Step in the Replace_Data callback.
            d.tg_ids = self.vtg_ids_list[0]

        return d

    @property
    def data_desc(self):
        return self._data_desc

    @data_desc.setter
    def data_desc(self, data_desc):
        self._handle_data_desc(data_desc)

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

    @property
    def tasks_to_start(self):
        if self._tasks is None:
            return
        else:
            for t in self._tasks:
                yield t

    @property
    def tasks_to_stop(self):
        if self._tasks_to_stop is None:
            return
        else:
            for tid in self._tasks_to_stop:
                yield tid


    def set_transitions(self, transitions):
        self._transitions = transitions

    def get_desc(self, oneliner=True):
        if self._step_desc:
            step_desc = self._step_desc
        else:
            step_desc = ''
            for idx, d in enumerate(self._data_desc):
                if isinstance(d, DataProcess):
                    step_desc += 'DP({:s})'.format(d.formatted_str(oneliner=oneliner))
                elif isinstance(d, Data):
                    if self.__class__.__name__ != 'Step':
                        step_desc += '[' + self.__class__.__name__ + ']'
                    else:
                        if isinstance(d.content, Node):
                            step_desc += d.content.name.upper()
                        else:
                            step_desc += data_graph_desc_fstr.format(d.to_str()[:10]) if d.description is None else f'"{d.description}"'
                elif isinstance(d, str):
                    step_desc += "{:s}".format(self._node_name[idx].upper())
                elif isinstance(d, EmptyDataProcess):
                    step_desc += 'DP(not defined yet)'
                else:
                    assert d is None, f'incorrect object: {d}'
                    step_desc += '[' + self.__class__.__name__ + ']'
                vtgids_str = ' -(vtg)-\> {:s}'.format(str(self.vtg_ids_list[idx])) if self.vtg_ids_list is not None else ''
                step_desc += vtgids_str + '\n'
            step_desc = step_desc[:-1]

        return step_desc

    def __str__(self):
        return self.get_desc(oneliner=True)

    def get_full_description(self, oneliner=True):
        # Note the provided string is dot/graphviz oriented.
        step_desc = self.get_desc(oneliner=oneliner).replace('\n', '\\n') # for graphviz display in 'record' boxes

        if self._do_before_sending is not None or self._do_before_data_processing is not None:
            if self._do_before_data_processing is None:
                cbk_before_dataproc_str = ' x '
            else:
                cbk_before_dataproc_str = ' \<-- {:s}()  '.format(self._do_before_data_processing.__name__)
            if self._do_before_sending is None:
                cbk_before_sending_str = ' x '
            else:
                cbk_before_sending_str = ' --\> {:s}() '.format(self._do_before_sending.__name__)

            if self.is_blocked():
                step_desc = step_desc + '|{:s}'.format(cbk_before_dataproc_str)
            else:
                step_desc = step_desc + '|{{{:s}|{:s}}}'.format(cbk_before_dataproc_str, cbk_before_sending_str)

        fbk_mode = None if self.feedback_mode is None else Target.get_fbk_mode_desc(self.feedback_mode, short=True)
        if self.feedback_timeout is not None and self.feedback_mode is not None:
            step_desc = '{{fbk timeout {!s}s|{:s}}}|{:s}'.format(self.feedback_timeout, fbk_mode, step_desc)
        elif self.feedback_timeout is not None:
            step_desc = 'fbk timeout\\n{!s}s|{:s}'.format(self.feedback_timeout, step_desc)
        elif self.feedback_mode is not None:
            step_desc = 'fbk mode\\n{:s}|{:s}'.format(fbk_mode, step_desc)
        else:
            pass

        return step_desc

    def is_periodic_set(self):
        return bool(self._periodic_data)

    def is_periodic_cleared(self):
        return bool(self._periodic_data_to_remove)

    def has_tasks_to_start(self):
        return bool(self._tasks)

    def has_tasks_to_stop(self):
        return bool(self._tasks_to_stop)

    def get_periodic_description(self):
        # Note the provided string is dot/graphviz oriented.
        if self.is_periodic_set() or self.is_periodic_cleared():
            desc = '{'
            if self.is_periodic_set():
                for p in self.periodic_to_set:
                    desc += 'SET Periodic [{:s}]\l [{:s}]\l|'.format(str(id(p))[-6:], str(p))

            if self.is_periodic_cleared():
                for p in self.periodic_to_clear:
                    desc += 'CLEAR Periodic [{:s}]\l|'.format(str(p)[-6:])
            desc = desc[:-1] + '}'
            return desc
        else:
            return 'No periodic to set'

    def get_tasks_description(self):
        # Note the provided string is dot/graphviz oriented.
        if self.has_tasks_to_start() or self.has_tasks_to_stop():
            desc = '{'
            if self.has_tasks_to_start():
                for t in self.tasks_to_start:
                    desc += 'START Task [{:s}]\l [{:s}]\l|'.format(str(id(t))[-6:], str(t))

            if self.has_tasks_to_stop():
                for t in self.tasks_to_stop:
                    desc += 'STOP Task [{:s}]\l|'.format(str(t)[-6:])
            desc = desc[:-1] + '}'
            return desc
        else:
            return 'No tasks to start'

    def get_periodic_ref(self):
        if self.is_periodic_set():
            ref = id(self._periodic_data)
        elif self.is_periodic_cleared():
            ref = id(self._periodic_data_to_remove)
        else:
            ref = None

        return ref

    def get_tasks_ref(self):
        if self.has_tasks_to_start():
            ref = id(self._tasks)
        elif self.has_tasks_to_stop():
            ref = id(self._tasks_to_stop)
        else:
            ref = None

        return ref

    def __hash__(self):
        return id(self)

    def __copy__(self):
        new_step = type(self)(final=True) # final=True to shorten __init__()
        new_step.__dict__.update(self.__dict__)
        data_desc_copy = [copy.copy(d) for d in self._data_desc]
        new_step._handle_data_desc(data_desc_copy)
        # Periodic should not be copied, only the list that contains them, as
        # their IDs (memory addr) are used for registration and cancellation
        new_step._periodic_data = copy.copy(self._periodic_data)
        new_step._periodic_data_to_remove = copy.copy(self._periodic_data_to_remove)
        new_step._tasks = copy.copy(self._tasks)
        new_step._tasks_to_stop = copy.copy(self._tasks_to_stop)
        new_step._periodic_data_to_remove = copy.copy(self._periodic_data_to_remove)
        new_step._scenario_env = None  # we ignore the environment, a new one will be provided
        new_step._transitions = copy.copy(self._transitions)
        new_step.data_attrs = copy.copy(self.data_attrs)
        return new_step


class FinalStep(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 start_tasks=None, stop_tasks=None,
                 do_before_data_processing=None, do_before_sending=None, valid=True, vtg_ids=None):
        Step.__init__(self, final=True, do_before_data_processing=do_before_data_processing,
                      do_before_sending=do_before_sending,
                      valid=valid, vtg_ids=vtg_ids)

class NoDataStep(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 start_tasks=None, stop_tasks=None,
                 do_before_data_processing=None, do_before_sending=None, valid=True, vtg_ids=None):
        Step.__init__(self, data_desc=Data(''), final=final,
                      fbk_timeout=fbk_timeout, fbk_mode=fbk_mode,
                      set_periodic=set_periodic, clear_periodic=clear_periodic,
                      start_tasks=start_tasks, stop_tasks=stop_tasks,
                      step_desc=step_desc, do_before_data_processing=do_before_data_processing,
                      do_before_sending=do_before_sending,
                      valid=valid, vtg_ids=vtg_ids)
        self.make_blocked()

    def make_free(self):
        pass

class StepStub(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 start_tasks=None, stop_tasks=None,
                 do_before_data_processing=None, do_before_sending=None, valid=True, vtg_ids=None):
        Step.__init__(self, data_desc=EmptyDataProcess(), final=final,
                      fbk_timeout=fbk_timeout, fbk_mode=fbk_mode,
                      set_periodic=set_periodic, clear_periodic=clear_periodic,
                      start_tasks=start_tasks, stop_tasks=stop_tasks,
                      step_desc=step_desc, do_before_data_processing=do_before_data_processing,
                      do_before_sending=do_before_sending,
                      valid=valid, vtg_ids=vtg_ids)

class Transition(object):

    def __init__(self, obj, dp_completed_guard=False, cbk_after_sending=None, cbk_after_fbk=None):
        self._scenario_env = None
        self._obj = obj
        self.dp_completed_guard = dp_completed_guard
        self._callbacks = {}
        if cbk_after_sending:
            self._callbacks[HOOK.after_sending] = cbk_after_sending
        if cbk_after_fbk:
            self._callbacks[HOOK.after_fbk] = cbk_after_fbk
        self._callbacks_qty = self._callbacks_pending = len(self._callbacks)

        self._invert_conditions = False
        self._crossable = True

    @property
    def step(self):
        if isinstance(self._obj, Step):
            return self._obj
        elif isinstance(self._obj, Scenario):
            return self._obj.anchor
        else:
            raise NotImplementedError

    @step.setter
    def step(self, value):
        self._obj = value

    def set_scenario_env(self, env, merge_user_contexts: bool = True):
        self._scenario_env = env
        if isinstance(self._obj, Step):
            self._obj.set_scenario_env(env)
        elif isinstance(self._obj, Scenario):
            self._obj.set_scenario_env(env, merge_user_contexts=merge_user_contexts)
        else:
            raise NotImplementedError

    def register_callback(self, callback, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        self._callbacks[hook] = callback

    def run_callback(self, current_step, feedback=None, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)

        if self._callbacks_pending <= 0:
            # we assume that run_callback() is called only once per hook. Thus when all the callback
            # has been called, a new call to this method means that we re-evaluate the transition
            # from the beginning.
            self._callbacks_pending = self._callbacks_qty

        if hook not in self._callbacks:
            return None

        cbk = self._callbacks[hook]
        if hook == HOOK.after_fbk:
            go_on = cbk(self._scenario_env, current_step, self.step, feedback)
        else:
            go_on = cbk(self._scenario_env, current_step, self.step)

        self._callbacks_pending -= 1

        if not self._crossable:
            return False

        return not go_on if self._invert_conditions else go_on

    def has_callback(self):
        return bool(self._callbacks)

    def has_callback_pending(self):
        return self._callbacks_pending > 0

    def invert_conditions(self):
        self._invert_conditions = not self._invert_conditions

    def make_uncrossable(self):
        self._crossable = False

    def is_crossable(self):
        return self._crossable

    def __str__(self):
        if self.dp_completed_guard:
            desc = 'DP completed?'
        else:
            desc = ''
            for k, v in self._callbacks.items():
                desc += str(k) + '\n' + v.__name__ + '()\n'
            desc = desc[:-1]

        return desc

    def __hash__(self):
        return id(self)

    def __copy__(self):
        new_transition = type(self)(self._obj)
        new_transition.__dict__.update(self.__dict__)
        new_transition._callbacks = copy.copy(self._callbacks)
        new_transition._callbacks_qty = new_transition._callbacks_pending
        new_transition._scenario_env = None
        return new_transition


class ScenarioEnv(object):

    knowledge_source = None

    def __init__(self):
        self._dm = None
        self._target = None
        self._scenario = None
        self._context = None
        # self._knowledge_source = None

    @property
    def dm(self):
        return self._dm

    @dm.setter
    def dm(self, val):
        self._dm = val

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, val):
        self._target = val

    @property
    def scenario(self):
        return self._scenario

    @scenario.setter
    def scenario(self, val):
        self._scenario = val

    @property
    def user_context(self):
        return self._context

    @user_context.setter
    def user_context(self, val):
        self._context = val

    def __copy__(self):
        new_env = type(self)()
        new_env.__dict__.update(self.__dict__)
        new_env._target = None
        new_env._scenario = None
        new_env._context = copy.copy(self._context)
        # new_env._knowledge_source = None
        return new_env


PLATFORM = platform.system().lower()
viewer_format = None
viewer_app = None
viewer_app_name = None
viewer_filename = None

class Scenario(object):

    def __init__(self, name, anchor=None, reinit_anchor=None, user_context=None,
                 user_args=None):
        """
        Note: only at copy the ScenarioEnv are propagated to the steps and transitions

        Args:
            name:
            anchor:
            reinit_anchor:
            user_context:
            user_args:
        """

        self.name = name
        self._user_args = user_args
        self._steps = None
        self._reinit_steps = None
        self._transitions = None
        self._reinit_transitions = None
        self._dm = None
        self._env = ScenarioEnv()
        self._env.scenario = self
        self._env.user_context = user_context
        self._periodic_ids = set()
        self._task_ids = set()
        self._current = None
        self._anchor = None
        self._reinit_anchor = None
        if anchor is not None:
            self.set_anchor(anchor)
        if reinit_anchor is not None:
            self.set_reinit_anchor(reinit_anchor)

    def __str__(self):
        return "Scenario '{:s}'".format(self.name)

    def clone(self, new_name):
        new_sc = copy.copy(self)
        new_sc.name = new_name
        return new_sc

    def reset(self):
        self._current = self._anchor

    @property
    def user_context(self):
        return self._env.user_context

    @user_context.setter
    def user_context(self, user_context):
        self._env.user_context = user_context

    def merge_user_context_with(self, user_context):
        self._env.user_context.merge_with(user_context)

    def set_data_model(self, dm):
        self._dm = dm
        self._env.dm = dm

    def set_target(self, target):
        self._env.target = target

    def _graph_setup(self, init_step, steps, transitions):
        for tr in init_step.transitions:
            transitions.append(tr)
            tr.set_scenario_env(self.env)
            if tr.step in steps:
                continue
            else:
                steps.append(tr.step)
                tr.step.set_scenario_env(self.env)
                self._graph_setup(tr.step, steps, transitions)

    def _init_main_properties(self):
        assert self._anchor is not None
        self._steps = []
        self._transitions = []
        self._steps.append(self._anchor)
        self._graph_setup(self._anchor, self._steps, self._transitions)

    def _init_reinit_seq_properties(self):
        assert self._reinit_anchor is not None
        self._reinit_steps = []
        self._reinit_transitions = []
        self._graph_setup(self._reinit_anchor, self._reinit_steps, self._reinit_transitions)

    def set_anchor(self, anchor, current=None):
        if current is not None:
            self._current = current
        else:
            self._current = anchor
        self._anchor = anchor
        self._steps = None
        self._transitions = None

    def set_reinit_anchor(self, reinit_anchor):
        self._reinit_anchor = reinit_anchor
        self._reinit_steps = None
        self._reinit_transitions = None

    @property
    def env(self):
        return self._env

    def set_scenario_env(self, env: ScenarioEnv, merge_user_contexts: bool = True):
        """

        Args:
            env:
            merge_user_contexts: the new env will have a user_context that is the merging of
              the current one and the one provided through the new env.
              In case some parameter names overlaps, the new values are kept.

        """
        if merge_user_contexts:
            self._env.user_context.merge_with(env.user_context)
            env.user_context = self._env.user_context

        self._env = env
        self._init_main_properties()

    @property
    def steps(self):
        if self._steps is None:
            self._init_main_properties()
        return copy.copy(self._steps)

    @property
    def transitions(self):
        if self._transitions is None:
            self._init_main_properties()
        return copy.copy(self._transitions)

    @property
    def reinit_steps(self):
        if self._reinit_steps is None:
            self._init_reinit_seq_properties()
        return copy.copy(self._reinit_steps)

    @property
    def reinit_transitions(self):
        if self._reinit_transitions is None:
            self._init_reinit_seq_properties()
        return copy.copy(self._reinit_transitions)

    def walk_to(self, step):
        step.cleanup()
        self._current = step

    def branch_to_reinit(self, step, prepend=True):
        if self._reinit_anchor is None:
            step.connect_to(self._anchor, prepend=prepend)
        else:
            step.connect_to(self._reinit_anchor, prepend=prepend)

    def walk_to_reinit(self):
        if self._reinit_anchor is None:
            self._anchor.cleanup()
            self._current = self._anchor
        else:
            self._reinit_anchor.cleanup()
            self._current = self._reinit_anchor

    @property
    def current_step(self):
        return self._current

    @property
    def anchor(self):
        return self._anchor

    @property
    def periodic_to_clear(self):
        for pid in self._periodic_ids:
            yield pid

    @property
    def tasks_to_stop(self):
        for tid in self._task_ids:
            yield tid


    def _view_linux(self, filepath, graph_filename):
        """Open filepath in the user's preferred application (linux)."""
        global viewer_format
        global viewer_app
        global viewer_app_name

        if viewer_app_name is None:
            viewer_app_name = retrieve_app_handler(graph_filename)

        if viewer_app_name is None:
            print("\n*** WARNING: No built-in viewer found for the format ('{:s}') ***"
                  .format(viewer_format))
        else:
            viewer_app = subprocess.Popen([viewer_app_name, filepath],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _view_windows(self, filepath, graph_filename):
        """Start filepath with its associated application (windows)."""
        os.startfile(os.path.normpath(filepath))

    def graph(self, fmt='pdf', select_current=False, display_ucontext=True):
        global viewer_format
        global viewer_app
        global viewer_app_name
        global viewer_filename

        current_color = 'blue'
        current_fillcolor = 'lightblue'
        current_fontcolor = 'blue'
        current_step = self._current if select_current else None
        if fmt != viewer_format:
            viewer_format = fmt
            viewer_app = None
            viewer_app_name = None

        def graph_creation(init_step, node_list, edge_list, graph):

            def graph_periodic(step, node_list):
                if (step.is_periodic_set() or step.is_periodic_cleared()) \
                        and step.get_periodic_ref() not in node_list:
                    id_node = str(id(step))
                    id_periodic = str(step.get_periodic_ref())
                    graph.node(id_periodic, label=step.get_periodic_description(),
                               shape='record', style='filled', color='black', fillcolor='palegreen',
                               fontcolor='black', fontsize='8')
                    node_list.append(step.get_periodic_ref())
                    graph.edge(id_node, id_periodic, arrowhead='dot') # headport='se', tailport='nw')

            def graph_tasks(step, node_list):
                if (step.has_tasks_to_start() or step.has_tasks_to_stop()) \
                        and step.get_tasks_ref() not in node_list:
                    id_node = str(id(step))
                    id_tasks = str(step.get_tasks_ref())
                    graph.node(id_tasks, label=step.get_tasks_description(),
                               shape='record', style='filled', color='black', fillcolor='palegreen',
                               fontcolor='black', fontsize='8')
                    node_list.append(step.get_tasks_ref())
                    graph.edge(id_node, id_tasks, arrowhead='dot') # headport='se', tailport='nw')

            step_color = current_color if init_step is current_step else 'black'
            if init_step.final or init_step is self._anchor:
                step_fillcolor = current_fillcolor if init_step is current_step else 'slategray'
                step_fontcolor = current_fontcolor if init_step is current_step else 'white'
                step_style = 'rounded,filled,dotted,bold' if isinstance(init_step, NoDataStep) else 'rounded,filled,bold'
                graph.attr('node', fontcolor=step_fontcolor, shape='record', style=step_style,
                       color=step_color, fillcolor=step_fillcolor)
            else:
                step_style = 'rounded,dotted' if isinstance(init_step, NoDataStep) else 'rounded,filled'
                step_fillcolor = current_fillcolor if init_step is current_step else 'lightgray'
                step_fontcolor = current_fontcolor if init_step is current_step else 'black'
                graph.attr('node', fontcolor=step_fontcolor, shape='record', style=step_style,
                       color=step_color, fillcolor=step_fillcolor)
            graph.node(str(id(init_step)), label=init_step.get_full_description(oneliner=False))
            graph_periodic(init_step, node_list)
            graph_tasks(init_step, node_list)
            for idx, tr in enumerate(init_step.transitions):
                if tr.step not in node_list:
                    step_color = current_color if tr.step is current_step else 'black'
                    if tr.step.final:
                        step_fillcolor = current_fillcolor if tr.step is current_step else 'slategray'
                        step_fontcolor = current_fontcolor if tr.step is current_step else 'white'
                        graph.attr('node', fontcolor=step_fontcolor, shape='record', style='rounded,filled,bold',
                               fillcolor=step_fillcolor, color=step_color)
                    else:
                        step_fillcolor = current_fillcolor if tr.step is current_step else 'lightgray'
                        step_fontcolor = current_fontcolor if tr.step is current_step else 'black'
                        step_style = 'rounded,dotted' if isinstance(tr.step, NoDataStep) else 'rounded,filled'
                        graph.attr('node', fontcolor=step_fontcolor, shape='record', style=step_style,
                               fillcolor=step_fillcolor, color=step_color)
                    graph.node(str(id(tr.step)), label=tr.step.get_full_description(oneliner=False))
                    graph_periodic(tr.step, node_list)
                    graph_tasks(tr.step, node_list)
                if id(tr) not in edge_list:
                    graph.edge(str(id(init_step)), str(id(tr.step)), label='[{:d}] {!s}'.format(idx+1, tr))
                    edge_list.append(id(tr))
                if tr.step in node_list:
                    continue
                if tr.step not in node_list:
                    node_list.append(tr.step)
                graph_creation(tr.step, node_list=node_list, edge_list=edge_list, graph=graph)

        if not graphviz_module:
            print("\n*** ERROR: need python graphviz module to be installed ***")
            return

        graph_filename = os.path.join(workspace_folder, self.name+'.gv')

        try:
            g = graphviz.Digraph(self.name, format=fmt, filename=graph_filename)
        except:
            print("\n*** ERROR: Unknown format ('{!s}') ***".format(fmt))
        else:
            if display_ucontext and self.env.user_context:
                with g.subgraph(name='cluster_1') as graph:
                    graph.attr(label='SCENARIO', fontcolor='black', labelloc='b')
                    graph_creation(self._anchor, node_list=[], edge_list=[], graph=graph)

                with g.subgraph(name='cluster_2') as h:
                    h.attr(label='USER CONTEXT', style='filled', color='gray90', labelloc='b')
                    context_id = str(id(self.env.user_context))
                    if isinstance(self.env.user_context, UI):
                        uctxt_desc = '{'
                        uinputs = self.env.user_context.get_inputs()
                        for k, v in uinputs.items():
                            uctxt_desc += '{:s} = {!s}\l|'.format(k, v)
                        uctxt_desc = uctxt_desc[:-1] + '}'
                    else:
                        uctxt_desc = str(self.env.user_context)
                    h.node(context_id, label=uctxt_desc,
                           shape='record', style='filled,bold', color='black', fillcolor='deepskyblue',
                           fontcolor='black', fontsize='10')
            else:
                graph_creation(self._anchor, node_list=[], edge_list=[], graph=g)

            try:
                rendered = g.render()
            except:
                print("\n*** The renderer has stopped! (because of an unexpected event) ***")
                return

            if graph_filename != viewer_filename or viewer_app is None or viewer_app.poll() is not None:
                viewer_filename = graph_filename
                view_method = getattr(self, '_view_{:s}'.format(PLATFORM), None)
                if view_method is None:
                    raise RuntimeError('{!r} has no built-in viewer support for {!r} '
                                       'on {!r} platform'.format(self.__class__, fmt, PLATFORM))
                view_method(rendered, graph_filename+'.'+viewer_format)

    def __copy__(self):

        def graph_copy(init_step, dico, env):
            new_transitions = [copy.copy(tr) for tr in init_step.transitions]
            init_step.set_transitions(new_transitions)
            for periodic in init_step.periodic_to_set:
                new_sc._periodic_ids.add(id(periodic))
            for task in init_step.tasks_to_start:
                new_sc._task_ids.add(id(task))

            for tr in init_step.transitions:
                tr.set_scenario_env(env)
                if tr.step in dico.values():
                    continue
                if tr.step in dico:
                    new_step = dico[tr.step]
                else:
                    new_step = copy.copy(tr.step)
                    dico[tr.step] = new_step
                new_step.set_scenario_env(env)
                tr.step = new_step
                graph_copy(new_step, dico, env)

        new_sc = type(self)(self.name)
        new_sc.__dict__.update(self.__dict__)
        new_sc._env = copy.copy(self._env)
        new_sc._env.scenario = new_sc
        new_sc._periodic_ids = set()  # periodic ids are gathered only during graph_copy()
        new_sc._task_ids = set()  # task ids are gathered only during graph_copy()
        if self._current is self._anchor:
            new_current = new_anchor = copy.copy(self._current)
        else:
            new_current = copy.copy(self._current)
            new_anchor = copy.copy(self._anchor)
        new_anchor.set_scenario_env(new_sc._env)
        dico = {self._anchor: new_anchor}
        graph_copy(new_anchor, dico, new_sc._env)
        new_sc.set_anchor(new_anchor, current=new_current)

        if self._reinit_anchor is not None:
            new_reinit_anchor = copy.copy(self._reinit_anchor)
            new_reinit_anchor.set_scenario_env(new_sc._env)
            dico.update({self._reinit_anchor: new_reinit_anchor})
            graph_copy(new_reinit_anchor, dico, new_sc._env)
            new_sc.set_reinit_anchor(new_reinit_anchor)

        return new_sc
