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
from framework.data import Data
from framework.node import Node
from libs.external_modules import *
from libs.utils import find_file, retrieve_app_handler

class DataProcess(object):
    def __init__(self, process, seed=None, auto_regen=False, vtg_ids=None):
        """
        Describe a process to generate a data.

        Args:
            process (list): List of disruptors (possibly complemented by parameters) to apply to
              a ``seed``. However, if the list begin with a generator, the disruptor chain will apply
              to the outcome of the generator. The generic form for a process is:
              ``[action_1, (action_2, generic_UI_2, specific_UI_2), ... action_n]``
              where ``action_N`` can be either: ``dmaker_type_N`` or ``(dmaker_type_N, dmaker_name_N)``
            seed: (Optional) Can be a registered :class:`framework.data_model.Node` name or
              a :class:`framework.data_model.Data`. Will be provided to the first disruptor in
              the disruptor chain (described by the parameter ``process``) if it does not begin
              with a generator.
            auto_regen (boolean): If ``True``, the data process will notify the framework to
              rerun the data maker chain after a disruptor has yielded (meaning it is exhausted with
              the data that has been provided to it).
              It will make the chain going on with new data coming either from the first
              non-exhausted disruptor (preceding the exhausted one), or from the generator if
              all disruptors are exhausted. If ``False``, the data process won't notify the
              framework to rerun the data maker chain, thus triggering the end of the scenario
              that embeds this data process.
            vtg_ids (list): Virtual ID list of the targets to which the outcomes of this data process will be sent.
              If ``None``, the outcomes will be sent to the first target that has been enabled.
        """
        self.seed = seed
        self.auto_regen = auto_regen
        self.auto_regen_cpt = 0
        self.outcomes = None
        self.feedback_timeout = None
        self.feedback_mode = None
        self.vtg_ids = vtg_ids
        self._process = [process]
        self._process_idx = 0
        self._blocked = False

    def append_new_process(self, process):
        """
        Append a new process to the list.
        """
        self._process.append(process)

    def next_process(self):
        if self._process_idx == len(self._process) - 1:
            self._process_idx = 0
            return False
        else:
            self._process_idx += 1
            return True

    def reset(self):
        self.auto_regen_cpt = 0
        self.outcomes = None
        self._process_idx = 0

    @property
    def process(self):
        return self._process[self._process_idx]

    @process.setter
    def process(self, value):
        self._process[self._process_idx] = value

    @property
    def process_qty(self):
        return len(self._process)

    def make_blocked(self):
        self._blocked = True
        if self.outcomes is not None:
            self.outcomes.make_blocked()

    def make_free(self):
        self._blocked = False
        if self.outcomes is not None:
            self.outcomes.make_free()

    def formatted_str(self, oneliner=False):
        desc = ''
        suffix = ', Process=' if oneliner else '\n'
        if isinstance(self.seed, str):
            desc += 'Seed=' + self.seed + suffix
        elif isinstance(self.seed, Data):
            seed_str = self.seed.content.name if isinstance(self.seed.content, Node) else 'Data(...)'
            desc += 'Seed={:s}'.format(seed_str) + suffix
        else:
            desc += suffix[2:]

        for proc in self._process:
            for d in proc:
                if isinstance(d, (list, tuple)):
                    desc += '{!s}/'.format(d[0])
                else:
                    assert isinstance(d, str)
                    desc += '{!s}/'.format(d)
            desc = desc[:-1]
            desc += ',' if oneliner else '\n'
        desc = desc[:-1] # if oneliner else desc[:-1]

        return desc

    def __repr__(self):
        return self.formatted_str(oneliner=True)

    def __copy__(self):
        new_datap = type(self)(self.process)
        new_datap.__dict__.update(self.__dict__)
        new_datap._process = copy.copy(self._process)
        new_datap.reset()
        return new_datap


class Periodic(object):
    def __init__(self, data, period=None):
        self.data = data
        self.period = period


class Step(object):

    def __init__(self, data_desc=None, final=False,
                 fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
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
        """

        self.final = final
        self.valid = valid
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
        self._periodic_data = set_periodic
        if clear_periodic:
            self._periodic_data_to_remove = []
            for p in clear_periodic:
                self._periodic_data_to_remove.append(id(p))
        else:
            self._periodic_data_to_remove = None

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
            assert isinstance(desc, (str, Data, DataProcess)), '{!r}, class:{:s}'.format(desc, self.__class__.__name__)

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

    def connect_to(self, step, cbk_after_sending=None, cbk_after_fbk=None, prepend=False):
        if isinstance(self, NoDataStep):
            assert cbk_after_sending is None
        tr = Transition(step,
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

    def is_blocked(self):
        return self._blocked

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
            self._data_desc = atom_list
        if isinstance(atom_list, Node):
            self._data_desc = [atom_list]
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
                    d.add_info(repr(d_desc))
                elif isinstance(d_desc, Data):
                    d.add_info('User-provided Data()')
                else:
                    assert isinstance(d_desc, str)
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


    def set_transitions(self, transitions):
        self._transitions = transitions

    def __str__(self):
        if self._step_desc:
            step_desc = self._step_desc
        else:
            step_desc = ''
            for idx, d in enumerate(self._data_desc):
                if isinstance(d, DataProcess):
                    step_desc += d.formatted_str(oneliner=False)
                elif isinstance(d, Data):
                    if self.__class__.__name__ != 'Step':
                        step_desc += '[' + self.__class__.__name__ + ']'
                    else:
                        step_desc += d.content.name if isinstance(d.content, Node) else 'Data(...)'
                elif isinstance(d, str):
                    step_desc += "{:s}".format(self._node_name[idx].upper())
                else:
                    assert d is None
                    step_desc += '[' + self.__class__.__name__ + ']'
                step_desc += '\n'
            step_desc = step_desc[:-1]

        return step_desc

    def get_description(self):
        # Note the provided string is dot/graphviz oriented.
        step_desc = str(self).replace('\n', '\\n') # for graphviz display in 'record' boxes

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

        if self.feedback_timeout is not None:
            step_desc = '{:s}\\n{!s}s|'.format('wait', self.feedback_timeout) + step_desc

        return step_desc

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
        new_step._scenario_env = None  # we ignore the environment, a new one will be provided
        new_step._transitions = copy.copy(self._transitions)
        return new_step


class FinalStep(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 do_before_data_processing=None, valid=True, vtg_ids=None):
        Step.__init__(self, final=True, do_before_data_processing=do_before_data_processing,
                      valid=valid, vtg_ids=vtg_ids)

class NoDataStep(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 do_before_data_processing=None, valid=True, vtg_ids=None):
        Step.__init__(self, data_desc=Data(''), final=final,
                      fbk_timeout=fbk_timeout, fbk_mode=fbk_mode,
                      set_periodic=set_periodic, clear_periodic=clear_periodic,
                      step_desc=step_desc, do_before_data_processing=do_before_data_processing,
                      valid=valid, vtg_ids=vtg_ids)
        self.make_blocked()

    def make_free(self):
        pass

class Transition(object):

    def __init__(self, step, cbk_after_sending=None, cbk_after_fbk=None):
        self._scenario_env = None
        self._step = step
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
        return self._step

    @step.setter
    def step(self, value):
        self._step = value

    def set_scenario_env(self, env):
        self._scenario_env = env
        self._step.set_scenario_env(env)

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
        desc = ''
        for k, v in self._callbacks.items():
            desc += str(k) + '\n' + v.__name__ + '()\n'
        desc = desc[:-1]

        return desc

    def __hash__(self):
        return id(self)

    def __copy__(self):
        new_transition = type(self)(self._step)
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

    # @property
    # def knowledge_source(self):
    #     return self._knowledge_source
    #
    # @knowledge_source.setter
    # def knowledge_source(self, val):
    #     self._knowledge_source = val

    def __copy__(self):
        new_env = type(self)()
        new_env.__dict__.update(self.__dict__)
        new_env._target = None
        new_env._scenario = None
        # new_env._knowledge_source = None
        return new_env


PLATFORM = platform.system().lower()
viewer_format = None
viewer_app = None
viewer_app_name = None
viewer_filename = None

class Scenario(object):

    def __init__(self, name, anchor=None, reinit_anchor=None):
        self.name = name
        self._steps = None
        self._reinit_steps = None
        self._transitions = None
        self._reinit_transitions = None
        self._dm = None
        self._env = ScenarioEnv()
        self._env.scenario = self
        self._periodic_ids = set()
        self._current = None
        self._anchor = None
        self._reinit_anchor = None
        if anchor is not None:
            self.set_anchor(anchor)
        if reinit_anchor is not None:
            self.set_reinit_anchor(reinit_anchor)

    def __str__(self):
        return "Scenario '{:s}'".format(self.name)

    def reset(self):
        self._current = self._anchor

    def set_data_model(self, dm):
        self._dm = dm
        self._env.dm = dm

    def set_target(self, target):
        self._env.target = target

    # @property
    # def knowledge_source(self):
    #     return self._env.knowledge_source
    #
    # @knowledge_source.setter
    # def knowledge_source(self, val):
    #     self._env.knowledge_source = val

    def _graph_setup(self, init_step, steps, transitions):
        for tr in init_step.transitions:
            transitions.append(tr)
            if tr.step in steps:
                continue
            else:
                steps.append(tr.step)
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

    def graph(self, fmt='pdf', select_current=False):
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

        def graph_creation(init_step, node_list, edge_list):
            step_color = current_color if init_step is current_step else 'black'
            if init_step.final or init_step is self._anchor:
                step_fillcolor = current_fillcolor if init_step is current_step else 'slategray'
                step_fontcolor = current_fontcolor if init_step is current_step else 'white'
                step_style = 'rounded,filled,dotted,bold' if isinstance(init_step, NoDataStep) else 'rounded,filled,bold'
                f.attr('node', fontcolor=step_fontcolor, shape='record', style=step_style,
                       color=step_color, fillcolor=step_fillcolor)
            else:
                step_style = 'rounded,dotted' if isinstance(init_step, NoDataStep) else 'rounded,filled'
                step_fillcolor = current_fillcolor if init_step is current_step else 'lightgray'
                step_fontcolor = current_fontcolor if init_step is current_step else 'black'
                f.attr('node', fontcolor=step_fontcolor, shape='record', style=step_style,
                       color=step_color, fillcolor=step_fillcolor)
            f.node(str(id(init_step)), label=init_step.get_description())
            for idx, tr in enumerate(init_step.transitions):
                if tr.step not in node_list:
                    step_color = current_color if tr.step is current_step else 'black'
                    if tr.step.final:
                        step_fillcolor = current_fillcolor if tr.step is current_step else 'slategray'
                        step_fontcolor = current_fontcolor if tr.step is current_step else 'white'
                        f.attr('node', fontcolor=step_fontcolor, shape='record', style='rounded,filled,bold',
                               fillcolor=step_fillcolor, color=step_color)
                    else:
                        step_fillcolor = current_fillcolor if tr.step is current_step else 'lightgray'
                        step_fontcolor = current_fontcolor if tr.step is current_step else 'black'
                        step_style = 'rounded,dotted' if isinstance(tr.step, NoDataStep) else 'rounded,filled'
                        f.attr('node', fontcolor=step_fontcolor, shape='record', style=step_style,
                               fillcolor=step_fillcolor, color=step_color)
                    f.node(str(id(tr.step)), label=tr.step.get_description())
                if id(tr) not in edge_list:
                    f.edge(str(id(init_step)), str(id(tr.step)), label='[{:d}] {!s}'.format(idx+1, tr))
                    edge_list.append(id(tr))
                if tr.step in node_list:
                    continue
                if tr.step not in node_list:
                    node_list.append(tr.step)
                graph_creation(tr.step, node_list=node_list, edge_list=edge_list)

        if not graphviz_module:
            print("\n*** ERROR: need python graphviz module to be installed ***")
            return

        graph_filename = os.path.join(workspace_folder, self.name+'.gv')

        try:
            f = graphviz.Digraph(self.name, format=fmt, filename=graph_filename)
        except:
            print("\n*** ERROR: Unknown format ('{!s}') ***".format(fmt))
        else:
            graph_creation(self._anchor, node_list=[], edge_list=[])

            rendered = f.render()

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
