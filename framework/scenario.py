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
from framework.data_model import Data, Node
from libs.external_modules import *

class DataProcess(object):
    def __init__(self, process, seed=None, auto_regen=False):
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
        """
        self.seed = seed
        self.auto_regen = auto_regen
        self.outcomes = None
        self.feedback_timeout = None
        self.feedback_mode = None
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

    @property
    def process(self):
        return self._process[self._process_idx]

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
        suffix = ', PROCESS: ' if oneliner else '\n'
        if isinstance(self.seed, str):
            desc += 'SEED: ' + self.seed + suffix
        elif isinstance(self.seed, Data):
            desc += 'SEED: Data(...)' + suffix
        else:
            desc += suffix[2:]

        for proc in self._process:
            for d in proc:
                if isinstance(d, (list, tuple)):
                    desc += '{!s} / '.format(d[0])
                else:
                    assert isinstance(d, str)
                    desc += '{!s} / '.format(d)
            desc = desc[:-3]
            desc += ' - ' if oneliner else '\n'
        desc = desc[:-3] if oneliner else desc[:-1]

        return desc

    def __repr__(self):
        return self.formatted_str(oneliner=True)

    def __copy__(self):
        new_datap = type(self)(self.process, seed=self.seed, auto_regen=self.auto_regen)
        new_datap._process = copy.copy(self._process)
        new_datap._process_idx = self._process_idx
        new_datap._blocked = self._blocked
        new_datap.feedback_timeout = self.feedback_timeout
        new_datap.feedback_mode = self.feedback_mode
        return new_datap


class Periodic(object):
    def __init__(self, data, period=None):
        self.data = data
        self.period = period


class Step(object):

    def __init__(self, data_desc=None, final=False,
                 fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 do_before_data_processing=None, do_before_sending=None):

        self.final = final
        self._step_desc = step_desc
        self._transitions = []
        self._do_before_data_processing = do_before_data_processing
        self._do_before_sending = do_before_sending

        if not final:
            self._handle_data_desc(data_desc)
        else:
            self._node_name = [None]
            self._data_desc = [None]
            self._node = None

        self.make_free()

        # need to be set after self._data_desc
        self.feedback_timeout = fbk_timeout
        self.feedback_mode = fbk_mode

        self._dm = None
        self._scenario_env = None
        self._periodic_data = set_periodic
        if clear_periodic:
            self._periodic_data_to_remove = []
            for p in clear_periodic:
                self._periodic_data_to_remove.append(id(p))
        else:
            self._periodic_data_to_remove = None

    def _handle_data_desc(self, data_desc):
        self._node = None
        assert data_desc is not None
        if isinstance(data_desc, list):
            self._data_desc = data_desc
        else:
            self._data_desc = [data_desc]

        for desc in self._data_desc:
            assert isinstance(desc, (str, Data, DataProcess))

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


    def set_data_model(self, dm):
        self._dm = dm

    def set_scenario_env(self, env):
        self._scenario_env = env

    def connect_to(self, step, cbk_after_sending=None, cbk_after_fbk=None):
        tr = Transition(step,
                        cbk_after_sending=cbk_after_sending,
                        cbk_after_fbk=cbk_after_fbk)
        self._transitions.append(tr)

    def do_before_data_processing(self):
        if self._do_before_data_processing is not None:
            self._do_before_data_processing(self, self._scenario_env)

    def do_before_sending(self):
        if self._do_before_sending is not None:
            self._do_before_sending(self, self._scenario_env)

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
    def node(self):
        """
        Provide the node of the step if possible.
        In the case of a DataProcess, if it has been carried out, then the resulting node is returned,
        otherwise the seed node is returned if it exists.
        """
        node_list = []
        update_node = False
        for idx, d in enumerate(self._data_desc):
            if isinstance(d, DataProcess):
                if d.outcomes is not None and d.outcomes.node:
                    # that means that a data creation process has been registered and it has been
                    # carried out
                    node_list.append(d.outcomes.node)
                elif d.seed is not None:
                    # We provide the seed in this case
                    if isinstance(d.seed, str):
                        seed_name = d.seed
                        node = self._dm.get_data(d.seed)
                        d.seed = Data(node)
                        d.seed.set_initial_dmaker([seed_name.upper(), 'g_'+seed_name, None])
                        node_list.append(node)
                    elif isinstance(d.seed, Data):
                        node_list.append(d.seed.node)  # if data is raw, .node is None
                    else:
                        node_list.append(None)
                else:
                    node_list.append(None)
            elif isinstance(d, Data):
                node_list.append(d.node)  # if data is raw, .node is None
            elif isinstance(d, Data) or self._node_name[idx] is None:
                # that means that a data creation process has been registered and will be
                # carried out by the framework through a callback
                node_list.append(None)
            else:
                if self._node is None:
                    update_node = True
                    self._node = {}
                if update_node:
                    self._node[idx] = self._dm.get_data(self._node_name[idx])
                node_list.append(self._node[idx])

        return node_list[0] if len(node_list) == 1 else node_list

    @node.setter
    def node(self, node_list):
        if isinstance(node_list, list):
            self._data_desc = node_list
        if isinstance(node_list, Node):
            self._data_desc = [node_list]
        else:
            raise ValueError

    def get_data(self):
        node_list = self.node
        if not isinstance(node_list, list):
            d_desc = self._data_desc[0]
            if isinstance(d_desc, Data):
                d = d_desc
            elif node_list is not None:
                d = Data(node_list)
            else:
                # in this case a data creation process is provided to the framework through the
                # callback HOOK.before_sending_step1
                d = Data('')
        else:
            # In this case we have multiple data
            # Practically it means that the creation of these data need to be performed
            # by data framework callback (CallBackOps.Replace_Data) because
            # a generator (by which a scenario will be executed) can only provide one data.
            d = Data('')

        if self._step_desc is None:
            for idx, d_desc in enumerate(self._data_desc):
                if isinstance(d_desc, DataProcess):
                    d.add_info(repr(d_desc))
                elif isinstance(d_desc, Data):
                    d.add_info('Use provided Data(...)')
                else:
                    assert isinstance(d_desc, str)
                    d.add_info("Instantiate a node '{!s}' from the model".format(self._node_name[idx]))
            if self._periodic_data is not None:
                p_sz = len(self._periodic_data)
                d.add_info("Set {:d} periodic{:s}".format(p_sz, 's' if p_sz > 1 else ''))
            if self._periodic_data_to_remove is not None:
                p_sz = len(self._periodic_data_to_remove)
                d.add_info("Clear {:d} periodic{:s}".format(p_sz, 's' if p_sz > 1 else ''))
        else:
            d.add_info(self._step_desc)

        if self.is_blocked():
            d.make_blocked()
        else:
            d.make_free()
        if self._feedback_timeout is not None:
            d.feedback_timeout = self._feedback_timeout
        if self._feedback_mode is not None:
            d.feedback_mode = self._feedback_mode

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
                        step_desc += 'Data(...)'
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
                cbk_before_dataproc_str = '! [1]'
            else:
                cbk_before_dataproc_str = '[1] {:s}'.format(self._do_before_data_processing.__name__)
            if self._do_before_sending is None:
                cbk_before_sending_str = '! [2]'
            else:
                cbk_before_sending_str = '[2] {:s}'.format(self._do_before_sending.__name__)
            step_desc = step_desc + '|{{{:s}|{:s}}}'.format(cbk_before_dataproc_str, cbk_before_sending_str)

        return step_desc

    def __hash__(self):
        return id(self)

    def __copy__(self):
        # Periodic should not be copied, only the list that contains them.
        # Indeed their ids (memory addr) are used for registration and cancellation
        new_dm = self._dm
        new_periodic_to_rm = copy.copy(self._periodic_data_to_remove)
        new_transitions = copy.copy(self._transitions)
        data_desc_copy = [copy.copy(d) for d in self._data_desc]
        new_step = type(self)(data_desc=data_desc_copy, final=self.final,
                              fbk_timeout=self.feedback_timeout, fbk_mode=self.feedback_mode,
                              set_periodic=copy.copy(self._periodic_data),
                              step_desc=self._step_desc,
                              do_before_data_processing=self._do_before_data_processing,
                              do_before_sending=self._do_before_sending)
        new_step._node = None
        new_step._periodic_data_to_remove = new_periodic_to_rm
        new_step._dm = new_dm
        new_step._scenario_env = None  # we ignore the environment, a new one will be provided
        new_step._transitions = new_transitions
        return new_step


class FinalStep(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 do_before_data_processing=None, do_before_sending=None):
        Step.__init__(self, final=True, do_before_data_processing=do_before_data_processing)

class NoDataStep(Step):
    def __init__(self, data_desc=None, final=False, fbk_timeout=None, fbk_mode=None,
                 set_periodic=None, clear_periodic=None, step_desc=None,
                 do_before_data_processing=None, do_before_sending=None):
        Step.__init__(self, data_desc=Data(''), final=final,
                      fbk_timeout=fbk_timeout, fbk_mode=fbk_mode,
                      set_periodic=set_periodic, clear_periodic=clear_periodic,
                      step_desc=step_desc, do_before_data_processing=do_before_data_processing)
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

    def set_step(self, step):
        self._step = step
        self._step.set_scenario_env(self._scenario_env)

    @property
    def step(self):
        return self._step

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

        return go_on

    def has_callback(self):
        return bool(self._callbacks)

    def has_callback_pending(self):
        return self._callbacks_pending > 0

    def __str__(self):
        desc = ''
        for k, v in self._callbacks.items():
            desc += str(k) + '\n' + v.__name__ + '()\n'
        desc = desc[:-1]

        return desc

    def __hash__(self):
        return id(self)

    def __copy__(self):
        new_cbks = copy.copy(self._callbacks)
        new_transition = type(self)(self._step)
        new_transition._callbacks = new_cbks
        new_transition._scenario_env = None
        new_transition._callbacks_pending = len(new_cbks)
        new_transition._callbacks_qty = new_transition._callbacks_pending
        return new_transition


class ScenarioEnv(object):

    def __init__(self):
        self._dm = None
        self._target = None

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

    def __copy__(self):
        new_env = type(self)()
        new_env.__dict__.update(self.__dict__)
        new_env._target = None
        return new_env

class Scenario(object):

    def __init__(self, name, anchor=None):
        self.name = name
        self._dm = None
        self._env = ScenarioEnv()
        self._periodic_ids = set()
        self._anchor = anchor
        self._orig_anchor = anchor

    def reset(self):
        self._anchor = self._orig_anchor

    def set_data_model(self, dm):
        self._dm = dm
        self._env.dm = dm

    def set_target(self, target):
        self._env.target = target

    def set_anchor(self, step):
        self._anchor = step
        self._orig_anchor = self._anchor

    def walk_to(self, step):
        step.cleanup()
        self._anchor = step

    @property
    def current_step(self):
        return self._anchor

    @property
    def periodic_to_clear(self):
        for pid in self._periodic_ids:
            yield pid

    def graph(self, fmt='pdf'):

        def graph_creation(init_step, node_list, edge_list):
            step_style = 'rounded,dotted' if init_step.is_blocked() else 'rounded,filled'
            if init_step.final or init_step is self._orig_anchor:
                f.attr('node', fontcolor='white', shape='record', style='rounded,filled',
                       fillcolor='slategray')
            else:
                f.attr('node', fontcolor='black', shape='record', style=step_style,
                       fillcolor='lightgray')
            f.node(str(id(init_step)), label=init_step.get_description())
            for idx, tr in enumerate(init_step.transitions):
                if tr.step not in node_list:
                    step_style = 'rounded,dotted' if tr.step.is_blocked() else 'rounded,filled'
                    if tr.step.final:
                        f.attr('node', fontcolor='white', shape='record', style=step_style,
                               fillcolor='slategray')
                    else:
                        f.attr('node', fontcolor='black', shape='record', style=step_style,
                               fillcolor='lightgray')
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

        try:
            f = graphviz.Digraph(self.name, format=fmt,
                                 filename=os.path.join(workspace_folder, self.name+'.gv'))
        except:
            print("\n*** ERROR: Unknown format ({!s})! ***".format(fmt))
        else:
            graph_creation(self._orig_anchor, node_list=[], edge_list=[])
            f.view()

    def __copy__(self):

        def graph_copy(init_step, dico):
            new_transitions = [copy.copy(tr) for tr in init_step.transitions]
            init_step.set_transitions(new_transitions)
            for periodic in init_step.periodic_to_set:
                new_sc._periodic_ids.add(id(periodic))

            for tr in init_step.transitions:
                tr.set_scenario_env(new_sc._env)
                if tr.step in dico.values():
                    continue
                if tr.step in dico:
                    new_step = dico[tr.step]
                else:
                    new_step = copy.copy(tr.step)
                    dico[tr.step] = new_step
                new_step.set_data_model(self._dm)
                new_step.set_scenario_env(new_sc._env)
                tr.set_step(new_step)
                graph_copy(new_step, dico)


        orig_dm = self._dm
        orig_env = self._env
        if self._anchor is self._orig_anchor:
            new_anchor = new_orig_anchor = copy.copy(self._anchor)
        else:
            new_anchor = copy.copy(self._anchor)
            new_orig_anchor = copy.copy(self._orig_anchor)
        new_orig_anchor.set_data_model(orig_dm)
        dico = {self._orig_anchor: new_orig_anchor}
        new_sc = type(self)(self.name)
        new_sc._env = copy.copy(orig_env)
        new_orig_anchor.set_scenario_env(new_sc._env)
        new_sc._dm = orig_dm
        new_sc._periodic_ids = set()  # periodic ids are gathered only during graph_copy()
        new_sc._anchor = new_anchor
        new_sc._orig_anchor = new_orig_anchor

        graph_copy(new_sc._orig_anchor, dico)

        return new_sc
