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

from __future__ import print_function

import random
import copy
import collections
from functools import partial

from framework.data import *
from framework.global_resources import *
import framework.scenario as sc
import framework.node as nd

DEBUG = False

XT_NAME_LIST_K = 1
XT_CLS_LIST_K = 2
XT_WEIGHT_K = 3
XT_VALID_CLS_LIST_K = 4
XT_RELATED_DM = 5

class Tactics(object):

    def __init__(self):
        self.disruptors = {}
        self.generators = {}
        self.disruptor_clones = {}
        self.generator_clones = {}
        self._fmkops = None
        self._related_dm = None

    def set_additional_info(self, fmkops, related_dm=None):
        self._fmkops = fmkops
        self._related_dm = related_dm
        for dtype in self.generator_types:
            self.generators[dtype][XT_RELATED_DM] = related_dm
            for name, attrs in self.get_generators_list(dtype).items():
                attrs['obj'].set_exportable_fmk_ops(fmkops)
                if self._related_dm:
                    attrs['obj'].related_dm_name = self._related_dm.name
        for dtype in self.disruptor_types:
            self.disruptors[dtype][XT_RELATED_DM] = related_dm
            for name, attrs in self.get_disruptors_list(dtype).items():
                attrs['obj'].set_exportable_fmk_ops(fmkops)
                if self._related_dm:
                    attrs['obj'].related_dm_name = self._related_dm.name

    @staticmethod
    def scenario_ref_from(scenario):
        return 'SC_' + scenario.name.upper()

    def register_scenarios(self, *scenarios):
        for sc in scenarios:
            dyn_generator_from_scenario.scenario = sc
            dmaker_type = self.scenario_ref_from(sc)
            gen_cls_name = 'g_' + sc.name.lower()
            gen = dyn_generator_from_scenario(gen_cls_name, (DynGeneratorFromScenario,), {})()
            self.register_new_generator(gen_cls_name, gen, weight=1, dmaker_type=dmaker_type,
                                        valid=True)

    def __register_new_data_maker(self, dict_var, name, obj, weight, dmaker_type, valid):
        if dmaker_type not in dict_var:
            dict_var[dmaker_type] = {}
            dict_var[dmaker_type][XT_NAME_LIST_K] = {}
            dict_var[dmaker_type][XT_CLS_LIST_K] = {}
            dict_var[dmaker_type][XT_WEIGHT_K] = 0
            dict_var[dmaker_type][XT_VALID_CLS_LIST_K] = {}
            dict_var[dmaker_type][XT_RELATED_DM] = self._related_dm

        if name in dict_var[dmaker_type][XT_NAME_LIST_K]:
            print("\n*** /!\\ ERROR: The name '%s' is already used for the dmaker_type '%s'\n" % \
                      (name, dmaker_type))
            raise ValueError

        if self._fmkops is not None:
            obj.set_exportable_fmk_ops(self._fmkops)
        if self._related_dm is not None:
            obj.related_dm_name = self._related_dm.name

        dict_var[dmaker_type][XT_NAME_LIST_K][name] = {
            'obj': obj,
            'weight': weight,
            'valid': False,
            }

        dict_var[dmaker_type][XT_CLS_LIST_K][obj] = name

        dict_var[dmaker_type][XT_WEIGHT_K] += weight

        if valid:
            dict_var[dmaker_type][XT_NAME_LIST_K][name]['valid'] = True
            dict_var[dmaker_type][XT_VALID_CLS_LIST_K][name] = \
                dict_var[dmaker_type][XT_NAME_LIST_K][name]


    def register_new_disruptor(self, name, obj, weight, dmaker_type, valid=False):
        self.__register_new_data_maker(self.disruptors, name, obj,
                                    weight, dmaker_type, valid)

    def register_new_generator(self, name, obj, weight, dmaker_type, valid=False):
        self.__register_new_data_maker(self.generators, name, obj,
                                    weight, dmaker_type, valid)

    def __clone_dmaker(self, dmaker, dmaker_clones, dmaker_type, new_dmaker_type, dmaker_name=None, register_func=None):
        if dmaker_type not in dmaker:
            return False, None

        if dmaker_type not in dmaker_clones:
            dmaker_clones[dmaker_type] = []

        for name, val in dmaker[dmaker_type][XT_NAME_LIST_K].items():
            if dmaker_name is not None and name != dmaker_name:
                continue

            new_obj = val['obj'].__class__()
            name = val['obj'].__class__.__name__
            weight = val['weight']
            valid = val['valid']

            new_obj.set_attr(DataMakerAttr.Active)
            new_obj.clear_attr(DataMakerAttr.HandOver)
            new_obj.set_attr(DataMakerAttr.SetupRequired)
            if val['obj'].is_attr_set(DataMakerAttr.Controller):
                new_obj.set_attr(DataMakerAttr.Controller)
            else:
                new_obj.clear_attr(DataMakerAttr.Controller)
            break

        else:
            return False, None


        if new_dmaker_type is None:
            new_dmaker_type = dmaker_type + '#{:d}'.format(len(dmaker_clones[dmaker_type] + 1))
        
        if new_dmaker_type == dmaker_type:
            raise ValueError

        register_func(name, new_obj, weight, new_dmaker_type, valid)
        dmaker_clones[dmaker_type].append(new_dmaker_type)

        return True, name


    def __clear_dmaker_clones(self, dmaker, dmaker_clones):
        for xt, nxt_list in dmaker_clones.items():
            for nxt in nxt_list:
                del dmaker[nxt]

    def clone_generator(self, dmaker_type, new_dmaker_type=None, dmaker_name=None):
        return self.__clone_dmaker(self.generators, self.generator_clones, dmaker_type, new_dmaker_type=new_dmaker_type,
                                   dmaker_name=dmaker_name, register_func=self.register_new_generator)

    def clear_generator_clones(self):
        self.__clear_dmaker_clones(self.generators, self.generator_clones)
        self.generator_clones = {}

    def clone_disruptor(self, dmaker_type, new_dmaker_type=None, dmaker_name=None):
        return self.__clone_dmaker(self.disruptors, self.disruptor_clones, dmaker_type, new_dmaker_type=new_dmaker_type,
                                   dmaker_name=dmaker_name, register_func=self.register_new_disruptor)

    def clear_disruptor_clones(self):
        self.__clear_dmaker_clones(self.disruptors, self.disruptor_clones)
        self.disruptor_clones = {}

    @property
    def generator_types(self):
        return self.generators.keys()

    @property
    def disruptor_types(self):
        return self.disruptors.keys()

    def get_disruptors_list(self, dmaker_type):
        try:
            ret = self.disruptors[dmaker_type][XT_NAME_LIST_K]
        except KeyError:
            return None

        return ret

    def get_generators_list(self, dmaker_type):
        try:
            ret = self.generators[dmaker_type][XT_NAME_LIST_K]
        except KeyError:
            return None

        return ret

    def generators_info(self):
        for gen_type, attrs in self.generators.items():
            yield gen_type, attrs[XT_RELATED_DM]

    def disruptors_info(self):
        for dis_type, attrs in self.disruptors.items():
            yield dis_type, attrs[XT_RELATED_DM]

    def get_disruptor_weight(self, dmaker_type, name):
        try:
            ret = self.disruptors[dmaker_type][XT_NAME_LIST_K][name]['weight']
        except KeyError:
            return None

        return ret

    def get_generator_weight(self, dmaker_type, name):
        try:
            ret = self.generators[dmaker_type][XT_NAME_LIST_K][name]['weight']
        except KeyError:
            return None

        return ret

    def get_disruptor_validness(self, dmaker_type, name):
        try:
            ret = self.disruptors[dmaker_type][XT_NAME_LIST_K][name]['valid']
        except KeyError:
            return None

        return ret

    def get_generator_validness(self, dmaker_type, name):
        try:
            ret = self.generators[dmaker_type][XT_NAME_LIST_K][name]['valid']
        except KeyError:
            return None

        return ret


    def get_info_from_obj(self, obj):
        for dmaker_type in self.disruptors:
            for name, info in self.disruptors[dmaker_type][XT_NAME_LIST_K].items():
                if info['obj'] is obj:
                    return dmaker_type, name

        for dmaker_type in self.generators:
            for name, info in self.generators[dmaker_type][XT_NAME_LIST_K].items():
                if info['obj'] is obj:
                    return dmaker_type, name
        
        return None, None


    def get_disruptor_obj(self, dmaker_type, name):
        try:
            ret = self.disruptors[dmaker_type][XT_NAME_LIST_K][name]['obj']
        except KeyError:
            return None

        return ret

    def get_generator_obj(self, dmaker_type, name):
        try:
            ret = self.generators[dmaker_type][XT_NAME_LIST_K][name]['obj']
        except KeyError:
            return None

        return ret


    def get_disruptor_name(self, dmaker_type, obj):
        try:
            ret = self.disruptors[dmaker_type][XT_CLS_LIST_K][obj]
        except KeyError:
            return None

        return ret

    def get_generator_name(self, dmaker_type, obj):
        try:
            ret = self.generators[dmaker_type][XT_CLS_LIST_K][obj]
        except KeyError:
            return None

        return ret



    def __set_data_maker_weight(self, dict_var, dmaker_type, name, weight):

        if dmaker_type not in dict_var:
            return False
        if name not in dict_var[dmaker_type][XT_NAME_LIST_K]:
            return False

        dict_var[dmaker_type][XT_WEIGHT_K] -= \
            dict_var[dmaker_type][XT_NAME_LIST_K][name]['weight']
        dict_var[dmaker_type][XT_NAME_LIST_K][name]['weight'] = weight
        dict_var[dmaker_type][XT_WEIGHT_K] += weight

        return True

    def set_disruptor_weight(self, dmaker_type, name, weight):
        return self.__set_data_maker_weight(self.disruptors, dmaker_type, name, weight)

    def set_generator_weight(self, dmaker_type, name, weight):
        return self.__set_data_maker_weight(self.generators, dmaker_type, name, weight)


    def get_dmaker_type_total_weight(self, dmaker_type):
        try:
            ret = self.disruptors[dmaker_type][XT_WEIGHT_K]
        except KeyError:
            return None

        return ret

    def get_datatype_total_weight(self, dmaker_type):
        try:
            ret = self.generators[dmaker_type][XT_WEIGHT_K]
        except KeyError:
            return None

        return ret

    
    def __get_random_data_maker(self, dict_var, dmaker_type, total_weight, valid):
        r = random.uniform(0, total_weight)
        s = 0

        if not valid:
            items = dict_var[dmaker_type][XT_NAME_LIST_K].items()
        else:
            items = dict_var[dmaker_type][XT_VALID_CLS_LIST_K].items()

        for name, val in items:
            obj, weight = val['obj'], val['weight']
            s += weight
            if s >= r:
                return obj
        else: # Might occur because of floating point inaccuracies (TBC)
            return obj


    def get_random_disruptor(self, dmaker_type, valid):
        if dmaker_type not in self.disruptors:
            return None
        if valid:
            if len(self.disruptors[dmaker_type][XT_VALID_CLS_LIST_K]) == 0:
                return None

        return self.__get_random_data_maker(self.disruptors, dmaker_type,
                                         self.get_dmaker_type_total_weight(dmaker_type), valid)

    def get_random_generator(self, dmaker_type, valid):
        if dmaker_type not in self.generators:
            return None
        if valid:
            if len(self.generators[dmaker_type][XT_VALID_CLS_LIST_K]) == 0:
                return None

        return self.__get_random_data_maker(self.generators, dmaker_type,
                                         self.get_datatype_total_weight(dmaker_type), valid)


    def print_disruptor(self, dmaker_type, disruptor_name):
        print("### Register Disruptor ###\n" + \
                  " |_ type: %s\n" % dmaker_type + \
                  "     \_ total weight: %d\n" % self.get_dmaker_type_total_weight(dmaker_type) + \
                  " |_ name: %s\n" % disruptor_name + \
                  " |_ weight: %d\n" % self.get_disruptor_weight(dmaker_type, disruptor_name) + \
                  " \_ valid data: %r\n" % self.get_disruptor_validness(dmaker_type, disruptor_name)
              )

    def print_generator(self, dmaker_type, generator_name):
        print("### Register Generator ###\n" + \
                  " |_ type: %s\n" % dmaker_type + \
                  "     \_ total weight: %d\n" % self.get_datatype_total_weight(dmaker_type) + \
                  " |_ name: %s\n" % generator_name + \
                  " \_ weight: %d\n" % self.get_generator_weight(dmaker_type, generator_name) + \
                  " \_ valid data: %r\n" % self.get_generator_validness(dmaker_type, generator_name)
              )


def _user_input_conformity(self, user_input, _args_desc):
    if not user_input:
        return True

    if _args_desc:
        ok, guilty = user_input.check_conformity(_args_desc.keys())
        if not ok:
            print("\n*** Unknown parameter: '{:s}'".format(guilty))
            return False

    return True


def _handle_user_inputs(dmaker, user_input):

    if user_input is None:
        for k, v in dmaker._args_desc.items():
            desc, default, arg_type = v
            setattr(dmaker, k, default)
    else:
        for k, v in dmaker._args_desc.items():
            desc, default, arg_type = v
            ui_val = getattr(user_input, k)
            if isinstance(arg_type, tuple):
                assert(type(ui_val) in arg_type or ui_val is None)
            elif isinstance(arg_type, type):
                assert(type(ui_val) == arg_type or issubclass(type(ui_val), arg_type) or ui_val is None)
            elif arg_type is None:
                # we ignore type verification
                pass
            else:
                raise ValueError
            if ui_val is None:
                setattr(dmaker, k, default)
            else:
                setattr(dmaker, k, ui_val)

    if isinstance(dmaker, DataMaker) and dmaker.modelwalker_user:
        modelwalker_inputs_handling_helper(dmaker)


def _restore_dmaker_internals(dmaker):
    for k, v in dmaker._args_desc.items():
        desc, default, arg_type = v
        setattr(dmaker, k, default)


################################
# ModelWalker Helper Functions #
################################

GENERIC_ARGS = {
    'init': ('make the model walker ignore all the steps until the provided one', 1, int),
    'max_steps': ('maximum number of steps (-1 means until the end)', -1, int),
    'runs_per_node': ('maximum number of test cases for a single node (-1 means until the end)', -1, int),
    'clone_node': ('if True the dmaker will always return a copy ' \
                   'of the node. (for stateless diruptors dealing with ' \
                   'big data it can be usefull to set it to False)', True, bool)
}

def modelwalker_inputs_handling_helper(dmaker):
    assert(dmaker.runs_per_node > 0 or dmaker.runs_per_node == -1)

    if dmaker.runs_per_node == -1:
        dmaker.max_runs_per_node = -1
        dmaker.min_runs_per_node = -1
    else:
        dmaker.max_runs_per_node = dmaker.runs_per_node + 3
        dmaker.min_runs_per_node = max(dmaker.runs_per_node - 2, 1)

### Generator & Disruptor

class DataMakerAttr:
    Active = 1
    Controller = 2
    HandOver = 3
    SetupRequired = 4
    NeedSeed = 5

class DataMaker(object):
    knowledge_source = None
    _modelwalker_user = False
    _args_desc = None
    related_dm_name = None

    def __init__(self):
        self._fmkops = None

    def set_exportable_fmk_ops(self, fmkops):
        self._fmkops = fmkops

    @property
    def modelwalker_user(self):
        return self._modelwalker_user

class Generator(DataMaker):
    produced_seed = None

    def __init__(self):
        DataMaker.__init__(self)
        self.__attrs = {
            DataMakerAttr.Active: True,
            DataMakerAttr.Controller: False,
            DataMakerAttr.HandOver: False,
            DataMakerAttr.SetupRequired: True
            }

    def set_attr(self, name):
        if name not in self.__attrs:
            raise ValueError
        if name == DataMakerAttr.Controller:
            raise ValueError("The attribute 'DataMakerAttr.Controller' must never be set on Generator!")
        self.__attrs[name] = True

    def clear_attr(self, name):
        if name not in self.__attrs:
            raise ValueError
        self.__attrs[name] = False

    def is_attr_set(self, name):
        if name not in self.__attrs:
            raise ValueError
        return self.__attrs[name]

    def _setup(self, dm, user_input):
        self.clear_attr(DataMakerAttr.SetupRequired)
        if not _user_input_conformity(self, user_input, self._args_desc):
            return False

        _handle_user_inputs(self, user_input)
        try:
            ok = self.setup(dm, user_input)
        except:
            ok = False
            raise
        finally:
            if not ok:
                _restore_dmaker_internals(self)

        return ok

    def _cleanup(self):
        self.set_attr(DataMakerAttr.Active)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.cleanup(self._fmkops)

    def need_reset(self):
        self.set_attr(DataMakerAttr.SetupRequired)
        self.cleanup(self._fmkops)

    def setup(self, dm, user_input):
        '''
        --> Specific code
        return True if setup has succeeded, otherwise return False
        '''
        return True

    def cleanup(self, fmkops):
        '''
        --> Specific code
        '''
        pass

    def generate_data(self, dm, monitor, target):
        raise NotImplementedError


class dyn_generator(type):
    data_id = ''
    def __init__(cls, name, bases, attrs):
        attrs['_args_desc'] = DynGenerator._args_desc
        type.__init__(cls, name, bases, attrs)
        cls.data_id = dyn_generator.data_id


class DynGenerator(Generator):
    data_id = ''
    _args_desc = {
        'finite': ('Make the data model finite', False, bool),
        'determinist': ("Make the data model determinist if set to 'True', random if set to "
                        "'False', or do nothing if set to 'None'", None, bool),
        'tnode_determinist': ("If set to 'True', all the typed nodes of the model will be "
                              "set to determinist mode prior to any fuzzing. If set "
                              "to 'False', they will be set to random mode. "
                              "Otherwise, if set to 'None', nothing will be done.", None, bool),
        'min_def': ("Set the default quantity of all the nodes to the defined minimum quantity if "
                    "this parameter is set to 'True', or maximum quantity if set to 'False'. "
                    "Otherwise if set to 'None', nothing is done.", None, bool),
        'freeze': ("Freeze the generated node.", False, bool)
    }

    def setup(self, dm, user_input):
        return True

    def generate_data(self, dm, monitor, target):
        atom = dm.get_atom(self.data_id)
        if isinstance(atom, Node):
            if self.finite:
                atom.make_finite(all_conf=True, recursive=True)

            if self.determinist is None:
                pass
            elif self.determinist:
                atom.make_determinist(all_conf=True, recursive=True)
            else:
                atom.make_random(all_conf=True, recursive=True)

            if self.tnode_determinist is not None:
                nic = nd.NodeInternalsCriteria(node_kinds=[nd.NodeInternals_TypedValue])
                nl = atom.get_reachable_nodes(internals_criteria=nic, ignore_fstate=True)
                for n in nl:
                    if self.tnode_determinist:
                        n.make_determinist()
                    else:
                        n.make_random()

            if self.min_def is not None:
                nic = nd.NodeInternalsCriteria(node_kinds=[nd.NodeInternals_NonTerm])
                nl = atom.get_reachable_nodes(internals_criteria=nic, ignore_fstate=True)
                for node in nl:
                    subnodes = node.subnodes_set
                    for snd in subnodes:
                        min, max = node.get_subnode_minmax(snd)
                        node.set_subnode_default_qty(snd, min if self.min_def else max)

        if self.freeze:
            atom.freeze()

        return Data(atom)


class dyn_generator_from_scenario(type):
    scenario = None
    def __init__(cls, name, bases, attrs):
        attrs['_args_desc'] = DynGeneratorFromScenario._args_desc
        if dyn_generator_from_scenario.scenario._user_args:
            attrs['_args_desc'].update(dyn_generator_from_scenario.scenario._user_args)
        type.__init__(cls, name, bases, attrs)
        cls.scenario = dyn_generator_from_scenario.scenario

class DynGeneratorFromScenario(Generator):
    scenario = None
    _args_desc = collections.OrderedDict([
        ('graph', ('Display the scenario and highlight the current step each time the generator '
                  'is called.', False, bool)),
        ('graph_format', ('Format to be used for displaying the scenario (e.g., xdot, pdf, png).',
                         'xdot', str)),
        ('data_fuzz', ('For each scenario step that generates data, a new scenario is created '
                       'where the data generated by the step is fuzzed.', False, bool)),
        ('cond_fuzz', ('For each scenario step having guarded transitions, a new scenario is '
                       'created where transition conditions are inverted. [compatible with ignore_timing]',
                       False, bool)),
        ('ignore_timing', ('For each scenario step enforcing a timing constraint, a new scenario is '
                           'created where any timeout conditions are removed (i.e., set to 0 second). '
                           '[compatible with cond_fuzz]',
                          False, bool)),
        ('stutter', ("For each scenario step that generates data, a new scenario is created where "
                     "the step is altered to stutter 'stutter_max' times, meaning that data-sending "
                     "steps would be triggered 'stutter_max' times.",
                     False, bool)),
        ('stutter_max', ("The number of times a step will stutter [to be used with 'stutter']", 2, int)),
        ('reset', ("If set, scenarios created by 'data_fuzz', 'cond_fuzz', or 'ignore_timing' "
                   "will reinitialize the scenario after each corruption case, without waiting for "
                   "the normal continuation of the scenario.", True, bool)),
        ('init', ("Used in combination with 'data_fuzz', 'cond_fuzz', or 'ignore_timing'. Make "
                  "the generator begin with the Nth corrupted scenario (where N is provided "
                  "through this parameter).", 0, int))
        ])

    @property
    def produced_seed(self):
        return None

    @produced_seed.setter
    def produced_seed(self, val):
        # The scenario infrastructure needs to prevent the triggering of the 'produced_seed'
        # mechanism
        pass

    def graph_scenario(self, fmt, select_current=False):
        self.scenario.graph(fmt=fmt, select_current=select_current)

    def cleanup(self, fmkops):
        self._cleanup_walking_attrs()
        for periodic_id in self.scenario.periodic_to_clear:
            fmkops.unregister_task(periodic_id, ign_error=True)
        for task_id in self.scenario.tasks_to_stop:
            fmkops.unregister_task(task_id, ign_error=True)

    def _cleanup_walking_attrs(self):
        self.tr_selected = None
        self.pending_tr_eval = []
        self.tr_selected_idx = -1

    def setup(self, dm, user_input):
        if not _user_input_conformity(self, user_input, self._args_desc):
            return False
        self.__class__.scenario.set_data_model(dm)
        # self.__class__.scenario.knowledge_source = self.knowledge_source
        self.scenario = copy.copy(self.__class__.scenario)

        assert (self.data_fuzz and not (self.cond_fuzz or self.ignore_timing)) or not self.data_fuzz
        assert not self.stutter or (self.stutter and not (self.cond_fuzz or self.ignore_timing or self.data_fuzz))

        # internal attributes used for scenario alteration
        self._current_fuzzed_step = None
        self._ign_final = False
        self._alteration_just_performed = False

        if self.stutter:
            self._step_stutter_complete = False
            self._stutter_cpt = 0
            self._step_num = self.init
            self._ign_final = self._make_step_stutter()
            if not self._ign_final:
                self.scenario.current_step.final = True

        elif self.data_fuzz:
            self._data_fuzz_change_step = False
            self._step_num = self.init
            self._ign_final = self._alter_data_step()
            if not self._ign_final:
                self.scenario.current_step.final = True

        elif self.cond_fuzz or self.ignore_timing:
            self._step_num = self.init
            self._ign_final = self._alter_transition_conditions()
            if not self._ign_final:
                self.scenario.current_step.final = True

        return True

    def _stutter_cbk(self, env, current_step, next_step):
        self._stutter_cpt += 1
        if self._stutter_cpt > self.stutter_max:
            self._step_stutter_complete = True
            return False
        else:
            return True

    def _make_step_stutter(self):
        self._alteration_just_performed = True
        self._scenario_steps = filter(lambda x: not x.is_blocked(), self.scenario.steps)
        self._scenario_steps = list(filter(lambda x: not x.final, self._scenario_steps))
        if self._step_num >= len(self._scenario_steps):
            return False

        self._current_fuzzed_step = self._scenario_steps[self._step_num]
        self._stutter_cpt = 0
        if self.reset:
            self.scenario.branch_to_reinit(self._current_fuzzed_step)
        self._current_fuzzed_step.connect_to(self._current_fuzzed_step,
                                             prepend=True, cbk_after_sending=self._stutter_cbk)

        return True

    def _alter_data_step(self):
        self._alteration_just_performed = True
        self._scenario_steps = filter(lambda x: not x.is_blocked(), self.scenario.steps)
        self._scenario_steps = list(filter(lambda x: not x.final, self._scenario_steps))
        if self._step_num >= len(self._scenario_steps):
            return False

        step = self._scenario_steps[self._step_num]
        data_desc = step.data_desc
        if isinstance(data_desc[0], str) \
                or (isinstance(data_desc[0], Data) and data_desc[0].content is not None):
            dp = DataProcess(process=['tTYPE#{:d}'.format(self._step_num)], seed=data_desc[0],
                                auto_regen=True)
            dp.append_new_process([('tSTRUCT#{:d}'.format(self._step_num), UI(init=1, deep=True))])
            data_desc[0] = dp
            step.data_desc = data_desc
        elif isinstance(data_desc[0], DataProcess):
            proc = copy.copy(data_desc[0].process)
            proc2 = copy.copy(data_desc[0].process)
            proc.append('tTYPE#{:d}'.format(self._step_num))
            data_desc[0].process = proc
            proc2.append(('tSTRUCT#{:d}'.format(self._step_num), UI(init=1, deep=True)))
            data_desc[0].append_new_process(proc2)
            data_desc[0].auto_regen = True
        elif isinstance(data_desc[0], Data):
            dp = DataProcess(process=['C#{:d}'.format(self._step_num)], seed=data_desc[0],
                                auto_regen=True)
            data_desc[0] = dp
            step.data_desc = data_desc
        if self.reset:
            self.scenario.branch_to_reinit(step)
        self._prev_func = step._do_before_sending
        step._do_before_sending = self._check_data_fuzz_completion_cbk
        self._current_fuzzed_step = step

        return True

    def _check_data_fuzz_completion_cbk(self, env, step):
        # print('\n+++ check fuzz completion')
        if self._prev_func is not None:
            self._prev_func(env, step)
        data_desc = step.data_desc[0]
        assert isinstance(data_desc, DataProcess)
        if data_desc.auto_regen_cpt > 0:
            data_desc.auto_regen_cpt = 0
            self._data_fuzz_change_step = True
            step.make_blocked()
            step._do_before_sending = self._prev_func

    def _alter_transition_conditions(self):
        self._alteration_just_performed = True
        self._scenario_steps = []
        for step in self.scenario.steps:
            if self.ignore_timing and step.feedback_timeout is not None \
                    and step.feedback_timeout > 0:
                self._scenario_steps.append(step)
                continue
            if self.cond_fuzz:
                tr = next(step.transitions, None)
                if tr is not None and tr.has_callback():
                    self._scenario_steps.append(step)

        if self._step_num >= len(self._scenario_steps):
            return False

        self._current_fuzzed_step = self._scenario_steps[self._step_num]
        for tr in self._current_fuzzed_step.transitions:
            if self.reset \
                    and tr.step is not self._current_fuzzed_step \
                    and tr.step is not self.scenario.anchor:
                self.scenario.branch_to_reinit(tr.step, prepend=True)
            if self.cond_fuzz:
                tr.invert_conditions()
            if tr.step.final:
                tr.make_uncrossable()

        if self.reset and self._current_fuzzed_step is not self.scenario.anchor:
            self.scenario.branch_to_reinit(self._current_fuzzed_step, prepend=False)
        if self.ignore_timing and self._current_fuzzed_step.feedback_timeout is not None:
            self._current_fuzzed_step.feedback_timeout = 0

        return True

    def generate_data(self, dm, monitor, target):
        self._cleanup_walking_attrs()

        if self.data_fuzz:
            if not self._alteration_just_performed:
                if self.scenario.current_step is self.scenario.anchor \
                        and self._data_fuzz_change_step:
                    self._data_fuzz_change_step = False
                    self.scenario = copy.copy(self.__class__.scenario)
                    self._step_num += 1
                    self._ign_final = self._alter_data_step()
                    if not self._ign_final:
                        self.scenario.current_step.final = True
                elif self._data_fuzz_change_step:
                    self.scenario.walk_to_reinit() # because _callback_dispatcher_after_fbk() won't be called
            else:
                self._alteration_just_performed = False

        elif self.cond_fuzz or self.ignore_timing:
            if not self._alteration_just_performed:
                if self.scenario.current_step is self.scenario.anchor:
                    self.scenario = copy.copy(self.__class__.scenario)
                    self._step_num += 1
                    self._ign_final = self._alter_transition_conditions()
                    if not self._ign_final:
                        self.scenario.current_step.final = True
            else:
                self._alteration_just_performed = False

        elif self.stutter:
            if not self._alteration_just_performed:
                if self._step_stutter_complete \
                        and self.scenario.current_step is self.scenario.anchor:
                    self._step_stutter_complete = False
                    self.scenario = copy.copy(self.__class__.scenario)
                    self._step_num += 1
                    self._ign_final = self._make_step_stutter()
                    if not self._ign_final:
                        self.scenario.current_step.final = True
            else:
                self._alteration_just_performed = False

        self.scenario.set_target(target)
        if self.scenario._user_args:
            for ua in self.scenario._user_args.keys():
                setattr(self.scenario.env, str(ua), getattr(self, str(ua)))
        self.step = self.scenario.current_step

        self.step.do_before_data_processing()

        if self.graph:
            self.graph_scenario(self.graph_format, select_current=True)

        if self.step.final:
            if self._ign_final:
                self.scenario.walk_to_reinit()
                self.step = self.scenario.current_step
            else:
                self.need_reset()
                data = Data()
                # data.register_callback(self._callback_cleanup_periodic, hook=HOOK.after_dmaker_production)
                data.make_unusable()
                data.origin = self.scenario
                data.scenario_dependence = self.scenario.name
                return data

        data = self.step.get_data()
        data.origin = self.scenario
        data.cleanup_all_callbacks()
        data.altered = not self.step.valid

        if self.cond_fuzz or self.ignore_timing or self.data_fuzz:
            data.add_info("Current fuzzed step: '{:s}'"
                          .format(str(self._current_fuzzed_step).replace('\n', ' ')))

        data.register_callback(self._callback_dispatcher_before_sending_step1, hook=HOOK.before_sending_step1)
        data.register_callback(self._callback_dispatcher_before_sending_step2, hook=HOOK.before_sending_step2)
        data.register_callback(self._callback_dispatcher_after_sending, hook=HOOK.after_sending)
        data.register_callback(self._callback_dispatcher_after_fbk, hook=HOOK.after_fbk)
        data.register_callback(self._callback_dispatcher_final, hook=HOOK.final)

        data.scenario_dependence = self.scenario.name

        return data


    def __handle_transition_callbacks(self, hook, feedback=None):
        for idx, tr in self.pending_tr_eval:
            if tr.run_callback(self.step, feedback=feedback, hook=hook):
                self.tr_selected = tr
                self.tr_selected_idx = idx
                break

        self.pending_tr_eval = []

        if self.tr_selected is None:
            for idx, tr in enumerate(self.step.transitions):
                if self.tr_selected is None:
                    if tr.dp_completed_guard:
                        for d_desc in self.step.data_desc:
                            if isinstance(d_desc, DataProcess) and d_desc.dp_completed:
                                # d_desc.dp_completed = False
                                self.tr_selected = tr
                                self.tr_selected_idx = idx
                                break
                    elif not tr.has_callback() and tr.is_crossable():
                        self.tr_selected = tr
                        self.tr_selected_idx = idx
                        break
                    elif tr.run_callback(self.step, feedback=feedback, hook=hook):
                        self.tr_selected = tr
                        self.tr_selected_idx = idx
                        break
                else:
                    break

        for idx, tr in enumerate(self.step.transitions):
            if tr.has_callback_pending() and idx <= self.tr_selected_idx:
                self.pending_tr_eval.append((idx, tr))

    def _callback_dispatcher_before_sending_step1(self):
        # Any existing DataProcess are resolved thanks to this callback
        cbkops = CallBackOps()
        if self.step.has_dataprocess():
            cbkops.add_operation(CallBackOps.Replace_Data,
                                 param=(self.step.data_desc, self.step.vtg_ids_list))
            if self.step.transition_on_dp_complete:
                cbkops.set_flag(CallBackOps.ForceDataHandling)

        return cbkops

    def _callback_dispatcher_before_sending_step2(self):
        # Callback called after any data have been processed but not sent yet
        did_something = self.step.do_before_sending()

        self.__handle_transition_callbacks(HOOK.before_sending_step2)

        cbkops = CallBackOps()
        if did_something:
            # We add again the operation CallBackOps.Replace_Data, because the step contents could have changed
            cbkops.add_operation(CallBackOps.Replace_Data,
                                 param=(self.step.data_desc, self.step.vtg_ids_list))

        return cbkops

    def _callback_dispatcher_after_sending(self):
        self.__handle_transition_callbacks(HOOK.after_sending)

    def _callback_dispatcher_after_fbk(self, fbk):
        """
        This callback is always called by the framework
        It allows for a NoDataStep to perform actions (trigger periodic data, tasks, ...)
        """

        self.__handle_transition_callbacks(HOOK.after_fbk, feedback=fbk)

        cbkops = CallBackOps()
        for desc in self.step.periodic_to_set:
            cbkops.add_operation(CallBackOps.Add_PeriodicData, id=id(desc),
                                 param=desc, period=desc.period)

        for periodic_id in self.step.periodic_to_clear:
            cbkops.add_operation(CallBackOps.Del_PeriodicData, id=periodic_id)

        for desc in self.step.tasks_to_start:
            cbkops.add_operation(CallBackOps.Start_Task, id=id(desc),
                                 param=desc, period=desc.period)

        for task_id in self.step.tasks_to_stop:
            cbkops.add_operation(CallBackOps.Stop_Task, id=task_id)

        return cbkops

    def _callback_dispatcher_final(self):
        if self.tr_selected is not None:
            self.scenario.walk_to(self.tr_selected.step)
        else:
            # we stay on the current step
            pass

        # In case the same Data is used again without going through self.generate_data()
        self._cleanup_walking_attrs()


class Disruptor(DataMaker):

    def __init__(self):
        DataMaker.__init__(self)
        self.__attrs = {
            DataMakerAttr.Active: True,
            DataMakerAttr.Controller: False,
            DataMakerAttr.HandOver: False,
            DataMakerAttr.SetupRequired: True
            }

    def disrupt_data(self, dm, target, prev_data):
        raise NotImplementedError

    def setup(self, dm, user_input):
        '''
        --> Specific code
        return True if setup has succeeded, otherwise return False
        '''
        return True

    def cleanup(self, fmkops):
        '''
        --> Specific code
        '''
        pass

    def set_attr(self, name):
        if name not in self.__attrs:
            raise ValueError
        self.__attrs[name] = True

    def clear_attr(self, name):
        if name not in self.__attrs:
            raise ValueError
        self.__attrs[name] = False

    def is_attr_set(self, name):
        if name not in self.__attrs:
            raise ValueError
        return self.__attrs[name]


    def _setup(self, dm, user_input):
        # sys.stdout.write("\n__ setup disruptor '%s' __" % self.__class__.__name__)
        self.clear_attr(DataMakerAttr.SetupRequired)
        if not _user_input_conformity(self, user_input, self._args_desc):
            return False

        _handle_user_inputs(self, user_input)
        try:
            ok = self.setup(dm, user_input)
        except:
            ok = False
            raise
        finally:
            if not ok:
                _restore_dmaker_internals(self)

        return ok


    def _cleanup(self):
        # sys.stdout.write("\n__ cleanup disruptor '%s' __" % self.__class__.__name__)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.set_attr(DataMakerAttr.Active)
        self.cleanup(self._fmkops)



class StatefulDisruptor(DataMaker):

    def __init__(self):
        DataMaker.__init__(self)
        self.__attrs = {
            DataMakerAttr.Active: True,
            DataMakerAttr.Controller: False,
            DataMakerAttr.HandOver: False,
            DataMakerAttr.SetupRequired: True,
            DataMakerAttr.NeedSeed: True
            }

    def set_seed(self, prev_data):
        raise NotImplementedError

    def disrupt_data(self, dm, target, data):
        '''
        @data: it is either equal to prev_data the first time disrupt_data()
        is called by the FMK, or it is a an empty data (that is Data()).
        '''
        raise NotImplementedError

    def handover(self):
        # sys.stdout.write("\n__ disruptor handover '%s' __" % self.__class__.__name__)
        self.set_attr(DataMakerAttr.HandOver)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.set_attr(DataMakerAttr.NeedSeed)
        self.cleanup(self._fmkops)

    def setup(self, dm, user_input):
        '''
        --> Specific code
        return True if setup has succeeded, otherwise return False
        '''
        return True

    def cleanup(self, fmkops):
        '''
        --> Specific code
        '''
        pass

    def set_attr(self, name):
        if name not in self.__attrs:
            raise ValueError
        self.__attrs[name] = True

    def clear_attr(self, name):
        if name not in self.__attrs:
            raise ValueError
        self.__attrs[name] = False

    def is_attr_set(self, name):
        if name not in self.__attrs:
            raise ValueError
        return self.__attrs[name]

    def _setup(self, dm, user_input):
        # sys.stdout.write("\n__ setup disruptor '%s' __" % self.__class__.__name__)
        self.clear_attr(DataMakerAttr.SetupRequired)
        if not _user_input_conformity(self, user_input, self._args_desc):
            return False

        _handle_user_inputs(self, user_input)
        try:
            ok = self.setup(dm, user_input)
        except:
            ok = False
            raise
        finally:
            if not ok:
                _restore_dmaker_internals(self)

        return ok

    def _cleanup(self):
        # sys.stdout.write("\n__ cleanup disruptor '%s' __" % self.__class__.__name__)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.set_attr(DataMakerAttr.NeedSeed)
        self.set_attr(DataMakerAttr.Active)
        self.cleanup(self._fmkops)

    def _set_seed(self, prev_data):
        if self.is_attr_set(DataMakerAttr.NeedSeed):
            ret = self.set_seed(prev_data)
            self.clear_attr(DataMakerAttr.NeedSeed)
            return ret


def disruptor(st, dtype, weight=1, valid=False, args=None, modelwalker_user=False):
    def internal_func(disruptor_cls):
        disruptor_cls._modelwalker_user = modelwalker_user
        if modelwalker_user:
            if set(GENERIC_ARGS.keys()).intersection(set(args.keys())):
                raise ValueError('At least one parameter is in conflict with a built-in parameter')
            disruptor_cls._args_desc = copy.copy(GENERIC_ARGS)
            if args:
                disruptor_cls._args_desc.update(args)
        else:
            disruptor_cls._args_desc = {} if args is None else args
        # register an object of this class
        disruptor = disruptor_cls()
        if issubclass(disruptor_cls, StatefulDisruptor):
            disruptor.set_attr(DataMakerAttr.Controller)
        st.register_new_disruptor(disruptor.__class__.__name__, disruptor, weight, dtype, valid)

        return disruptor_cls

    return internal_func


def generator(st, gtype, weight=1, valid=False, args=None, modelwalker_user=False):
    def internal_func(generator_cls):
        generator_cls._modelwalker_user = modelwalker_user
        if modelwalker_user:
            if set(GENERIC_ARGS.keys()).intersection(set(args.keys())):
                raise ValueError('At least one parameter is in conflict with a built-in parameter')
            generator_cls._args_desc = copy.copy(GENERIC_ARGS)
            if args:
                generator_cls._args_desc.update(args)
        else:
            generator_cls._args_desc = {} if args is None else args
        # register an object of this class
        gen = generator_cls()
        st.register_new_generator(gen.__class__.__name__, gen, weight, gtype, valid)

        return generator_cls

    return internal_func



if __name__ == "__main__":

    ui = UI(plip=2, plop=True)
    print(ui)

    ui.plip = 3
    print(ui) # 'plip' should be still equal to 2

    print(ui.is_attrs_defined('test'))
    print(ui.dont_exist) # should print None

    ui = UI()
    ui.set_user_inputs({'test_new':5, 'ascii_new':False})
    print(ui)


