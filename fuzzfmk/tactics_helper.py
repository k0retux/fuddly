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

from __future__ import print_function

import sys
import random
import threading

import fuzzfmk.data_model as fdm
from fuzzfmk.data_model_helpers import modelwalker_inputs_handling_helper

DEBUG = False


XT_NAME_LIST_K = 1
XT_CLS_LIST_K = 2
XT_WEIGHT_K = 3
XT_VALID_CLS_LIST_K = 4


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



class Tactics(object):

    def __init__(self):
        self.disruptors = {}
        self.generators = {}
        self.probes = {}
        self.operators = {}

        self.disruptor_clones = {}
        self.generator_clones = {}


    def set_logger(self, logger):
        self.logger = logger

    def set_target(self, target):
        self.target = target

    def set_monitor(self, monitor):
        self.monitor = monitor



    def register_new_operator(self, name, obj):

        if name in self.operators:
            print("\n*** /!\\ ERROR: The operator name '%s' is already used\n" % name)
            raise ValueError

        self.operators[name] = {
            'obj': obj
            }


    def get_operator_obj(self, name):
        try:
            ret = self.operators[name]['obj']
        except KeyError:
            return None

        return ret


    def get_operators(self):
        return self.operators



    def register_new_probe(self, name, func, obj=None, blocking=False):

        if name in self.probes:
            print("\n*** /!\\ ERROR: The probe name '%s' is already used\n" % name)
            raise ValueError

        self.probes[name] = {
            'func': func,
            'obj': obj,
            'lock': threading.Lock(),
            'status': ProbeStatus(0),
            'delay': 1.0,
            'stop': threading.Event(),
            'started': False,
            'blocking': blocking
            }

    def is_probe_launched(self, name):
        try:
            self.probes[name]['lock'].acquire()
            ret = self.probes[name]['started']
            self.probes[name]['lock'].release()
        except KeyError:
            return False

        return ret

    def launch_probe(self, name):

        lck = self.probes[name]['lock']

        lck.acquire()
        if self.probes[name]['started']:
            lck.release()
            return False
        lck.release()

        func = self.get_probe_func(name)
        if not func:
            return False

        stop_event = self.probes[name]['stop']

        if self.probes[name]['blocking']:
            evts = self.monitor.get_evts(name)
        else:
            evts = None

        th = threading.Thread(None, func, 'probe.' + name,
                              args=(stop_event, evts, self.target, self.logger))
        th.start()

        lck.acquire()
        self.probes[name]['started'] = True
        lck.release()

        return True


    def quick_reset_probe(self, name, *args):
        try:
            with self.probes[name]['lock']:
                self.probes[name]['obj'].quick_reset(*args)
            return True
        except KeyError:
            return False

    def get_probe_func(self, name):
        try:
            ret = self.probes[name]['func']
        except KeyError:
            return None

        return ret

    def get_probe_lock(self, name):
        try:
            ret = self.probes[name]['lock']
        except KeyError:
            return None

        return ret

    def stop_probe(self, name):
        try:
            self.probes[name]['lock'].acquire()
            if self.probes[name]['started']:
                self.probes[name]['stop'].set()
            self.probes[name]['lock'].release()
        except KeyError:
            return False

        return True

    def reset_probe(self, name):
        try:
            self.probes[name]['lock'].acquire()
            self.probes[name]['status'] = ProbeStatus(0)
            self.probes[name]['started'] = False
            self.probes[name]['stop'].clear()
            self.probes[name]['lock'].release()
        except KeyError:
            return False

        return True


    def set_probe_delay(self, name, delay):
        try:
            self.probes[name]['lock'].acquire()
            self.probes[name]['delay'] = delay
            self.probes[name]['lock'].release()
        except KeyError:
            return False

        return True

    def get_probe_delay(self, name):
        try:
            self.probes[name]['lock'].acquire()
            ret = self.probes[name]['delay']
            self.probes[name]['lock'].release()
        except KeyError:
            return None

        return ret

    def set_probe_status(self, name, status):
        try:
            self.probes[name]['lock'].acquire()
            self.probes[name]['status'] = status
            self.probes[name]['lock'].release()
        except KeyError:
            return False

        return True

    def get_probe_status(self, name):
        try:
            self.probes[name]['lock'].acquire()
            ret = self.probes[name]['status']
            self.probes[name]['lock'].release()
        except KeyError:
            return None

        return ret

    def get_probes(self):
        return self.probes


    def __register_new_data_maker(self, dict_var, name, obj, weight, dmaker_type, valid):
        if dmaker_type not in dict_var:
            dict_var[dmaker_type] = {}
            dict_var[dmaker_type][XT_NAME_LIST_K] = {}
            dict_var[dmaker_type][XT_CLS_LIST_K] = {}
            dict_var[dmaker_type][XT_WEIGHT_K] = 0
            dict_var[dmaker_type][XT_VALID_CLS_LIST_K] = {}

        if name in dict_var[dmaker_type][XT_NAME_LIST_K]:
            print("\n*** /!\\ ERROR: The name '%s' is already used for the dmaker_type '%s'\n" % \
                      (name, dmaker_type))
            raise ValueError

        dict_var[dmaker_type][XT_NAME_LIST_K][name] = {
            'obj': obj,
            'weight': weight,
            'valid': False
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
            return False

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
            return False


        if new_dmaker_type is None:
            new_dmaker_type = dmaker_type + '#{:d}'.format(len(dmaker_clones[dmaker_type] + 1))
        
        if new_dmaker_type == dmaker_type:
            raise ValueError

        register_func(name, new_obj, weight, new_dmaker_type, valid)
        dmaker_clones[dmaker_type].append(new_dmaker_type)

        return True


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

    def get_disruptors(self):
        return self.disruptors

    def get_generators(self):
        return self.generators


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


class UI(object):
    '''
    Once initialized attributes cannot be modified
    '''
    def __init__(self, **kwargs):
        self.inputs = {}
        for k, v in kwargs.items():
            self.inputs[k] = v

    def is_attrs_defined(self, *names):
        for n in names:
            if n not in self.inputs:
                return False
        return True

    def set_user_inputs(self, user_inputs):
        assert isinstance(user_inputs, dict)
        self.inputs = user_inputs

    def check_conformity(self, valid_args):
        for arg in self.inputs:
            if arg not in valid_args:
                return False, arg
        return True, None

    def __getattr__(self, name):
        if name in self.inputs:
            return self.inputs[name]
        else:
            return None

    def __str__(self):
        if self.inputs:
            ui = '['
            for k, v in self.inputs.items():
                ui += "{:s}={!r},".format(k, v)
            return ui[:-1]+']'
        else:
            return '[ ]'


def _user_input_conformity(self, user_input, _gen_args_desc, _args_desc):
    if not user_input:
        return True
    generic_ui = user_input.get_generic()
    specific_ui = user_input.get_specific()

    if _gen_args_desc and generic_ui is not None:
        ok, guilty = generic_ui.check_conformity(_gen_args_desc.keys())
        if not ok:
            print("\n*** Unknown parameter: '{:s}'".format(guilty))
            return False
    if _args_desc and specific_ui is not None:
        ok, guilty = specific_ui.check_conformity(_args_desc.keys())
        if not ok:
            print("\n*** Unknown parameter: '{:s}'".format(guilty))
            return False

    return True


def _handle_user_inputs(dmaker, ui):
    generic_ui = ui.get_generic()
    specific_ui = ui.get_specific()
    if generic_ui is None:
        for k, v in dmaker._gen_args_desc.items():
            desc, default, arg_type = v
            setattr(dmaker, k, default)
    else:
        for k, v in dmaker._gen_args_desc.items():
            desc, default, arg_type = v
            ui_val = getattr(generic_ui, k)
            if isinstance(arg_type, tuple):
                assert(type(ui_val) in arg_type or ui_val is None)
            elif isinstance(arg_type, type):
                assert(type(ui_val) == arg_type or ui_val is None)
            else:
                raise ValueError
            if ui_val is None:
                setattr(dmaker, k, default)
            else:
                setattr(dmaker, k, ui_val)

    if dmaker._gen_args_desc and \
       (issubclass(dmaker.__class__, Disruptor) or issubclass(dmaker.__class__, StatefulDisruptor)):
        modelwalker_inputs_handling_helper(dmaker, generic_ui)

    if specific_ui is None:
        for k, v in dmaker._args_desc.items():
            desc, default, arg_type = v
            setattr(dmaker, k, default)
    else:
        for k, v in dmaker._args_desc.items():
            desc, default, arg_type = v
            ui_val = getattr(specific_ui, k)
            if isinstance(arg_type, tuple):
                assert(type(ui_val) in arg_type or ui_val is None)
            elif isinstance(arg_type, type):
                assert(type(ui_val) == arg_type or ui_val is None)
            else:
                raise ValueError
            if ui_val is None:
                setattr(dmaker, k, default)
            else:
                setattr(dmaker, k, ui_val)


def _restore_dmaker_internals(dmaker):
    for k, v in dmaker._gen_args_desc.items():
        desc, default, arg_type = v
        setattr(dmaker, k, default)
    for k, v in dmaker._args_desc.items():
        desc, default, arg_type = v
        setattr(dmaker, k, default)


class UserInputContainer(object):

    def __init__(self, generic=None, specific=None):
        self._generic_input = generic
        self._specific_input = specific

    # for python2 compatibility
    def __nonzero__(self):
        return self._generic_input is not None or self._specific_input is not None

    # for python3 compatibility
    def __bool__(self):
        return self._generic_input is not None or self._specific_input is not None

    def get_generic(self):
        return self._generic_input

    def get_specific(self):
        return self._specific_input

    def __str__(self):
        return "G="+str(self._generic_input)+", S="+str(self._specific_input)

    def __repr__(self):
        return str(self)


### Generator & Disruptor decorator

class DataMakerAttr:
    Active = 1
    Controller = 2
    HandOver = 3
    SetupRequired = 4
    NeedSeed = 5

class Generator(object):
    produced_seed = None

    def __init__(self):
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
        sys.stdout.write("\n__ setup generator '%s' __" % self.__class__.__name__)
        self.clear_attr(DataMakerAttr.SetupRequired)
        if not _user_input_conformity(self, user_input, self._gen_args_desc, self._args_desc):
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
        sys.stdout.write("\n__ cleanup generator '%s' __" % self.__class__.__name__)
        self.set_attr(DataMakerAttr.Active)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.cleanup()


    def need_reset(self):
        sys.stdout.write("\n__ generator need reset '%s' __" % self.__class__.__name__)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.cleanup()

    def setup(self, dm, user_input):
        '''
        --> Specific code
        return True if setup has succeeded, otherwise return False
        '''
        return True

    def cleanup(self):
        '''
        --> Specific code
        '''
        pass

    def generate_data(self, dm, monitor, target):
        raise NotImplementedError


class dyn_generator(type):
    data_id = ''
    
    def __init__(cls, name, bases, attrs):
        attrs['_gen_args_desc'] = DynGenerator._gen_args_desc
        attrs['_args_desc'] = DynGenerator._args_desc
        type.__init__(cls, name, bases, attrs)
        cls.data_id = dyn_generator.data_id


class DynGenerator(Generator):
    data_id = ''
    _gen_args_desc = {
        'finite': ('make the data model finite', False, bool),
        'determinist': ('make the data model determinist', False, bool),
        'random': ('make the data model random', False, bool)
    }
    _args_desc = {}

    def setup(self, dm, user_input):

        if not _user_input_conformity(self, user_input, self._gen_args_desc, self._args_desc):
            return False

        generic_ui = user_input.get_generic()

        if generic_ui is None:
            self.make_finite = False
            self.make_determinist = False
            self.make_random = False
        else:
            val = generic_ui.finite
            assert(type(val) == bool or val is None)
            self.make_finite = False if val is None else val

            val = generic_ui.determinist
            assert(type(val) == bool or val is None)
            self.make_determinist = False if val is None else val

            val = generic_ui.random
            assert(type(val) == bool or val is None)
            self.make_random = False if val is None else val

        if self.make_determinist or self.make_random:
            assert(self.make_random != self.make_determinist)

        return True

    def generate_data(self, dm, monitor, target):
        data = fdm.Data()

        node = dm.get_data(self.data_id)

        if self.make_finite:
            node.make_finite(all_conf=True, recursive=True)
        if self.make_determinist:
            node.make_determinist(all_conf=True, recursive=True)
        if self.make_random:
            node.make_random(all_conf=True, recursive=True)

        return fdm.Data(node)


class Disruptor(object):

    def __init__(self):
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

    def cleanup(self):
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
        sys.stdout.write("\n__ setup disruptor '%s' __" % self.__class__.__name__)
        self.clear_attr(DataMakerAttr.SetupRequired)
        if not _user_input_conformity(self, user_input, self._gen_args_desc, self._args_desc):
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
        sys.stdout.write("\n__ cleanup disruptor '%s' __" % self.__class__.__name__)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.set_attr(DataMakerAttr.Active)
        self.cleanup()



class StatefulDisruptor(object):

    def __init__(self):
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
        sys.stdout.write("\n__ disruptor handover '%s' __" % self.__class__.__name__)
        self.set_attr(DataMakerAttr.HandOver)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.set_attr(DataMakerAttr.NeedSeed)
        self.cleanup()

    def setup(self, dm, user_input):
        '''
        --> Specific code
        return True if setup has succeeded, otherwise return False
        '''
        return True

    def cleanup(self):
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
        sys.stdout.write("\n__ setup disruptor '%s' __" % self.__class__.__name__)
        self.clear_attr(DataMakerAttr.SetupRequired)
        if not _user_input_conformity(self, user_input, self._gen_args_desc, self._args_desc):
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
        sys.stdout.write("\n__ cleanup disruptor '%s' __" % self.__class__.__name__)
        self.set_attr(DataMakerAttr.SetupRequired)
        self.set_attr(DataMakerAttr.NeedSeed)
        self.set_attr(DataMakerAttr.Active)
        self.cleanup()

    def _set_seed(self, prev_data):
        if self.is_attr_set(DataMakerAttr.NeedSeed):
            ret = self.set_seed(prev_data)
            self.clear_attr(DataMakerAttr.NeedSeed)
            return ret


def disruptor(st, dtype, weight, valid=False, gen_args={}, args={}):
    def internal_func(disruptor_cls):
        disruptor_cls._gen_args_desc = gen_args
        disruptor_cls._args_desc = args
        # check conflict between gen_args & args
        for k in gen_args:
            if k in args.keys():
                raise ValueError("Specific parameter '{:s}' is in conflict with a generic parameter!".format(k))
        # create generic attributes
        for k, v in gen_args.items():
            desc, default, arg_type = v
            setattr(disruptor_cls, k, default)
        # create specific attributes
        for k, v in args.items():
            desc, default, arg_type = v
            setattr(disruptor_cls, k, default)
        # register an object of this class
        disruptor = disruptor_cls()
        if issubclass(disruptor_cls, StatefulDisruptor):
            disruptor.set_attr(DataMakerAttr.Controller)
        st.register_new_disruptor(disruptor.__class__.__name__, disruptor, weight, dtype, valid)
        # st.print_disruptor(dtype, disruptor.__class__.__name__)

        return disruptor_cls

    return internal_func


def generator(st, gtype, weight, valid=False, gen_args={}, args={}):
    def internal_func(generator_cls):
        generator_cls._gen_args_desc = gen_args
        generator_cls._args_desc = args
        # check conflict between gen_args & args
        for k in gen_args:
            if k in args.keys():
                raise ValueError("Specific parameter '{:s}' is in conflict with a generic parameter!".format(k))
        # create generic attributes
        for k, v in gen_args.items():
            desc, default, arg_type = v
            setattr(generator_cls, k, default)
        # create specific attributes
        for k, v in args.items():
            desc, default, arg_type = v
            setattr(generator_cls, k, default)
        # register an object of this class
        gen = generator_cls()
        st.register_new_generator(gen.__class__.__name__, gen, weight, gtype, valid)
        # st.print_generator(gtype, gen.__class__.__name__)

        return generator_cls

    return internal_func



import time


# Probes

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



def probe(st):
    def internal_func(probe_cls):
        probe = probe_cls()

        def probe_func(stop_event, evts, *args, **kargs):
            probe._start(*args, **kargs)
            while not stop_event.is_set():
                delay = st.get_probe_delay(probe.__class__.__name__)
                status = probe.main(*args, **kargs)
                st.set_probe_status(probe.__class__.__name__, status)

                stop_event.wait(delay)

            probe._stop(*args, **kargs)
            st.reset_probe(probe.__class__.__name__)

        st.register_new_probe(probe.__class__.__name__, probe_func, obj=probe, blocking=False)

        return probe_cls

    return internal_func



def blocking_probe(st):
    def internal_func(probe_cls):
        probe = probe_cls()

        def probe_func(stop_event, evts, *args, **kargs):
            probe._start(*args, **kargs)
            while not stop_event.is_set():
                delay = st.get_probe_delay(probe.__class__.__name__)
                
                evts.wait_for_data_ready()

                probe.arm_probe(*args, **kargs)

                evts.wait_until_data_is_emitted()

                status = probe.main(*args, **kargs)
                st.set_probe_status(probe.__class__.__name__, status)

                evts.lets_fuzz_continue()

                stop_event.wait(delay)

            probe._stop(*args, **kargs)
            st.reset_probe(probe.__class__.__name__)

        st.register_new_probe(probe.__class__.__name__, probe_func, obj=probe, blocking=True)

        return probe_cls

    return internal_func


# Operators

class Operation(object):
    
    Stop = 1
    Exportable = 2
    CleanupDMakers = 3

    def __init__(self):
        self.action_register = []
        self.status = 0
        self.flags = {
            Operation.Stop: False,
            Operation.Exportable: False,
            Operation.CleanupDMakers: False
            }

    def set_flag(self, name):
        if name in self.flags:
            self.flags[name] = True
        else:
            raise ValueError

    def is_flag_set(self, name):
        if name not in self.flags:
            raise ValueError
        return self.flags[name]

    def set_status(self, status):
        self.status = status

    def add_instruction(self, actions, orig_data=None):
        if actions is None:
            l = None
        else:
            l = []
            for a in actions:
                l.append(a)

        self.action_register.append((l, orig_data))

    def get_instructions(self):
        return self.action_register


class LastInstruction(object):

    ExportData = 1

    def __init__(self):
        self.comments = None
        self.feedback_info = None
        self.instructions = {
            LastInstruction.ExportData: False
            }

    def set_instruction(self, name):
        if name in self.instructions:
            self.instructions[name] = True
        else:
            raise ValueError

    def is_instruction_set(self, name):
        if name not in self.instructions:
            raise ValueError
        return self.instructions[name]

    def set_comments(self, comments):
        self.comments = comments

    def get_comments(self):
        return self.comments

    def set_target_feedback_info(self, info):
        self.feedback_info = info

    def get_target_feedback_info(self):
        return self.feedback_info



class Operator(object):

    def __init__(self):
        pass

    def start(self, fmk_ops, dm, monitor, target, logger, user_input):
        '''
        --> Specific code
        return True if setup has succeeded, otherwise return False
        '''
        return True

    def stop(self, fmk_ops, dm, monitor, target, logger):
        '''
        --> Specific code
        '''
        pass

    def plan_next_operation(self, fmk_ops, dm, monitor, target, logger, fmk_feedback):
        '''
        Shall return a Operation object that contains the fuzzing
        action to carry out.
        '''
        raise NotImplementedError('Operators shall implement this method!')

    def do_after_all(self, fmk_ops, dm, monitor, target, logger):
        '''
        This action is executed after data has been sent to the target
        AND that all blocking probes have returned.
        BUT just before data is logged.

        Return Value: LastInstruction object
        '''

        linst = LastInstruction()

        # In order to export data in
        # any case, that is even if the Logger has been set to
        # export data only when requested (i.e. explicit_export == True)
        linst.set_instruction(LastInstruction.ExportData)

        return linst

    def _start(self, fmk_ops, dm, monitor, target, logger, user_input):
        sys.stdout.write("\n__ setup operator '%s' __" % self.__class__.__name__)
        if not _user_input_conformity(self, user_input, self._gen_args_desc, self._args_desc):
            return False

        _handle_user_inputs(self, user_input)
        try:
            ok = self.start(fmk_ops, dm, monitor, target, logger, user_input)
        except:
            ok = False
            raise
        finally:
            if not ok:
                _restore_dmaker_internals(self)

        return ok


def operator(st, gen_args={}, args={}):
    def internal_func(operator_cls):
        operator_cls._gen_args_desc = gen_args
        operator_cls._args_desc = args
        # check conflict between gen_args & args
        for k in gen_args:
            if k in args.keys():
                raise ValueError("Specific parameter '{:s}' is in conflict with a generic parameter!".format(k))
        # create generic attributes
        for k, v in gen_args.items():
            desc, default, arg_type = v
            setattr(operator_cls, k, default)
        # create specific attributes
        for k, v in args.items():
            desc, default, arg_type = v
            setattr(operator_cls, k, default)
        # register an object of this class
        operator = operator_cls()
        st.register_new_operator(operator.__class__.__name__, operator)
        return operator_cls

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



### OBSOLETE
class Memory:
    '''
    memory that can be used within fuzzing_primitives.py
    '''
    def __init__(self):
        self.new = True 

