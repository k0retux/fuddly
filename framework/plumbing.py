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


import sys
import os
import traceback
import random
import collections

import copy
import re
import pickle
import readline
import cmd
import atexit
import datetime
import time
import signal

from libs.external_modules import *

from framework.data_model import *
from framework.data import *
from framework.data_model_builder import DataModel
from framework.database import FeedbackHandler
from framework.error_handling import *
from framework.evolutionary_helpers import EvolutionaryScenariosFactory
from framework.logger import *
from framework.monitor import *
from framework.operator_helpers import *
from framework.project import *
from framework.scenario import *
from framework.tactics_helpers import *
from framework.target_helpers import *
from framework.targets.local import LocalTarget
from framework.targets.printer import PrinterTarget
from libs.utils import *

import framework.generic_data_makers

import data_models
import projects

from framework.global_resources import *
from libs.utils import *

sys.path.insert(0, fuddly_data_folder)
sys.path.insert(0, external_libs_folder)

user_dm_mod = os.path.basename(os.path.normpath(user_data_models_folder))
user_prj_mod = os.path.basename(os.path.normpath(user_projects_folder))
exec('import ' + user_dm_mod)
exec('import ' + user_prj_mod)

sig_int_handler = signal.getsignal(signal.SIGINT)

r_pyfile = re.compile(".*\.py$")
def is_python_file(fname):
    return r_pyfile.match(fname)


class ExportableFMKOps(object):

    def __init__(self, fmk):
        self.set_fuzz_delay = fmk.set_fuzz_delay
        self.set_fuzz_burst = fmk.set_fuzz_burst
        self.set_health_check_timeout = fmk.set_health_check_timeout
        self.cleanup_all_dmakers = fmk.cleanup_all_dmakers
        self.cleanup_dmaker = fmk.cleanup_dmaker
        self.dynamic_generator_ids = fmk.dynamic_generator_ids
        self.set_error = fmk.set_error
        self.load_data_model = fmk.load_data_model
        self.load_multiple_data_model = fmk.load_multiple_data_model
        self.reload_all = fmk.reload_all
        self.get_data = fmk.get_data
        self.unregister_task = fmk._unregister_task

class FmkFeedback(object):
    
    NeedChange = 1

    def __init__(self):
        self.flags = {
            FmkFeedback.NeedChange: (False, None)
            }

        self.__data_list = None

    def set_flag(self, name, context=None):
        if name in self.flags:
            self.flags[name] = (True, context)
        else:
            raise ValueError

    def clear_flag(self, name):
        if name in self.flags:
            self.flags[name] = (False, None)
        else:
            raise ValueError

    def is_flag_set(self, name):
        if name not in self.flags:
            raise ValueError
        return self.flags[name][0]

    def get_flag_context(self, name):
        if name not in self.flags:
            raise ValueError
        return self.flags[name][1]

    def add_produced_data(self, data):
        if self.__data_list is None:
            self.__data_list = []
        self.__data_list.append(data)

    def clear_produced_data(self):
        self.__data_list = []

    def get_produced_data(self):
        return self.__data_list


class EnforceOrder(object):

    current_state = None

    def __init__(self, accepted_states=[], final_state=None,
                 initial_func=False, always_callable=False, transition=None):
        if initial_func:
            self.accepted_states = accepted_states + [None]
        else:
            self.accepted_states = accepted_states
        self.final_state = final_state
        self.always_callable = always_callable
        self.transition = transition

    def __call__(self, func):
        
        def wrapped_func(*args, **kargs):
            if not self.always_callable and EnforceOrder.current_state not in self.accepted_states:
                print(colorize("[INVALID CALL] function '%s' cannot be called in the state '%r'!" \
                                       % (func.__name__, EnforceOrder.current_state),
                               rgb=Color.ERROR))
                return False
            ok = func(*args, **kargs)
            if (ok or ok is None) and self.final_state is not None:
                EnforceOrder.current_state = self.final_state

            elif (ok or ok is None) and self.transition is not None and EnforceOrder.current_state == self.transition[0]:
                EnforceOrder.current_state = self.transition[1]

            return ok

        return wrapped_func


class FmkTask(threading.Thread):

    def __init__(self, name, func, arg, period=None,
                 error_func=lambda x: x, cleanup_func=lambda x: None):
        threading.Thread.__init__(self)
        self._name = name
        self._func = func
        self._arg = arg
        self._period = period
        self._stop = threading.Event()
        self._error_func = error_func
        self._cleanup_func=cleanup_func

    def run(self):
        while not self._stop.is_set():
            try:
                # print("\n*** Function '{!s}' executed by Task '{!s}' ***".format(self._func, self._name))
                self._func(self._arg)
            except DataProcessTermination:
                break
            except:
                self._error_func("Task '{!s}' has crashed!".format(self._name))
                break
            if self._period is not None:
                self._stop.wait(max(self._period,0.01))
            else:
                self._cleanup_func()
                break

    def stop(self):
        self._stop.set()


class FmkPlumbing(object):

    ''' 
    Defines the methods to operate every sub-systems of fuddly
    '''

    def __init__(self):
        self.__started = False
        self.__first_loading = True

        self.error = False
        self.fmk_error = []
        self._sending_error = None

        self.__tg_enabled = False
        self.__prj_to_be_reloaded = False

        self._exportable_fmk_ops = ExportableFMKOps(self)

        self._generic_tactics = framework.generic_data_makers.tactics
        self._generic_tactics.set_exportable_fmk_ops(self._exportable_fmk_ops)

        self.import_text_reg = re.compile('(.*?)(#####)', re.S)
        self.check_clone_re = re.compile('(.*)#(\w{1,20})')

        self.prj_list = []
        self._prj_dict = {}

        self.dm_list = []
        self.__st_dict = {}
        self.__target_dict = {}
        self.__current_tg = 0
        self.__logger_dict = {}
        self.__monitor_dict = {}
        self.__initialized_dmaker_dict = {}
        self.__dm_rld_args_dict= {}
        self.__prj_rld_args_dict= {}

        self.__dyngenerators_created = {}
        self.__dynamic_generator_ids = {}

        self._name2dm = {}
        self._name2prj = {}

        self._task_list = {}
        self._task_list_lock = threading.Lock()

        self.fmkDB = Database()
        ok = self.fmkDB.start()
        if not ok:
            raise InvalidFmkDB("The database {:s} is invalid!".format(self.fmkDB.fmk_db_path))
        self.feedback_handler = FeedbackHandler(self.fmkDB)

        self._fmkDB_insert_dm_and_dmakers('generic', self._generic_tactics)

        self.group_id = 0
        self._saved_group_id = None  # used by self._recover_target()

        self.enable_wkspace()

        self.get_data_models()
        self.get_projects()

        print(colorize(FontStyle.BOLD + '='*44 + '[ Fuddly Data Folder Information ]==\n',
                       rgb=Color.FMKINFOGROUP))

        if hasattr(gr, 'new_fuddly_data_folder'):
            print(colorize(FontStyle.BOLD + \
                           ' *** New Fuddly Data Folder Has Been Created ***\n',
                           rgb=Color.FMKINFO_HLIGHT))

        print(colorize(' --> path: {:s}'.format(gr.fuddly_data_folder),
                       rgb=Color.FMKINFO))
        print(colorize(' --> contains: - fmkDB.db, logs, imported/exported data, ...\n'
                       '               - user projects and user data models',
                       rgb=Color.FMKSUBINFO))

    def set_error(self, msg='', context=None, code=Error.Reserved):
        self.error = True
        self.fmk_error.append(Error(msg, context=context, code=code))
        if hasattr(self, 'lg'):
            self.lg.log_fmk_info(msg)

    def get_error(self):
        self.error = False
        fmk_err = self.fmk_error
        self.fmk_error = []
        return fmk_err

    def is_not_ok(self):
        return self.error

    def is_ok(self):
        return not self.error

    def flush_errors(self):
        self.error = False
        self.fmk_error = []

    def __reset_fmk_internals(self, reset_existing_seed=True):
        self.cleanup_all_dmakers(reset_existing_seed)
        # Warning: fuzz delay is not set to 0 by default in order to have a time frame
        # where SIGINT is accepted from user
        self.set_fuzz_delay(0.01)
        self.set_fuzz_burst(1)
        self._recompute_health_check_timeout(self.tg.feedback_timeout, self.tg.sending_delay)

    def _recompute_health_check_timeout(self, base_timeout, sending_delay, do_show=True):
        if base_timeout is not None:
            if base_timeout != 0:
                if 0 < base_timeout < 1:
                    hc_timeout = base_timeout + sending_delay + 0.5
                else:
                    hc_timeout = base_timeout + sending_delay + 2.0
                self.set_health_check_timeout(hc_timeout, do_show=do_show)
            else:
                # base_timeout comes from feedback_timeout, if it is equal to 0
                # this is a special meaning used internally to collect residual feedback.
                # Thus, we don't change the current health_check timeout.
                return
        else:
            self.set_health_check_timeout(max(10,sending_delay), do_show=do_show)

    def _handle_no_stdout_exception(self):
        if sys.stdout == sys.__stdout__:
            return

        wrapper = sys.stdout
        sys.stdout = sys.__stdout__

        try:
            wrapper.handler(force=True)
        except:
            pass

        try:
            wrapper.restore()
        except:
            pass


    def _handle_user_code_exception(self, msg='', context=None):
        self._handle_no_stdout_exception()

        self.set_error(msg, code=Error.UserCodeError, context=context)
        if hasattr(self, 'lg'):
            self.lg.log_error("Exception in user code detected! Outcomes " \
                              "of this log entry has to be considered with caution.\n" \
                              "    (_ cause: '%s' _)" % msg)
        print("Exception in user code:")
        print('-'*60)
        traceback.print_exc(file=sys.stdout)
        print('-'*60)

    def _handle_fmk_exception(self, cause=''):
        self._handle_no_stdout_exception()

        self.set_error(cause, code=Error.UserCodeError)
        if hasattr(self, 'lg'):
            self.lg.log_error("Not handled exception detected! Outcomes " \
                                "of this log entry has to be considered with caution.\n" \
                                "    (_ cause: '%s' _)" % cause)
        print("Call trace:")
        print('-'*60)
        traceback.print_exc(file=sys.stdout)
        print('-'*60)

    def _is_data_valid(self, data):
        def is_valid(d):
            if d.is_unusable():
                return True
            elif d.raw is None and d.node is None:
                return False
            else:
                return True

        if isinstance(data, Data):
            return is_valid(data)
        elif isinstance(data, list):
            if len(data) == 0:
                return False

            for d in data:
                if not is_valid(d):
                    return False
            else:
                return True
        else:
            raise ValueError


    @EnforceOrder(accepted_states=['S2'])
    def reload_dm(self):
        prefix = self.__dm_rld_args_dict[self.dm][0]
        name = self.__dm_rld_args_dict[self.dm][1]

        if prefix is None:
            # In this case we face a composed DM, name is in fact a dm_list
            dm_list = name
            name_list = []

            self.cleanup_all_dmakers()

            for dm in dm_list:
                name_list.append(dm.name)
                self.dm = dm
                self.reload_dm()

            # reloading is based on name because DM objects have changed
            if not self.load_multiple_data_model(name_list=name_list, reload_dm=True):
                self.set_error("Error encountered while reloading the composed Data Model")

        else:
            self.cleanup_all_dmakers()
            self.dm.cleanup()

            dm_params = self.__import_dm(prefix, name, reload_dm=True)
            if dm_params is not None:
                self.__add_data_model(dm_params['dm'], dm_params['tactics'],
                                      dm_params['dm_rld_args'], reload_dm=True)
                self.__dyngenerators_created[dm_params['dm']] = False
                self.dm = dm_params['dm']
            else:
                return False

            self._cleanup_dm_attrs_from_fmk()

            if not self._load_data_model():
                return False

            self.prj.set_data_model(self.dm)
            if hasattr(self, 'tg'):
                self.tg.set_data_model(self.dm)
            if hasattr(self, 'mon'):
                self.mon.set_data_model(self.dm)
            self._fmkDB_insert_dm_and_dmakers(self.dm.name, dm_params['tactics'])

        return True

    def _cleanup_dm_attrs_from_fmk(self):
        self._generic_tactics.clear_generator_clones()
        self._generic_tactics.clear_disruptor_clones()
        if hasattr(self, '_tactics'):
            self._tactics.clear_generator_clones()
            self._tactics.clear_disruptor_clones()
        self._tactics = self.__st_dict[self.dm]
        self._recompute_current_generators()


    @EnforceOrder(accepted_states=['S2'])
    def reload_all(self, tg_num=None):
        return self.__reload_all(tg_num=tg_num)

    def __reload_all(self, tg_num=None):
        prj_prefix = self.__prj_rld_args_dict[self.prj][0]
        prj_name = self.__prj_rld_args_dict[self.prj][1]

        dm_prefix = self.__dm_rld_args_dict[self.dm][0]
        dm_name = self.__dm_rld_args_dict[self.dm][1]

        self.__stop_fmk_plumbing()

        if tg_num is not None:
            self.set_target(tg_num)

        prj_params = self._import_project(prj_prefix, prj_name, reload_prj=True)
        if prj_params is not None:
            self._add_project(prj_params['project'], prj_params['target'], prj_params['logger'],
                              prj_params['prj_rld_args'], reload_prj=True)

            if dm_prefix is None:
                # it is ok to call reload_dm() here because it is a
                # composed DM, and it won't call the methods used within
                # __init_fmk_internals_step1().
                self.reload_dm()
                self.__init_fmk_internals_step1(prj_params['project'], self.dm)
            else:
                dm_params = self.__import_dm(dm_prefix, dm_name, reload_dm=True)
                if dm_params is not None:
                    self.__add_data_model(dm_params['dm'], dm_params['tactics'],
                                          dm_params['dm_rld_args'], reload_dm=True)
                    self.__dyngenerators_created[dm_params['dm']] = False
                    self.__init_fmk_internals_step1(prj_params['project'], dm_params['dm'])

        self.__start_fmk_plumbing()
        if self.is_not_ok():
            self.__stop_fmk_plumbing()
            return False

        if prj_params is not None:
            self.__init_fmk_internals_step2(prj_params['project'], self.dm)

        return True


    def _fmkDB_insert_dm_and_dmakers(self, dm_name, tactics):
        self.fmkDB.insert_data_model(dm_name)
        disruptor_types = tactics.disruptor_types
        if disruptor_types:
            for dis_type in sorted(disruptor_types):
                disruptor_names = tactics.get_disruptors_list(dis_type)
                for dis_name in disruptor_names:
                    dis_obj = tactics.get_disruptor_obj(dis_type, dis_name)
                    stateful = True if issubclass(dis_obj.__class__, StatefulDisruptor) else False
                    self.fmkDB.insert_dmaker(dm_name, dis_type, dis_name, False, stateful)
        generator_types = tactics.generator_types
        if generator_types:
            for gen_type in sorted(generator_types):
                generator_names = tactics.get_generators_list(gen_type)
                for gen_name in generator_names:
                    gen_obj = tactics.get_generator_obj(gen_type, gen_name)
                    self.fmkDB.insert_dmaker(dm_name, gen_type, gen_name, True, True)

    def _recover_target(self):
        if self.group_id == self._saved_group_id:
            # This method can be called after checking target health, feedback and
            # probes status. However, we have to avoid to recover the target twice.
            return True
        else:
            self._saved_group_id = self.group_id

        target_recovered = False
        try:
            target_recovered = self.tg.recover_target()
        except NotImplementedError:
            self.lg.log_fmk_info("No method to recover the target is implemented! (assumption: no need "
                                 "to recover)")
            target_recovered = True  # assumption: no need to recover
        except:
            self.lg.log_fmk_info("Exception raised while trying to recover the target!")
        else:
            if target_recovered:
                self.lg.log_fmk_info("The target has been recovered!")
            else:
                self.lg.log_fmk_info("The target has not been recovered! All further operations "
                                     "will be terminated.")
        return target_recovered

    def monitor_probes(self, prefix=None, force_record=False):
        probes = self.mon.get_probes_names()
        ok = True
        prefix_printed = False
        for pname in probes:
            if self.mon.is_probe_launched(pname):
                pstatus = self.mon.get_probe_status(pname)
                err = pstatus.get_status()
                if err < 0 or force_record:
                    if err < 0:
                        ok = False
                    if prefix and not prefix_printed:
                        prefix_printed = True
                        self.lg.print_console('\n*** {:s} ***'.format(prefix), rgb=Color.FMKINFO)
                    tstamp = pstatus.get_timestamp()
                    priv = pstatus.get_private_info()
                    self.lg.log_probe_feedback(source="Probe '{:s}'".format(pname),
                                               timestamp=tstamp,
                                               content=priv, status_code=err)

        ret = self._recover_target() if not ok else True

        if prefix and not ok:
            self.lg.print_console('*'*(len(prefix)+8)+'\n', rgb=Color.FMKINFO)

        return ret

    @EnforceOrder(initial_func=True, final_state='get_projs')
    def get_data_models(self):

        data_models = collections.OrderedDict()
        def populate_data_models(path):
            dm_dir = os.path.basename(os.path.normpath(path))
            for (dirpath, dirnames, filenames) in os.walk(path):
                if filenames:
                    data_models[dm_dir] = []
                    data_models[dm_dir].extend(filenames)
                for d in dirnames:
                    full_path = os.path.join(path, d)
                    rel_path = os.path.join(dm_dir, d)
                    data_models[rel_path] = []
                    for (dth, dnames, fnm) in os.walk(full_path):
                        data_models[rel_path].extend(fnm)
                        break
                break

        populate_data_models(gr.data_models_folder)
        populate_data_models(gr.user_data_models_folder)

        dms = copy.copy(data_models)
        for k in dms:
            data_models[k] = list(filter(is_python_file, data_models[k]))
            if '__init__.py' in data_models[k]:
                data_models[k].remove('__init__.py')
            if not data_models[k]:
                del data_models[k]

        rexp_strategy = re.compile("(.*)_strategy\.py$")

        print(colorize(FontStyle.BOLD + "="*63+"[ Data Models ]==", rgb=Color.FMKINFOGROUP))

        for dname, file_list in data_models.items():
            print(colorize(">>> Look for Data Models within '%s' directory" % dname,
                           rgb=Color.FMKINFOSUBGROUP))
            prefix = dname.replace(os.sep, '.') + '.'
            for f in file_list:
                res = rexp_strategy.match(f)
                if res is None:
                    continue
                name = res.group(1)
                if name + '.py' in file_list:
                    dm_params = self.__import_dm(prefix, name)
                    if dm_params is not None:
                        self.__add_data_model(dm_params['dm'], dm_params['tactics'],
                                              dm_params['dm_rld_args'],
                                              reload_dm=False)
                        self.__dyngenerators_created[dm_params['dm']] = False
                        # populate FMK DB
                        self._fmkDB_insert_dm_and_dmakers(dm_params['dm'].name, dm_params['tactics'])

        self.fmkDB.insert_data_model(Database.DEFAULT_DM_NAME)
        self.fmkDB.insert_dmaker(Database.DEFAULT_DM_NAME, Database.DEFAULT_GTYPE_NAME,
                                 Database.DEFAULT_GEN_NAME, True, True)


    def __import_dm(self, prefix, name, reload_dm=False):

        try:
            if reload_dm:
                if sys.version_info[0] == 2:
                    eval('reload(' + prefix + name + ')')
                    eval('reload(' + prefix + name + '_strategy' + ')')
                else:
                    exec('import importlib')
                    eval('importlib.reload(' + prefix + name + ')')
                    eval('importlib.reload(' + prefix + name + '_strategy' + ')')
            else:
                exec('import ' + prefix + name)
                exec('import ' + prefix + name + '_strategy')
        except:
            if reload_dm:
                print(colorize("*** Problem during reload of '%s.py' and/or '%s_strategy.py' ***" % (name, name), rgb=Color.ERROR))
            else:
                print(colorize("*** Problem during import of '%s.py' and/or '%s_strategy.py' ***" % (name, name), rgb=Color.ERROR))
            print('-'*60)
            traceback.print_exc(file=sys.stdout)
            print('-'*60)

            return None

        else:
            dm_params = {}

            dm_params['dm_rld_args'] = (prefix, name)

            try:
                dm_params['dm'] = eval(prefix + name + '.data_model')
            except:
                print(colorize("*** ERROR: '%s.py' shall contain a global variable 'data_model' ***" % (name), rgb=Color.ERROR))
                return None
            try:
                dm_params['tactics'] = eval(prefix + name + '_strategy' + '.tactics')
            except:
                print(colorize("*** ERROR: '%s_strategy.py' shall contain a global variable 'tactics' ***" % (name), rgb=Color.ERROR))
                return None

            try:
                evol_scs = eval(prefix + name + '_strategy' + '.evolutionary_scenarios')
            except:
                pass
            else:
                built_evol_scs = []
                for evol_sc in evol_scs:
                    built_evol_sc = EvolutionaryScenariosFactory.build(self._exportable_fmk_ops, *evol_sc)
                    built_evol_scs.append(built_evol_sc)

                dm_params['tactics'].register_scenarios(*built_evol_scs)

            dm_params['tactics'].set_exportable_fmk_ops(self._exportable_fmk_ops)

            if dm_params['dm'].name is None:
                dm_params['dm'].name = name
            self._name2dm[dm_params['dm'].name] = dm_params['dm']

            if reload_dm:
                print(colorize("*** Data Model '%s' updated ***" % dm_params['dm'].name, rgb=Color.DATA_MODEL_LOADED))
            else:
                print(colorize("*** Found Data Model: '%s' ***" % dm_params['dm'].name, rgb=Color.FMKSUBINFO))

            return dm_params


    def __add_data_model(self, data_model, strategy, dm_rld_args,
                         reload_dm=False):

        if data_model.name not in map(lambda x: x.name, self.dm_list):
            self.dm_list.append(data_model)
            old_dm = None
        elif reload_dm:
            for dm in self.dm_list:
                if dm.name == data_model.name:
                    break
            else:
                raise ValueError
            old_dm = dm
            self.dm_list.remove(dm)
            self.dm_list.append(data_model)
        else:
            raise ValueError("A data model with the name '%s' already exist!" % data_model.name)

        if old_dm is not None:
            self.__dm_rld_args_dict.pop(old_dm)
            self.__st_dict.pop(old_dm)
            self.__st_dict[data_model] = strategy
        else:
            self.__st_dict[data_model] = strategy

        self.__dm_rld_args_dict[data_model] = dm_rld_args




    @EnforceOrder(accepted_states=['get_projs'], final_state='20_load_prj')
    def get_projects(self):

        projects = collections.OrderedDict()
        def populate_projects(path):
            prj_dir = os.path.basename(os.path.normpath(path))
            for (dirpath, dirnames, filenames) in os.walk(path):
                if filenames:
                    projects[prj_dir] = []
                    projects[prj_dir].extend(filenames)
                for d in dirnames:
                    full_path = os.path.join(path, d)
                    rel_path = os.path.join(prj_dir, d)
                    projects[rel_path] = []
                    for (dth, dnames, fnm) in os.walk(full_path):
                        projects[rel_path].extend(fnm)
                        break
                break

        populate_projects(gr.projects_folder)
        populate_projects(gr.user_projects_folder)

        prjs = copy.copy(projects)
        for k in prjs:
            projects[k] = list(filter(is_python_file, projects[k]))
            if '__init__.py' in projects[k]:
                projects[k].remove('__init__.py')
            if not projects[k]:
                del projects[k]

        rexp_proj = re.compile("(.*)_proj\.py$")

        print(colorize(FontStyle.BOLD + "="*66+"[ Projects ]==", rgb=Color.FMKINFOGROUP))

        for dname, file_list in projects.items():
            print(colorize(">>> Look for Projects within '%s' Directory" % dname,
                           rgb=Color.FMKINFOSUBGROUP))
            prefix = dname.replace(os.sep, '.') + '.'
            for f in file_list:
                res = rexp_proj.match(f)
                if res is None:
                    continue
                name = res.group(1)
                prj_params = self._import_project(prefix, name)
                if prj_params is not None:
                    self._add_project(prj_params['project'],
                                      prj_params['target'], prj_params['logger'],
                                      prj_params['prj_rld_args'],
                                      reload_prj=False)
                    self.fmkDB.insert_project(prj_params['project'].name)


    def _import_project(self, prefix, name, reload_prj=False):

        try:
            if reload_prj:
                if sys.version_info[0] == 2:
                    eval('reload(' + prefix + name + '_proj' + ')')
                else:
                    exec('import importlib')
                    eval('importlib.reload(' + prefix + name + '_proj' + ')')
            else:
                exec('import ' + prefix + name + '_proj')
        except:
            if reload_prj:
                print(colorize("*** Problem during reload of '%s_proj.py' ***" % (name), rgb=Color.ERROR))
            else:
                print(colorize("*** Problem during import of '%s_proj.py' ***" % (name), rgb=Color.ERROR))
            print(prefix)
            print('-'*60)
            traceback.print_exc(file=sys.stdout)
            print('-'*60)

            return None

        else:
            prj_params = {}

            prj_params['prj_rld_args'] = (prefix, name)

            try:
                prj_params['project'] = eval(prefix + name + '_proj' + '.project')
            except:
                print(colorize("*** ERROR: '%s_proj.py' shall contain a global variable 'project' ***" % (name), rgb=Color.ERROR))
                return None

            try:
                logger = eval(prefix + name + '_proj' + '.logger')
            except:
                logger = Logger(name, prefix=' || ')
            logger.fmkDB = self.fmkDB
            if logger.name is None:
                logger.name = name
            prj_params['logger'] = logger
            try:
                targets = eval(prefix + name + '_proj' + '.targets')
                targets.insert(0, EmptyTarget())
            except:
                targets = [EmptyTarget()]
            else:
                new_targets = []
                for obj in targets:
                    if isinstance(obj, (tuple, list)):
                        tg = obj[0]
                        obj = obj[1:]
                        tg.remove_probes()
                        for p in obj:
                            tg.add_probe(p)
                    else:
                        assert issubclass(obj.__class__, Target), 'project: {!s}'.format(name)
                        tg = obj
                        tg.remove_probes()
                    new_targets.append(tg)
                targets = new_targets

            if self.__current_tg >= len(targets):
                self.__current_tg = 0
            
            prj_params['target'] = targets

            if prj_params['project'].name is None:
                prj_params['project'].name = name
            self._name2prj[prj_params['project'].name] = prj_params['project']

            if reload_prj:
                print(colorize("*** Project '%s' updated ***" % prj_params['project'].name, rgb=Color.FMKSUBINFO))
            else:
                print(colorize("*** Found Project: '%s' ***" % prj_params['project'].name, rgb=Color.FMKSUBINFO))

            return prj_params


    def _add_project(self, project, target, logger, prj_rld_args,
                     reload_prj=False):

        if project.name not in map(lambda x: x.name, self.prj_list):
            self.prj_list.append(project)
            old_prj = None
        elif reload_prj:
            for prj in self.prj_list:
                if prj.name == project.name:
                    break
            else:
                raise ValueError
            old_prj = prj
            self.prj_list.remove(prj)
            self.prj_list.append(project)
        else:
            raise ValueError("A project with the name '%s' already exist!" % project.name)

        if old_prj is not None:
            self.__prj_rld_args_dict.pop(old_prj)
            self.__initialized_dmaker_dict.pop(old_prj)
            self._prj_dict.pop(old_prj)
            self._prj_dict[project] = project
            mon = self.__monitor_dict.pop(old_prj)
            lg = self.__logger_dict.pop(old_prj)
            tg = self.__target_dict.pop(old_prj)
            self.__target_dict[project] = target
            self.__logger_dict[project] = logger
            self.__monitor_dict[project] = project.monitor
            self.__monitor_dict[project].set_fmk_ops(fmk_ops=self._exportable_fmk_ops)
            self.__monitor_dict[project].set_logger(self.__logger_dict[project])
            self.__monitor_dict[project].set_target(self.__target_dict[project])
            self._prj_dict[project].set_logger(self.__logger_dict[project])
            self._prj_dict[project].set_monitor(self.__monitor_dict[project])
        else:
            self._prj_dict[project] = project
            self.__target_dict[project] = target
            self.__logger_dict[project] = logger
            self.__monitor_dict[project] = project.monitor
            self.__monitor_dict[project].set_fmk_ops(fmk_ops=self._exportable_fmk_ops)
            self.__monitor_dict[project].set_logger(self.__logger_dict[project])
            self.__monitor_dict[project].set_target(self.__target_dict[project])
            self._prj_dict[project].set_logger(self.__logger_dict[project])
            self._prj_dict[project].set_monitor(self.__monitor_dict[project])

        self.__prj_rld_args_dict[project] = prj_rld_args
        self.__initialized_dmaker_dict[project] = {}




    def is_usable(self):
        return self.__is_started()

    def __is_started(self):
        return self.__started

    def __start(self):
        self.__started = True

    def __stop(self):
        self.__started = False


    def _load_data_model(self):
        try:
            self.dm.load_data_model(self._name2dm)

            if not self.__dyngenerators_created[self.dm]:
                self.__dyngenerators_created[self.dm] = True
                self.__dynamic_generator_ids[self.dm] = []
                for di in self.dm.data_identifiers():
                    dmaker_type = di.upper()
                    gen_cls_name = 'g_' + di.lower()
                    dyn_generator.data_id = di
                    gen = dyn_generator(gen_cls_name, (DynGenerator,), {})()
                    self._tactics.register_new_generator(gen_cls_name, gen, weight=1,
                                                          dmaker_type=dmaker_type, valid=True)
                    self.__dynamic_generator_ids[self.dm].append(dmaker_type)
                    self.fmkDB.insert_dmaker(self.dm.name, dmaker_type, gen_cls_name, True, True)

            print(colorize("*** Data Model '%s' loaded ***" % self.dm.name, rgb=Color.DATA_MODEL_LOADED))

        except:
            self._handle_user_code_exception()
            self.__prj_to_be_reloaded = True
            self.set_error("Error encountered while loading the data model. (checkup" \
                           " the associated '%s.py' file)" % self.dm.name)
            return False

        return True

    def __start_fmk_plumbing(self):
        if not self.__is_started():
            signal.signal(signal.SIGINT, signal.SIG_IGN)

            self.lg.start()

            ok = self._load_data_model()
            if not ok:
                self.set_error("Project cannot be launched because of data model loading error")
                return

            try:
                ok = self.tg._start()
            except:
                self._handle_user_code_exception()
                self.set_error("The Target has not been initialized correctly (checkup" \
                               " the associated '%s_strategy.py' file)" % self.dm.name)
            else:
                if ok:
                    self.__enable_target()
                    self.mon.start()
                    for p in self.tg.probes:
                        pname, delay = self._extract_info_from_probe(p)
                        if delay is not None:
                            self.mon.set_probe_delay(pname, delay)
                        self.mon.start_probe(pname)
                    self.mon.wait_for_probe_initialization()
                    self.prj.start()
                    if self.tg.probes:
                        time.sleep(0.5)
                        self.monitor_probes(force_record=True)
                else:
                    self.set_error("The Target has not been initialized correctly")
            
            self.__current = []
            self.__db_idx = 0
            self.__data_bank = {}

            self.__start()


    def __stop_fmk_plumbing(self):
        self.flush_errors()
        if self.__is_started():
            if self.is_target_enabled():
                self.log_target_residual_feedback()

            self._cleanup_tasks()

            if self.is_target_enabled():
                self.mon.stop()
                try:
                    self.tg._stop()
                except:
                    self._handle_user_code_exception()
                finally:
                    self.__disable_target()

            self.lg.stop()
            self.prj.stop()

            self.__stop()

            signal.signal(signal.SIGINT, sig_int_handler)


    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'])
    def exit_fmk(self):
        self.__stop_fmk_plumbing()
        self.fmkDB.stop()

    @EnforceOrder(accepted_states=['25_load_dm','S1','S2'])
    def set_target(self, num):
        return self.__set_target(num)

    def __set_target(self, num):
        if num >= len(self.__target_dict[self.prj]):
            self.set_error('The provided target number does not exist!',
                           code=Error.CommandError)
            return False

        self.__current_tg = num
        return True

    @EnforceOrder(accepted_states=['25_load_dm','S1','S2'])
    def get_available_targets(self):           
        for tg in self.__target_dict[self.prj]:
            yield tg


    def _extract_info_from_probe(self, p):
        if isinstance(p, (tuple, list)):
            assert(len(p) == 2)
            pname = p[0].__name__
            delay = p[1]
        else:
            pname = p.__name__
            delay = None
        return pname, delay


    def _get_detailed_target_desc(self, tg):
        if isinstance(tg, PrinterTarget):
            printer_name = tg.get_printer_name()
            printer_name = ', Name: ' + printer_name if printer_name is not None else ''
            detailed_desc = tg.__class__.__name__ + ' [IP: ' + tg.get_target_ip() + printer_name + ']'
        elif isinstance(tg, LocalTarget):
            pre_args = tg.get_pre_args()
            post_args = tg.get_post_args()
            args = ''
            if pre_args or post_args:
                if pre_args is not None:
                    args += pre_args
                if post_args is not None:
                    args += post_args
                args = ', Args: ' + args
            detailed_desc = tg.__class__.__name__ + ' [Program: ' + tg.get_target_path() + args + ']'
        else:
            desc = tg.get_description()
            if desc is None:
                desc = ''
            else:
                desc = ' [' + desc + ']'
            detailed_desc = tg.__class__.__name__ + desc

        return detailed_desc

    @EnforceOrder(accepted_states=['25_load_dm','S1','S2'])
    def show_targets(self):
        print(colorize(FontStyle.BOLD + '\n-=[ Available Targets ]=-\n', rgb=Color.INFO))
        idx = 0
        for tg in self.get_available_targets():
            name = self._get_detailed_target_desc(tg)

            msg = "[{:d}] {:s}".format(idx, name)

            probes = tg.probes
            if probes:
                msg += '\n     \-- monitored by:'
                for p in probes:
                    pname, delay = self._extract_info_from_probe(p)
                    if delay:
                        msg += " {:s}(refresh={:.2f}s),".format(pname, delay)
                    else:
                        msg += " {:s},".format(pname)
                msg = msg[:-1]

            if self.__current_tg == idx:
                msg = colorize(FontStyle.BOLD + msg, rgb=Color.SELECTED)
            else:
                msg = colorize(msg, rgb=Color.SUBINFO)
            print(msg)
            idx += 1


    @EnforceOrder(accepted_states=['S2'])
    def dynamic_generator_ids(self):
        for genid in self.__dynamic_generator_ids[self.dm]:
            yield genid

    @EnforceOrder(accepted_states=['S2'])
    def show_fmk_internals(self):
        if not self.tg.supported_feedback_mode:
            fbk_mode = 'Target does not provide feedback'
        elif self.tg.fbk_wait_full_time_slot_mode:
            fbk_mode = self.tg.fbk_wait_full_time_slot_msg
        else:
            fbk_mode = self.tg.fbk_wait_until_recv_msg

        print(colorize(FontStyle.BOLD + '\n-=[ FMK Internals ]=-\n', rgb=Color.INFO))
        print(colorize('                     Fuzz delay: ', rgb=Color.SUBINFO) + str(self._delay))
        print(colorize('   Number of data sent in burst: ', rgb=Color.SUBINFO) + str(self._burst))
        print(colorize('    Target health-check timeout: ', rgb=Color.SUBINFO) + str(self._hc_timeout))
        print(colorize('        Target feedback timeout: ', rgb=Color.SUBINFO) + str(self.tg.feedback_timeout))
        print(colorize('           Target feedback mode: ', rgb=Color.SUBINFO) + fbk_mode)
        print(colorize('              Workspace enabled: ', rgb=Color.SUBINFO) + repr(self._wkspace_enabled))
        print(colorize('                  FmkDB enabled: ', rgb=Color.SUBINFO) + repr(self.fmkDB.enabled))

    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'])
    def projects(self):
        for prj in self.prj_list:
            yield prj

    def _projects(self):
        for prj in self.prj_list:
            yield prj

    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'])
    def show_projects(self):
        print(colorize(FontStyle.BOLD + '\n-=[ Projects ]=-\n', rgb=Color.INFO))
        idx = 0
        for prj in self._projects():
            print(colorize('[%d] ' % idx + prj.name, rgb=Color.SUBINFO))
            idx += 1


    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'])
    def iter_data_models(self):
        for dm in self.dm_list:
            yield dm

    def __iter_data_models(self):
        for dm in self.dm_list:
            yield dm

    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'])
    def show_data_models(self):
        print(colorize(FontStyle.BOLD + '\n-=[ Data Models ]=-\n', rgb=Color.INFO))
        idx = 0
        for dm in self.__iter_data_models():
            print(colorize('[%d] ' % idx + dm.name, rgb=Color.SUBINFO))
            idx += 1

    def __init_fmk_internals_step1(self, prj, dm):
        self.prj = prj
        self.dm = dm
        self.lg = self.__logger_dict[prj]
        try:
            self.tg = self.__target_dict[prj][self.__current_tg]
        except IndexError:
            self.__current_tg = 0
            self.tg = self.__target_dict[prj][self.__current_tg]

        self.tg_name = self._get_detailed_target_desc(self.tg)

        self.tg.set_logger(self.lg)
        self.tg.set_data_model(self.dm)
        self.prj.set_target(self.tg)
        self.prj.set_data_model(self.dm)

        if self.__first_loading:
            self.__first_loading = False
        else:
            # Clear all cloned dmakers
            self._generic_tactics.clear_generator_clones()
            self._generic_tactics.clear_disruptor_clones()
            self._tactics.clear_generator_clones()
            self._tactics.clear_disruptor_clones()

        self._tactics = self.__st_dict[dm]

        self.mon = self.__monitor_dict[prj]
        self.mon.set_target(self.tg)
        self.mon.set_logger(self.lg)
        self.mon.set_data_model(self.dm)
        self.__initialized_dmakers = self.__initialized_dmaker_dict[prj]

    def __init_fmk_internals_step2(self, prj, dm):
        self._recompute_current_generators()
        # need the logger active
        self.__reset_fmk_internals()


    def _recompute_current_generators(self):
        specific_gen = self._tactics.generator_types
        generic_gen = self._generic_tactics.generator_types
        self.__current_gen = list(specific_gen) + list(generic_gen)

    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'])
    def get_data_model_by_name(self, name):
        for model in self.__iter_data_models():
            if model.name == name:
                ret = model
                break
        else:
            ret = None
        return ret

    @EnforceOrder(accepted_states=['25_load_dm','S1','S2'], transition=['25_load_dm','S1'])
    def load_data_model(self, dm=None, name=None):
        if name is not None:
            dm = self.get_data_model_by_name(name)
            if dm is None:
                self.set_error("Data model '{:s}' has not been found!".format(name), 
                               code=Error.CommandError)
                return False

        elif dm is not None:
            if dm not in self.dm_list:
                return False

        if self.__is_started():
            self.cleanup_all_dmakers()
        self.dm = dm
        self.prj.set_data_model(self.dm)
        if hasattr(self, 'tg'):
            self.tg.set_data_model(self.dm)
        if hasattr(self, 'mon'):
            self.mon.set_data_model(self.dm)
        if self.__is_started():
            self._cleanup_dm_attrs_from_fmk()
            ok = self._load_data_model()
            if not ok:
                return False

        return True

    @EnforceOrder(accepted_states=['25_load_dm','S1','S2'], transition=['25_load_dm','S1'])
    def load_multiple_data_model(self, dm_list=None, name_list=None, reload_dm=False):
        if name_list is not None:
            dm_list = []
            for name in name_list:
                dm = self.get_data_model_by_name(name)
                if dm is None:
                    self.set_error("Data model '{:s}' has not been found!".format(name), 
                                   code=Error.CommandError)
                    return False
                dm_list.append(dm)
            
        elif dm_list is not None:
            for dm in dm_list:
                if dm not in self.dm_list:
                    return False

        if self.__is_started():
            self.cleanup_all_dmakers()

        new_dm = DataModel()
        new_tactics = Tactics()
        dyn_gen_ids = []
        name = ''
        for dm in dm_list:
            name += dm.name + '+'
            if not reload_dm:
                self.dm = dm
                self._cleanup_dm_attrs_from_fmk()
                ok = self._load_data_model()
                if not ok:
                    return False
            new_dm.merge_with(dm)
            tactics = self.__st_dict[dm]
            for k, v in tactics.disruptors.items():
                if k in new_tactics.disruptors:
                    raise ValueError("the disruptor '{:s}' exists already".format(k))
                else:
                    new_tactics.disruptors[k] = v
            for k, v in tactics.generators.items():
                if k in new_tactics.disruptors:
                    raise ValueError("the generator '{:s}' exists already".format(k))
                else:
                    new_tactics.generators[k] = v
            for dmk_id in self.__dynamic_generator_ids[dm]:
                dyn_gen_ids.append(dmk_id)

        new_dm.name = name[:-1]
        is_dm_name_exists = new_dm.name in map(lambda x: x.name, self.dm_list)

        if reload_dm or not is_dm_name_exists:
            self.fmkDB.insert_data_model(new_dm.name)
            self.__add_data_model(new_dm, new_tactics,
                                  (None, dm_list),
                                  reload_dm=reload_dm)

            # In this case DynGens have already been generated through
            # the reloading of the included DMs
            self.__dyngenerators_created[new_dm] = True
            self.__dynamic_generator_ids[new_dm] = dyn_gen_ids

        elif is_dm_name_exists:
            new_dm = self.get_data_model_by_name(new_dm.name)

        else:  # unreachable
            raise ValueError

        self.dm = new_dm
        self.prj.set_data_model(self.dm)
        if hasattr(self, 'tg'):
            self.tg.set_data_model(self.dm)
        if hasattr(self, 'mon'):
            self.mon.set_data_model(self.dm)
        if self.__is_started():
            self._cleanup_dm_attrs_from_fmk()
            ok = self._load_data_model()
            if not ok:
                return False

        return True


    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'])
    def get_project_by_name(self, name):
        for prj in self._projects():
            if prj.name == name:
                ret = prj
                break
        else:
            ret = None
        return ret


    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'], final_state='S2')
    def run_project(self, prj=None, name=None, tg=None, dm_name=None):
        ok = self.load_project(prj=prj, name=name)
        if not ok:
           return False

        if dm_name is None:
            if self.prj.default_dm is None:
                self.set_error("The attribute 'default_dm' is not set!")
                return False
            else:
                dm_name = self.prj.default_dm

        if isinstance(dm_name, list):
            ok = self.load_multiple_data_model(name_list=dm_name)
        else:
            ok = self.load_data_model(name=dm_name)

        if not ok:
            return False
 
        if tg is not None:
            assert(isinstance(tg, int))
            self.__set_target(tg)
        else:
            self.__set_target(0)

        return self.launch()


    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'], final_state='25_load_dm')
    def load_project(self, prj=None, name=None):
        if name is not None:
            prj = self.get_project_by_name(name)
            if prj is None:
                return False

        elif prj is not None:
            if prj not in self.prj_list:
                return False

        self.prj = prj

        self.__stop_fmk_plumbing()

        return True


    @EnforceOrder(accepted_states=['S1'], final_state='S2')
    def launch(self):
        if not self.__prj_to_be_reloaded:
            self.__init_fmk_internals_step1(self.prj, self.dm)
            self.__start_fmk_plumbing()
            if self.is_not_ok():
                self.__stop_fmk_plumbing()
                return False

            self.__init_fmk_internals_step2(self.prj, self.dm)
            return True

        else:
            self.__prj_to_be_reloaded = False
            self.__reload_all()
            return True

    def is_target_enabled(self):
        return self.__tg_enabled

    def __enable_target(self):
        self.__tg_enabled = True
        self.mon.enable_hooks()

    def __disable_target(self):
        self.__tg_enabled = False
        self.mon.disable_hooks()

    @EnforceOrder(always_callable=True)
    def enable_wkspace(self):
        self._wkspace_enabled = True

    @EnforceOrder(always_callable=True)
    def disable_wkspace(self):
        self._wkspace_enabled = False

    @EnforceOrder(accepted_states=['S1','S2'])
    def set_fuzz_delay(self, delay, do_record=False):
        if delay >= 0 or delay == -1:
            self._delay = delay
            self.lg.log_fmk_info('Fuzz delay = {:.1f}s'.format(self._delay), do_record=do_record)
            return True
        else:
            self.lg.log_fmk_info('Wrong delay value!', do_record=False)
            return False

    @EnforceOrder(accepted_states=['S1','S2'])
    def set_fuzz_burst(self, val, do_record=False):
        if val >= 1:
            self._burst = int(val)
            self._burst_countdown = self._burst
            self.lg.log_fmk_info('Number of data sent in burst = %d' % self._burst,
                                 do_record=do_record)
            return True
        else:
            self.lg.log_fmk_info('Wrong burst value!', do_record=False)
            return False

    @EnforceOrder(accepted_states=['S1','S2'])
    def set_health_check_timeout(self, timeout, do_record=False, do_show=True):
        if timeout >= 0:
            self._hc_timeout = timeout
            if do_show or do_record:
                self.lg.log_fmk_info('Target health-check timeout = {:.1f}s'.format(self._hc_timeout),
                                     do_record=do_record)
            return True
        else:
            self.lg.log_fmk_info('Wrong timeout value!', do_record=False)
            return False

    @EnforceOrder(accepted_states=['S1','S2'])
    def set_feedback_timeout(self, timeout, do_record=False, do_show=True):
        if timeout is None:
            # This case occurs in self._do_sending_and_logging_init()
            # if the Target has not defined a feedback_timeout (like the EmptyTarget)
            self._recompute_health_check_timeout(timeout, self.tg.sending_delay, do_show=do_show)
        elif timeout >= 0:
            self.tg.set_feedback_timeout(timeout)
            if do_show or do_record:
                self.lg.log_fmk_info('Target feedback timeout = {:.1f}s'.format(timeout),
                                     do_record=do_record)
            self._recompute_health_check_timeout(timeout, self.tg.sending_delay, do_show=do_show)
            return True
        else:
            self.lg.log_fmk_info('Wrong timeout value!', do_record=False)
            return False

    @EnforceOrder(accepted_states=['S1','S2'])
    def set_feedback_mode(self, mode, do_record=False, do_show=True):
        ok = self.tg.set_feedback_mode(mode)
        if not ok:
            self.set_error('The target does not support this feedback Mode', code=Error.CommandError)
        elif do_show or do_record:
            if self.tg.fbk_wait_full_time_slot_mode:
                msg = 'Feedback Mode = ' + self.tg.fbk_wait_full_time_slot_msg
            else:
                msg = 'Feedback Mode = ' + self.tg.fbk_wait_until_recv_msg
            self.lg.log_fmk_info(msg, do_record=do_record)

    @EnforceOrder(accepted_states=['S1','S2'])
    def switch_feedback_mode(self, do_record=False, do_show=True):
        if self.tg.fbk_wait_full_time_slot_mode:
            self.set_feedback_mode(Target.FBK_WAIT_UNTIL_RECV, do_record=do_record, do_show=do_show)
        else:
            self.set_feedback_mode(Target.FBK_WAIT_FULL_TIME, do_record=do_record, do_show=do_show)

    # Used to introduce some delay after sending data
    def __delay_fuzzing(self):
        '''
        return False if the user want to stop fuzzing (action possible if
        delay is set to -1)
        '''
        ret = True
        if self._burst_countdown <= 1:
            self._burst_countdown = self._burst

            if self.__tg_enabled:
                if self._delay == -1.0:
                    try:
                        signal.signal(signal.SIGINT, sig_int_handler)
                        if sys.version_info[0] == 2:
                            cont = raw_input("\n*** Press [ENTER] to continue ('q' to exit) ***\n")
                        else:
                            cont = input("\n*** Press [ENTER] to continue ('q' to exit) ***\n")
                        if cont == 'q':
                            ret = False
                    except KeyboardInterrupt:
                        ret = False
                        self.set_error("The operation has been cancelled by the user (while in delay step)!",
                                       code=Error.OperationCancelled)
                    finally:
                        signal.signal(signal.SIGINT, signal.SIG_IGN)

                elif self._delay == 0.0:
                    pass
                elif self._delay > 0:
                    try:
                        signal.signal(signal.SIGINT, sig_int_handler)
                        time.sleep(self._delay)
                    except KeyboardInterrupt:
                        ret = False
                        self.set_error("The operation has been cancelled by the user (while in delay step)!",
                                       code=Error.OperationCancelled)
                    finally:
                        signal.signal(signal.SIGINT, signal.SIG_IGN)
                else:
                    raise ValueError
        else:
            self._burst_countdown -= 1

        return ret


    def _do_before_sending_data(self, data_list):
        # Monitor hook function before sending
        self.mon.notify_imminent_data_sending()
        # Callbacks that triggers before sending a data are executed here
        data_list = self._handle_data_callbacks(data_list, hook=HOOK.before_sending_step1,
                                                resolve_dataprocess=True)
        # In this step2, we execute data callbacks, but in the case a DataProcess exists,
        # it will not be resolved if it has already been resolved in step1 (meaning DataProcess.outcomes
        # is not None).
        # It allows to make some modification to an already resolved DataProcess
        # (.outcomes modifications).
        # This hook is especially used in a Scenario() to implement the parameter
        # "do_before_sending" of Step()
        data_list = self._handle_data_callbacks(data_list, hook=HOOK.before_sending_step2,
                                                resolve_dataprocess=False)
        data_list = list(filter(lambda x: not x.is_blocked(), data_list))

        return data_list

    def _do_after_sending_data(self, data_list):
        self._handle_data_callbacks(data_list, hook=HOOK.after_sending)

    def _do_sending_and_logging_init(self, data_list):

        # If feedback_timeout = 0 then we don't consider residual feedback.
        # We try to avoid unnecessary latency in this case, as well as
        # to avoid retrieving some feedback that could be a trigger for sending the next data
        # (e.g., with a NetworkTarget in server_mode + wait_for_client)
        do_residual_fbk_gathering = True if self.tg.feedback_timeout is None else self.tg.feedback_timeout > 0

        for d in data_list:
            if d.feedback_timeout is not None:
                self.set_feedback_timeout(d.feedback_timeout)
            if d.feedback_mode is not None:
                self.set_feedback_mode(d.feedback_mode)

        blocked_data = list(filter(lambda x: x.is_blocked(), data_list))
        data_list = list(filter(lambda x: not x.is_blocked(), data_list))

        user_interrupt = False
        go_on = True
        if self._burst_countdown == self._burst and do_residual_fbk_gathering:
            # log residual just before sending new data to avoid
            # polluting feedback logs of the next emission
            if not blocked_data:
                fbk_timeout = self.tg.feedback_timeout
                # we change feedback timeout as the target could use it to determine if it is
                # ready to accept new data (check_target_readiness). For instance, the NetworkTarget
                # launch a thread when collect_feedback_without_sending() is called for a duration
                # of 'feedback_timeout'.
                self.set_feedback_timeout(0, do_show=False)

            # print('\nDBG: before collecting residual', self.tg._feedback_handled)
            if self.tg.collect_feedback_without_sending():
                # We have to make sure the target is ready for sending data after
                # collecting feedback.
                # print('\nDBG: collecting residual', self.tg._feedback_handled)
                ret = self.check_target_readiness()
                # print('\nDBG: target_ready', self.tg._feedback_handled)
                user_interrupt = ret == -2
            go_on = self.log_target_residual_feedback()
            # print('\nDBG: residual fbk logged')

            if not blocked_data:
                self.set_feedback_timeout(fbk_timeout, do_show=False)

            self.tg.cleanup()
            self.monitor_probes(prefix='Probe Status Before Sending Data')

        if blocked_data:
            self._handle_data_callbacks(blocked_data, hook=HOOK.after_fbk)

        if user_interrupt:
            raise UserInterruption
        elif go_on:
            return data_list
        else:
            raise TargetFeedbackError

    def _do_after_feedback_retrieval(self, data_list):
        self._handle_data_callbacks(data_list, hook=HOOK.after_fbk)

    def _do_after_dmaker_data_retrieval(self, data):
        self._handle_data_callbacks([data], hook=HOOK.after_dmaker_production)

    def _handle_data_desc(self, data_desc, resolve_dataprocess=True, original_data=None):

        if isinstance(data_desc, Data):
            data = data_desc
            data.generate_info_from_content(original_data=original_data)

        elif isinstance(data_desc, DataProcess):
            if isinstance(data_desc.seed, str):
                try:
                    seed_node = self.dm.get_data(data_desc.seed)
                except:
                    self.set_error(msg='Cannot create the seed from the '
                                       'name {:s}!'.format(data_desc.seed),
                                   code=Error.UserCodeError)
                    return None
                else:
                    seed = Data(seed_node)
                    seed.generate_info_from_content(original_data=original_data)

            elif data_desc.seed is not None and not isinstance(data_desc.seed, Data):
                self.set_error(msg='DataProcess object contains an unrecognized seed type!',
                                   code=Error.UserCodeError)
                return None
            else:
                seed = data_desc.seed
                seed.generate_info_from_content(original_data=original_data)

            if resolve_dataprocess or data_desc.outcomes is None:
                data = self.get_data(data_desc.process, data_orig=seed)
                if data is None and data_desc.auto_regen:
                    data_desc.auto_regen_cpt += 1
                if data is None:
                    other_process = data_desc.next_process()
                    if other_process or data_desc.auto_regen:
                        data = self.get_data(data_desc.process, data_orig=seed)
                        if data is None and data_desc.process_qty > 1:
                            for i in range(data_desc.process_qty-1):
                                data_desc.next_process()
                                data = self.get_data(data_desc.process, data_orig=seed)
                                if data is not None:
                                    break

                data_desc.outcomes = data
            else:
                data = data_desc.outcomes

            if data is None:
                self.set_error(msg='Data creation process has yielded!',
                               code=Error.DPHandOver)
                print('\n+++ DP yield', data_desc.auto_regen)
                return None

        elif isinstance(data_desc, str):
            try:
                node = self.dm.get_data(data_desc)
            except:
                self.set_error(msg='Cannot retrieved a data called {:s}!'.format(data_desc),
                               code=Error.UserCodeError)
                return None
            else:
                data = Data(node)
                data.generate_info_from_content(original_data=original_data)
        else:
            self.set_error(
                msg='Data descriptor type is not recognized {!s}!'.format(type(data_desc)),
                code=Error.UserCodeError)
            return None

        if original_data is not None:
            data.origin = original_data.origin

        return data

    def _handle_data_callbacks(self, data_list, hook, resolve_dataprocess=True):

        new_data_list = []
        for data in data_list:
            try:
                if hook == HOOK.after_fbk:
                    data.run_callbacks(feedback=self.feedback_handler, hook=hook)
                else:
                    data.run_callbacks(feedback=None, hook=hook)
            except:
                self._handle_user_code_exception("A Data callback (called at {!r}) has crashed! "
                                                 "(Data object internal ID: {:d})".format(hook, id(data)))
                new_data_list.append(data)
                continue

            new_data = data

            pending_ops = data.pending_callback_ops(hook=hook)
            if pending_ops:
                for op in pending_ops:

                    fbk_timeout = op[CallBackOps.Set_FbkTimeout]
                    if fbk_timeout is not None:
                        self.set_feedback_timeout(fbk_timeout)

                    data_desc = op[CallBackOps.Replace_Data]
                    if data_desc is not None:
                        new_data = []
                        first_step = True
                        for d_desc in data_desc:
                            data_tmp = self._handle_data_desc(d_desc,
                                                              resolve_dataprocess=resolve_dataprocess,
                                                              original_data=data)
                            if data_tmp is not None:
                                if first_step:
                                    first_step = False
                                    data_tmp.copy_callback_from(data)
                                new_data.append(data_tmp)
                            else:
                                newd = Data()
                                newd.make_unusable()
                                new_data = [newd]
                                break

                    for idx in op[CallBackOps.Del_PeriodicData]:
                        self._unregister_task(idx)

                    for idx, obj in op[CallBackOps.Add_PeriodicData].items():
                        data_desc, period = obj
                        if isinstance(data_desc, DataProcess):
                            # In this case each time we send the periodic we walk through the process
                            # (thus, sending a new data each time)
                            periodic_data = data_desc
                            func = self._send_periodic
                        else:
                            periodic_data = self._handle_data_desc(data_desc,
                                                                   resolve_dataprocess=resolve_dataprocess,
                                                                   original_data=data)
                            func = self.tg.send_data_sync

                        if periodic_data is not None:
                            task = FmkTask(idx, func, periodic_data, period=period,
                                           error_func=self._handle_user_code_exception,
                                           cleanup_func=functools.partial(self._unregister_task, idx))
                            self._register_task(idx, task)
                            if self.is_ok():
                                self.lg.log_fmk_info('A periodic data sending has been registered (Task ID #{!s})'.format(idx))
                        else:
                            self.set_error(msg='Data descriptor is incorrect!',
                                           code=Error.UserCodeError)

            if isinstance(new_data, list):
                for newd in new_data:
                    if not newd.is_unusable():
                        new_data_list.append(newd)
            elif not new_data.is_unusable():
                new_data_list.append(new_data)

        return new_data_list

    def _send_periodic(self, data_desc):
        data = self._handle_data_desc(data_desc)
        if data is not None:
            self.tg.send_data_sync(data)
        else:
            self.set_error(msg="Data descriptor handling returned 'None'!", code=Error.UserCodeError)
            raise DataProcessTermination

    def _unregister_task(self, id, ign_error=False):
        with self._task_list_lock:
            if id in self._task_list:
                self._task_list[id].stop()
                del self._task_list[id]
                self.lg.log_fmk_info('Removal of a periodic data sending '
                                     '(Task ID #{!s})'.format(id))
            elif not ign_error:
                self.set_error('ERROR: Task ID #{!s} does not exist. '
                               'Cannot unregister.'.format(id, code=Error.UserCodeError))

    def _register_task(self, id, task):
        with self._task_list_lock:
            if id not in self._task_list:
                self._task_list[id] = task
                task.start()
            else:
                self.set_error('WARNING: Task ID #{!s} already exists. '
                               'Task ignored.'.format(id, code=Error.UserCodeError))

    def _cleanup_tasks(self):
        for id in self._task_list:
            self._task_list[id].stop()
        self._task_list = {}

    @EnforceOrder(accepted_states=['S2'])
    def stop_all_tasks(self):
        self._cleanup_tasks()

    @EnforceOrder(accepted_states=['S2'])
    def send_data_and_log(self, data_list, original_data=None, verbose=False):

        orig_data_provided = original_data is not None

        if isinstance(data_list, Data):
            data_list = [data_list]
            if orig_data_provided:
                original_data = [original_data]
        elif isinstance(data_list, list):
            assert original_data is None or isinstance(original_data, (list, tuple))
        else:
            raise ValueError

        try:
            data_list = self._do_sending_and_logging_init(data_list)
        except (TargetFeedbackError, UserInterruption):
            return False

        if not data_list:
            return True

        data_list = self._send_data(data_list, add_preamble=True)
        if data_list is None:
            # In this case, some data callbacks have triggered to block the emission of
            # what was in data_list. We go on because this is a normal behavior (especially in the
            # context of Scenario() execution).
            return True

        if self._sending_error:
            return False

        # All feedback entries that are available for relevant framework users (scenario
        # callbacks, operators, ...) are flushed just after sending a new data because it
        # means the previous feedback entries are obsolete.
        self.fmkDB.flush_current_feedback()

        if len(data_list) > 1:
            # the provided data_list can be changed after having called self._send_data()
            multiple_data = True
        else:
            multiple_data = False

        if self._wkspace_enabled:
            for idx, dt in zip(range(len(data_list)), data_list):
                if orig_data_provided:
                    self.__current.append((original_data[idx], dt))
                else:
                    self.__current.append((None, dt))

        if orig_data_provided:
            for dt_orig in original_data:
                if dt_orig is not None:
                    dt_orig.make_recordable()

        for dt in data_list:
            dt.make_recordable()

        if multiple_data:
            self._log_data(data_list, original_data=original_data,
                           verbose=verbose)
        else:
            orig = original_data[0] if orig_data_provided else None
            self._log_data(data_list[0], original_data=orig, verbose=verbose)

        # When checking target readiness, feedback timeout is taken into account indirectly
        # through the call to Target.is_target_ready_for_new_data()
        cont0 = self.check_target_readiness() >= 0

        ack_date = self.tg.get_last_target_ack_date()
        self.lg.log_target_ack_date(ack_date)

        if cont0:
            cont0 = self.__delay_fuzzing()

        cont1 = True
        cont2 = True
        # That means this is the end of a burst
        if self._burst_countdown == self._burst:
            cont1 = self.log_target_feedback()

        self.mon.notify_target_feedback_retrieval()
        self.mon.wait_for_probe_status_retrieval()

        if self._burst_countdown == self._burst:
            # We handle probe feedback if any
            cont2 = self.monitor_probes(force_record=True)
            self.tg.cleanup()

        self._do_after_feedback_retrieval(data_list)

        return cont0 and cont1 and cont2


    @EnforceOrder(accepted_states=['S2'])
    def _send_data(self, data_list, add_preamble=False):
        '''
        @data_list: either a list of Data() or a Data()
        '''

        if self.__tg_enabled:

            if not self._is_data_valid(data_list):
                self.set_error("_send_data(): Data has been provided empty --> won't be sent",
                               code=Error.DataInvalid)
                self.mon.notify_error()
                return None

            data_list = self._do_before_sending_data(data_list)

            if not data_list:
                self.set_error("_send_data(): No more data to send",
                               code=Error.NoMoreData)
                self.mon.notify_error()
                return None

            if not self._is_data_valid(data_list):
                self.set_error("_send_data(): Data became empty --> won't be sent",
                               code=Error.DataInvalid)
                self.mon.notify_error()
                return None

            self._sending_error = False
            try:
                if len(data_list) == 1:
                    self.tg.send_data_sync(data_list[0], from_fmk=True)
                elif len(data_list) > 1:
                    self.tg.send_multiple_data_sync(data_list, from_fmk=True)
                else:
                    raise ValueError
            except TargetStuck as e:
                self.lg.log_target_feedback_from(
                    '*** WARNING: Unable to send data to the target! [reason: {!s}]'.format(e),
                    datetime.datetime.now(), status_code=-1, source='Fuddly FmK'
                )
                self.mon.notify_error()
                self._sending_error = True
            except:
                self._handle_user_code_exception()
                self.mon.notify_error()
                self._sending_error = True
            else:
                if add_preamble:
                    self.new_transfer_preamble()
                self.mon.notify_data_sending_event()

            self._do_after_sending_data(data_list)

        return data_list


    @EnforceOrder(accepted_states=['S2'])
    def _log_data(self, data_list, original_data=None, verbose=False):

        if self.__tg_enabled:

            if not self._is_data_valid(data_list):
                self.set_error('Data is empty and miss some needed meta-info --> will not be '
                               'logged',
                               code=Error.DataInvalid)
                return

            self.group_id += 1
            gen = self.__current_gen

            if original_data is None:
                orig_data_provided = False
            else:
                orig_data_provided = True

            if isinstance(data_list, Data):
                data_list = [data_list]
                if orig_data_provided:
                    original_data = [original_data]
                multiple_data = False
            elif isinstance(data_list, list):
                multiple_data = True
            else:
                raise ValueError

            if multiple_data:
                 self.lg.log_fmk_info("MULTIPLE DATA EMISSION", nl_after=True, delay_recording=True)

            for idx, dt in zip(range(len(data_list)), data_list):
                dt_mk_h = dt.get_history()
                if multiple_data:
                    self.lg.log_fmk_info("Data #%d" % (idx+1), nl_before=True, delay_recording=True)
                    self.lg.log_fn("--------------------------", rgb=Color.SUBINFO)

                gen_info = dt.get_initial_dmaker()
                gen_type_initial, gen_name, gen_ui = gen_info if gen_info is not None else (None, None, None)

                data_id = dt.get_data_id()
                # if data_id is not None, the data has been created from fmkDB
                # because new data have not a data_id yet at this point in the code.
                # if data_id is not None:
                if dt.from_fmkdb:
                    num = 1
                    self.lg.log_dmaker_step(num)
                    self.lg.log_generator_info(gen_type_initial, gen_name, None, data_id=data_id)
                    self.lg.log_data_info(("Data fetched from FMKDB",), gen_type_initial, gen_name)
                else:
                    num = 0

                if dt_mk_h is not None:
                    if orig_data_provided:
                        self.lg.log_orig_data(original_data[idx])
                    else:
                        self.lg.log_orig_data(None)

                    for dmaker_type, data_maker_name, user_input in dt_mk_h:
                        num += 1

                        if num == 1 and data_id is None:
                            # if data_id is not None then no need to log an initial generator
                            # because data comes from FMKDB and it has been dealt previously
                            if dmaker_type != gen_type_initial:
                                self.lg.log_generator_info(gen_type_initial, gen_name, gen_ui, disabled=True)

                        self.lg.log_dmaker_step(num)

                        if dmaker_type in gen:
                            dmaker_obj = self._generic_tactics.get_generator_obj(dmaker_type, data_maker_name)
                            if dmaker_obj is None:
                                dmaker_obj = self._tactics.get_generator_obj(dmaker_type, data_maker_name)
                            if dmaker_obj in self.__initialized_dmakers and self.__initialized_dmakers[dmaker_obj][0]:
                                ui = self.__initialized_dmakers[dmaker_obj][1]
                            else:
                                ui = user_input

                            self.lg.log_generator_info(dmaker_type, data_maker_name, ui)

                        else:
                            dmaker_obj = self._generic_tactics.get_disruptor_obj(dmaker_type, data_maker_name)
                            if dmaker_obj is None:
                                dmaker_obj = self._tactics.get_disruptor_obj(dmaker_type, data_maker_name)
                            if dmaker_obj in self.__initialized_dmakers and self.__initialized_dmakers[dmaker_obj][0]:
                                ui = self.__initialized_dmakers[dmaker_obj][1]
                            else:
                                ui = user_input

                            self.lg.log_disruptor_info(dmaker_type, data_maker_name, ui)

                        for info in dt.read_info(dmaker_type, data_maker_name):
                            self.lg.log_data_info(info, dmaker_type, data_maker_name)

                else:
                    if gen_type_initial is None:
                        self.lg.log_dmaker_step(1)
                        self.lg.log_generator_info(Database.DEFAULT_GTYPE_NAME,
                                                   Database.DEFAULT_GEN_NAME,
                                                   None)
                        self.lg.log_data_info(("RAW DATA (data makers not provided)",),
                                              Database.DEFAULT_GTYPE_NAME, Database.DEFAULT_GEN_NAME)
                    # else:
                    #     self.lg.log_initial_generator(gen_type_initial, gen_name, gen_ui)

                self.lg.log_data(dt, verbose=verbose)


                if self.fmkDB.enabled:
                    data_id = self.lg.commit_log_entry(self.group_id, self.prj.name, self.tg_name)
                    if data_id is None:
                        self.lg.print_console('### Data not recorded in FmkDB',
                                              rgb=Color.DATAINFO, nl_after=True)
                    else:
                        self.lg.print_console('### FmkDB Data ID: {!r}'.format(data_id),
                                              rgb=Color.DATAINFO, nl_after=True)

                if multiple_data:
                    self.lg.log_fn("--------------------------", rgb=Color.SUBINFO)


    @EnforceOrder(accepted_states=['S2'])
    def new_transfer_preamble(self):
        if self._burst > 1 and self._burst_countdown == self._burst:
            p = "\n::[ START BURST ]::\n"
        else:
            p = "\n"
        self.lg.start_new_log_entry(preamble=p)

    @EnforceOrder(accepted_states=['S2'])
    def log_target_feedback(self):
        err_detected1, err_detected2 = False, False
        if self.__tg_enabled:
            if self._burst > 1:
                p = "::[ END BURST ]::\n"
            else:
                p = None
            try:
                err_detected1 = self.lg.log_collected_target_feedback(preamble=p)
            except NotImplementedError:
                pass
            finally:
                err_detected2 = self._log_directly_retrieved_target_feedback(preamble=p)

        go_on = self._recover_target() if err_detected1 or err_detected2 else True

        return go_on

    @EnforceOrder(accepted_states=['S2'])
    def log_target_residual_feedback(self):
        err_detected1, err_detected2 = False, False
        if self.__tg_enabled:
            p = "*** RESIDUAL TARGET FEEDBACK ***"
            e = "********************************"
            try:
                err_detected1 = self.lg.log_collected_target_feedback(preamble=p, epilogue=e)
            except NotImplementedError:
                pass
            finally:
                err_detected2 = self._log_directly_retrieved_target_feedback(preamble=p, epilogue=e)

        go_on = self._recover_target() if err_detected1 or err_detected2 else True

        return go_on

    def _log_directly_retrieved_target_feedback(self, preamble=None, epilogue=None):
        """
        This method is to be used when the target does not make use
        of Logger.collect_target_feedback() facility. We thus try to
        access the feedback from Target directly
        """
        err_detected = False
        tg_fbk = self.tg.get_feedback()
        if tg_fbk is not None:
            err_code = tg_fbk.get_error_code()
            if err_code is not None and err_code < 0:
                err_detected = True

            if tg_fbk.has_fbk_collector():
                for ref, fbk, status, tstamp in tg_fbk.iter_and_cleanup_collector():
                    if status < 0:
                        err_detected = True
                    self.lg.log_target_feedback_from(fbk, tstamp, preamble=preamble,
                                                     epilogue=epilogue,
                                                     source=ref, status_code=status)

            raw_fbk = tg_fbk.get_bytes()
            if raw_fbk is not None:
                self.lg.log_target_feedback_from(raw_fbk,
                                                 tg_fbk.get_timestamp(),
                                                 status_code=err_code,
                                                 preamble=preamble,
                                                 epilogue=epilogue)

            tg_fbk.cleanup()

        return err_detected

    @EnforceOrder(accepted_states=['S2'])
    def check_target_readiness(self):

        if self.__tg_enabled:
            t0 = datetime.datetime.now()

            # Wait until the target is ready or timeout expired
            try:
                signal.signal(signal.SIGINT, sig_int_handler)
                ret = 0
                while not self.tg.is_target_ready_for_new_data():
                    time.sleep(0.01)
                    now = datetime.datetime.now()
                    if (now - t0).total_seconds() > self._hc_timeout:
                        print('\n***DBG: FBK timeout')
                        self.lg.log_target_feedback_from(
                            '*** Timeout! The target does not seem to be ready.',
                            now, status_code=-1, source='Fuddly FmK'
                        )
                        ret = -1
                        self.tg.cleanup()
                        break
            except KeyboardInterrupt:
                self.lg.log_comment("*** Waiting for target to become ready has been cancelled by the user!\n")
                self.set_error("Waiting for target to become ready has been cancelled by the user!",
                               code=Error.OperationCancelled)
                ret = -2
                self.tg.cleanup()
            except:
                self._handle_user_code_exception()
                ret = -3
                self.tg.cleanup()
            finally:
                signal.signal(signal.SIGINT, signal.SIG_IGN)

            return ret

        else:
            return 0

    @EnforceOrder(accepted_states=['S2'])
    def show_data(self, data, verbose=True):
        if not data.node:
            return

        self.lg.print_console('-=[ Data Paths ]=-\n', rgb=Color.INFO, style=FontStyle.BOLD)
        data.node.show(raw_limit=400)
        self.lg.print_console('\n\n', nl_before=False)

    @EnforceOrder(accepted_states=['S2'])
    def show_scenario(self, sc_name, fmt='pdf'):
        generators_gen = self._generic_tactics.generator_types
        generators_spe = self._tactics.generator_types
        err_msg = "The scenario '{!s}' does not exist!".format(sc_name)

        if generators_gen and sc_name in generators_gen:
            generators_list = self._generic_tactics.get_generators_list(sc_name)
            tactics = self._generic_tactics
        elif generators_spe and sc_name in generators_spe:
            generators_list = self._tactics.get_generators_list(sc_name)
            tactics = self._tactics
        else:
            self.set_error(err_msg, code=Error.FmkWarning)
            return False

        if generators_list:
            cls_name = list(generators_list.keys())[0]
            sc_obj = tactics.get_generator_obj(sc_name, cls_name)
            if sc_obj and isinstance(sc_obj, DynGeneratorFromScenario):
                sc_obj.graph_scenario(fmt=fmt)
            else:
                self.set_error(err_msg, code=Error.FmkWarning)
        else:
            self.set_error(err_msg, code=Error.FmkWarning)

    @EnforceOrder(accepted_states=['S2'])
    def show_dm_data_identifiers(self):

        self.lg.print_console('-=[ Data IDs of the current data model ]=-', nl_after=True, rgb=Color.INFO, style=FontStyle.BOLD)
        for k in self.dm.data_identifiers():
            self.lg.print_console(k, rgb=Color.SUBINFO)
        self.lg.print_console('\n\n', nl_before=False)


    @EnforceOrder(accepted_states=['S2'])
    def log_comment(self, comments):
        self.lg.log_comment(comments)

    @EnforceOrder(accepted_states=['S2'])
    def __register_in_data_bank(self, data_orig, data):
        self.__db_idx += 1
        self.__data_bank[self.__db_idx] = (data_orig, data)

    @EnforceOrder(accepted_states=['S2'])
    def fmkdb_fetch_data(self, start_id=1, end_id=-1):
        for record in self.fmkDB.fetch_data(start_id=start_id, end_id=end_id):
            data_id, content, dtype, dmk_name, dm_name = record
            data = Data(content)
            data.set_data_id(data_id)
            data.set_initial_dmaker((str(dtype), str(dmk_name), None))
            data.from_fmkdb = True
            if dm_name != Database.DEFAULT_DM_NAME:
                dm = self.get_data_model_by_name(dm_name)
                data.set_data_model(dm)
            self.__register_in_data_bank(None, data)

    @EnforceOrder(accepted_states=['S2'])
    def enable_fmkdb(self):
        self.fmkDB.enable()
        self.lg.log_fmk_info('Enable FmkDB', do_record=False)

    @EnforceOrder(accepted_states=['S2'])
    def disable_fmkdb(self):
        self.fmkDB.disable()
        self.lg.log_fmk_info('Disable FmkDB', do_record=False)

    @EnforceOrder(accepted_states=['S2'])
    def get_last_data(self):
        if not self._wkspace_enabled:
            self.set_error('Workspace is disabled!',
                           code=Error.CommandError)
            return None, None

        if self.__current:
            entry = self.__current[-1]
            return entry
        else:
            return None, None

    @EnforceOrder(accepted_states=['S2'])
    def get_from_data_bank(self, i):
        try:
            entry = self.__data_bank[i]
        except KeyError:
            return None, None

        return entry

    @EnforceOrder(accepted_states=['S2'])
    def iter_data_bank(self):
        for i in self.__data_bank:
            entry = self.__data_bank[i]
            yield entry

    def __iter_data_bank(self):
        for i in self.__data_bank:
            entry = self.__data_bank[i]
            yield entry

    def __show_entry(self, data_orig, data):
        if data_orig != None:
            self.lg.print_console('|_ IN  < ', rgb=Color.SUBINFO)
            self.lg.print_console(data_orig, nl_before=False)
        else:
            self.lg.print_console('|_ !IN', rgb=Color.SUBINFO)

        gen = self.__current_gen

        data_id  = data.get_data_id()
        data_makers_history = data.get_history()
        if data_makers_history:
            first_pass = True
            for dmaker_type, data_maker_name, user_input in data_makers_history:
                if first_pass:
                    first_pass = False
                    gen_info = data.get_initial_dmaker()
                    gen_type_initial, gen_name, gen_ui = (None, None, None) if gen_info is None else gen_info
                    if gen_type_initial is None:
                        msg = "|- data id: %r | no generator (seed was used)"
                    elif gen_ui:
                        msg = "|- data id: %r | generator type: %s | generator name: %s | User input: %s" % \
                            (data_id, gen_type_initial, gen_name, gen_ui)
                    else:
                        msg = "|- data id: %r | generator type: %s | generator name: %s | No user input" % \
                            (data_id, gen_type_initial, gen_name)
                    self.lg.print_console(msg, rgb=Color.SUBINFO)

                if dmaker_type not in gen:
                    if user_input:
                        msg = "|- disruptor type: %s | data_maker name: %s | User input: %s" % \
                            (dmaker_type, data_maker_name, user_input)
                    else:
                        msg = "|- disruptor type: %s | data_maker name: %s | No user input" % \
                            (dmaker_type, data_maker_name)
                    self.lg.print_console(msg, rgb=Color.SUBINFO)

                    self.lg.print_console("|- data info:", rgb=Color.SUBINFO)

                    for data_info in data.read_info(dmaker_type, data_maker_name):
                        for msg in data_info:
                            self.lg.print_console('   |_ ' + msg, rgb=Color.SUBINFO)
        else:
            init_dmaker = data.get_initial_dmaker()
            if init_dmaker is None:
                dtype, dmk_name = Database.DEFAULT_GTYPE_NAME, Database.DEFAULT_GEN_NAME
            else:
                dtype, dmk_name, _ = init_dmaker
            dm = data.get_data_model()
            dm_name = None if dm is None else dm.name
            msg = "|- data id: {!r} | type: {:s} | data model: {!s}".format(
                data_id, dtype, dm_name
            )
            self.lg.print_console(msg, rgb=Color.SUBINFO)

        self.lg.print_console('|_ OUT > ', rgb=Color.SUBINFO)
        self.lg.print_console(data, nl_before=False)
        self.lg.print_console('='*80+'\n', rgb=Color.INFO)


    @EnforceOrder(accepted_states=['S2'])
    def show_data_bank(self):
        self.lg.print_console("-=[ Data Bank ]=-\n", rgb=Color.INFO, style=FontStyle.BOLD)

        for idx, entry in self.__data_bank.items():
            msg = '===[ {:d} ]==='.format(idx)
            msg += '='*(max(80-len(msg),0))
            self.lg.print_console(msg, rgb=Color.INFO)
            self.__show_entry(*entry)

        self.lg.print_console('\n', nl_before=False)

    @EnforceOrder(accepted_states=['S2'])
    def show_wkspace(self):
        if not self._wkspace_enabled:
            self.set_error('Workspace is disabled!',
                           code=Error.CommandError)
            return

        self.lg.print_console("-=[ Workspace ]=-\n", rgb=Color.INFO, style=FontStyle.BOLD)

        for data_orig, data in self.__current:
            self.__show_entry(data_orig, data)

        self.lg.print_console('\n', nl_before=False)

    @EnforceOrder(accepted_states=['S2'])
    def dump_db_to_file(self, f):
        if f:
            try:
                pickle.dump(self.__data_bank, f)
            except (pickle.PicklingError, TypeError):
                print("*** ERROR: Can't pickle the data bank!")
                print('-'*60)
                traceback.print_exc(file=sys.stdout)
                print('-'*60)

    @EnforceOrder(accepted_states=['S2'])
    def load_db_from_file(self, f):
        if f:
            self.__data_bank = pickle.load(f)
            self.__idx = len(self.__data_bank)

    @EnforceOrder(accepted_states=['S2'])
    def load_db_from_text_file(self, f):
        if f:
            text = f.read()

            self.__data_bank = {}
            self.__idx = 0

            while True:
                obj = self.import_text_reg.match(text)
                if obj is None:
                    break

                data = Data(obj.group(1)[:-1])

                self.__register_in_data_bank(None, data)
                text = text[len(obj.group(0))+1:]
                
    @EnforceOrder(accepted_states=['S2'])
    def empty_data_bank(self):
        self.__data_bank = {}
        self.__db_idx = 0

    @EnforceOrder(accepted_states=['S2'])
    def empty_workspace(self):
        if not self._wkspace_enabled:
            self.set_error('Workspace is disabled!', code=Error.CommandError)
            return

        self.__current = []

    @EnforceOrder(accepted_states=['S2'])
    def register_current_in_data_bank(self):
        if not self._wkspace_enabled:
            self.set_error('Workspace is disabled!', code=Error.CommandError)
            return

        if self.__current:
            for data_orig, data in self.__current:
                self.__register_in_data_bank(data_orig, data)

    @EnforceOrder(accepted_states=['S2'])
    def register_last_in_data_bank(self):
        if not self._wkspace_enabled:
            self.set_error('Workspace is disabled!', code=Error.CommandError)
            return

        if self.__current:
            data_orig, data = self.__current[-1]
            self.__register_in_data_bank(data_orig, data)

    @EnforceOrder(accepted_states=['S2'])
    def show_operators(self):
        operators = self.prj.get_operators()
        self.lg.print_console('-=[ Operators ]=-', rgb=Color.INFO, style=FontStyle.BOLD)
        self.lg.print_console('')
        for o in operators:
            self.lg.print_console(o, rgb=Color.SUBINFO)
            desc = self.__dmaker_desc_str(self.prj.get_operator(o))
            self.lg.print_console(desc, limit_output=False)

        self.lg.print_console('\n\n', nl_before=False)


    @EnforceOrder(accepted_states=['S2'])
    def launch_operator(self, name, user_input=UserInputContainer(), use_existing_seed=True, verbose=False):
        
        operator = self.prj.get_operator(name)
        if operator is None:
            self.set_error('Invalid operator', code=Error.InvalidOp)
            return False

        self.__reset_fmk_internals(reset_existing_seed=(not use_existing_seed))

        try:
            ok = operator._start(self._exportable_fmk_ops, self.dm, self.mon, self.tg, self.lg, user_input)
        except:
            self._handle_user_code_exception('Operator has crashed during its start() method')
            return False
        finally:
            self.mon.wait_for_probe_initialization() # operator.start() can start probes.

        if not ok:
            self.set_error("The _start() method of Operator '%s' has returned an error!" % name,
                           code=Error.UnrecoverableError)
            return False

        fmk_feedback = FmkFeedback()

        exit_operator = False
        while not exit_operator:

            try:
                operation = operator.plan_next_operation(self._exportable_fmk_ops, self.dm,
                                                         self.mon, self.tg, self.lg, fmk_feedback)
            except:
                self._handle_user_code_exception('Operator has crashed during its plan_next_operation() method')
                return False

            if operation is None:
                self.set_error("An operator shall always return an Operation() object in its plan_next_operation()",
                               code=Error.UserCodeError)
                return False

            if operation.is_flag_set(Operation.CleanupDMakers):
                self.cleanup_all_dmakers(reset_existing_seed=False)

            if operation.is_flag_set(Operation.Stop):
                self.log_target_feedback()
                break
            else:
                retry = False
                data_list = []
                change_list = []

                instr_list = operation.get_instructions()
                for idx, instruction in enumerate(instr_list):
                    action_list, orig = instruction

                    if action_list is None:
                        data = orig
                    else:
                        data = self.get_data(action_list, data_orig=orig,
                                             save_seed=use_existing_seed)

                    data_list.append(data)

                    if self.is_not_ok():
                        if fmk_feedback.is_flag_set(FmkFeedback.NeedChange):
                            self.set_error('Operator has not made a choice that allows to produce usable data',
                                           code=Error.WrongOpPlan)
                            return False
                        else:
                            err_list = self.get_error()
                            for e in err_list:
                                self.lg.log_fmk_info(e.msg)
                                if e.code in [Error.DataUnusable, Error.HandOver]:
                                    if e.code == Error.DataUnusable:
                                        change_list.append((e.context, idx))
                                    retry = True
                                else:
                                    self.set_error('Unrecoverable error in get_data() method!',
                                                   code=Error.UnrecoverableError)
                                    return False

                if retry:
                    fmk_feedback.set_flag(FmkFeedback.NeedChange, context=change_list)
                    continue

                fmk_feedback.clear_produced_data()
                for d in data_list:
                    fmk_feedback.add_produced_data(d)

                fmk_feedback.clear_flag(FmkFeedback.NeedChange)

                try:
                    data_list = self._do_sending_and_logging_init(data_list)
                except TargetFeedbackError:
                    self.lg.log_fmk_info("Operator will shutdown because residual target "
                                         "feedback indicate a negative status code")
                    break

                if not data_list:
                    continue

                data_list = self._send_data(data_list, add_preamble=True)
                if self._sending_error:
                    self.lg.log_fmk_info("Operator will shutdown because of a sending error")
                    break
                elif data_list is None:
                    self.lg.log_fmk_info("Operator will shutdown because there is no data to send")
                    break

                # All feedback entries that are available for relevant framework users (scenario
                # callbacks, operators, ...) are flushed just after sending a new data because it
                # means the previous feedback entries are obsolete.
                self.fmkDB.flush_current_feedback()

                multiple_data = len(data_list) > 1

                try:
                    linst = operator.do_after_all(self._exportable_fmk_ops, self.dm, self.mon, self.tg, self.lg)
                except:
                    self._handle_user_code_exception('Operator has crashed during its .do_after_all() method')
                    return False

                if linst.is_instruction_set(LastInstruction.RecordData):
                    for dt in data_list:
                        dt.make_recordable()
                        self.__register_in_data_bank(None, dt)

                if multiple_data:
                    self._log_data(data_list, verbose=verbose)
                else:
                    self._log_data(data_list[0], verbose=verbose)

                ret = self.check_target_readiness()
                # Note: the condition (ret = -1) is supposed to be managed by the operator
                if ret < -1:
                    exit_operator = True
                    if ret == -2:
                        self.lg.log_fmk_info("Operator will shutdown because waiting has been cancelled by the user")
                    elif ret == -3:
                        self.lg.log_fmk_info("Operator will shutdown because of exception in user code")

                ack_date = self.tg.get_last_target_ack_date()
                self.lg.log_target_ack_date(ack_date)

                # Delay introduced after logging data
                if not self.__delay_fuzzing():
                    exit_operator = True
                    self.lg.log_fmk_info("Operator will shutdown because waiting has been cancelled by the user")


                # Target fbk is logged only at the end of a burst
                if self._burst_countdown == self._burst:
                    cont1 = self.log_target_feedback()

                self.mon.notify_target_feedback_retrieval()
                self.mon.wait_for_probe_status_retrieval()

                if self._burst_countdown == self._burst:
                    cont2 = self.monitor_probes(force_record=True)
                    if not cont1 or not cont2:
                        exit_operator = True
                        self.lg.log_fmk_info("Operator will shutdown because something is going wrong with "
                                             "the target and the recovering procedure did not succeed...")

                self._do_after_feedback_retrieval(data_list)

                op_feedback = linst.get_operator_feedback()
                op_status = linst.get_operator_status()
                op_tstamp = linst.get_timestamp()
                if op_feedback or op_status:
                    self.lg.log_operator_feedback(op_feedback, op_tstamp,
                                                  op_name=operator.__class__.__name__,
                                                  status_code=op_status)

                comments = linst.get_comments()
                if comments:
                    self.lg.log_comment(comments)

                if op_status is not None and op_status < 0:
                    exit_operator = True
                    self.lg.log_fmk_info("Operator will shutdown because it returns a negative status")
                    self._recover_target()

                if self._burst_countdown == self._burst:
                    self.tg.cleanup()
        try:
            operator.stop(self._exportable_fmk_ops, self.dm, self.mon, self.tg, self.lg)
        except:
            self._handle_user_code_exception('Operator has crashed during its stop() method')
            return False

        self.__reset_fmk_internals(reset_existing_seed=(not use_existing_seed))

        return True

    @EnforceOrder(accepted_states=['S2'])
    def get_data(self, action_list, data_orig=None, valid_gen=False, save_seed=False):
        '''
        @action_list shall have the following formats:
        [(action_1, generic_UI_1, specific_UI_1), ...,
         (action_n, generic_UI_n, specific_UI_n)]

        [action_1, (action_2, generic_UI_2, specific_UI_2), ... action_n]

        where action_N can be either: dmaker_type_N or (dmaker_type_N, dmaker_name_N)
        '''

        l = []
        action_list = action_list[:]

        first = True
        last = False
        dmaker_switch_performed = False

        get_dmaker_obj = self._tactics.get_generator_obj
        get_random_dmaker_obj = self._tactics.get_random_generator
        get_generic_dmaker_obj = self._generic_tactics.get_generator_obj
        get_random_generic_dmaker_obj = self._generic_tactics.get_random_generator

        get_dmaker_name = self._tactics.get_generator_name
        get_generic_dmaker_name = self._generic_tactics.get_generator_name

        specific_dmaker_types = self._tactics.generator_types
        generic_dmaker_types = self._generic_tactics.generator_types
        clone_dmaker = self._tactics.clone_generator
        clone_gen_dmaker = self._generic_tactics.clone_generator

        if data_orig != None:
            data = copy.copy(data_orig)
            initial_generator_info = data_orig.get_initial_dmaker()
            # print('\n***')
            # print(data_orig.get_history(), data_orig.info_list, data_orig.info)
            data.generate_info_from_content(original_data=data_orig)
            history = data.get_history()
            # print(history, data_orig.info_list, data_orig.info)
            if history:
                for h_entry in history:
                    l.append(h_entry)
            first = False
        else:
            # needed because disruptors can take over the data generation
            data = Data()
            initial_generator_info = None

        current_dmobj_list = []
        shortcut_history = []
        unrecoverable_error = False
        activate_all = False

        for full_action, idx in zip(action_list, range(len(action_list))):

            if isinstance(full_action, (tuple, list)):
                if len(full_action) == 2:
                    action, gen_args = full_action
                    user_input = UserInputContainer(generic=gen_args, specific=None)
                elif len(full_action) == 3:
                    action, gen_args, args = full_action
                    user_input = UserInputContainer(generic=gen_args, specific=args)
                else:
                    print(full_action)
                    raise ValueError
            else:
                action = full_action
                user_input = UserInputContainer(generic=None, specific=None)

            if unrecoverable_error:
                break

            if idx == len(action_list) - 1:
                last = True

            generic = False

            if not first and not dmaker_switch_performed:
                dmaker_switch_performed = True
                get_dmaker_obj = self._tactics.get_disruptor_obj
                get_random_dmaker_obj = self._tactics.get_random_disruptor
                get_generic_dmaker_obj = self._generic_tactics.get_disruptor_obj
                get_random_generic_dmaker_obj = self._generic_tactics.get_random_disruptor
                get_dmaker_name = self._tactics.get_disruptor_name
                get_generic_dmaker_name = self._generic_tactics.get_disruptor_name
                specific_dmaker_types = self._tactics.disruptor_types
                generic_dmaker_types = self._generic_tactics.disruptor_types
                clone_dmaker = self._tactics.clone_disruptor
                clone_gen_dmaker = self._generic_tactics.clone_disruptor

            if isinstance(action, (tuple, list)):
                dmaker_type = action[0]
                provided_dmaker_name = action[1]
                dmaker_ref = 'type: ' + dmaker_type + ', name: ' + provided_dmaker_name
            else:
                dmaker_type = action
                provided_dmaker_name = None
                dmaker_ref = dmaker_type

            # Handle cloned data makers or data makers to be cloned
            if dmaker_type not in specific_dmaker_types and dmaker_type not in generic_dmaker_types:
                parsed = self.check_clone_re.match(dmaker_type)
                if parsed is not None:
                    cloned_dmaker_type = parsed.group(1)
                    dmaker_type = parsed.group(0)

                    err_msg = "Can't clone: invalid generator/disruptor IDs (%s)" % dmaker_ref

                    if cloned_dmaker_type in specific_dmaker_types:
                        ok, cloned_dmaker_name = clone_dmaker(cloned_dmaker_type, new_dmaker_type=dmaker_type, dmaker_name=provided_dmaker_name)
                        self._recompute_current_generators()
                        dmaker_obj = get_dmaker_obj(dmaker_type, cloned_dmaker_name)
                    elif cloned_dmaker_type in generic_dmaker_types:
                        ok, cloned_dmaker_name = clone_gen_dmaker(cloned_dmaker_type, new_dmaker_type=dmaker_type, dmaker_name=provided_dmaker_name)
                        self._recompute_current_generators()
                        dmaker_obj = get_generic_dmaker_obj(dmaker_type, cloned_dmaker_name)
                    else:
                        self.set_error(err_msg, code=Error.CloneError)
                        return None

                    assert(dmaker_obj is not None)
                    is_gen = issubclass(dmaker_obj.__class__, Generator)
                    stateful = is_gen or issubclass(dmaker_obj.__class__, StatefulDisruptor)

                    if not ok:
                        self.set_error(err_msg, code=Error.CloneError)
                        return None

                    self.fmkDB.insert_dmaker(self.dm.name, dmaker_type, cloned_dmaker_name, is_gen,
                                             stateful, clone_type=cloned_dmaker_type)


            if provided_dmaker_name is None:
                dmaker_obj = get_random_dmaker_obj(dmaker_type, valid_gen)
            else:
                dmaker_obj = get_dmaker_obj(dmaker_type, provided_dmaker_name)
            if dmaker_obj is None:
                generic = True
                if provided_dmaker_name is None:
                    dmaker_obj = get_random_generic_dmaker_obj(dmaker_type, valid_gen)
                else:
                    dmaker_obj = get_generic_dmaker_obj(dmaker_type, provided_dmaker_name)
                if dmaker_obj is None:
                    self.set_error("Invalid generator/disruptor (%s)" % dmaker_ref,
                                   code=Error.InvalidDmaker)
                    return None

            get_name = get_generic_dmaker_name if generic else get_dmaker_name
            dmaker_name = get_name(dmaker_type, dmaker_obj)

            if first:
                if dmaker_obj in self.__initialized_dmakers and self.__initialized_dmakers[dmaker_obj][0]:
                    ui = self.__initialized_dmakers[dmaker_obj][1]
                else:
                    ui = user_input
                initial_generator_info = [dmaker_type, dmaker_name, ui]

            # Make sure that if a Generator is active (i.e., it has
            # not been disabled by a 'controller' disruptor), all
            # disruptors that follows are active. Moreover if it is a
            # controller disruptor, it has to be reset, to handle the
            # new generated data.
            if activate_all:
                dmaker_obj.set_attr(DataMakerAttr.Active)
                if dmaker_obj.is_attr_set(DataMakerAttr.Controller):
                    try:
                        dmaker_obj._cleanup()
                    except Exception:
                        unrecoverable_error = True
                        self._handle_user_code_exception("The cleanup() method of Data Maker '%s' has crashed!" % dmaker_ref)
                        return None
                    self.__initialized_dmakers[dmaker_obj] = (False, None)

            if isinstance(dmaker_obj, Generator) and dmaker_obj.is_attr_set(DataMakerAttr.Active):
                activate_all = True

            current_dmobj_list.append(dmaker_obj)

            if not dmaker_obj.is_attr_set(DataMakerAttr.Active):
                shortcut_history.append("Data maker [#{:d}] of type '{:s}' (name: {:s}) has been disabled " \
                                        "by this disruptor taking over it.".format(idx+1, dmaker_type, dmaker_name))
                first = False
                continue


            if dmaker_obj.is_attr_set(DataMakerAttr.Controller) and not dmaker_obj.is_attr_set(DataMakerAttr.HandOver):
                for dmobj in current_dmobj_list[:-1]:
                    # if a disruptor is used at least twice in the action list
                    # we should avoid disabling it
                    if dmobj is not dmaker_obj:
                        dmobj.clear_attr(DataMakerAttr.Active)
                    else:
                        # this case is certainly not a thing the user want so alert him
                        msg = ("A disruptor taking over the data generation is at least present twice! " \
                                   "The resulting behaviour is certainly not what you want, because it will execute twice the " \
                                   "disrupt_data() method on this disruptor with the same inputs (user + data). You should avoid " \
                                   "this situation by cloning first the disruptor you want to use twice.")
                        self.set_error(msg, code=Error.CommandError)
                        for dmobj in current_dmobj_list[:-1]:
                            self.cleanup_dmaker(dmaker_obj=dmobj)
                        return None

            setup_crashed = False
            setup_err = False

            try:
                if dmaker_obj not in self.__initialized_dmakers:
                    self.__initialized_dmakers[dmaker_obj] = (False, None)

                if not self.__initialized_dmakers[dmaker_obj][0]:
                    initialized = dmaker_obj._setup(self.dm, user_input)
                    if not initialized:
                        setup_err = True
                        unrecoverable_error = True
                        self.set_error("The _setup() method of Data Maker '%s' has returned an error!" % dmaker_ref,
                                       code=Error.UnrecoverableError)

                    self.__initialized_dmakers[dmaker_obj] = (True, user_input)

            except Exception:
                setup_crashed = True
                unrecoverable_error = True
                self._handle_user_code_exception("The _setup() method of Data Maker '%s' has crashed!" % dmaker_ref)


            if not setup_crashed and not setup_err:
                try:
                    invalid_data = False
                    if isinstance(dmaker_obj, Generator):
                        if dmaker_obj.produced_seed is not None:
                            data = Data(dmaker_obj.produced_seed.get_contents(do_copy=True))
                        else:
                            data = dmaker_obj.generate_data(self.dm, self.mon,
                                                            self.tg)
                            if save_seed and dmaker_obj.produced_seed is None:
                                # Usefull to replay from the beginning a modelwalking sequence
                                data.materialize()
                                dmaker_obj.produced_seed = Data(data.get_contents(do_copy=True))
                        invalid_data = not self._is_data_valid(data)
                    elif isinstance(dmaker_obj, Disruptor):
                        if not self._is_data_valid(data):
                            invalid_data = True
                        else:
                            data = dmaker_obj.disrupt_data(self.dm, self.tg, data)
                    elif isinstance(dmaker_obj, StatefulDisruptor):
                        # we only check validity in the case the stateful disruptor is
                        # has not been seeded
                        if dmaker_obj.is_attr_set(DataMakerAttr.NeedSeed) and not \
                                self._is_data_valid(data):
                            invalid_data = True
                        else:
                            ret = dmaker_obj._set_seed(data)
                            if isinstance(ret, Data):
                                data = ret
                                dmaker_obj.set_attr(DataMakerAttr.NeedSeed)
                            else:
                                data = dmaker_obj.disrupt_data(self.dm, self.tg, data)
                    else:
                        raise ValueError

                    self._do_after_dmaker_data_retrieval(data)

                    if invalid_data:
                        unrecoverable_error = True
                        self.set_error("The data maker ({:s}) returned an empty data (probable "
                                       "reason: the left-side data maker is disabled and need"
                                       "to be reset)".format(dmaker_ref),
                                       code=Error.DataInvalid,
                                       context={'dmaker_name': dmaker_name, 'dmaker_type': dmaker_type})

                    elif data is None:
                        unrecoverable_error = True
                        self.set_error("A Data maker shall never return None! (guilty: '%s')" % dmaker_ref,
                                       code=Error.UserCodeError)

                    elif data.is_unusable():
                        unrecoverable_error = True
                        self.set_error("The data maker ({:s}) has returned unusable data.".format(dmaker_ref),
                                       code=Error.DataUnusable,
                                       context={'dmaker_name': dmaker_name, 'dmaker_type': dmaker_type})

                except Exception:
                    unrecoverable_error = True
                    self._handle_user_code_exception("The generate_data()/disrupt_data()/set_seed() " \
                                                     "method of Data Maker '%s' has crashed!" % dmaker_ref)


                # If a generator need a reset or a ('controller') disruptor has yielded
                if dmaker_obj.is_attr_set(DataMakerAttr.SetupRequired):
                    assert(dmaker_obj in self.__initialized_dmakers)
                    self.__initialized_dmakers[dmaker_obj] = (False, None)
                

                def _handle_disruptors_handover(dmlist):
                    # dmlist[-1] is the current disruptor
                    dmlist[-1].clear_attr(DataMakerAttr.HandOver)

                    # We traverse the list in opposite order till we
                    # find another controller or till we run through
                    # all the list.  We also ignore the last element
                    # which is the current disruptor
                    dmlist_mangled = dmlist[-2::-1]
                    dmlist_mangled_size = len(dmlist_mangled)
                    for dmobj, idx in zip(dmlist_mangled, range(dmlist_mangled_size)):
                        if dmobj.is_attr_set(DataMakerAttr.Controller):
                            dmobj.set_attr(DataMakerAttr.Active)
                            if dmobj.is_attr_set(DataMakerAttr.HandOver):
                                _handle_disruptors_handover(dmlist[:dmlist_mangled_size-idx])
                            break
                        else:
                            dmobj.set_attr(DataMakerAttr.Active)

                # Apply to controller disruptor only
                if dmaker_obj.is_attr_set(DataMakerAttr.HandOver):
                    _handle_disruptors_handover(current_dmobj_list)
                    self.set_error("Disruptor '{:s}' ({:s}) has yielded!".format(dmaker_name, dmaker_type),
                                   context={'dmaker_name': dmaker_name, 'dmaker_type': dmaker_type},
                                   code=Error.HandOver)
                    return None


            if not setup_crashed:
                try:
                    if setup_err:
                        dmaker_obj._cleanup()
                        self.__initialized_dmakers[dmaker_obj] = (False, None)

                except Exception:
                    unrecoverable_error = True
                    self._handle_user_code_exception("The cleanup() method of Data Maker '%s' has crashed!" % dmaker_ref)
        
            # if this is the Disruptor that has took over
            if dmaker_obj.is_attr_set(DataMakerAttr.Controller):
                for info in shortcut_history:
                    data.add_info(info)
                shortcut_history = []

            data.bind_info(dmaker_type, dmaker_name)
            l.append((dmaker_type, dmaker_name, user_input))
            first = False

        if unrecoverable_error:
            return None

        data.set_history(l)
        data.set_initial_dmaker(initial_generator_info)

        if not self._is_data_valid(data):
            self.set_error('Data is empty (probable reason: used data maker is disabled and need '
                           'to be reset)',
                           code=Error.DataInvalid)
            return None
        else:
            return data

    @EnforceOrder(accepted_states=['S1','S2'])
    def cleanup_all_dmakers(self, reset_existing_seed=True):

        for dmaker_obj in self.__initialized_dmakers:
            if self.__initialized_dmakers[dmaker_obj][0]:
                try:
                    dmaker_obj._cleanup()
                    self.__initialized_dmakers[dmaker_obj] = (False, None)
                except Exception:
                    self._handle_user_code_exception()

        if reset_existing_seed:
            for dmaker_obj in self.__initialized_dmakers:
                if isinstance(dmaker_obj, Generator):
                    dmaker_obj.produced_seed = None

    @EnforceOrder(accepted_states=['S1','S2'])
    def cleanup_dmaker(self, dmaker_type=None, name=None, dmaker_obj=None, reset_existing_seed=True, error_on_init=True):
        
        if dmaker_obj is not None:
            if reset_existing_seed and isinstance(dmaker_obj, Generator):
                dmaker_obj.produced_seed = None

            if dmaker_obj in self.__initialized_dmakers:
                dmaker_obj._cleanup()
                self.__initialized_dmakers[dmaker_obj] = (False, None)
            else:
                self.set_error('The specified data maker is not initialized!',
                               code=Error.FmkWarning)
            return

        if dmaker_type is None:
            self.set_error("You shall specify either 'dmaker_type' or 'dmaker_obj'!",
                           code=Error.CommandError)
            return

        ok = False
        for dmaker_obj in self.__initialized_dmakers:
            if self.__initialized_dmakers[dmaker_obj][0] or reset_existing_seed:
                xt, n = self._generic_tactics.get_info_from_obj(dmaker_obj)
                if xt is None:
                    xt, n = self._tactics.get_info_from_obj(dmaker_obj)
                    if xt is None:
                        raise ValueError('Implementation Error!')

                if dmaker_type == xt:
                    cond = True if name is None else name == n
                    if cond:
                        if reset_existing_seed and isinstance(dmaker_obj, Generator):
                            dmaker_obj.produced_seed = None

                        if self.__initialized_dmakers[dmaker_obj][0]:
                            try:
                                dmaker_obj._cleanup()
                                self.__initialized_dmakers[dmaker_obj] = (False, None)
                                ok = True
                            except Exception:
                                self._handle_user_code_exception()


        if not ok and error_on_init:
            self.set_error('The specified data maker is not initialized!',
                           code=Error.FmkWarning)

    @EnforceOrder(accepted_states=['S2'])
    def set_disruptor_weight(self, dmaker_type, data_maker_name, weight):
        self._tactics.set_disruptor_weight(dmaker_type, data_maker_name, weight)

    @EnforceOrder(accepted_states=['S2'])
    def set_generator_weight(self, generator_type, data_maker_name, weight):
        self._tactics.set_generator_weight(generator_type, data_maker_name, weight)

    @EnforceOrder(accepted_states=['S2'])
    def show_tasks(self):
        self.lg.print_console('-=[ Running Tasks ]=-', rgb=Color.INFO, style=FontStyle.BOLD)
        self.lg.print_console('')
        if not self._task_list:
            self.lg.print_console('No task is currently running', rgb=Color.SUBINFO)
        else:
            for tk_id, tk in self._task_list.items():
                msg = "Task ID #{!s}".format(tk_id)
                self.lg.print_console(msg, rgb=Color.SUBINFO)
        self.lg.print_console('\n', nl_before=False)

    @EnforceOrder(accepted_states=['S2'])
    def show_probes(self):
        probes = self.prj.get_probes()
        self.lg.print_console('-=[ Probes ]=-', rgb=Color.INFO, style=FontStyle.BOLD)
        self.lg.print_console('')
        for p in probes:
            try:
                status = self.mon.get_probe_status(p).get_status()
            except:
                status = None
            msg = "name: %s (status: %s, delay: %f) --> " % \
                (p, repr(status),
                 self.mon.get_probe_delay(p))

            if self.mon.is_probe_stuck(p):
                msg += "stuck"
            elif self.mon.is_probe_launched(p):
                msg += "launched"
            else:
                msg += "stopped"
            self.lg.print_console(msg, rgb=Color.SUBINFO)

        self.lg.print_console('\n', nl_before=False)


    @EnforceOrder(accepted_states=['S2'])
    def launch_probe(self, name):
        ok = self.mon.start_probe(name)
        if not ok:
            self.set_error('Probe does not exist (or already launched)',
                           code=Error.CommandError)
        self.mon.wait_for_probe_initialization()

        return ok

    @EnforceOrder(accepted_states=['S2'])
    def stop_all_probes(self):
        self.mon.stop_all_probes()

    @EnforceOrder(accepted_states=['S2'])
    def stop_probe(self, name):
        self.mon.stop_probe(name)

    @EnforceOrder(accepted_states=['S2'])
    def get_probe_delay(self, name):
        self.mon.get_probe_delay(name)

    @EnforceOrder(accepted_states=['S2'])
    def set_probe_delay(self, name, delay):
        ok = self.mon.set_probe_delay(name, delay)
        if not ok:
            self.set_error("Probe '%s' does not exist" % name,
                           code=Error.CommandError)
        return ok

    @EnforceOrder(accepted_states=['S2'])
    def show_data_maker_types(self):

        def print_dmaker(dmaker_list, title):
            if not dmaker_list:
                return

            ln = ''
            sep = colorize(', ', rgb=Color.FMKINFO)
            lines =[]
            for idx, entry in enumerate(dmaker_list, start=1):
                if idx % 5 != 0:
                    ln += colorize(entry, rgb=Color.FMKSUBINFO) + sep
                else:
                    ln += colorize(entry, rgb=Color.FMKSUBINFO)
                    lines.append(colorize('   | ', rgb=Color.FMKINFO) + ln)
                    ln = ''

            if len(dmaker_list) % 5 != 0:
                lines.append(colorize('   | ', rgb=Color.FMKINFO) + ln[:-len(sep)])

            self.lg.print_console(' [ ' + title + ' ]', rgb=Color.FMKINFO, nl_before=True, nl_after=False)
            for ln in lines:
                self.lg.print_console(ln)
            self.lg.print_console('')

        self.lg.print_console('===[ Generator Types ]' + '='*58, rgb=Color.FMKINFOGROUP, nl_after=True)
        l1 = []
        for dt in self._tactics.generator_types:
            l1.append(dt)
        l1 = sorted(l1)

        l2 = []
        for dt in self._generic_tactics.generator_types:
            l2.append(dt)
        l2 = sorted(l2)

        print_dmaker(l1, 'Specific')
        print_dmaker(l2, 'Generic')

        self.lg.print_console('===[ Disruptor Types ]' + '='*58, rgb=Color.FMKINFOGROUP, nl_after=True)
        l1 = []
        for dmaker_type in self._tactics.disruptor_types:
            l1.append(dmaker_type)
        l1 = sorted(l1)

        l2 = []
        for dmaker_type in self._generic_tactics.disruptor_types:
            l2.append(dmaker_type)
        l2 = sorted(l2)

        print_dmaker(l1, 'Specific')
        print_dmaker(l2, 'Generic')


    def __chunk_lines(self, string, length):
        l = string.split(' ')
        chk_list = []
        full_line = ''
        for wd in l:
            full_line += wd + ' '
            if len(full_line) > (length - 1):
                chk_list.append(full_line)
                full_line = ''
        if full_line:
            chk_list.append(full_line)
        # remove last space char
        if chk_list:
            chk_list[-1] = (chk_list[-1])[:-1]
        return chk_list

    def __dmaker_desc_str(self, obj):

        def _make_str(k, v):
            desc, default, arg_type = v
            l = self.__chunk_lines(desc, 60)
            k_len = len(k)
            prefix_len = len('\n    |_ ') + 3 - len("desc: ")
            prefix = '\n    |_ ' + colorize(k, rgb=Color.INFO_ALT) +  \
                     '\n    |      | ' + colorize("desc: ", rgb=Color.SUBINFO_ALT)
            msg = prefix
            indent = 0
            for chk, cpt in zip(l, range(len(l),0,-1)):
                msg += '    |'*indent + ' '*prefix_len*indent + \
                       ' |       '*indent + chk + '\n'
                indent = 1

            if isinstance(arg_type, tuple):
                args_type_desc = ''
                for x in arg_type:
                    args_type_desc += x.__name__ + ', '
                args_type_desc = args_type_desc[:-2]
            else:
                args_type_desc = arg_type.__name__
            msg += '    |' + ' '*prefix_len + \
                   ' | ' + colorize('default: ', rgb=Color.SUBINFO_ALT) + \
                   colorize(repr(default), rgb=Color.SUBINFO_ALT_HLIGHT) + ' [type: {:s}]'.format(args_type_desc)
            return msg

        if obj.__doc__:
            msg = '\n' + colorize(obj.__doc__, rgb=Color.INFO_ALT_HLIGHT)
        else:
            msg = ''
        if obj._gen_args_desc:
            msg += "\n  generic args: "
            for k, v in obj._gen_args_desc.items():
                msg += _make_str(k, v)
        if obj._args_desc:
            msg += "\n  specific args: "
            for k, v in obj._args_desc.items():
                msg += _make_str(k, v)

        return msg


    @EnforceOrder(accepted_states=['S2'])
    def show_generators(self, dmaker_type=None):
        generators = self._tactics.generator_types
        gen_generators = self._generic_tactics.generator_types
        if dmaker_type:
            if dmaker_type not in generators and dmaker_type not in gen_generators:
                self.set_error('The specified data maker does not exist!',
                               code=Error.FmkWarning)                                
                return
            else:
                generators = None if dmaker_type not in generators else [dmaker_type]
                gen_generators = None if dmaker_type not in gen_generators else [dmaker_type]

        if generators:
            self.lg.print_console('\n-=[ SPECIFIC GENERATORS ]=-', rgb=Color.INFO, style=FontStyle.BOLD)
            for dt in sorted(generators):
                msg = "\n*** Available generators of type '%s' ***" % dt
                self.lg.print_console(msg, rgb=Color.INFO)
                generators_list = self._tactics.get_generators_list(dt)
                for name in generators_list:
                    msg = "  name: %s (weight: %d, valid: %r)" % \
                        (name, self._tactics.get_generator_weight(dt, name),
                         self._tactics.get_generator_validness(dt, name))
                    msg += self.__dmaker_desc_str(self._tactics.get_generator_obj(dt, name))
                    self.lg.print_console(msg, limit_output=False)

        if gen_generators:
            self.lg.print_console('\n-=[ GENERIC GENERATORS ]=-', rgb=Color.INFO, style=FontStyle.BOLD)
            for dt in sorted(gen_generators):
                msg = "\n*** Generic generators of type '%s' ***" % dt
                self.lg.print_console(msg, rgb=Color.INFO)
                gen_generators_list = self._generic_tactics.get_generators_list(dt)
                for name in gen_generators_list:
                    msg = "  name: %s (weight: %d, valid: %r)" % \
                        (name, self._generic_tactics.get_generator_weight(dt, name),
                         self._generic_tactics.get_generator_validness(dt, name))
                    msg += self.__dmaker_desc_str(self._generic_tactics.get_generator_obj(dt, name))
                    self.lg.print_console(msg, limit_output=False)

        self.lg.print_console('\n', nl_before=False)

    @EnforceOrder(accepted_states=['S2'])
    def show_disruptors(self, dmaker_type=None):
        disruptors = self._tactics.disruptor_types
        gen_disruptors = self._generic_tactics.disruptor_types
        if dmaker_type:
            if dmaker_type not in disruptors and dmaker_type not in gen_disruptors:
                self.set_error('The specified data maker does not exist!',
                               code=Error.FmkWarning)                                
                return
            else:
                disruptors = [] if dmaker_type not in disruptors else [dmaker_type]
                gen_disruptors = [] if dmaker_type not in gen_disruptors else [dmaker_type]

        if disruptors:
            self.lg.print_console('\n-=[ SPECIFIC DISRUPTORS ]=-', rgb=Color.INFO, style=FontStyle.BOLD)
            for dmt in sorted(disruptors):
                msg = "\n*** Specific disruptors of type '%s' ***" % dmt
                self.lg.print_console(msg, rgb=Color.INFO)
                disruptors_list = self._tactics.get_disruptors_list(dmt)
                for name in disruptors_list:
                    dis_obj = self._tactics.get_disruptor_obj(dmt, name)
                    if issubclass(dis_obj.__class__, StatefulDisruptor):
                        dis_type = 'stateful disruptor'
                    else:
                        dis_type = 'stateless disruptor'
                    msg = "  name: {:s} ".format(name) + \
                          " (weight: {:d}, valid: {!r})" \
                              .format(self._tactics.get_disruptor_weight(dmt, name),
                                      self._tactics.get_disruptor_validness(dmt, name))
                    msg += ' ' + colorize("[{:s}]".format(dis_type), rgb=Color.INFO_ALT)
                    msg += self.__dmaker_desc_str(dis_obj)
                    self.lg.print_console(msg, limit_output=False)

        if gen_disruptors:
            self.lg.print_console('\n-=[ GENERIC DISRUPTORS ]=-', rgb=Color.INFO, style=FontStyle.BOLD)
            for dmt in sorted(gen_disruptors):
                msg = "\n*** Generic disruptors of type '%s' ***" % dmt
                self.lg.print_console(msg, rgb=Color.INFO)
                gen_disruptors_list = self._generic_tactics.get_disruptors_list(dmt)
                for name in gen_disruptors_list:
                    dis_obj = self._generic_tactics.get_disruptor_obj(dmt, name)
                    if issubclass(dis_obj.__class__, StatefulDisruptor):
                        dis_type = 'stateful disruptor'
                    else:
                        dis_type = 'stateless disruptor'
                    msg = "  name: {:s} ".format(name) + \
                          " (weight: {:d}, valid: {!r})" \
                              .format(self._generic_tactics.get_disruptor_weight(dmt, name),
                                      self._generic_tactics.get_disruptor_validness(dmt, name))
                    msg += ' ' + colorize("[{:s}]".format(dis_type), rgb=Color.INFO_ALT)
                    msg += self.__dmaker_desc_str(dis_obj)
                    self.lg.print_console(msg, limit_output=False)

        self.lg.print_console('\n', nl_before=False)

    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1', 'S2'])
    def display_color_theme(self):
        Color.display()
    


class FmkShell(cmd.Cmd):

    def __init__(self, title, fmk_plumbing, completekey='tab', stdin=None, stdout=None):
        cmd.Cmd.__init__(self, completekey, stdin, stdout)
        self.fz = fmk_plumbing
        self.prompt = '>> '
        self.intro = colorize(FontStyle.BOLD + "\n-=[ %s ]=- (with Fuddly FmK %s)\n" % (title, fuddly_version), rgb=Color.TITLE)

        self.__allowed_cmd = re.compile(
            '^quit$|^show_projects$|^show_data_models$|^load_project|^load_data_model|^set_target|^show_targets$|^launch$' \
            '|^run_project|^display_color_theme$|^help'
            )

        self.dmaker_name_re = re.compile('([#\-\w]+)(.*)', re.S)
        # the symbol '<' shall not be used within group(3)
        self.input_gen_arg_re = re.compile('<(.*)>(.*)', re.S)
        self.input_spe_arg_re = re.compile('\((.*)\)', re.S)
        self.input_arg_re = re.compile('(.*)=(.*)', re.S)

        self.__error = False
        self.__error_msg = ''
        self.__error_fmk = ''
        self._quit_shell = False

        history_path = os.path.expanduser(gr.fuddly_data_folder + 'fuddly_shell_history')

        def save_history(history_path=history_path):
            readline.write_history_file(history_path)

        if os.path.exists(history_path):
            readline.read_history_file(history_path)

        atexit.register(save_history)

        signal.signal(signal.SIGINT, signal.SIG_IGN)


    def postcmd(self, stop, line):
        if self._quit_shell:
            self._quit_shell = False
            msg = colorize(FontStyle.BOLD + "\nReally Quit? [Y/n]", rgb=Color.WARNING)
            if sys.version_info[0] == 2:
                cont = raw_input(msg)
            else:
                cont = input(msg)
            cont = cont.upper()
            if cont == 'Y' or cont == '':
                self.fz.exit_fmk()
                return True
            else:
                return False

        printed_err = False
        print('')
        if self.fz.is_not_ok() or self.__error:
            printed_err = True
            msg = '| ERROR / WARNING / INFO |'
            print(colorize('-'*len(msg), rgb=Color.WARNING))
            print(colorize(msg, rgb=Color.WARNING))
            print(colorize('-'*len(msg), rgb=Color.WARNING))

        if self.fz.is_not_ok():
            err_list = self.fz.get_error()
            for e in err_list:
                print(colorize("    (_ FMK [#{err!s:s}]: {msg:s} _)".format(err=e, msg=e.msg), rgb=e.color))

        if self.__error:
            self.__error = False
            if self.__error_msg != '':
                print(colorize("    (_ SHELL: {:s} _)".format(self.__error_msg), rgb=Color.WARNING))

        if printed_err:
            print('')

        self.__error_msg = ''
        self.__error_fmk = ''
        return stop

    def emptyline(self):
        return False

    def cmdloop(self, intro=None):
        try:
            cmd.Cmd.cmdloop(self, intro)            
        except BaseException as e:
            color = Error(code=Error.OperationCancelled).color
            sys.stdout.write(colorize(repr(e)+'\n', rgb=color))
            self.fz._handle_fmk_exception(cause='unknown error')
            self.__error = False
            self.__error_msg = ''
            self.intro = None
            self.cmdloop()

    def precmd(self, line):
        if line == 'EOF':
            self._quit_shell = True
            return ''

        if self.fz.is_usable():
            return line

        elif self.__allowed_cmd.match(line):
            return line

        else:
            self.__error = True
            self.__error_msg = 'You shall first load a project and/or enable all the framework components!'
            return ''


    def do_show_projects(self, line):
        '''Show the available Projects'''
        self.fz.show_projects()

        return False


    def do_show_data_models(self, line):
        '''Show the available Data Models'''
        self.fz.show_data_models()

        return False

    def do_display_color_theme(self, line):
        '''Display the color theme'''
        self.fz.display_color_theme()

        return False

    def do_load_data_model(self, line):
        '''Load a Data Model by name'''
        self.__error = True

        arg = line.strip()

        ok = False
        for dm in self.fz.iter_data_models():
            if dm.name == arg:
                ok = True
                break

        self.__error_msg = "Data Model '%s' is not available" % arg

        if not ok:
            return False

        if not self.fz.load_data_model(dm=dm):
            return False

        self.__error = False
        return False

    def do_load_multiple_data_model(self, line):
        '''
        Load a multiple Data Model by name
        |_ syntax: load_multiple_data_model <dm_name_1> <dm_name_2> ... [dm_name_n]
        '''
        self.__error = True

        args = line.split()

        ok = True
        dm_name_list = [x.name for x in self.fz.dm_list]
        for dm_name in args:
            if dm_name not in dm_name_list:
                ok = False
                break

        self.__error_msg = "Data Model '%s' is not available" % dm_name

        if not ok:
            return False

        if not self.fz.load_multiple_data_model(name_list=args):
            return False

        self.__error = False
        return False


    
    def do_load_project(self, line):
        '''Load an available Project'''
        self.__error = True

        arg = line.strip()

        ok = False
        for prj in self.fz.projects():
            if prj.name == arg:
                ok = True
                break

        self.__error_msg = "Project '%s' is not available" % arg

        if not ok:
            return False

        if not self.fz.load_project(prj=prj):
            return False

        self.__error = False
        return False


    def do_run_project(self, line):
        '''
        Load a Project by name & Launch it:
        1. Enable the specified target
        2. Load the default data model of the project file
        3. Launch the project by starting fuddly subsystems

        |_ syntax: run_project <project_name> [target_number]
        '''

        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len < 1 or args_len > 2:
            self.__error_msg = "Syntax Error!"
            return False

        prj_name = args[0].strip()
        try:
            tg_id = args[1]
        except IndexError:
            tg_id = None

        if tg_id:
            try:
                tg_id = int(tg_id)
            except ValueError:
                self.__error_msg = "Parameter 2 shall be an integer!"
                return False

        ok = False
        for prj in self.fz.projects():
            if prj.name == prj_name:
                ok = True
                break

        self.__error_msg = "Project '%s' is not available" % prj_name
        if not ok:
            return False

        self.__error_msg = "Unable to launch the project '%s'" % prj_name
        if not self.fz.run_project(prj=prj, tg=tg_id):
            return False

        self.__error = False
        return False



    def do_set_target(self, line):
        '''
        Set the target number to use
        |_ syntax: set_target <target_number>
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False
        try:
            num = int(args[0])
        except ValueError:
            return False

        self.fz.set_target(num)

        self.__error = False
        return False


    def do_show_targets(self, line):
        '''Show the available Targets for the current Data Model'''
        self.fz.show_targets()

        return False


    def do_show_fmk_internals(self, line):
        '''Show the framework internals'''
        self.fz.show_fmk_internals()

        return False


    def do_launch(self, line):
        '''Launch the loaded project by starting every needed components'''
        self.__error = True
        self.fz.launch()
        self.__error = False
        return False

    def do_show_tasks(self, line):
        self.fz.show_tasks()
        return False

    def do_stop_all_tasks(self, line):
        self.fz.stop_all_tasks()
        return False

    def do_launch_probe(self, line):
        '''
        Launch a probe
        |_ syntax: launch_probe <probe_name>
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False

        self.fz.launch_probe(args[0])

        self.__error = False
        return False

    def do_show_probes(self, line):
        self.fz.show_probes()
        return False

    def do_stop_all_probes(self, line):
        self.fz.stop_all_probes()
        return False

    def do_stop_probe(self, line):
        '''
        Stop a probe
        |_ syntax: stop_probe <probe_name>
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False

        self.fz.stop_probe(args[0])
        
        self.__error = False
        return False

    def do_set_probe_delay(self, line):
        '''
        Delay a probe.
        |  syntax: set_probe_delay <name> <delay>
        |  |_ possible values for <delay>:
        |      0  : no delay
        |     x>0 : delay expressed in seconds (fraction is possible)
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 2:
            return False
        try:
            name = args[0]
            delay = float(args[1])
        except:
            return False

        self.fz.set_probe_delay(name, delay)

        self.__error = False
        return False


    def do_show_disruptors(self, line):
        '''
        Show all the disruptors description or the ones of the
        provided type
        |_ syntax: show_disruptors [disruptor_type]
        '''
        args = line.split()
        args_len = len(args)

        if args_len > 1:
            return False

        if args_len == 1:
            dmt = args[0].strip()
        else:
            dmt = None

        self.fz.show_disruptors(dmaker_type=dmt)
        return False


    def do_show_generators(self, line):
        '''
        Show all the generators description or the ones of the
        provided type
        |_ syntax: show_generators [generator_type]
        '''
        args = line.split()
        args_len = len(args)

        if args_len > 1:
            return False

        if args_len == 1:
            dmt = args[0].strip()
        else:
            dmt = None

        self.fz.show_generators(dmaker_type=dmt)
        return False


    def do_show_dmaker_types(self, line):
        self.fz.show_data_maker_types()
        return False


    def do_show_data_identifiers(self, line):
        '''
        Provide the Data IDs of the data types available in the current data model.

        Note: these IDs are used as parameters by generic
        generators/disruptors for dealing with specific data types.
        '''
        self.fz.show_dm_data_identifiers()
        return False


    def do_enable_wkspace(self, line):
        self.fz.enable_wkspace()
        return False

    def do_disable_wkspace(self, line):
        self.fz.disable_wkspace()
        return False

    def do_send_valid(self, line):
        '''
        Build a data in multiple step from a valid source
        |_ syntax: send_fullvalid <generator_type> [disruptor_type_1 ... disruptor_type_n]
            |_ Note: generator_type shall have at least one valid generator
        '''
        ret = self.do_send(line, valid_gen=True)
        return ret

    def do_send_loop_valid(self, line):
        '''
        Loop ( Build a data in multiple step from a valid source )
        |_ syntax: send_loop_valid <#loop> <generator_type> [disruptor_type_1 ... disruptor_type_n]
            |_ Note: generator_type shall have at least one valid generator
        '''
        ret = self.do_send_loop(line, valid_gen=True)
        return ret

    def do_send_loop_noseed(self, line):
        '''
        Loop ( Build a data in multiple step from a valid source )
        |_ syntax: send_loop_noseed <#loop> <generator_type> [disruptor_type_1 ... disruptor_type_n]
            |_ Note: generator_type shall have at least one valid generator
        '''
        ret = self.do_send_loop(line, use_existing_seed=False)
        return ret


    def do_set_generator_weight(self, line):
        '''
        Set the weight of the given generator
        |_ syntax: set_generator_weight <generator_type> <generator> <weight>
        '''
        args = line.split()

        self.__error = True
        if len(args) != 3:
            return False
        try:
            w = int(args[2])
        except ValueError:
            return False

        self.__error = False

        self.fz.set_generator_weight(args[0], args[1], w)

        return False

        
    def do_set_disruptor_weight(self, line):
        '''
        Set the weight of the given disruptor
        |_ syntax: set_disruptor_weight <dmaker_type> <disruptor> <weight>
        '''
        args = line.split()

        self.__error = True
        if len(args) != 3:
            return False
        try:
            w = int(args[2])
        except ValueError:
            return False

        self.__error = False

        self.fz.set_disruptor_weight(args[0], args[1], w)

        return False


    def do_launch_operator(self, line, use_existing_seed=True, verbose=False):
        '''
        Launch the specified operator and use any existing seed
        |_ syntax: launch_operator <op_name>
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False

        t = self.__parse_instructions(args)
        if t is None:
            self.__error_msg = "Syntax Error!"
            return False

        operator = t[0][0]
        user_input = UserInputContainer(generic=t[0][1], specific=t[0][2])

        self.fz.launch_operator(operator, user_input, use_existing_seed=use_existing_seed,
                                verbose=verbose)

        self.__error = False
        return False


    def do_launch_operator_noseed(self, line):
        '''
        Launch the specified operator without using any current seed
        |_ syntax: launch_operator_noseed  <op_name>
        '''
        ret = self.do_launch_operator(line, use_existing_seed=False)
        return ret


    def do_launch_operator_verbose(self, line):
        '''
        Launch the specified operator and use any existing seed (pretty print enabled)
        |_ syntax: launch_operator_verbose <op_name>
        '''
        ret = self.do_launch_operator(line, use_existing_seed=False, verbose=True)
        return ret


    def do_show_operators(self, line):
        self.fz.show_operators()
        return False


    def __parse_instructions(self, cmdline):
        '''
        return a list of the following format:
        [(action_1, [gen_arg_11, ..., gen_arg_1n], [arg_11, ..., arg_1n]), ...,
        (action_n, [gen_arg_n1, ..., gen_arg_nn], [arg_n1, ..., arg_nn])]
        '''

        def __extract_arg(exp, dico):
            re_obj = self.input_arg_re.match(exp)
            if re_obj is None:
                return False
            key, val = re_obj.group(1), re_obj.group(2)
            try:
                arg = eval(val)
            except:
                arg = val.strip()
            dico[key] = arg
            return True


        d = []
        for a in cmdline:
            parsed = self.dmaker_name_re.match(a)
            if parsed is not None:
                name = parsed.group(1)
                allargs_str = parsed.group(2)
            else:
                name = 'INCORRECT_NAME'
                allargs_str = None

            if allargs_str is not None:
                parsed = self.input_gen_arg_re.match(allargs_str)
                # Parse generic arguments
                if parsed:
                    arg_str = parsed.group(1)
                    specific_args_str = parsed.group(2)
                    gen_args = {}
                    l = arg_str.split(':')
                    for a in l:
                        ok = __extract_arg(a, gen_args)
                        if not ok:
                            return None
                else:
                    gen_args = None
                    specific_args_str = allargs_str

                # Parse specific arguments
                if specific_args_str is not None:
                    parsed = self.input_spe_arg_re.match(specific_args_str)
                else:
                    parsed = None
                if parsed:
                    arg_str = parsed.group(1)
                    args = {}
                    l = arg_str.split(':')
                    for a in l:
                        ok = __extract_arg(a, args)
                        if not ok:
                            return None
                else:
                    args = None

            else:
                gen_args = None
                args = None

            gen_ui = UI()
            spe_ui = UI()
            if gen_args is not None and len(gen_args) > 0:
                gen_ui.set_user_inputs(gen_args)
            if args is not None and len(args) > 0:
                spe_ui.set_user_inputs(args)

            d.append((name, gen_ui, spe_ui))

        return d

    def do_reload_data_model(self, line):
        '''
        Reload the current data model
        |_ syntax: reload_data_model
        '''
        self.fz.reload_dm()

        return False

    def do_reload_all(self, line):
        '''
        Reload the current data model and all its associated components (target, monitor, logger)
        |_ syntax: reload_all [target_number]
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        num = None
        if args_len > 0:
            try:
                num = int(args[0])
            except ValueError:
                return False

        self.fz.reload_all(tg_num=num)

        self.__error = False
        return False


    def do_cleanup_all_dmakers(self, line):
        '''
        Clean up all initialized Data Makers
        |_ syntax: cleanup_all_dmakers
        '''
        self.fz.cleanup_all_dmakers(reset_existing_seed=False)

        return False

    def do_reset_all_dmakers(self, line):
        '''
        Reset all initialized Data Makers
        (Note: like cleanup_all_dmaker but clean also existing seeds)
        |_ syntax: reset_all_dmakers
        '''
        self.fz.cleanup_all_dmakers(reset_existing_seed=True)

        return False


    def do_cleanup_dmaker(self, line, reset_existing_seed=False):
        '''
        Clean up a specified initialized Data Maker
        |_ syntax: cleanup_dmaker <dmaker_type> [dmaker_name]
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len < 1 or args_len > 2:
            return False

        xt = args[0]
        try:
            n = args[1]
        except:
            n = None

        self.fz.cleanup_dmaker(dmaker_type=xt, name=n, reset_existing_seed=reset_existing_seed)

        self.__error = False
        return False


    def do_reset_dmaker(self, line):
        '''
        Reset a specified initialized Data Maker
        (Note: like cleanup_dmaker but clean also the seed if present)
        |_ syntax: reset_dmaker <dmaker_type> [dmaker_name]
        '''
        ret = self.do_cleanup_dmaker(line, reset_existing_seed=True)
        return ret


    def do_send(self, line, valid_gen=False, verbose=False):
        '''
        Carry out multiple fuzzing steps in sequence
        |_ syntax: send <generator_type> [disruptor_type_1 ... disruptor_type_n]
        '''
        self.__error = True

        args = line.split()

        if len(args) < 1:
            return False

        t = self.__parse_instructions(args)
        if t is None:
            self.__error_msg = "Syntax Error!"
            return False

        data = self.fz.get_data(t, valid_gen=valid_gen)
        
        if data is None:
            return False

        self.fz.send_data_and_log(data, verbose=verbose)

        self.__error = False
        return False


    def do_send_verbose(self, line):
        '''
        Carry out multiple fuzzing steps in sequence (pretty print enabled)
        |_ syntax: send_verbose <generator_type> [disruptor_type_1 ... disruptor_type_n]
        '''
        ret = self.do_send(line, verbose=True)
        return ret


    def do_send_loop(self, line, valid_gen=False, use_existing_seed=True):
        '''
        Loop ( Carry out multiple fuzzing steps in sequence )
        |_ syntax: send_loop <#loop> <generator_type> [disruptor_type_1 ... disruptor_type_n]

        Note: To loop indefinitely use -1 for #loop. To stop the loop use Ctrl+C
        '''
        args = line.split()

        self.__error = True

        if len(args) < 2:
            return False
        try:
            max_loop = int(args.pop(0))
            if max_loop < 2 and max_loop != -1:
                return False
        except ValueError:
            return False

        t = self.__parse_instructions(args)
        if t is None:
            self.__error_msg = "Syntax Error!"
            return False

        def do_loop():
            # for i in range(nb):
            cpt = 0
            while cpt < max_loop or max_loop == -1:
                cpt += 1
                data = self.fz.get_data(t, valid_gen=valid_gen, save_seed=use_existing_seed)
                if data is None:
                    return False
                cont = self.fz.send_data_and_log(data)
                if not cont:
                    break

            return

        def do_loop_cosmetics():
            # type () -> None

            """ do_send_loop cosmetics, buffer stdout before sending payloads.
            """

            # add an attribute to check import's health
            if not hasattr(self, 'do_send_loop_import_error'):
                setattr(self, 'do_send_loop_import_error', False)
                try:
                    import curses, io, contextlib, os, termios
                except ImportError as e:
                    print("\n\n!! " + e + "\n  "
                            + "   (cosmetics require curses & POSIX tty)"
                            + "\n\n")
                    self.do_send_loop_import_error = True

            # (if we have failed to import something)
            if self.do_send_loop_import_error:
                do_loop()
                return

            # (if we reached this point, imports shall succeed)
            import curses, io, contextlib, os, termios

            #: io.BytesIO: the buffer that will replace the standard output
            stream = io.BytesIO()
            stdout = sys.stdout #: (backuped value of the standard output)

            #: int: count how much payloads have been send since the last flush
            stream.countp = 0

            def setup_term():
                # type: () -> None

                """ do_send_loop cosmetics, handle curses vs readline issues

                See `issue 2675`__ for further informations, enables resizing
                the terminal.

                __ https://bugs.python.org/issue2675

                """

                try:
                    # unset env's LINES and COLUMNS to trigger a size update
                    os.unsetenv('LINES')
                    os.unsetenv('COLUMNS')

                    # curses's setupterm with the real output (sys.__stdout__)
                    curses.setupterm(fd=sys.__stdout__.fileno())
                except:
                    pass

            # !! call curses's setupterm at least one time for tiget{str, num}
            setup_term()

            # retrieve common terminal capabilities
            el = curses.tigetstr("el")
            ed = curses.tigetstr("ed")
            cup = curses.tparm(curses.tigetstr("cup"), 0, 0)
            civis = curses.tigetstr("civis")
            cvvis = curses.tigetstr("cvvis")

            def get_size(
                    cutby=(0, 3), # type: Tuple[int, int]
                    refresh=True  # type: bool
                    ):
                # type: (...) -> Tuple[int, int]

                """ do_send_loop cosmetics, return the terminal size as a tuple

                Args:
                    refresh (bool): Try to refresh the terminal's size,
                        required if you use readline.
                    cutby (Tuple[int, int]):
                        Cut the terminal size by an offset, the first integer
                        of the tuple correspond to the width, the second to the
                        height of the terminal.

                Returns:
                    The (width, height) tuple corresponding to the terminal's
                    size (reduced slightly by the :literal:`cutby` argument).
                    The minimal value for the width or the height is 1.
                """

                # handle readline/curses interactions
                if refresh:
                    setup_term()

                # retrieve the terminal's size:
                #  - if refresh, initiate a curses window for an updated size,
                #  - else, retrieve it via a numeric capability.
                #
                if refresh:
                    height, width = curses.initscr().getmaxyx()
                    curses.endwin()
                else:
                    height = curses.tigetnum("lines")
                    width = curses.tigetnum("cols")

                # now *cut* the terminal by the specified offset
                width -= cutby[0]
                height -= cutby[1]

                # handle negative values
                if width < 2:
                    width = 1
                if height < 2:
                    height = 1

                # return the tuple
                return (width, height)

            def estimate_nblines(
                    width         # type: int
                    ):
                # type: (...) -> int

                """ do_send_loop cosmetics, return the estimated number of lines

                Args:
                    width (int): width of the terminal, used to calculate lines
                        wrapping in the buffer.

                Returns:
                    The estimated number of lines that the payload will take on
                    screen.
                """

                nblines = 0
                payload = stream.getvalue()
                lines = payload.splitlines()
                for line in lines:
                    length = len(line)
                    nblines += length // width + 1
                return nblines + 1

            def buffer_noecho():
                # type: () -> None

                """ do_send_loop cosmetics, disable echo mode for the tty
                """

                # (!! we use POSIX tty, as we do not use full curses)
                fd = stdout.fileno()
                flags = termios.tcgetattr(fd)
                flags[3] = flags[3] & ~termios.ECHO
                termios.tcsetattr(fd, termios.TCSADRAIN, flags)
                stdout.write(civis)

            # (hide the cursor before moving it)
            buffer_noecho()

            def buffer_echo():
                # type: () -> None

                """ do_send_loop cosmetics, reenable echo mode for the tty
                """

                # (!! we use POSIX tty, as we do not use full curses)
                fd = stdout.fileno()
                flags = termios.tcgetattr(fd)
                flags[3] = flags[3] | termios.ECHO
                termios.tcsetattr(fd, termios.TCSADRAIN, flags)
                stdout.write(cvvis + ed)

            def buffer_output(
                    batch=False, # type: bool
                    force=False  # type: bool
                    ):
                # type: (...) -> None

                """ do_send_loop cosmetics, display the buffer on screen

                Args:
                    batch (bool): try to put as much as possilbe text on screen
                    force (bool): force the buffer to output its content
                """

                # retrieve the terminal size
                width, height = get_size()
 
                # flush the buffer, then estimate the number of lines
                stream.flush()
                nblines = estimate_nblines(width)

                # batch mode needs to estimate payloads size (skipped if force)
                if (not force) or batch:
                    if stream.countp > 0:
                        avg_size_per_payload = nblines // stream.countp
                    else:
                        avg_size_per_payload = nblines
                    stream.countp += 1

                # (if force, or non-batch, or sufficient output, display it)
                if (force
                        or (not batch)
                        or nblines + avg_size_per_payload > height
                        ):

                    # use `el` term capabilitie to wipe endlines as we display
                    payload = stream.getvalue().replace(b'\n', el + b'\n')

                    # if not force (continuous display), we erase the first
                    # payload (to have a log entry without disturbing scrolling
                    # nor getting a blinking terminal), then we display the
                    # payload a second time (in order to see it on screen), else
                    # (force == True), then we have the last payload to display,
                    # no need to duplicate it with unnecessary buffering.
                    #
                    if not force:
                        pad = b'\n' * (height - nblines + 3)
                        stdout.write(cup + payload * 2 + pad)
                    else:
                        stdout.write(cup + payload)

                    # empty the buffer, reset the payload counter
                    stream.__init__()
                    stream.countp = 0

                # if it is the last payload, reenable echo-ing.
                if force:
                    buffer_echo()

                # (provide callbacks for tracebacks handling)
                stream.handler = buffer_output
                stream.restore = buffer_echo

            @contextlib.contextmanager
            def buffer_stdout():
                # type: () -> None

                """ do_send_loop cosmetics, contextualize stdout's wrapper
                """

                sys.stdout = stream
                yield
                sys.stdout = stdout

            # main loop, similar to do_loop
            with buffer_stdout():
                cpt = 0
                batch_mode = (max_loop == -1)
                while cpt < max_loop or max_loop == -1:
                    buffer_output(batch=batch_mode)
                    cpt += 1
                    data = self.fz.get_data(t, valid_gen=valid_gen, save_seed=use_existing_seed)
                    if data is None:
                        buffer_output(force=True)
                        return False
                    cont = self.fz.send_data_and_log(data)
                    if not cont:
                        break
                buffer_output(force=True)

        # TODO: make cosmetics optional
        cosmetics = True
        if not cosmetics:
            do_loop()
        else:
            do_loop_cosmetics()

        self.__error = False
        return False


    def do_send_with(self, line):
        '''
        Generate data from specific generator
        |_ syntax: send_with <generator_type> <generator_name>
        '''
        self.__error = True

        args = line.split()

        if len(args) != 2:
            return False

        t = self.__parse_instructions([args[0]])[0]
        if t is None:
            self.__error_msg = "Syntax Error!"
            return False

        action = [((t[0], args[1]), t[1])]
        data = self.fz.get_data(action)
        if data is None:
            return False

        self.fz.send_data_and_log(data)

        self.__error = False
        return False


    def do_send_loop_with(self, line):
        '''
        Loop ( Generate data from specific generator )
        |_ syntax: send_loop_with <#loop> <generator_type> <generator_name>
        '''
        self.__error = True

        args = line.split()

        if len(args) != 3:
            return False
        try:
            nb = int(args[0])
        except ValueError:
            return False

        t = self.__parse_instructions([args[1]])[0]
        if t is None:
            self.__error_msg = "Syntax Error!"
            return False

        action = [((t[0], args[2]), t[1])]

        for i in range(nb):
            data = self.fz.get_data(action)
            if data is None:
                return False

            self.fz.send_data_and_log(data)

        self.__error = False
        return False



    def do_multi_send(self, line):
        '''
        Send multi-data to a target. Generation instructions must be provided when
        requested (same format as the command 'send').
        |_ syntax: multi_send [#loop]
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len > 1:
            return False
        try:
            loop_count = int(args[0])
        except:
            loop_count = 1

        actions_list = []

        idx = 0
        while True:
            idx += 1

            msg = "*** Data generation instructions [#%d] (type '!' when all instructions are provided):\n" % idx
            if sys.version_info[0] == 2:
                actions_str = raw_input(msg)
            else:
                actions_str = input(msg)

            if actions_str == '!':
                print("*** Configuration terminated.")
                break

            l = actions_str.split()
            if len(l) < 1:
                return False

            actions = self.__parse_instructions(l)
            if actions is None:
                self.__error_msg = "Syntax Error!"
                return False

            actions_list.append(actions)

        prev_data_list = None
        exhausted_data_cpt = 0
        exhausted_data = {}
        nb_data = len(actions_list)

        for i in range(loop_count):
            data_list = []

            for j in range(nb_data):
                if j not in exhausted_data:
                    exhausted_data[j] = False

                if not exhausted_data[j]:
                    data = self.fz.get_data(actions_list[j])
                else:
                    if prev_data_list is not None:
                        data = prev_data_list[j]
                    else:
                        self.__error_msg = 'The loop has terminated too soon! (number of exhausted data: %d)' % exhausted_data_cpt
                        return False

                if data is None and exhausted_data_cpt < nb_data:
                    exhausted_data_cpt += 1
                    if prev_data_list is not None:
                        data = prev_data_list[j]
                        exhausted_data[j] = True
                    else:
                        self.__error_msg = 'The loop has terminated too soon! (number of exhausted data: %d)' % exhausted_data_cpt
                        return False

                    if exhausted_data[j] and exhausted_data_cpt >= nb_data:
                        self.__error_msg = 'The loop has terminated because all data are exhausted ' \
                            '(number of exhausted data: %d)' % exhausted_data_cpt
                        return False
                
                data_list.append(data)

            prev_data_list = data_list

            self.fz.send_data_and_log(data_list)

        if exhausted_data_cpt > 0:
            print("\nThe loop has terminated normally, but it remains non exhausted " \
                  "data (number of exhausted data: %d)" % exhausted_data_cpt)

        self.__error = False
        return False

    def do_set_feedback_timeout(self, line):
        '''
        Set the time duration for feedback gathering (if supported by the target)
        |  syntax: set_feedback_timeout <arg>
        |  |_ possible values for <arg>:
        |      0  : no timeout
        |     x>0 : timeout expressed in seconds (fraction is possible)
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False
        try:
            timeout = float(args[0])
            self.fz.set_feedback_timeout(timeout)
        except:
            return False

        self.__error = False
        return False

    def do_switch_feedback_mode(self, line):
        '''
        Switch target feedback mode between:
          - wait for the full time slot allocated for feedback retrieval
          - wait until the target has send something back to us
        '''
        self.fz.switch_feedback_mode(do_record=True, do_show=True)
        return False

    def do_set_health_timeout(self, line):
        '''
        Set the timeout when the FMK checks the target readiness (Default = 10).
        |  syntax: set_health_timeout <arg>
        |  |_ possible values for <arg>:
        |      0  : no timeout
        |     x>0 : timeout expressed in seconds (fraction is possible)
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False
        try:
            timeout = float(args[0])
            self.fz.set_health_check_timeout(timeout)
        except:
            return False

        self.__error = False
        return False


    def do_set_delay(self, line):
        '''
        Delay sending. Can be usefull during a loop.
        |  syntax: set_delay <arg>
        |  |_ possible values for <arg>:
        |     -1  : wait for keyboard input after each emission of data
        |      0  : no delay
        |     x>0 : delay expressed in seconds (fraction is possible)
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False
        try:
            delay = float(args[0])
            self.fz.set_fuzz_delay(delay)
        except:
            return False

        self.__error = False
        return False


    def do_set_burst(self, line):
        '''
        Set the burst value. Used by the FMK to decide when delay
        shall be applied (Default = 1).
        |  syntax: set_burst <arg>
        |  |_ possible values for <arg>:
        |      1  : delay is applied to each data emission
        |      N : delay is applied after N data emission
        '''
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False
        try:
            val = float(args[0])
            self.fz.set_fuzz_burst(val)
        except:
            return False

        self.__error = False
        return False


    def do_show_db(self, line):
        '''Show the Data Bank'''
        self.fz.show_data_bank()

        return False

    def do_show_wkspace(self, line):
        '''Show the Data Bank'''
        self.fz.show_wkspace()

        return False

    def do_empty_db(self, line):
        '''Empty the Data Bank'''
        self.fz.empty_data_bank()

        return False

    def do_empty_wkspace(self, line):
        '''Empty the current data in the working space'''
        self.fz.empty_workspace()

        return False

    def do_replay_db(self, line):
        '''
        Replay data from the Data Bank and optionnaly apply new disruptors on it
        |_ syntax: replay_db <idx_from_db> [disruptor_type_1 ... disruptor_type_n]
        '''

        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len < 1:
            return False
        try:
            idx = int(args.pop(0))
        except ValueError:
            return False

        data_orig, data = self.fz.get_from_data_bank(idx)
        if data is None:
            return False

        if args_len > 1:
            data_orig = data

            t = self.__parse_instructions(args)
            if t is None:
                self.__error_msg = "Syntax Error!"
                return False

            data = self.fz.get_data(t, data_orig=data)
            if data is None:
                return False

        self.__error = False

        self.fz.send_data_and_log(data, original_data=data_orig)

        return False


    def do_replay_db_loop(self, line):
        '''
        Loop ( Replay data from the Data Bank and optionnaly apply new disruptors on it )
        |_ syntax: replay_db_loop <#loop> <idx_from_db> [disruptor_type_1 ... disruptor_type_n]
        '''

        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len < 2:
            return False
        try:
            nb = int(args.pop(0))
            idx = int(args.pop(0))
        except ValueError:
            return False

        data_orig, data = self.fz.get_from_data_bank(idx)
        if data is None:
            return False

        if args_len > 2:
            data_orig = data

            t = self.__parse_instructions(args)
            if t is None:
                self.__error_msg = "Syntax Error!"
                return False

            for i in range(nb):
                new_data = self.fz.get_data(t, data_orig=data)
                if new_data is None:
                    return False

                self.fz.send_data_and_log(new_data, original_data=data_orig)

        else:
            for i in range(nb):
                self.fz.send_data_and_log(data, original_data=data_orig)

        self.__error = False

        return False


    def do_replay_db_all(self, line):
        '''Replay all data from the Data Bank'''

        try:
            next(self.fz.iter_data_bank())
        except StopIteration:
            self.__error = True
            self.__error_msg = "the Data Bank is empty"
            return False

        for data_orig, data in self.fz.iter_data_bank():
            self.fz.send_data_and_log(data, original_data=data_orig)

        return False

    def do_show_data_paths(self, line):
        '''
        Show the graph paths of the last generated data.
        Can be used as inputs for some generators or disruptors.
        '''
        self.__error = True

        data_orig, data = self.fz.get_last_data()
        if data is None:
            return False

        self.fz.show_data(data, verbose=False)

        self.__error = False
        return False

    def do_show_data(self, line):
        '''
        Show the last generated data.
        '''
        self.__error = True

        data_orig, data = self.fz.get_last_data()
        if data is None:
            return False

        self.fz.show_data(data, verbose=True)

        self.__error = False
        return False

    def do_show_scenario(self, line):
        '''
        Show a scenario in the specific format FMT (e.g., xdot, png, pdf, ...)
        |_ syntax: show_scenario SCENARIO_NAME [FMT]

        FMT defaults to 'pdf'
        '''

        self.__error = True
        self.__error_msg = "Syntax Error!"

        args = line.split()

        if len(args) > 2 or len(args) < 1:
            return False

        if len(args) == 2:
            sc_name = args[0]
            fmt = args[1]
        else:
            sc_name = args[0]
            fmt = 'pdf'

        self.fz.show_scenario(sc_name=sc_name, fmt=fmt)

        self.__error = False
        return False


    def do_replay_last(self, line):
        '''
        Replay last data and optionnaly apply new disruptors on it
        |_ syntax: replay_last [disruptor_type_1 ... disruptor_type_n]
        '''

        self.__error = True

        data_orig, data = self.fz.get_last_data()
        if data is None:
            return False

        if line:
            args = line.split()
            data_orig = data

            t = self.__parse_instructions(args)
            if t is None:
                self.__error_msg = "Syntax Error!"
                return False

            data = self.fz.get_data(t, data_orig=data)
            if data is None:
                return False

        self.__error = False

        self.fz.send_data_and_log(data, original_data=data_orig)

        return False


    def do_send_raw(self, line):
        '''
        Send raw data
        |_ syntax: send_raw <data>
        '''

        if line:
            data = Data(line)
            
            self.fz.send_data_and_log(data, None)
        else:
            self.__error = True

        return False

    def do_send_eval(self, line):
        '''
        Send python-evaluation of the parameter <data>
        |_ syntax: send_eval <data>
        '''

        if line:
            try:
                data = Data(eval(line))
            except:
                self.__error = True
                return False

            self.fz.send_data_and_log(data, None)
        else:
            self.__error = True

        return False


    def do_register_wkspace(self, line):
        '''Register the workspace to the Data Bank'''
        self.fz.register_current_in_data_bank()

        return False

    def do_register_last(self, line):
        '''Register last emitted data to the Data Bank'''
        self.fz.register_last_in_data_bank()

        return False

    def do_fmkdb_fetch_data(self, line):
        '''
        Fetch the data from the FMKDB and fill the Data Bank with it. If data IDs are given,
        only fetch the data between the two references.
        |_ syntax: fmkdb_fetch_data [first_data_id] [last_data_id]
        '''

        self.__error = True
        self.__error_msg = "Syntax Error!"

        args = line.split()

        if len(args) > 2:
            return False
        elif len(args) == 2:
            try:
                sid = int(args[0])
                eid = int(args[1])
            except ValueError:
                return False
        elif len(args) == 1:
            try:
                sid = int(args[0])
                eid = -1
            except ValueError:
                return False
        else:
            sid = 1
            eid = -1

        self.fz.fmkdb_fetch_data(start_id=sid, end_id=eid)

        self.__error = False
        return False

    def do_fmkdb_enable(self, line):
        '''Enable FmkDB recording'''
        self.fz.enable_fmkdb()
        return False

    def do_fmkdb_disable(self, line):
        '''Enable FmkDB recording'''
        self.fz.disable_fmkdb()
        return False

    def do_dump_db_to_file(self, line):
        '''
        Dump the Data Bank to a file in pickle format
        |_ syntax: dump_db_to_file <filename>
        '''

        if line:
            arg = line.split()[0]

            f = open(arg, 'wb')
            self.fz.dump_db_to_file(f)
            f.close()
        else:
            self.__error = True

        return False


    def do_load_db_from_file(self, line):
        '''
        Load a previous saved Data Bank from a file
        |_ syntax: load_db_from_file <filename>
        '''

        if line:
            arg = line.split()[0]

            f = open(arg, 'rb')
            self.fz.load_db_from_file(f)
            f.close()
        else:
            self.__error = True

        return False

    def do_load_db_from_text_file(self, line):
        '''
        Load a previous saved Data Bank from a file
        |_ syntax: load_db_from_text_file <filename>
        '''

        if line:
            arg = line.split()[0]

            f = open(arg, 'r')
            self.fz.load_db_from_text_file(f)
            f.close()
        else:
            self.__error = True

        return False


    def do_comment(self, line):
        if sys.version_info[0] == 2:
            comments = raw_input("*** Write your comments:\n")
        else:
            comments = input("*** Write your comments:\n")

        self.fz.log_comment(comments)
        return False

    def do_quit(self, line):
        self.fz.exit_fmk()
        return True



