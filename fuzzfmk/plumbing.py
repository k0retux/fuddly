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
import datetime
import time
import signal

from libs.external_modules import *

from fuzzfmk.database import Database
from fuzzfmk.tactics_helpers import *
from fuzzfmk.data_model import *
from fuzzfmk.data_model_helpers import DataModel
from fuzzfmk.target import *
from fuzzfmk.logger import *
from fuzzfmk.monitor import *
from fuzzfmk.operator_helpers import *
from fuzzfmk.project import *

import fuzzfmk.generic_data_makers

import data_models
import projects

from fuzzfmk.global_resources import *


sig_int_handler = signal.getsignal(signal.SIGINT)

r_pyfile = re.compile(".*\.py$")
def is_python_file(fname):
    if r_pyfile.match(fname):
        return True
    else:
        return False


class ExportableFMKOps(object):

    def __init__(self, fmk):
        self.set_fuzz_delay = fmk.set_fuzz_delay
        self.set_fuzz_burst = fmk.set_fuzz_burst
        self.set_timeout = fmk.set_timeout
        self.cleanup_all_dmakers = fmk.cleanup_all_dmakers
        self.cleanup_dmaker = fmk.cleanup_dmaker
        self.dynamic_generator_ids = fmk.dynamic_generator_ids
        self.set_error = fmk.set_error
        self.load_data_model = fmk.load_data_model
        self.load_multiple_data_model = fmk.load_multiple_data_model

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



class Fuzzer(object):

    ''' 
    Defines the methods to operate every sub-systems of fuddly
    '''

    def __init__(self):
        self.__started = False
        self.__first_loading = True

        self.error = False
        self.fmk_error = []

        self.__tg_enabled = False
        self.__prj_to_be_reloaded = False

        self._exportable_fmk_ops = ExportableFMKOps(self)

        self._generic_tactics = fuzzfmk.generic_data_makers.tactics

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
        self.__stats_dict = {}
        self.__initialized_dmaker_dict = {}
        self.__dm_rld_args_dict= {}
        self.__prj_rld_args_dict= {}

        self.__dyngenerators_created = {}
        self.__dynamic_generator_ids = {}

        self._name2dm = {}
        self._name2prj = {}

        self.fmkDB = Database()
        self.fmkDB.start()
        self._fmkDB_insert_dm_and_dmakers('generic', self._generic_tactics)
        self.fmkDB.commit()

        self.group_id = 0
        self._saved_group_id = None  # used by self._recover_target()

        self.enable_wkspace()
        self.get_data_models()
        self.get_projects()

    def set_error(self, msg='', context=None, code=Error.Reserved):
        self.error = True
        self.fmk_error.append(Error(msg, context=context, code=code))

    def get_error(self):
        self.error = False
        fmk_err = self.fmk_error
        self.fmk_error = []
        return fmk_err

    def is_not_ok(self):
        return self.error

    def __reset_fmk_internals(self, reset_existing_seed=True):
        self.cleanup_all_dmakers(reset_existing_seed)
        # Warning: fuzz delay is not set to 0 by default in order to have a time frame
        # where SIGINT is accepted from user
        self.set_fuzz_delay(0.5)
        self.set_fuzz_burst(1)

        base_timeout = self.tg._time_beetwen_data_emission
        if base_timeout is not None:
            self.set_timeout(base_timeout + 2.0)
        else:
            self.set_timeout(10)

    def _handle_user_code_exception(self, msg='', context=None):
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
        self.set_error(cause, code=Error.UserCodeError)
        if hasattr(self, 'lg'):
            self.lg.log_error("Not handled exception detected! Outcomes " \
                                "of this log entry has to be considered with caution.\n" \
                                "    (_ cause: '%s' _)" % cause)
        print("Call trace:")
        print('-'*60)
        traceback.print_exc(file=sys.stdout)
        print('-'*60)



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
            ok = self.load_multiple_data_model(name_list=name_list, reload_dm=True)
            if not ok:
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
            self._cleanup_dm_attrs_from_fmk()
            ok = self._load_data_model()
            if not ok:
                return False

            self._fmkDB_insert_dm_and_dmakers(self.dm.name, dm_params['tactics'])
            self.fmkDB.commit()

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

        self.__stop_fuzzing()

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

        self.__start_fuzzing()
        if self.is_not_ok():
            self.__stop_fuzzing()
            return False

        if prj_params is not None:
            self.__init_fmk_internals_step2(prj_params['project'], self.dm)

        return True


    def _fmkDB_insert_dm_and_dmakers(self, dm_name, tactics):
        self.fmkDB.insert_data_model(dm_name)
        disruptor_types = tactics.get_disruptors().keys()
        if disruptor_types:
            for dis_type in sorted(disruptor_types):
                disruptor_names = tactics.get_disruptors_list(dis_type)
                for dis_name in disruptor_names:
                    dis_obj = tactics.get_disruptor_obj(dis_type, dis_name)
                    stateful = True if issubclass(dis_obj.__class__, StatefulDisruptor) else False
                    self.fmkDB.insert_dmaker(dm_name, dis_type, dis_name, False, stateful)
        generator_types = tactics.get_generators().keys()
        if generator_types:
            for gen_type in sorted(generator_types):
                generator_names = tactics.get_generators_list(gen_type)
                for gen_name in generator_names:
                    gen_obj = tactics.get_generator_obj(gen_type, gen_name)
                    self.fmkDB.insert_dmaker(dm_name, gen_type, gen_name, True, True)

    def _recover_target(self):
        if self.group_id == self._saved_group_id:
            # This method can be called after checking target feedback or checking
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

    def monitor_probes(self):
        probes = self.prj.get_probes()
        ok = True
        for pname in probes:
            if self.prj.is_probe_launched(pname):
                pstatus = self.prj.get_probe_status(pname)
                err = pstatus.get_status()
                if err < 0:
                    ok = False
                    priv = pstatus.get_private_info()
                    self.lg.log_probe_feedback(source="Probe '{:s}'".format(pname), content=priv, status_code=err)

        if not ok:
            return self._recover_target()
        else:
            return True


    @EnforceOrder(initial_func=True, final_state='get_projs')
    def get_data_models(self):
        dm_dir = 'data_models'
        path = os.path.join(app_folder, dm_dir)
        data_models = collections.OrderedDict()
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
        self.fmkDB.commit()


    def __import_dm(self, prefix, name, reload_dm=False):

        try:
            if reload_dm:
                if sys.version_info[0] == 2:
                    eval('reload(' + prefix + name + ')')
                    eval('reload(' + prefix + name + '_strategy' + ')')
                else:
                    exec('import imp')
                    eval('imp.reload(' + prefix + name + ')')
                    eval('imp.reload(' + prefix + name + '_strategy' + ')')
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
        prj_dir = 'projects'
        path = os.path.join(app_folder, prj_dir)
        projects = collections.OrderedDict()
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

        self.fmkDB.commit()

        print(colorize(FontStyle.BOLD + "="*80, rgb=Color.FMKINFOGROUP))


    def _import_project(self, prefix, name, reload_prj=False):

        try:
            if reload_prj:
                if sys.version_info[0] == 2:
                    eval('reload(' + prefix + name + '_proj' + ')')
                else:
                    exec('import imp')
                    eval('imp.reload(' + prefix + name + '_proj' + ')')
            else:
                exec('import ' + prefix + name + '_proj')
        except:
            if reload_prj:
                print(colorize("*** Problem during reload of '%s_proj.py' ***" % (name), rgb=Color.ERROR))
            else:
                print(colorize("*** Problem during import of '%s_proj.py' ***" % (name), rgb=Color.ERROR))
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
                    if isinstance(obj, list) or isinstance(obj, tuple):
                        tg = obj[0]
                        obj = obj[1:]
                        tg.remove_probes()
                        for p in obj:
                            tg.add_probe(p)
                    else:
                        assert(issubclass(obj.__class__, Target))
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
            stats = self.__stats_dict.pop(old_prj)
            lg = self.__logger_dict.pop(old_prj)
            tg = self.__target_dict.pop(old_prj)
            self.__target_dict[project] = target
            self.__logger_dict[project] = logger
            self.__stats_dict[project] = Stats(self._generic_tactics.get_generators())
            self.__monitor_dict[project] = Monitor(project, fmk_ops=self._exportable_fmk_ops)
            self.__monitor_dict[project].set_logger(self.__logger_dict[project])
            self._prj_dict[project].set_logger(self.__logger_dict[project])
            self._prj_dict[project].set_monitor(self.__monitor_dict[project])
            self.__logger_dict[project].set_stats(self.__stats_dict[project])
        else:
            self._prj_dict[project] = project
            self.__target_dict[project] = target
            self.__logger_dict[project] = logger
            self.__stats_dict[project] = Stats(self._generic_tactics.get_generators())
            self.__monitor_dict[project] = Monitor(project, fmk_ops=self._exportable_fmk_ops)
            self.__monitor_dict[project].set_logger(self.__logger_dict[project])
            self._prj_dict[project].set_logger(self.__logger_dict[project])
            self._prj_dict[project].set_monitor(self.__monitor_dict[project])
            self.__logger_dict[project].set_stats(self.__stats_dict[project])

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

    def __start_fuzzing(self):
        if not self.__is_started():
            signal.signal(signal.SIGINT, signal.SIG_IGN)

            ok = self._load_data_model()
            if not ok:
                self.set_error("Project cannot be launched because of data model loading error")
                return

            self.lg.start()
            try:
                ok = self.tg._start()
            except:
                self._handle_user_code_exception()
                self.set_error("The Target has not been initialized correctly (checkup" \
                               " the associated '%s_strategy.py' file)" % self.dm.name)
            else:
                if ok:
                    self.__enable_target()
                    self.__mon.start()
                    for p in self.tg.probes:
                        pname, delay = self._extract_info_from_probe(p)
                        if delay is None:
                            self.__mon.start_probe(pname)
                        else:
                            self.__mon.set_probe_delay(pname, delay)
                            self.__mon.start_probe(pname)
                    self.prj.start()
                else:
                    self.set_error("The Target has not been initialized correctly")
            
            self.__current = []
            self.__db_idx = 0
            self.__data_bank = {}

            self.__start()


    def __stop_fuzzing(self):
        if self.__is_started():
            signal.signal(signal.SIGINT, sig_int_handler)

            if self.is_target_enabled():
                self.log_target_residual_feedback()

            if self.is_target_enabled():
                self.__mon.stop()
                try:
                    self.tg._stop()
                except:
                    self._handle_user_code_exception()
                finally:
                    self.__disable_target()

            self.lg.stop()
            self.__stats.reset()
            self.prj.stop()

            self.__stop()

        # TODO: propose to save the data bank


    @EnforceOrder(accepted_states=['20_load_prj','25_load_dm','S1','S2'])
    def exit_fuzzer(self):
        self.__stop_fuzzing()
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
        if isinstance(p, list) or isinstance(p, tuple):
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
        print(colorize(FontStyle.BOLD + '\n-=[ FMK Internals ]=-\n', rgb=Color.INFO))
        print(colorize('                     Fuzz delay: ', rgb=Color.SUBINFO) + str(self._delay))
        print(colorize('   Number of data sent in burst: ', rgb=Color.SUBINFO) + str(self._burst))
        print(colorize('    Target health-check timeout: ', rgb=Color.SUBINFO) + str(self._timeout))
        print(colorize('              Workspace enabled: ', rgb=Color.SUBINFO) + repr(self._wkspace_enabled))



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

    @EnforceOrder(accepted_states=['S2'])
    def show_stats(self):
        self.lg.print_console('-=[ Current Stats ]=-\n', nl_after=True, rgb=Color.INFO, style=FontStyle.BOLD)
        stats = self.__stats.get_formated_stats()
        print(stats)


    def __init_fmk_internals_step1(self, prj, dm):
        self.prj = prj
        self.dm = dm
        self.lg = self.__logger_dict[prj]
        try:
            self.tg = self.__target_dict[prj][self.__current_tg]
        except IndexError:
            self.__current_tg = 0
            self.tg = self.__target_dict[prj][self.__current_tg]
            
        self.tg.set_logger(self.lg)
        self.prj.set_target(self.tg)

        if self.__first_loading:
            self.__first_loading = False
        else:
            # Clear all cloned dmakers
            self._generic_tactics.clear_generator_clones()
            self._generic_tactics.clear_disruptor_clones()
            self._tactics.clear_generator_clones()
            self._tactics.clear_disruptor_clones()

        self._tactics = self.__st_dict[dm]
        # self._tactics.set_target(self.tg)

        self.__mon = self.__monitor_dict[prj]
        self.__stats = self.__stats_dict[prj]
        self.__initialized_dmakers = self.__initialized_dmaker_dict[prj]
        self.__stats_countdown = 9

    def __init_fmk_internals_step2(self, prj, dm):
        self._recompute_current_generators()
        # need the logger active
        self.__reset_fmk_internals()


    def _recompute_current_generators(self):
        specific_gen = self._tactics.get_generators()
        generic_gen = self._generic_tactics.get_generators()
        self.__current_gen = list(specific_gen.keys()) + list(generic_gen.keys())

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

        if reload_dm or new_dm.name not in map(lambda x: x.name, self.dm_list):
            self.fmkDB.insert_data_model(new_dm.name)
            self.__add_data_model(new_dm, new_tactics,
                                  (None, dm_list),
                                  reload_dm=reload_dm)
            self.fmkDB.commit()

            # In this case DynGens have already been generated through
            # the reloading of the included DMs
            self.__dyngenerators_created[new_dm] = True
            self.__dynamic_generator_ids[new_dm] = dyn_gen_ids
            self.dm = new_dm

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

        ok = self.launch()
        if not ok:
            return False

        return True


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

        self.__stop_fuzzing()

        return True


    @EnforceOrder(accepted_states=['S1'], final_state='S2')
    def launch(self):
        if not self.__prj_to_be_reloaded:
            self.__init_fmk_internals_step1(self.prj, self.dm)
            self.__start_fuzzing()
            if self.is_not_ok():
                self.__stop_fuzzing()
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
        self.__send_enabled = True
        self.__mon.enable_hooks()

    def __disable_target(self):
        self.__tg_enabled = False
        self.__send_enabled = False
        self.__mon.disable_hooks()

    @EnforceOrder(always_callable=True)
    def enable_wkspace(self):
        self._wkspace_enabled = True

    @EnforceOrder(always_callable=True)
    def disable_wkspace(self):
        self._wkspace_enabled = False

    @EnforceOrder(accepted_states=['S1','S2'])
    def set_fuzz_delay(self, delay):
        if delay >= 0 or delay == -1:
            self._delay = delay
            self.lg.log_fmk_info('Fuzz delay = {:.1f}s'.format(self._delay))
            return True
        else:
            self.lg.log_fmk_info('Wrong delay value!')
            return False

    @EnforceOrder(accepted_states=['S1','S2'])
    def set_fuzz_burst(self, val):
        if val >= 1:
            self._burst = int(val)
            self._burst_countdown = self._burst
            self.lg.log_fmk_info('Number of data sent in burst = %d' % self._burst)
            return True
        else:
            self.lg.log_fmk_info('Wrong burst value!')
            return False

    @EnforceOrder(accepted_states=['S1','S2'])
    def set_timeout(self, timeout):
        if timeout >= 0:
            self._timeout = timeout
            self.lg.log_fmk_info('Target health-check timeout = {:.1f}s'.format(self._timeout))
            return True
        else:
            self.lg.log_fmk_info('Wrong timeout value!')
            return False


    # Used to introduce some delay after sending data
    def __delay_fuzzing(self):
        '''
        return False if the user want to stop fuzzing (action possible if
        delay is set to -1)
        '''
        ret = True
        if self._burst_countdown <= 1:
            self._burst_countdown = self._burst

            if self.__send_enabled:
                if self._delay == -1.0:
                    try:
                        signal.signal(signal.SIGINT, sig_int_handler)
                        if sys.version_info[0] == 2:
                            cont = raw_input("\n*** Press [ENTER] to continue ('q' to exit).")
                        else:
                            cont = input("\n*** Press [ENTER] to continue ('q' to exit).")
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

    @EnforceOrder(accepted_states=['S2'])
    def send_data_and_log(self, data_list, original_data=None, verbose=False):

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

        if self._wkspace_enabled:
            for idx, dt in zip(range(len(data_list)), data_list):
                if orig_data_provided:
                    self.__current.append((original_data[idx], dt))
                else:
                    self.__current.append((None, dt))

        if self._burst_countdown == self._burst:
            # log residual just before sending new data to avoid
            # polluting feedback logs of the next emission
            cont = self.log_target_residual_feedback()
            if not cont:
                return False

        self.new_transfer_preamble()
        self.send_data(data_list)

        ret = self.check_target_readiness()
        if ret < 0:
            cont0 = False
        else:
            cont0 = True

        if orig_data_provided:
            for dt_orig in original_data:
                if dt_orig is not None:
                    dt_orig.make_exportable()

        for dt in data_list:
            dt.make_exportable()

        if multiple_data:
            self.log_data(data_list, original_data=original_data, get_target_ack=cont0,
                          verbose=verbose)
        else:
            orig = None if not orig_data_provided else original_data[0]
            self.log_data(data_list[0], original_data=orig, get_target_ack=cont0,
                          verbose=verbose)

        if cont0:
            cont1 = self.__delay_fuzzing()
        else:
            cont1 = False

        cont3 = True
        cont4 = True
        # That means this is the end of a burst
        if self._burst_countdown == self._burst:
            cont3 = self.log_target_feedback()
            # We handle probe feedback if any
            cont4 = self.monitor_probes()
            self.tg.cleanup()

        cont2 = self.__mon.do_after_sending_and_logging_data()

        return cont0 and cont1 and cont2 and cont3 and cont4

    @EnforceOrder(accepted_states=['S2'])
    def send_data(self, data_list):
        '''
        @data_list: either a list of Data() or a Data()
        '''
        if self.__send_enabled:

            # Monitor hook function before sending
            self.__mon.do_before_sending_data()

            try:
                # Allow the Target object to act before the FMK send data
                self.tg.do_before_sending_data(data_list)

                if len(data_list) == 1:
                    self.tg.send_data(data_list[0])
                elif len(data_list) > 1:
                    self.tg.send_multiple_data(data_list)
                else:
                    raise ValueError
            except TargetStuck as e:
                self.lg.log_comment("*** WARNING: Unable to send data to the target! [reason: %s]" % str(e))

            except:
                self._handle_user_code_exception()

            if self.__stats_countdown < 1:
                self.__stats_countdown = 9
                self.lg.log_stats()
            else:
                self.__stats_countdown -= 1

            # Monitor hook function after sending
            self.__mon.do_after_sending_data()

            # Monitor hook before resuming sending data
            self.__mon.do_before_resuming_sending_data()

    @EnforceOrder(accepted_states=['S2'])
    def log_data(self, data_list, original_data=None, get_target_ack=True, verbose=False):

        if self.__send_enabled:
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
                 self.lg.log_fmk_info("MULTIPLE DATA EMISSION", nl_after=True)

            if get_target_ack:
                ack_date = self.tg.get_last_target_ack_date()
            else:
                ack_date = None
            self.lg.log_target_ack_date(ack_date)

            for idx, dt in zip(range(len(data_list)), data_list):
                dt_mk_h = dt.get_history()
                if multiple_data:
                    self.lg.log_fmk_info("Data #%d" % (idx+1), nl_before=True)
                    self.lg.log_fn("--------------------------", rgb=Color.SUBINFO)

                gen_info = dt.get_initial_dmaker()
                gen_type_initial, gen_name, gen_ui = gen_info if gen_info is not None else (None, None, None)
                if gen_type_initial is not None:
                    parsed = self.check_clone_re.match(gen_type_initial)
                    if parsed is not None:
                        gen_type = parsed.group(1)
                    else:
                        gen_type = gen_type_initial
                else:
                    gen_type = gen_type_initial

                self.__stats.inc_stat(gen_type, gen_name, gen_ui)

                num = 1

                data_id = dt.get_data_id()
                # if data_id is not None, the data has been created from fmkDB
                # because new data have not a data_id yet at this point in the code.
                if data_id is not None:
                    self.lg.log_fuzzing_step(num)
                    self.lg.log_generator_info(gen_type_initial, gen_name, None, data_id=data_id)
                    self.lg.log_data_info(("Data fetched from FMKDB",), gen_type_initial, gen_name)

                if dt_mk_h is not None:
                    if orig_data_provided:
                        self.lg.log_orig_data(original_data[idx])
                    else:
                        self.lg.log_orig_data(None)

                    dt.init_read_info()

                    for dmaker_type, data_maker_name, user_input in dt_mk_h:
                        num += 1

                        if num == 1 and data_id is None:
                            # if data_id is not None then no need to log an initial generator
                            # because data comes from FMKDB
                            if dmaker_type != gen_type_initial:
                                self.lg.log_initial_generator(gen_type_initial, gen_name, gen_ui)

                        self.lg.log_fuzzing_step(num)

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

                        info = dt.read_info(data_maker_name, dmaker_type)
                        self.lg.log_data_info(info, dmaker_type, data_maker_name)

                else:
                    if gen_type_initial is None:
                        self.lg.log_fuzzing_step(1)
                        self.lg.log_generator_info(Database.DEFAULT_GTYPE_NAME,
                                                   Database.DEFAULT_GEN_NAME,
                                                   None)
                        self.lg.log_data_info(("RAW DATA (data makers not provided)",),
                                              Database.DEFAULT_GTYPE_NAME, Database.DEFAULT_GEN_NAME)

                self.lg.log_data(dt, verbose=verbose)
                if multiple_data:
                    self.lg.log_fn("--------------------------", rgb=Color.SUBINFO)

                data_id = self.lg.commit_log_entry(self.group_id)
                if data_id is not None:
                    tg_name = self._get_detailed_target_desc(self.tg)
                    self.lg.commit_project_record(dt, self.prj.name, tg_name)

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
        if self.__send_enabled:
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
        if self.__send_enabled:
            p = "\n::[ RESIDUAL TARGET FEEDBACK ]::"
            e = "::[ ------------------------ ]::\n"
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
                self.lg.log_comment('Error detected with the target (error code: {:d}) !'.format(err_code))
                err_detected = True

            if tg_fbk.has_fbk_collector():
                for ref, fbk in tg_fbk:
                    self.lg.log_target_feedback_from(fbk, preamble=preamble, epilogue=epilogue,
                                                     source=ref, status_code=err_code)
            else:
                self.lg.log_target_feedback_from(tg_fbk.get_bytes(), preamble=preamble,
                                                 epilogue=epilogue, status_code=err_code)

            tg_fbk.cleanup()

        return err_detected

    @EnforceOrder(accepted_states=['S2'])
    def check_target_readiness(self):

        if self.__send_enabled:
            t0 = datetime.datetime.now()

            # Wait until the target is ready or timeout expired
            try:
                signal.signal(signal.SIGINT, sig_int_handler)
                ret = 0
                while not self.tg.is_target_ready_for_new_data():
                    time.sleep(0.2)
                    now = datetime.datetime.now()
                    if (now - t0).total_seconds() > self._timeout:
                        self.lg.log_comment("*** Timeout! The target does not seem to be ready.\n")
                        ret = -1
                        break
            except KeyboardInterrupt:
                self.lg.log_comment("*** Waiting for target to become ready has been cancelled by the user!\n")
                self.set_error("Waiting for target to become ready has been cancelled by the user!",
                               code=Error.OperationCancelled)
                ret = -2
            except:
                self._handle_user_code_exception()
                ret = -3
            finally:
                signal.signal(signal.SIGINT, signal.SIG_IGN)

            return ret

    @EnforceOrder(accepted_states=['S2'])
    def show_data(self, data, verbose=True):
        if not data.node:
            return

        self.lg.print_console('-=[ Data Paths ]=-\n', rgb=Color.INFO, style=FontStyle.BOLD)
        data.node.show(raw_limit=400)
        self.lg.print_console('\n\n', nl_before=False)


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
            if dm_name != Database.DEFAULT_DM_NAME:
                dm = self.get_data_model_by_name(dm_name)
                data.set_data_model(dm)
            self.__register_in_data_bank(None, data)

    @EnforceOrder(accepted_states=['S2'])
    def get_last_data(self):
        if not self._wkspace_enabled:
            self.set_error('Workspace is disabled!',
                           code=Error.CommandError)
            return None, None

        if self.__current:
            entry = self.__current[-1]
            return entry

    @EnforceOrder(accepted_states=['S2'])
    def get_from_data_bank(self, i):
        try:
            entry = self.__data_bank[i]
        except KeyError:
            return (None, None, None)

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
            data.init_read_info()
            for dmaker_type, data_maker_name, user_input in data_makers_history:
                if dmaker_type in gen:
                    if user_input:
                        msg = "|- data id: %d | generator type: %s | generator name: %s | User input: %s" % \
                            (data_id, dmaker_type, data_maker_name, user_input)
                    else:
                        msg = "|- data id: %d | generator type: %s | generator name: %s | No user input" % \
                            (data_id, dmaker_type, data_maker_name)
                else:
                    if user_input:
                        msg = "|- disruptor type: %s | data_maker name: %s | User input: %s" % \
                            (dmaker_type, data_maker_name, user_input)
                    else:
                        msg = "|- disruptor type: %s | data_maker name: %s | No user input" % \
                            (dmaker_type, data_maker_name)
                self.lg.print_console(msg, rgb=Color.SUBINFO)

                self.lg.print_console("|- data info:", rgb=Color.SUBINFO)
                data_info = data.read_info(data_maker_name, dmaker_type)
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
            msg = "|- data id: {:d} | type: {:s} | data model: {:s}".format(
                data_id, dtype, dm_name
            )
            self.lg.print_console(msg, rgb=Color.SUBINFO)

        self.lg.print_console('|_ OUT > ', rgb=Color.SUBINFO)
        self.lg.print_console(data, nl_before=False)
        self.lg.print_console('==============================\n', rgb=Color.INFO)


    @EnforceOrder(accepted_states=['S2'])
    def show_data_bank(self):
        self.lg.print_console("-=[ Data Bank ]=-\n", rgb=Color.INFO, style=FontStyle.BOLD)

        for idx, entry in self.__data_bank.items():
            self.lg.print_console('==[ %d ]=======================' % idx, rgb=Color.INFO)
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
            desc = self.__dmaker_desc_str(self.prj.get_operator_obj(o))
            self.lg.print_console(desc, limit_output=False)

        self.lg.print_console('\n\n', nl_before=False)


    @EnforceOrder(accepted_states=['S2'])
    def launch_operator(self, name, user_input, use_existing_seed=True, verbose=False):
        
        operator = self.prj.get_operator_obj(name)
        if operator is None:
            self.set_error('Invalid operator', code=Error.InvalidOp)
            return False

        self.__reset_fmk_internals(reset_existing_seed=(not use_existing_seed))

        try:
            ok = operator._start(self._exportable_fmk_ops, self.dm, self.__mon, self.tg, self.lg, user_input)
        except:
            ok = False
            self._handle_user_code_exception('Operator has crashed during its start() method')
            return False

        if not ok:
            self.set_error("The _start() method of Operator '%s' has returned an error!" % name,
                           code=Error.UnrecoverableError)
            return False

        fmk_feedback = FmkFeedback()

        exit_operator = False
        while True:

            if exit_operator:                
                break

            try:
                operation = operator.plan_next_operation(self._exportable_fmk_ops, self.dm,
                                                         self.__mon, self.tg, self.lg, fmk_feedback)

                if operation is None:
                    self.set_error("An operator shall always return an Operation() object in its plan_next_operation()",
                                   code=Error.UserCodeError)
                    return False

            except:
                self._handle_user_code_exception('Operator has crashed during its plan_next_operation() method')
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
                for instruction, idx in zip(instr_list, range(len(instr_list))):
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

                if len(data_list) == 1:
                    multiple_data = False
                else:
                    multiple_data = True

                fmk_feedback.clear_flag(FmkFeedback.NeedChange)

                if self._burst_countdown == self._burst:
                    # log residual just before sending new data to avoid
                    # polluting feedback logs of the next emission
                    cont = self.log_target_residual_feedback()
                    if not cont:
                        self.lg.log_fmk_info("Operator will shutdown because residual target "
                                             "feedback indicate a negative status code")
                        break

                self.new_transfer_preamble()

                self.send_data(data_list)

                ret = self.check_target_readiness()
                # Note: the condition (ret = -1) is supposed to be managed by the operator
                if ret < 0:
                    get_target_ack = False
                else:
                    get_target_ack = True
 
                if ret < -1:
                    exit_operator = True
                    if ret == -2:
                        self.lg.log_fmk_info("Operator will shutdown because waiting has been cancelled by the user")
                    elif ret == -3:
                        self.lg.log_fmk_info("Operator will shutdown because of exception in user code")
                
                try:
                    linst = operator.do_after_all(self._exportable_fmk_ops, self.dm, self.__mon, self.tg, self.lg)
                except:
                    self._handle_user_code_exception('Operator has crashed during its .do_after_all() method')
                    return False

                if linst.is_instruction_set(LastInstruction.ExportData):
                    for dt in data_list:
                        dt.make_exportable()
                        self.__register_in_data_bank(None, dt.flatten_copy())

                if multiple_data:
                    self.log_data(data_list, get_target_ack=get_target_ack, verbose=verbose)
                else:
                    self.log_data(data_list[0], get_target_ack=get_target_ack, verbose=verbose)

                # Delay introduced after logging data
                cont = self.__delay_fuzzing()
                if not cont:
                    exit_operator = True
                    self.lg.log_fmk_info("Operator will shutdown because waiting has been cancelled by the user")

                if linst.is_instruction_set(LastInstruction.ExportData):
                    # Target fbk is logged only at the end of a burst
                    if self._burst_countdown == self._burst:
                        cont1 = self.log_target_feedback()
                        cont2 = self.monitor_probes()
                        if not cont1 or not cont2:
                            exit_operator = True
                            self.lg.log_fmk_info("Operator will shutdown because something is going wrong with "
                                                 "the target and the recovering procedure did not succeed...")

                    op_feedback = linst.get_operator_feedback()
                    op_status = linst.get_operator_status()
                    if op_feedback or op_status:
                        self.lg.log_operator_feedback(op_feedback,
                                                      status_code=op_status)
                else:
                    op_status = None

                comments = linst.get_comments()
                if comments:
                    self.lg.log_comment(comments)

                if op_status is not None and op_status < 0:
                    exit_operator = True
                    self.lg.log_fmk_info("Operator will shutdown because it returns a negative status")

                if self._burst_countdown == self._burst:
                    self.tg.cleanup()
        try:
            operator.stop(self._exportable_fmk_ops, self.dm, self.__mon, self.tg, self.lg)
        except:
            self._handle_user_code_exception('Operator has crashed during its stop() method')
            return False

        self.__reset_fmk_internals(reset_existing_seed=(not use_existing_seed))

        return True

    @EnforceOrder(accepted_states=['S2'])
    def get_data(self, action_list, data_orig=None, valid_gen=False, save_seed=False):
        '''
        @action_list shall have the following format:
        [(action_1, generic_UI_1, specific_UI_1), ...,
         (action_n, generic_UI_1, specific_UI_1)]

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

        get_dmakers = self._tactics.get_generators
        get_gen_dmakers = self._generic_tactics.get_generators
        clone_dmaker = self._tactics.clone_generator
        clone_gen_dmaker = self._generic_tactics.clone_generator

        if data_orig != None:
            data = copy.copy(data_orig)
            initial_generator_info = data.get_initial_dmaker()
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

            if isinstance(full_action, list) or isinstance(full_action, tuple):
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
                get_dmakers = self._tactics.get_disruptors
                get_gen_dmakers = self._generic_tactics.get_disruptors
                clone_dmaker = self._tactics.clone_disruptor
                clone_gen_dmaker = self._generic_tactics.clone_disruptor

            if isinstance(action, list) or isinstance(action, tuple):
                dmaker_type = action[0]
                provided_dmaker_name = action[1]
                dmaker_ref = 'type: ' + dmaker_type + ', name: ' + provided_dmaker_name
            else:
                dmaker_type = action
                provided_dmaker_name = None
                dmaker_ref = dmaker_type

            # Handle cloned data makers or data makers to be cloned
            if dmaker_type not in get_dmakers() and dmaker_type not in get_gen_dmakers():
                parsed = self.check_clone_re.match(dmaker_type)
                if parsed is not None:
                    cloned_dmaker_type = parsed.group(1)
                    dmaker_type = parsed.group(0)

                    err_msg = "Can't clone: invalid generator/disruptor IDs (%s)" % dmaker_ref

                    if cloned_dmaker_type in get_dmakers():
                        ok, cloned_dmaker_name = clone_dmaker(cloned_dmaker_type, new_dmaker_type=dmaker_type, dmaker_name=provided_dmaker_name)
                        self._recompute_current_generators()
                        dmaker_obj = get_dmaker_obj(dmaker_type, cloned_dmaker_name)
                    elif cloned_dmaker_type in get_gen_dmakers():
                        ok, cloned_dmaker_name = clone_gen_dmaker(cloned_dmaker_type, new_dmaker_type=dmaker_type, dmaker_name=provided_dmaker_name)
                        self._recompute_current_generators()
                        dmaker_obj = get_generic_dmaker_obj(dmaker_type, cloned_dmaker_name)
                    else:
                        self.set_error(err_msg, code=Error.CloneError)
                        return None

                    assert(dmaker_obj is not None)
                    is_gen = True if issubclass(dmaker_obj.__class__, Generator) else False
                    if is_gen:
                        stateful = True
                    else:
                        stateful = True if issubclass(dmaker_obj.__class__, StatefulDisruptor) else False

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
                    if isinstance(dmaker_obj, Generator):
                        if dmaker_obj.produced_seed is not None:
                            data = Data(dmaker_obj.produced_seed.get_contents(copy=True))
                        else:
                            data = dmaker_obj.generate_data(self.dm, self.__mon,
                                                            self.tg)
                            if save_seed and dmaker_obj.produced_seed is None:
                                # Usefull to replay from the beginning a modelwalking sequence
                                data.materialize()
                                dmaker_obj.produced_seed = Data(data.get_contents(copy=True))
                    elif isinstance(dmaker_obj, Disruptor):
                        data = dmaker_obj.disrupt_data(self.dm, self.tg, data)
                    elif isinstance(dmaker_obj, StatefulDisruptor):
                        ret = dmaker_obj._set_seed(data)
                        if isinstance(ret, Data):
                            data = ret
                            dmaker_obj.set_attr(DataMakerAttr.NeedSeed)
                        else:
                            data = dmaker_obj.disrupt_data(self.dm, self.tg, data)
                    else:
                        raise ValueError

                    if data is None:
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


                # If a generator need a reset or a ('controller') disruptor has handed over
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
                    self.set_error("Disruptor '{:s}' ({:s}) has handed over!".format(dmaker_name, dmaker_type),
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

            data.bind_info(dmaker_name, dmaker_type)
            l.append((dmaker_type, dmaker_name, user_input))
            first = False

        if unrecoverable_error:
            return None

        data.set_history(l)
        data.set_initial_dmaker(initial_generator_info)
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
    def register_data_to_wkspace(self, data):
        if not self._wkspace_enabled:
            self.set_error('Workspace is disabled!', code=Error.CommandError)
            return

        self.__current.append((None, data, None))

    @EnforceOrder(accepted_states=['S2'])
    def set_disruptor_weight(self, dmaker_type, data_maker_name, weight):
        self._tactics.set_disruptor_weight(dmaker_type, data_maker_name, weight)

    @EnforceOrder(accepted_states=['S2'])
    def set_generator_weight(self, generator_type, data_maker_name, weight):
        self._tactics.set_generator_weight(generator_type, data_maker_name, weight)

    @EnforceOrder(accepted_states=['S2'])
    def show_probes(self):
        probes = self.prj.get_probes()
        self.lg.print_console('-=[ Probes ]=-', rgb=Color.INFO, style=FontStyle.BOLD)
        self.lg.print_console('')
        for p in probes:
            msg = "name: %s (status: %s, delay: %f) --> launched: %r" % \
                (p, repr(self.prj.get_probe_status(p).get_status()),
                 self.prj.get_probe_delay(p),
                 self.prj.is_probe_launched(p))
            self.lg.print_console(msg, rgb=Color.SUBINFO)

        self.lg.print_console('\n', nl_before=False)


    @EnforceOrder(accepted_states=['S2'])
    def launch_probe(self, name):
        ok = self.__mon.start_probe(name)
        if not ok:
            self.set_error('Probe does not exist (or already launched)',
                           code=Error.CommandError)
        return ok

    @EnforceOrder(accepted_states=['S2'])
    def stop_all_probes(self):
        self.__mon.stop_all_probes()

    @EnforceOrder(accepted_states=['S2'])
    def stop_probe(self, name):
        self.__mon.stop_probe(name)

    @EnforceOrder(accepted_states=['S2'])
    def get_probe_delay(self, name):
        self.__mon.get_probe_delay(name)

    @EnforceOrder(accepted_states=['S2'])
    def set_probe_delay(self, name, delay):
        ok = self.__mon.set_probe_delay(name, delay)
        if not ok:
            self.set_error("Probe '%s' does not exist" % name,
                           code=Error.CommandError)
        return ok

    @EnforceOrder(accepted_states=['S2'])
    def show_data_maker_types(self):
        disruptors = self._tactics.get_disruptors()
        generators = self._tactics.get_generators()

        self.lg.print_console('==[ Generator types ]=====')
        l1 = []
        for dt in self._tactics.get_generators():
            l1.append(dt)
        l1 = sorted(l1)

        l2 = []
        for dt in self._generic_tactics.get_generators():
            l2.append(dt)
        l2 = sorted(l2)

        l = l1 + ['...'] + l2

        self.lg.print_console('')
        for i in l:
            self.lg.print_console(i + ' | ', nl_before=False)

        self.lg.print_console('\n', nl_before=False)

        self.lg.print_console('==[ Disruptor types ]========')
        l1 = []
        for dmaker_type in self._tactics.get_disruptors():
            l1.append(dmaker_type)
        l1 = sorted(l1)

        l2 = []
        for dmaker_type in self._generic_tactics.get_disruptors():
            l2.append(dmaker_type)
        l2 = sorted(l2)

        l = l1 + ['...'] + l2

        self.lg.print_console('')
        for i in l:
            self.lg.print_console(i + ' | ', nl_before=False)

        self.lg.print_console('\n\n', nl_before=False)


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
        generators = self._tactics.get_generators().keys()
        gen_generators = self._generic_tactics.get_generators().keys()
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
        disruptors = self._tactics.get_disruptors().keys()
        gen_disruptors = self._generic_tactics.get_disruptors().keys()
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
    


class FuzzShell(cmd.Cmd):

    def __init__(self, title, fuzzer, completekey='tab', stdin=None, stdout=None):
        cmd.Cmd.__init__(self, completekey, stdin, stdout)
        self.fz = fuzzer
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

        signal.signal(signal.SIGINT, signal.SIG_IGN)


    def postcmd(self, stop, line):
        printed_err = False
        print('')
        if self.fz.is_not_ok() or self.__error:
            printed_err = True
            msg = '| ERROR / WARNING |'
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
        if self.fz.is_usable():
            return line

        elif self.__allowed_cmd.match(line):
            return line

        else:
            self.__error = True
            self.__error_msg = 'You shall first load a project and/or enable all fuzzing components!'
            return ''


    def do_show_projects(self, line):
        '''Show the available Projects'''
        self.fz.show_projects()

        return False


    def do_show_data_models(self, line):
        '''Show the available Data Models'''
        self.fz.show_data_models()

        return False


    def do_show_stats(self, line):
        '''Show the current generated data stats'''
        self.fz.show_stats()

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
        '''
        args = line.split()

        self.__error = True

        if len(args) < 2:
            return False
        try:
            nb = int(args.pop(0))
            if nb < 2:
                return False
        except ValueError:
            return False

        t = self.__parse_instructions(args)
        if t is None:
            self.__error_msg = "Syntax Error!"
            return False

        for i in range(nb):
            data = self.fz.get_data(t, valid_gen=valid_gen, save_seed=use_existing_seed)

            if data is None:
                return False

            cont = self.fz.send_data_and_log(data)

            if not cont:
                break
 
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



    def do_set_timeout(self, line):
        '''
        Set the timeout when the FMK checks the target readiness (Default = 10).
        |  syntax: set_timeout <arg>
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
            self.fz.set_timeout(timeout)
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
        self.fz.exit_fuzzer()
        return True



