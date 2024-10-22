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

from functools import wraps, partial
from typing import Sequence

from fuddly.framework.data import Data, DataProcess
from fuddly.framework.database import FeedbackGate
from fuddly.framework.knowledge.feedback_collector import FeedbackSource
from fuddly.framework.error_handling import *
from fuddly.framework.evolutionary_helpers import EvolutionaryScenariosFactory
from fuddly.framework.logger import *
from fuddly.framework.monitor import *
from fuddly.framework.operator_helpers import *
from fuddly.framework.project import *
from fuddly.framework.scenario import *
from fuddly.framework.tactics_helpers import *
from fuddly.framework.target_helpers import *
from fuddly.framework.cosmetics import aligned_stdout
from fuddly.framework.config import config, config_dot_proxy
from fuddly.libs.utils import *

from fuddly.framework import generic_data_makers

from fuddly.framework.global_resources import *
from fuddly.libs.utils import *

import importlib
from importlib.metadata import entry_points

import io

sys.path.insert(0, fuddly_data_folder)
sys.path.insert(0, external_libs_folder)

sig_int_handler = signal.getsignal(signal.SIGINT)

r_pyfile = re.compile(r'.*\.py$')
def is_python_file(fname):
    return r_pyfile.match(fname)


class Printer(io.StringIO):
    def __init__(self, fmk):
        io.StringIO.__init__(self)
        self.fmk = fmk

    def start(self):
        pass

    def stop(self):
        pass

    def write(self, data):
        if False and self.fmk.lg:
            self.fmk.lg.write(data)
        else:
            sys.__stdout__.write(data)

    def flush(self):
        if self.fmk.lg:
            self.fmk.lg.flush()
        else:
            sys.__stdout__.flush()

    def wait_for_sync(self):
        if self.fmk.lg:
            self.fmk.lg.wait_for_sync()

    def print(self, msg):
        self.write(msg + "\n")
        self.flush()


class ExportableFMKOps(object):
    def __init__(self, fmk):
        self.set_sending_delay = fmk.set_sending_delay
        self.set_sending_burst_counter = fmk.set_sending_burst_counter
        self.set_health_check_timeout = fmk.set_health_check_timeout
        self.cleanup_all_dmakers = fmk.cleanup_all_dmakers
        self.cleanup_dmaker = fmk.cleanup_dmaker
        self.dynamic_generator_ids = fmk.dynamic_generator_ids
        self.set_error = fmk.set_error
        self.load_data_model = fmk.load_data_model
        self.load_multiple_data_model = fmk.load_multiple_data_model
        self.reload_all = fmk.reload_all
        self.process_data = fmk.process_data
        self.unregister_task = fmk._unregister_task
        self.handle_data_desc = fmk.handle_data_desc


class FmkFeedback(object):
    NeedChange = 1

    def __init__(self):
        self.flags = {FmkFeedback.NeedChange: (False, None)}

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

    def __init__(self, accepted_states=None, final_state=None, reset_sm=False,
                 initial_func=False, always_callable=False, transition=None):
        accepted_states = [] if accepted_states is None else accepted_states
        if initial_func:
            self.accepted_states = accepted_states + [None]
        else:
            self.accepted_states = accepted_states
        self.final_state = final_state
        self.always_callable = always_callable
        self.transition = transition
        self.reset_sm = reset_sm

    def __call__(self, func):
        @wraps(func)
        def wrapped_func(*args, **kargs):
            if not self.always_callable and EnforceOrder.current_state not in self.accepted_states:
                print(colorize("[INVALID CALL] function '%s' cannot be called in the state '%r'!" \
                                       % (func.__name__, EnforceOrder.current_state),
                               rgb=Color.ERROR))
                return False
            ok = func(*args, **kargs)
            if (ok or ok is None) and self.reset_sm:
                EnforceOrder.current_state = None
            if (ok or ok is None) and self.final_state is not None:
                EnforceOrder.current_state = self.final_state

            elif  (ok or ok is None) and self.transition is not None and EnforceOrder.current_state == self.transition[0]:
                EnforceOrder.current_state = self.transition[1]

            return ok

        return wrapped_func


class FmkTask(threading.Thread):
    def __init__( self, name, func, arg, period=None, error_func=lambda x: x, cleanup_func=lambda: None):
        threading.Thread.__init__(self)
        self._name = name
        self._func = func
        self._arg = arg
        self._period = period
        self._stop = threading.Event()
        self._error_func = error_func
        self._cleanup_func = cleanup_func
        if isinstance(func, Task):
            func.stop_event = self._stop

    def run(self):
        if isinstance(self._func, Task):
            self._func._setup()

        if isinstance(self._func, Task):
            time.sleep(self._func.init_delay)

        while not self._stop.is_set():
            try:
                # print("\n*** Function '{!s}' executed by Task '{!s}' ***".format(self._func, self._name))
                if isinstance(self._func, list):
                    for f in self._func:
                        f(self._arg)
                else:
                    self._func(self._arg)
            except DataProcessTermination:
                break
            except:
                self._error_func("Task '{!s}' has crashed!".format(self._name))
                break
            if self._period is not None:
                self._stop.wait(max(self._period, 0.0001))
            else:
                self._cleanup_func()
                break

        if isinstance(self._func, Task):
            self._func._cleanup()

    def stop(self):
        self._stop.set()


class FmkPlumbing(object):
    """
    Defines the methods to operate every sub-systems of fuddly
    """

    def __init__(self, exit_on_error=False, debug_mode=False, quiet=False,
                 external_term=False, fmkdb_path=None):
        self._debug_mode = debug_mode
        self._exit_on_error = exit_on_error
        self._quiet = quiet
        self._fmkdb_path = fmkdb_path
        self.external_display = ExternalDisplay()
        if external_term:
            self.external_display.start_term(title="Fuddly log", keepterm=True)

        self.printer = Printer(self)
        self.print = self.printer.print

        self._reset_main_objects()

    def __str__(self):
        return "Fuddly FmK"

    def _reset_main_objects(self):
        self.prj_list = []
        self.dm_list = []

        self._prj = None
        self.dm = None
        self.lg = None

        self.targets = {}  # enabled targets, further initialized as a dict (tg_id -> tg obj)
        self._tg_ids = [0]  # further initialized as a list
        self.available_targets_desc = None  # further initialized as a dict (tg -> str description)
        self._currently_used_targets = []

        self.mon = None

        self.__started = False
        self.__first_loading = True

        self._exportable_fmk_ops = ExportableFMKOps(self)
        self._name2dm = {}
        self._name2prj = {}

        self._prj_dict = {}
        self.__st_dict = {}
        self.__target_dict = {}
        self.__logger_dict = {}
        self.__monitor_dict = {}
        self.__initialized_dmaker_dict = {}
        self.__dm_rld_args_dict = {}
        self.__prj_rld_args_dict = {}
        self.__initialized_dmakers = None

        self.__dyngenerators_created = {}
        self.__dynamic_generator_ids = {}

        self._task_list = {}
        self._task_list_lock = threading.Lock()

        self._hc_timeout = {}  # health-check tiemout, further initialized as a dict (tg -> hc_timeout)
        self._hc_timeout_max = None
        # self._hc_timeout_increment = 0.01

        self._fbk_timeout_max = 0
        self._fbk_timeout_default = 0.005
        self._last_sending_date = None

        self._current_sent_date = None

        self.error = False
        self.fmk_error = []
        self._sending_error = None
        self._stop_sending = None

        self.__tg_enabled = False
        self.__prj_to_be_reloaded = False
        self._dm_to_be_reloaded = False

        self._generic_tactics = generic_data_makers.tactics
        self._generic_tactics.set_additional_info(self._exportable_fmk_ops)

        self._tactics = None
        self.last_data_id = None
        self.next_data_id = None

    @EnforceOrder(initial_func=True)
    def start(self):
        self.printer.start()

        self.check_clone_re = re.compile(r'(.*)#(\w{1,30})')

        self.config = config(self, path=[config_folder])

        external_term = self.config.terminal.external_term
        if external_term and not self.external_display.is_enabled:
            self.switch_term()

        self.fmkDB = Database(fmkdb_path=self._fmkdb_path)
        ok = self.fmkDB.start()
        if not ok:
            raise InvalidFmkDB("The database {:s} is invalid!".format(self.fmkDB.fmk_db_path))

        self.last_data_id = None
        self.next_data_id = None

        # Fbk Gate to be used for sequencial tasks (scenario steps callbacks, etc.)
        self.last_feedback_gate = FeedbackGate(self.fmkDB, only_last_entries=True)

        # Fbk Gate to be used for out-of-fmk-order tasks (e.g., Tasks). This gate is agnostic to
        # fmkdb.flush_feedback(). Thus feedback entries last longer there.
        self.feedback_gate = FeedbackGate(self.fmkDB, only_last_entries=False)

        self._fmkDB_insert_dm_and_dmakers("generic", self._generic_tactics)

        self.group_id = 0
        self._recovered_tgs = None  # used by self._recover_target()

        self.import_successfull = True
        self.get_data_models()
        if self._exit_on_error and not self.import_successfull:
            self.fmkDB.stop()
            raise DataModelDefinitionError("Error with some DM imports")

        self.get_projects()
        if self._exit_on_error and not self.import_successfull:
            self.fmkDB.stop()
            raise ProjectDefinitionError("Error with some Project imports")

        if not self._quiet:
            self.print(colorize(FontStyle.BOLD + "=" * 68 + "[ Fuddly Home Information ]==\n",
                           rgb=Color.FMKINFOGROUP))

        if not self._quiet and hasattr(gr, "new_fuddly_data_folder"):
            self.print(colorize(FontStyle.BOLD + " *** New Fuddly Home Has Been Created ***\n",
                           rgb=Color.FMKINFO_HLIGHT))

        if not self._quiet:
            self.print(colorize(" --> data folder: {:s}".format(gr.fuddly_data_folder),
                                rgb=Color.FMKINFO))
            self.print(colorize(" --> contains: - fmkDB.db, logs, imported/exported data, ...\n"
                                "               - user projects and user data models, ...",
                                rgb=Color.FMKSUBINFO))
            self.print(colorize(" --> config folder: {:s}".format(gr.config_folder),
                                rgb=Color.FMKINFO))

    def switch_term(self):
        if not self.external_display.is_enabled:
            self.external_display.start_term(title="Fuddly log", keepterm=False)
        else:
            self.external_display.stop()

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"], reset_sm=True)
    def stop(self):
        self._stop_fmk_plumbing()
        self.fmkDB.stop()
        self._reset_main_objects()
        self.printer.stop()
        if self.external_display.is_enabled:
            self.external_display.stop()

    @property
    def prj(self):
        return self._prj

    @prj.setter
    def prj(self, obj):
        self._prj = obj
        self.fmkDB.current_project = obj

    def set_error(self, msg="", context=None, code=Error.Reserved):
        self.error = True
        self.fmk_error.append(Error(msg, context=context, code=code))
        if self.lg:
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

    def show_and_flush_errors(self):
        err_list = self.get_error()
        for e in err_list:
            self.print(colorize("    (_ [#{err!s:s}]: {msg:s} _)".format(err=e, msg=e.msg),rgb=e.color))

    def flush_errors(self):
        self.error = False
        self.fmk_error = []

    def _reset_fmk_internals(self, reset_existing_seed=True):
        self.cleanup_all_dmakers(reset_existing_seed)
        # Warning: fuzz delay is not set to 0 by default in order to have a time frame
        # where SIGINT is accepted from user
        delay = self.config.misc.fuzz.delay if self.prj.default_sending_delay is None else self.prj.default_sending_delay
        burst = self.config.misc.fuzz.burst if self.prj.default_burst_value is None else self.prj.default_burst_value
        self.set_sending_delay(delay)
        self.set_sending_burst_counter(burst)

        if self.prj.default_fbk_timeout is not None:
            self.set_feedback_timeout(self.prj.default_fbk_timeout)
        if self.prj.default_fbk_mode is not None:
            self.set_feedback_mode(self.prj.default_fbk_mode)

        for tg in self.targets.values():
            self._recompute_generic_timeouts(tg.feedback_timeout, tg.sending_delay, target=tg)

    def _recompute_generic_timeouts(self, fbk_timeout, sending_delay, target=None, do_show=True):
        # if target is None or target in self._currently_used_targets:
        self._fbk_timeout_max = max(0 if fbk_timeout is None else fbk_timeout, self._fbk_timeout_max)
        if fbk_timeout is not None:
            if fbk_timeout != 0:
                self.set_health_check_timeout(fbk_timeout + sending_delay, target=target, do_show=do_show)
            else:
                # if fbk_timeout is equal to 0
                # this is a special meaning used internally to collect residual feedback.
                # Thus, we don't change the current health_check timeout.
                return
        else:
            self.set_health_check_timeout(sending_delay, target=target, do_show=do_show)

    def _handle_user_code_exception(self, msg="", context=None):
        self.set_error(msg, code=Error.UserCodeError, context=context)
        if self.lg:
            self.lg.log_error("Exception in user code detected! Outcomes " \
                              "of this log entry has to be considered with caution.\n" \
                              "    (_ cause: '%s' _)" % msg)
        self.print("Exception in user code:")
        self.print("-" * 60)
        traceback.print_exc(file=self.printer)
        self.print("-" * 60)

    def _handle_fmk_exception(self, cause=""):
        self.set_error(cause, code=Error.UserCodeError)
        if self.lg:
            self.lg.log_error("Not handled exception detected! Outcomes " \
                                "of this log entry has to be considered with caution.\n" \
                                "    (_ cause: '%s' _)" % cause)
        self.print("Call trace:")
        self.print("-" * 60)
        traceback.print_exc(file=self.printer)
        self.print("-" * 60)

    def _is_data_valid(self, data):
        def is_valid(d):
            if d.is_unusable():
                return True
            elif d.is_empty():
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

    @EnforceOrder(accepted_states=["S2"])
    def reload_dm(self):
        return self._reload_dm()

    @EnforceOrder(always_callable=True, transition=["25_load_dm", "S1"])
    def _reload_dm(self, dm_name=None):
        if dm_name is None:
            prefix = self.__dm_rld_args_dict[self.dm][0]
            name = self.__dm_rld_args_dict[self.dm][1]
        else:
            if isinstance(dm_name, list):
                prefix = None
                name = dm_name
            else:
                dm_obj = self.get_data_model_by_name(dm_name)
                prefix = self.__dm_rld_args_dict[dm_obj][0]
                name = dm_name

        if prefix is None:
            # In this case we face a composed DM, name is in fact a dm_list
            dm_list = name
            name_list = []

            self._cleanup_all_dmakers()

            orig_dm = self.dm
            for dm_name in dm_list:
                assert isinstance(dm_name, str)
                # we always take the DM from self.dm_list, as self.__dm_rld_args_dict[self.dm][1]
                # could have obsolete references
                dm_obj = self.get_data_model_by_name(dm_name)

                name_list.append(dm_name)
                self.dm = dm_obj
                ok = self._reload_dm()

                if not ok:
                    self.dm = orig_dm
                    return False

            # reloading is based on name because DM objects have changed
            if not self.load_multiple_data_model(name_list=name_list, reload_dm=True):
                self.set_error("Error encountered while reloading the composed Data Model")

        else:
            self._cleanup_all_dmakers()
            self.dm.cleanup()

            dm_params = self._import_dm(prefix, name, reload_dm=True)
            if dm_params is not None:
                if self.dm in self.__dynamic_generator_ids:
                    del self.__dynamic_generator_ids[self.dm]
                if self.dm in self.__dyngenerators_created:
                    del self.__dyngenerators_created[self.dm]
                self._add_data_model(
                    dm_params["dm"],
                    dm_params["tactics"],
                    dm_params["dm_rld_args"],
                    reload_dm=True,
                )
                self.__dyngenerators_created[dm_params["dm"]] = False
                self.dm = dm_params["dm"]
            else:
                return False

            self._cleanup_dm_attrs_from_fmk()
            if self._is_started():
                if not self._load_data_model():
                    return False

            self.prj.set_data_model(self.dm)
            for tg in self.targets.values():
                tg.set_data_model(self.dm)
            if self.mon:
                self.mon.set_data_model(self.dm)
            self._fmkDB_insert_dm_and_dmakers(self.dm.name, dm_params["tactics"])

        return True

    def _cleanup_dm_attrs_from_fmk(self):
        self._generic_tactics.clear_generator_clones()
        self._generic_tactics.clear_disruptor_clones()
        if self._tactics:
            self._tactics.clear_generator_clones()
            self._tactics.clear_disruptor_clones()
        self._tactics = self.__st_dict[self.dm]
        self._recompute_current_generators()

    @EnforceOrder(accepted_states=["S2"])
    def reload_all(self, tg_ids=None):
        return self._reload_all(tg_ids=tg_ids)

    def _reload_all(self, tg_ids=None):
        prj_prefix = self.__prj_rld_args_dict[self.prj][0]
        prj_name = self.__prj_rld_args_dict[self.prj][1]

        dm_prefix = self.__dm_rld_args_dict[self.dm][0]
        dm_name = self.__dm_rld_args_dict[self.dm][1]

        self._stop_fmk_plumbing()

        if tg_ids is not None:
            self.load_targets(tg_ids)

        prj_params = self._import_project(prj_prefix, prj_name, reload_prj=True)
        if prj_params is not None:
            self._add_project(
                prj_params["project"],
                prj_params["target"],
                prj_params["logger"],
                prj_params["prj_rld_args"],
                reload_prj=True,
            )

            prj_params["project"].share_knowlegde_source()
            self._show_knowledge(knowledge_src=prj_params["project"].knowledge_source,
                                 do_record=True)

            if dm_prefix is None:
                # it is ok to call reload_dm() here because it is a
                # composed DM, and it won't call the methods used within
                # _init_fmk_internals_step1().
                self._reload_dm()
                self._init_fmk_internals_step1(prj_params["project"], self.dm)
            else:
                dm_params = self._import_dm(dm_prefix, dm_name, reload_dm=True)
                if dm_params is not None:
                    self._add_data_model(
                        dm_params["dm"],
                        dm_params["tactics"],
                        dm_params["dm_rld_args"],
                        reload_dm=True,
                    )
                    self.__dyngenerators_created[dm_params["dm"]] = False
                    self._init_fmk_internals_step1(prj_params["project"], dm_params["dm"])

        self._start_fmk_plumbing()
        if self.is_not_ok():
            self._stop_fmk_plumbing()
            return False

        if prj_params is not None:
            self._init_fmk_internals_step2(prj_params["project"], self.dm)

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

    def _recover_target(self, tg):
        if self._recovered_tgs and tg in self._recovered_tgs:
            # This method can be called after checking target health, feedback and
            # probes status. However, we have to avoid to recover the target twice.
            return True
        else:
            if self._recovered_tgs is None:
                self._recovered_tgs = {tg}
            else:
                self._recovered_tgs.add(tg)

        target_recovered = False
        try:
            target_recovered = tg.recover_target()
        except NotImplementedError:
            self.lg.log_fmk_info("No method to recover the target is implemented! (assumption: no need "
                                 "to recover)")
            target_recovered = True  # assumption: no need to recover
        except:
            self.lg.log_fmk_info("Exception raised while trying to recover the target!")
        else:
            tg_desc = self.available_targets_desc[tg]
            if target_recovered:
                self.lg.log_fmk_info("The target {!s} has been recovered!".format(tg_desc))
            else:
                self.lg.log_fmk_info("The target {!s} has not been recovered! All further operations "
                                     "will be terminated.".format(tg_desc))
        return target_recovered

    def monitor_probes(self, prefix=None, force_record=False):
        oks = {x: True for x in self.targets.values()}
        prefix_printed = False

        for probe in self.mon.iter_probes():
            if self.mon.is_probe_launched(probe):
                pstatus = self.mon.get_probe_status(probe)
                err = pstatus.value
                if err < 0 or force_record:
                    tg = self.mon.get_probe_related_tg(probe)
                    if err < 0:
                        if tg is not None:
                            oks[tg] = False
                    if prefix and not prefix_printed:
                        prefix_printed = True
                        self.lg.print_console("\n*** {:s} ***".format(prefix), rgb=Color.FMKINFO)
                    tstamp = pstatus.get_timestamp()
                    priv = pstatus.get_private_info()
                    self.lg.log_probe_feedback(probe=probe, content=priv, status_code=err,
                                               timestamp=tstamp, related_tg=tg)

        for tg, ok in oks.items():
            ret = self._recover_target(tg) if not ok else True

            if prefix and not ok:
                self.lg.print_console("*" * (len(prefix) + 8) + "\n", rgb=Color.FMKINFO)

        return ret

    @EnforceOrder(initial_func=True, final_state="get_projs")
    def get_data_models(self, fmkDB_update=True):
        self._get_data_models_from_fs(fmkDB_update)
        self._get_data_models_from_modules(fmkDB_update)

        if fmkDB_update:
            self.fmkDB.insert_data_model(Database.DEFAULT_DM_NAME)
            self.fmkDB.insert_dmaker(Database.DEFAULT_DM_NAME, Database.DEFAULT_GTYPE_NAME,
                                     Database.DEFAULT_GEN_NAME, True, True)

    def _get_data_models_from_fs(self, fmkDB_update=True):
        if not self._quiet:
            self.print(colorize(FontStyle.BOLD + "=" * 67 + "[ Data Models (filesystem) ]==", rgb=Color.FMKINFOGROUP))

        data_models = collections.OrderedDict()

        def populate_data_models(path, prefix=""):
            from pathlib import Path
            from os.path import dirname,basename

            if path[-1] == '/':
                path = path[:-1]
            if prefix != "" and prefix[-1] != '/':
                prefix = prefix + '/'

            base_path = dirname(path)
            _, dirs, _ = next(os.walk(path))
            for dirpath in dirs:
                p = Path(os.path.join(path, dirpath))
                # We only load modules that have a __init__.py, dm.py and strategy.py
                inits = [ dirname(x) for x in  p.glob('**/__init__.py') ]
                dms = [ dirname(x) for x in  p.glob('**/dm.py') ]
                strats = [ dirname(x) for x in  p.glob('**/strategy.py') ]
                modules = list(set(inits) & set(strats) & set(dms))
                for m in modules:
                    relpath = dirname(m)[len(base_path)+1:]
                    key=prefix+relpath
                    if data_models.get(key) is None:
                        data_models[key] = []
                    data_models[key].append(basename(m))

        if gr.is_running_from_fs:
            if not self._quiet:
                self.print(colorize("*** Running directly from sources, loading internal data_models ***", rgb=Color.WARNING))
            populate_data_models(gr.data_models_folder, prefix="fuddly")
        populate_data_models(gr.user_data_models_folder)

        for dname, names in data_models.items():
            if not self._quiet:
                self.print(colorize(f">>> Look for Data Models within '{dname}' directory",
                                    rgb=Color.FMKINFOSUBGROUP))
            prefix = dname.replace(os.sep, ".") + "."
            for name in names:
                dm_params = self._import_dm(prefix, name)
                if dm_params is None:
                    self.import_successfull = False
                    continue

                self._add_data_model(dm_params["dm"], dm_params["tactics"], dm_params["dm_rld_args"],
                                     reload_dm=False)
                self.__dyngenerators_created[dm_params["dm"]] = False
                if fmkDB_update:
                    # populate FMK DB
                    self._fmkDB_insert_dm_and_dmakers(dm_params["dm"].name, dm_params["tactics"])

    def _get_data_models_from_modules(self, fmkDB_update=True):
        if not self._quiet:
            self.print(colorize(FontStyle.BOLD + "="*63+"[ Data Models (python modules) ]==", rgb=Color.FMKINFOGROUP))

        group_name=gr.ep_group_names["data_models"]
        dms = entry_points(group=group_name)
        for module in dms:
            try:
                *prefix, name = module.module.split(".")
                prefix = ".".join(prefix)
                dm_params = self._import_dm(prefix + ".", name)
            except DataModelDuplicateError as e:
                if not self._quiet:
                    self.print(colorize(f"*** The data model '{e.name}' was already defined, "
                                        f"ignoring... [{module.module}] ***", rgb=Color.WARNING))
                continue

            if dm_params is None:
                self.import_successfull = False
                continue 

            self._add_data_model(dm_params["dm"], dm_params["tactics"], dm_params["dm_rld_args"],
                                 reload_dm=False)
            name = dm_params["dm"].name
            self.__dyngenerators_created[dm_params["dm"]] = False
            if fmkDB_update:
                # populate FMK DB
                self._fmkDB_insert_dm_and_dmakers(dm_params["dm"].name, dm_params["tactics"])

    def _import_dm(self, prefix, name, reload_dm=False):
        try:
            module = importlib.import_module(prefix + name)
            if reload_dm:
                importlib.reload(module.strategy)
                importlib.reload(module.dm)
        except:
            if not self._quiet:
                if reload_dm:
                    self.print(colorize(f"*** Problem during reload of '{name}' ***", rgb=Color.ERROR))
                else:
                    self.print(colorize(f"*** Problem during import of '{name}' ***", rgb=Color.ERROR))

                self.print("-" * 60)
                traceback.print_exc(file=self.printer)
                self.print("-" * 60)
            return None

        dm_params = {}
        dm_params["dm_rld_args"] = (prefix, name)
        try:
            dm_params["dm"] = module.dm.data_model
            dm_params["dm"].module_name = module.__package__
        except:
            if not self._quiet:
                self.print(colorize(f"*** ERROR: '{name}' shall contain a global variable 'data_model' ***",
                                    rgb=Color.ERROR))
            return None

        try:
            dm_params["tactics"] = module.strategy.tactics
        except AttributeError:
            if not self._quiet:
                self.print(colorize(f"*** ERROR: '{name}' shall contain a global variable 'tactics' ***",
                                    rgb=Color.ERROR))
            return None

        dm_params["tactics"].set_additional_info(fmkops=self._exportable_fmk_ops,
                                                 related_dm=dm_params['dm'])

        if dm_params["dm"].name is None:
            dm_params["dm"].name = name

        if not reload_dm and self._name2dm.get(dm_params['dm'].name) is not None:
            raise DataModelDuplicateError(dm_params['dm'].name)

        self._name2dm[dm_params["dm"].name] = dm_params["dm"]

        if not self._quiet:
            if reload_dm:
                self.print(colorize(f"*** Data Model '{dm_params['dm'].name}' updated ***",
                                    rgb=Color.DATA_MODEL_LOADED))
            else:
                self.print(colorize(f"*** Found Data Model: '{dm_params['dm'].name}' ***",
                                    rgb=Color.FMKSUBINFO))

        return dm_params

    def _add_data_model(self, data_model, strategy, dm_rld_args,
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
        self.__dm_rld_args_dict[data_model] = dm_rld_args

    @EnforceOrder(accepted_states=["get_projs"], final_state="20_load_prj")
    def get_projects(self, fmkDB_update=True):
        self._get_projects_fs(fmkDB_update)
        self._get_projects_module(fmkDB_update)

    def _get_projects_fs(self, fmkDB_update=True):
        if not self._quiet:
            self.print(colorize(FontStyle.BOLD + "=" * 70 + "[ Projects (filesystem) ]==", rgb=Color.FMKINFOGROUP))

        projects = collections.OrderedDict()

        def populate_projects(search_path, prefix=""):
            prj_dir = os.path.basename(os.path.normpath(search_path))
            (path, dirs, files) = next(os.walk(search_path))
            if "__init__.py" in files:
                # Normapath remove the / that will most likely be at the end of prefix
                projects[os.path.normpath(prefix)] = [os.path.basename(search_path)]
                return

            for d in [x for x in dirs if x != "__pycache__"]:
                # Done recursively manually even though walk does go down a depth of one folder
                # but only one folder, so it would be nicer to do it ourselves
                populate_projects(
                    os.path.join(search_path, d),
                    os.path.join(prefix, prj_dir) + os.sep
                )

            files = list(
                    map(
                        lambda x: x.removesuffix(".py"),
                        filter(lambda x: x.endswith(".py"), files)
                    )
                )
            if len(files) != 0:
                projects[prefix+prj_dir] = files

        if gr.is_running_from_fs:
            if not self._quiet:
                self.print(colorize("*** Running directly from sources, loading internal projects ***", rgb=Color.WARNING))
            populate_projects(gr.projects_folder, prefix="fuddly/")
        populate_projects(gr.user_projects_folder)

        for dname, file_list in projects.items():
            if not self._quiet:
                self.print(colorize(f">>> Look for Projects within '{dname}' Directory", rgb=Color.FMKINFOSUBGROUP))
            prefix = dname.replace(os.sep, ".") + "."
            for name in file_list:
                prj_params = self._import_project(prefix, name)
                if prj_params is not None:
                    self._add_project(
                        prj_params["project"],
                        prj_params["target"],
                        prj_params["logger"],
                        prj_params["prj_rld_args"],
                        reload_prj=False,
                    )
                    if fmkDB_update:
                        self.fmkDB.insert_project(prj_params["project"].name)
                else:
                    self.import_successfull = False

    def _get_projects_module(self, fmkDB_update=True):
        group_name=gr.ep_group_names["projects"]
        projects = entry_points(group=group_name)

        if not self._quiet:
            self.print(colorize(FontStyle.BOLD + "="*66+"[ Projects (python modules) ]==", rgb=Color.FMKINFOGROUP))

        for module in projects:
            try:
                # module_name.submodule.name -> (module_name.submdule., name)
                *prefix, name = module.module.split(".")
                prefix = ".".join(prefix)
                prj_params = self._import_project(prefix + ".", name)
            except ProjectDuplicateError as e:
                if not self._quiet:
                    self.print(colorize(f"*** The project '{e.name}' was already defined, "
                                        f"ignoring... [{module.module}] ***", rgb=Color.WARNING))
                continue

            if prj_params is not None:
                self._add_project(prj_params["project"], prj_params["target"],
                                  prj_params["logger"], prj_params["prj_rld_args"],
                                  reload_prj=False)
                if fmkDB_update:
                    self.fmkDB.insert_project(prj_params["project"].name)
            else:
                self.import_successfull = False

    def _import_project(self, prefix, name, reload_prj=False):
        try: 
            if importlib.util.find_spec(prefix + name) is None:
                name += "_proj"
            module = importlib.import_module(prefix + name)
            name = name.removesuffix("_proj")

            if reload_prj:
                importlib.reload(module)
                for i in list(filter(lambda x: x.startswith(prefix+name), sys.modules.keys())):
                    importlib.reload(sys.modules[i])

        except:
            if self._quiet:
                return None

            if reload_prj:
                self.print(colorize(f"*** Problem during reload of '{name}'/'{name}_proj' ***", rgb=Color.ERROR))
            else:
                self.print(colorize(f"*** Problem during import of '{name}'/'{name}_proj' ***", rgb=Color.ERROR))
            self.print("-" * 60)
            traceback.print_exc(file=self.printer)
            self.print("-" * 60)

            return None

        prj_params = {}
        prj_params["prj_rld_args"] = (prefix, name)

        # Project
        try:
            prj_params["project"] = module.project
        except:
            if not self._quiet:
                self.print(colorize(f"*** ERROR: '{name}'/'{name}_proj' shall contain a global variable 'project' ***", rgb=Color.ERROR))
            return None

        if prj_params["project"].name is None:
            prj_params["project"].name = name
        else:
            name = prj_params["project"].name

        if not reload_prj and self._name2prj.get(prj_params["project"].name) is not None:
            raise ProjectDuplicateError(prj_params["project"].name)

        self._name2prj[prj_params["project"].name] = prj_params["project"]
        prj = prj_params["project"]
        prj.set_exportable_fmk_ops(self._exportable_fmk_ops)
        if prj.evol_processes:
            for proc in prj.evol_processes:
                built_evol_sc = EvolutionaryScenariosFactory.build(self._exportable_fmk_ops, *proc)
                prj.register_scenarios(built_evol_sc)

        # Logger
        try:
            logger = module.logger
        except AttributeError:
            logger = Logger(name)
        logger.fmkDB = self.fmkDB
        logger.set_external_display(self.external_display)
        if logger.name is None:
            logger.name = name
        prj_params["logger"] = logger

        # Targets
        try:
            targets = module.targets
            targets.insert(0, EmptyTarget(verbose=self.config.targets.empty_tg.verbose))
        except AttributeError:
            tg = EmptyTarget(verbose=self.config.targets.empty_tg.verbose)
            tg.set_project(prj)
            targets = [tg]
        
        new_targets = []
        for obj in targets:
            if isinstance(obj, (tuple, list)):
                tg = obj[0]
                obj = obj[1:]
                tg.del_extensions()
                for p in obj:
                    tg.add_extensions(p)
            else:
                assert issubclass(obj.__class__, Target), 'project: {!s}'.format(name)
                tg = obj
                tg.del_extensions()
            tg.set_project(prj_params["project"])
            new_targets.append(tg)
        targets = new_targets

        for idx, tg_id in enumerate(self._tg_ids):
            if tg_id >= len(targets):
                self.print(colorize(f"*** Incorrect Target ID detected: {tg_id} --> replace with 0 ***",
                                    rgb=Color.WARNING))
                self._tg_ids[idx] = 0

        prj_params["target"] = targets

        if not self._quiet:
            if reload_prj:
                self.print(colorize(f"*** Project '{name}' updated ***", rgb=Color.FMKSUBINFO))
            else:
                self.print(colorize(f"*** Found Project: '{name}' ***", rgb=Color.FMKSUBINFO))

        return prj_params

    def _add_project(self, project, targets, logger, prj_rld_args, reload_prj=False):
        if project.name not in map(lambda x: x.name, self.prj_list):
            self.prj_list.append(project)
            old_prj = None
        elif reload_prj:
            for prj in self.prj_list:
                if prj.name == project.name:
                    break
            else:
                raise ValueError(project.name)
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
            self.__target_dict[project] = targets
            self.__logger_dict[project] = logger
            self.__monitor_dict[project] = project.monitor
            self.__monitor_dict[project].set_fmk_ops(fmk_ops=self._exportable_fmk_ops)
            self.__monitor_dict[project].set_logger(self.__logger_dict[project])
            # self.__monitor_dict[project].set_targets(self.__target_dict[project])
            self._prj_dict[project].set_logger(self.__logger_dict[project])
            self._prj_dict[project].set_monitor(self.__monitor_dict[project])
        else:
            self._prj_dict[project] = project
            self.__target_dict[project] = targets
            self.__logger_dict[project] = logger
            self.__monitor_dict[project] = project.monitor
            self.__monitor_dict[project].set_fmk_ops(fmk_ops=self._exportable_fmk_ops)
            self.__monitor_dict[project].set_logger(self.__logger_dict[project])
            # self.__monitor_dict[project].set_target(self.__target_dict[project])
            self._prj_dict[project].set_logger(self.__logger_dict[project])
            self._prj_dict[project].set_monitor(self.__monitor_dict[project])

        self.__prj_rld_args_dict[project] = prj_rld_args
        self.__initialized_dmaker_dict[project] = {}

    def is_usable(self):
        return self._is_started()

    def _is_started(self):
        return self.__started

    def _start(self):
        self.__started = True

    def _stop(self):
        self.__started = False

    def _load_data_model(self):
        try:
            self.dm.load_data_model(self._name2dm)
        except:
            msg = ("Error encountered while loading the data model. (checkup the associated" \
                   " '{:s}.py' file)".format(self.dm.name))
            self._handle_user_code_exception(msg=msg)
            self._dm_to_be_reloaded = True
            if self.dm in self.__dyngenerators_created:
                del self.__dyngenerators_created[self.dm]
            if self.dm in self.__dynamic_generator_ids:
                del self.__dynamic_generator_ids[self.dm]

            return False

        else:
            if not self.__dyngenerators_created[self.dm]:
                self.__dyngenerators_created[self.dm] = True
                self.__dynamic_generator_ids[self.dm] = []
                for di in self.dm.atom_identifiers():
                    dmaker_type = di.upper()
                    gen_cls_name = "g_" + di.lower()
                    dyn_generator.data_id = di
                    gen = dyn_generator(gen_cls_name, (DynGenerator,), {})()
                    self._tactics.register_new_generator(gen_cls_name, gen, weight=1,
                                                          dmaker_type=dmaker_type, valid=True)
                    self.__dynamic_generator_ids[self.dm].append(dmaker_type)
                    self.fmkDB.insert_dmaker(self.dm.name, dmaker_type, gen_cls_name, True, True)

            self.print(colorize("*** Data Model '%s' loaded ***" % self.dm.name, rgb=Color.DATA_MODEL_LOADED))
            self._dm_to_be_reloaded = False

        return True

    def _create_fmktask_from_task(self, task_obj, task_ref, period):
        task_obj.fmkops = self._exportable_fmk_ops
        task_obj.feedback_gate = self.feedback_gate
        task_obj.targets = self.targets
        task_obj.dm = self.dm
        task_obj.prj = self.prj

        fmktask = FmkTask(task_ref, func=task_obj, arg=None, period=period,
                          error_func=self._handle_user_code_exception,
                          cleanup_func=partial(self._unregister_task, task_ref))
        self._register_task(task_ref, fmktask)
        if self.is_ok():
            self.lg.log_fmk_info("A task has been registered (Task ID #{!s})".format(task_ref))

    def _start_fmk_plumbing(self):
        if not self._is_started():
            signal.signal(signal.SIGINT, signal.SIG_IGN)

            self.lg.start()

            ok = self._load_data_model()
            if not ok:
                self.set_error("Project cannot be launched because of data model loading error")
                return

            ok = {}
            try:
                for tg_id, tg in self.targets.items():
                    ok[tg_id] = tg._start(self.available_targets_desc[tg], tg_id)
            except:
                self._handle_user_code_exception()
                self.set_error("The Target {!s} has not been initialized correctly".format(self.available_targets_desc[tg]))
            else:
                for tg_id in self.targets:
                    if not ok[tg_id]:
                        self.set_error("The Target has not been initialized correctly")
                        return

                self._enable_target()
                self.mon.start()

                need_monitoring = False
                for tg in self.targets.values():
                    for ext in tg.extensions:
                        ext_obj, period = self._extract_info_from_tg_extensions(ext)
                        if isinstance(ext_obj, type) and issubclass(ext_obj, Probe):
                            need_monitoring = True
                            if period is not None:
                                self.mon.set_probe_delay(ext_obj, period)
                            self.mon.start_probe(ext_obj, related_tg=tg)
                        elif isinstance(ext_obj, Task):
                            self._create_fmktask_from_task(ext_obj, task_ref=id(ext_obj), period=ext_obj.period)
                        else:
                            raise ValueError

                self.mon.wait_for_probe_initialization()
                self.prj.start()
                if self.prj.fmkdb_enabled and not self.fmkDB.is_enabled():
                    self.enable_fmkdb()
                elif not self.prj.fmkdb_enabled and self.fmkDB.is_enabled():
                    self.disable_fmkdb()
                else:
                    pass

                if self.prj.project_scenarios:
                    self._generic_tactics.register_scenarios(*self.prj.project_scenarios)
                    self._fmkDB_insert_dm_and_dmakers("generic", self._generic_tactics)

                if need_monitoring:
                    time.sleep(0.5)
                    self.monitor_probes(force_record=True)

            finally:
                self.__current = []
                self.__db_idx = 0
                self.__data_bank = {}

                self._start()

    def _stop_fmk_plumbing(self):
        self.flush_errors()

        if self.prj and self.prj.project_scenarios:
            for sc_ref in [Tactics.scenario_ref_from(sc) for sc in self.prj.project_scenarios]:
                if sc_ref in self._generic_tactics.generators:
                    del self._generic_tactics.generators[sc_ref]

        if self._is_started():
            if self.is_target_enabled():
                self.log_target_residual_feedback()

            self._cleanup_tasks()
            self.fmkDB.flush_feedback()

            if self.is_target_enabled():
                self.mon.stop()
                try:
                    for tg_id, tg in self.targets.items():
                        tg._stop(self.available_targets_desc[tg], tg_id)
                except:
                    self._handle_user_code_exception()
                finally:
                    self._disable_target()

            self.lg.stop()
            self.prj.stop()

            self._stop()

            signal.signal(signal.SIGINT, sig_int_handler)

    @EnforceOrder(accepted_states=["25_load_dm", "S1", "S2"])
    def load_targets(self, tg_ids):
        return self._load_targets(tg_ids)

    def _load_targets(self, tg_ids):
        tg_ids = [tg_ids] if isinstance(tg_ids, int) else tg_ids
        for tg_id in tg_ids:
            if tg_id >= len(self.__target_dict[self.prj]):
                self.set_error(
                    "The provided target number does not exist!",
                    code=Error.CommandError,
                )
                return False

        self._tg_ids = tg_ids

        return True

    @EnforceOrder(accepted_states=["25_load_dm", "S1", "S2"])
    def get_available_targets(self):
        return self.__target_dict[self.prj]

    def _extract_info_from_tg_extensions(self, ext):
        if isinstance(ext, (tuple, list)):
            assert len(ext) == 2
            ext_obj = ext[0]
            delay = ext[1]
        else:
            ext_obj = ext
            delay = None
        return ext_obj, delay

    def _get_detailed_target_desc(self, tg):
        desc = " [" + tg.get_description() + "]"
        detailed_desc = tg.__class__.__name__ + desc

        return detailed_desc

    @EnforceOrder(accepted_states=["25_load_dm", "S1", "S2"])
    def show_targets(self):
        self.print(colorize(FontStyle.BOLD + "\n-=[ Available Targets ]=-\n", rgb=Color.INFO))
        idx = 0
        for tg in self.get_available_targets():
            name = self.available_targets_desc[tg]

            msg = "[{:d}] {:s}".format(idx, name)

            extensions = tg.extensions
            if extensions:
                msg += '\n     \\-- extensions:'
                for ext in extensions:
                    ext_obj, delay = self._extract_info_from_tg_extensions(ext)
                    ext_name = ext_obj.__name__ if isinstance(ext_obj, type) else ext_obj.__class__.__name__
                    if delay:
                        msg += " {:s}(refresh={:.2f}s),".format(ext_name, delay)
                    else:
                        msg += " {:s},".format(ext_name)
                msg = msg[:-1]

            if idx in self._tg_ids:
                msg = colorize(FontStyle.BOLD + msg, rgb=Color.SELECTED)
            else:
                msg = colorize(msg, rgb=Color.SUBINFO)
            self.print(msg)
            idx += 1

    @EnforceOrder(accepted_states=["S2"])
    def dynamic_generator_ids(self):
        for genid in self.__dynamic_generator_ids[self.dm]:
            yield genid

    @EnforceOrder(accepted_states=["S2"])
    def show_fmk_internals(self):
        delay_str = str(self._delay) if self._delay >= 0 else "Step by step mode"

        self.print(colorize(FontStyle.BOLD + "\n-=[ FMK Internals ]=-\n", rgb=Color.INFO))
        self.print(colorize("  [ General Information ]", rgb=Color.INFO))
        self.print(colorize("                  FmkDB enabled: ", rgb=Color.SUBINFO) + repr(self.fmkDB.enabled))
        self.print(colorize("              Workspace enabled: ", rgb=Color.SUBINFO) + repr(self.prj.wkspace_enabled))
        self.print(colorize("                  Sending delay: ", rgb=Color.SUBINFO) + delay_str)
        self.print(colorize("   Number of data sent in burst: ", rgb=Color.SUBINFO) + str(self._burst))
        self.print(colorize(" Target(s) health-check timeout: ", rgb=Color.SUBINFO) + str(self._hc_timeout_max))

        for tg_id, tg in self.targets.items():
            if not tg.supported_feedback_mode:
                fbk_mode = "Target does not provide feedback"
            elif tg.fbk_wait_full_time_slot_mode:
                fbk_mode = tg.fbk_wait_full_time_slot_msg
            else:
                fbk_mode = tg.fbk_wait_until_recv_msg
            fbk_timeout = str(tg.feedback_timeout)
            tg_name = self.available_targets_desc[tg]

            self.print(colorize("\n  [ Target Specific Information - ({:d}) {!s} ]".format(tg_id, tg_name), rgb=Color.INFO))
            self.print(colorize("               Feedback timeout: ", rgb=Color.SUBINFO) + fbk_timeout)
            self.print(colorize("                  Feedback mode: ", rgb=Color.SUBINFO) + fbk_mode)

    @EnforceOrder(accepted_states=["S2"])
    def show_knowledge(self):
        self._show_knowledge(do_record=False)

    def _show_knowledge(self, knowledge_src=None, do_record=False):
        k = self.prj.knowledge_source if knowledge_src is None else knowledge_src
        self.print(
            colorize(FontStyle.BOLD + "\n-=[ Status of Knowledge ]=-\n", rgb=Color.INFO)
        )
        if k:
            self.print(colorize(str(k), rgb=Color.SUBINFO))
        else:
            self.print(colorize("No knowledge", rgb=Color.SUBINFO))
        if do_record:
            msg = ("Status of Knowledge:\n" + str(k)) if k else "No knowledge"
            self.lg.log_fmk_info(msg, do_record=True, do_show=False)

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"])
    def projects(self):
        for prj in self.prj_list:
            yield prj

    def _projects(self):
        for prj in self.prj_list:
            yield prj

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"])
    def show_projects(self):
        self.print(colorize(FontStyle.BOLD + "\n-=[ Projects ]=-\n", rgb=Color.INFO))
        idx = 0
        for prj in self._projects():
            self.print(colorize("[%d] " % idx + prj.name, rgb=Color.SUBINFO))
            idx += 1

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"])
    def iter_data_models(self):
        for dm in self.dm_list:
            yield dm

    def _iter_data_models(self):
        for dm in self.dm_list:
            yield dm

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"])
    def show_data_models(self):
        self.print(colorize(FontStyle.BOLD + "\n-=[ Data Models ]=-\n", rgb=Color.INFO))
        idx = 0
        for dm in self._iter_data_models():
            if dm is self.dm:
                self.print(colorize(FontStyle.BOLD + "[{:d}] {!s}".format(idx, dm.name), rgb=Color.SELECTED))
            else:
                self.print(colorize("[{:d}] {!s}".format(idx, dm.name), rgb=Color.SUBINFO))
            idx += 1

    def _init_fmk_internals_step1(self, prj, dm):
        self.prj = prj
        self.dm = dm
        # self.dm.knowledge_source = prj.knowledge_source
        self.lg = self.__logger_dict[prj]

        self.targets = {}
        try:
            for tg_id in self._tg_ids:
                self.targets[tg_id] = self.__target_dict[prj][tg_id]
                # self.targets[tg_id].tg_id = tg_id
        except IndexError:
            self.set_error(msg="Invalid Target ID(s). Enable the EmptyTarget (0) only.", code=Error.FmkWarning)
            self.targets = {0: self.__target_dict[prj][0]}
            self._tg_ids = [0]

        self._update_targets_desc(prj)

        for tg in self.targets.values():
            tg.set_logger(self.lg)
            tg.set_data_model(self.dm)

        self.prj.set_targets(self.targets)
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
        self.mon.set_targets(self.targets)
        self.mon.set_logger(self.lg)
        self.mon.set_data_model(self.dm)
        self.__initialized_dmakers = self.__initialized_dmaker_dict[prj]

    def _init_fmk_internals_step2(self, prj, dm):
        self._recompute_current_generators()
        # need the logger active
        self._reset_fmk_internals()

    def _recompute_current_generators(self):
        specific_gen = self._tactics.generator_types
        generic_gen = self._generic_tactics.generator_types
        self.__current_gen = list(specific_gen) + list(generic_gen)

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"])
    def get_data_model_by_name(self, name):
        for model in self._iter_data_models():
            if model.name == name:
                ret = model
                break
        else:
            ret = None
        return ret

    @EnforceOrder(accepted_states=["25_load_dm", "S1", "S2"], transition=["25_load_dm", "S1"])
    def load_data_model(self, dm=None, name=None):
        if name is not None:
            dm = self.get_data_model_by_name(name)
            if dm is None:
                self.set_error("Data model '{:s}' has not been found!".format(name), code=Error.CommandError)
                return False

        elif dm is not None:
            if dm not in self.dm_list:
                return False

        if self._is_started():
            self.cleanup_all_dmakers()
        self.dm = dm
        self.prj.set_data_model(self.dm)
        for tg in self.targets.values():
            tg.set_data_model(self.dm)
        if self.mon:
            self.mon.set_data_model(self.dm)
        if self._is_started():
            self._cleanup_dm_attrs_from_fmk()
            ok = self._load_data_model()
            if not ok:
                return False

        return True

    @EnforceOrder(accepted_states=["25_load_dm", "S1", "S2"], transition=["25_load_dm", "S1"])
    def load_multiple_data_model(self, dm_list=None, name_list=None, reload_dm=False):
        if name_list is not None:
            dm_list = []
            for name in name_list:
                dm = self.get_data_model_by_name(name)
                if dm is None:
                    self.set_error("Data model '{:s}' has not been found!".format(name), code=Error.CommandError)
                    return False
                dm_list.append(dm)

        elif dm_list is not None:
            for dm in dm_list:
                if dm not in self.dm_list:
                    return False

        if self._is_started():
            self.cleanup_all_dmakers()

        new_dm = DataModel()
        new_tactics = Tactics()
        dyn_gen_ids = []
        name = ""
        for dm in dm_list:
            name += dm.name + "+"
            if not reload_dm or not self._is_started():
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
                if k in new_tactics.generators:
                    raise ValueError("the generator '{:s}' exists already".format(k))
                else:
                    new_tactics.generators[k] = v
            for dmk_id in self.__dynamic_generator_ids[dm]:
                dyn_gen_ids.append(dmk_id)

        new_dm.name = name[:-1]
        is_dm_name_exists = new_dm.name in map(lambda x: x.name, self.dm_list)

        if reload_dm or not is_dm_name_exists:
            self.fmkDB.insert_data_model(new_dm.name)
            dm_name_list = [dm.name for dm in dm_list]
            self._add_data_model(new_dm, new_tactics,
                                 dm_rld_args=[None, dm_name_list],
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

        for tg in self.targets.values():
            tg.set_data_model(self.dm)
        if self.mon:
            self.mon.set_data_model(self.dm)
        if self._is_started():
            self._cleanup_dm_attrs_from_fmk()
            ok = self._load_data_model()
            if not ok:
                return False

        return True

    def _update_targets_desc(self, prj):
        self.available_targets_desc = {}
        for tg in self.__target_dict[prj]:
            self.available_targets_desc[tg] = self._get_detailed_target_desc(tg)

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"])
    def get_project_by_name(self, name):
        for prj in self._projects():
            if prj.name == name:
                ret = prj
                break
        else:
            ret = None
        return ret

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"], final_state="S2" )
    def run_project(self, prj=None, name=None, tg_ids=None, dm_name=None):
        ok = self.load_project(prj=prj, name=name)
        if not ok:
            return False

        if dm_name is None:
            if self.prj.default_dm is None:
                self.set_error("The attribute 'default_dm' is not set!")
                return False
            else:
                dm_name = self.prj.default_dm

        if self._dm_to_be_reloaded:
            self._reload_dm(dm_name=dm_name)
            ok = self.is_ok()
        else:
            if isinstance(dm_name, list):
                ok = self.load_multiple_data_model(name_list=dm_name)
            else:
                ok = self.load_data_model(name=dm_name)

        if not ok:
            self._dm_to_be_reloaded = True
            return False
        else:
            self._dm_to_be_reloaded = False

        if tg_ids is not None:
            if isinstance(tg_ids, int):
                self._load_targets([tg_ids])
            else:
                self._load_targets(tg_ids)
        else:
            self._load_targets([0])

        return self._launch()

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"], final_state="25_load_dm")
    def load_project(self, prj=None, name=None):
        if name is not None:
            prj = self.get_project_by_name(name)
            if prj is None:
                return False

        elif prj is not None:
            if prj not in self.prj_list:
                return False

        self._stop_fmk_plumbing()
        self.prj = prj

        self._update_targets_desc(prj)

        self.prj.share_knowlegde_source()

        return True

    @EnforceOrder(accepted_states=["S1"], final_state="S2")
    def launch(self):
        if not self._dm_to_be_reloaded:
            return self._launch()
        else:
            self._dm_to_be_reloaded = False
            self._reload_dm()
            self._launch()
            # self._reload_all()
            return True

    def _launch(self):
        self._init_fmk_internals_step1(self.prj, self.dm)
        self._start_fmk_plumbing()
        if self.is_not_ok():
            self._stop_fmk_plumbing()
            return False

        self._show_knowledge(do_record=True)

        self._init_fmk_internals_step2(self.prj, self.dm)
        return True

    def is_target_enabled(self):
        return self.__tg_enabled

    def _enable_target(self):
        self.__tg_enabled = True
        self.mon.enable_hooks()

    def _disable_target(self):
        self.__tg_enabled = False
        self.mon.disable_hooks()

    @EnforceOrder(always_callable=True)
    def enable_wkspace(self):
        self.prj.wkspace_enabled = True

    @EnforceOrder(always_callable=True)
    def disable_wkspace(self):
        self.prj.wkspace_enabled = False

    @EnforceOrder(accepted_states=["S1", "S2"])
    def set_sending_delay(self, delay, do_record=True):
        if delay >= 0 or delay == -1:
            self._delay = delay
            self.lg.log_fmk_info("Sending delay = {:.2f}s".format(self._delay), do_record=do_record)
            return True
        else:
            self.lg.log_fmk_info("Wrong delay value!", do_record=False)
            return False

    @EnforceOrder(accepted_states=["S1", "S2"])
    def set_sending_burst_counter(self, val, do_record=False):
        if val >= 1:
            self._burst = int(val)
            self._burst_countdown = self._burst
            self.lg.log_fmk_info("Number of data sent in burst = %d" % self._burst,
                                 do_record=do_record)
            return True
        else:
            self.lg.log_fmk_info("Wrong burst value!", do_record=False)
            return False

    @EnforceOrder(accepted_states=["S1", "S2"])
    def set_health_check_timeout(
        self, timeout, target=None, do_record=True, do_show=True
    ):
        if timeout >= 0:
            if target is None:
                self._hc_timeout = {}
                for tg in self.targets.values():
                    self._hc_timeout[tg] = timeout
            else:
                self._hc_timeout[target] = timeout
            self._hc_timeout_max = max(self._hc_timeout.values())
            if do_show or do_record:
                if target is None:
                    self.lg.log_fmk_info("Target(s) health-check timeout = {:.1f}s".format(timeout),
                                         do_record=do_record)
                else:
                    tg_desc = self._get_detailed_target_desc(target)
                    self.lg.log_fmk_info("Target {!s} health-check timeout = {:.1f}s".format(tg_desc, timeout),
                                         do_record=do_record)

            return True
        else:
            self.lg.log_fmk_info("Wrong timeout value!", do_record=False)
            return False

    @EnforceOrder(accepted_states=["S1", "S2"])
    def set_feedback_timeout(self, timeout, tg_id=None, do_record=True, do_show=True):
        self._fbk_timeout_max = 0

        if tg_id is None:
            max_sending_delay = 0
            for tg in self.targets.values():
                max_sending_delay = max(max_sending_delay, tg.sending_delay)

        if timeout is None:
            # This case occurs in self._do_sending_and_logging_init()
            # if the Target has not defined a feedback_timeout (like the EmptyTarget)
            if tg_id is None:
                for tg in self.targets.values():
                    tg.set_feedback_timeout(None)
                self._recompute_generic_timeouts(timeout, max_sending_delay, do_show=do_show)
            else:
                tg = self.targets[tg_id]
                tg.set_feedback_timeout(None)
                self._recompute_generic_timeouts(timeout, tg.sending_delay, target=tg, do_show=do_show)

        elif timeout >= 0:
            if tg_id is None:
                for tg in self.targets.values():
                    tg.set_feedback_timeout(timeout)
                self._recompute_generic_timeouts(timeout, max_sending_delay, do_show=do_show)
                if do_show or do_record:
                    self.lg.log_fmk_info("Target(s) feedback timeout = {:.1f}s".format(timeout),
                                         do_record=do_record)
            else:
                tg = self.targets[tg_id]
                tg.set_feedback_timeout(timeout)
                self._recompute_generic_timeouts(
                    timeout, tg.sending_delay, target=tg, do_show=do_show
                )
                if do_show or do_record:
                    tg_desc = self._get_detailed_target_desc(tg)
                    self.lg.log_fmk_info("Target {!s} feedback timeout = {:.1f}s".format(tg_desc, timeout),
                                         do_record=do_record)
            return True
        else:
            self.lg.log_fmk_info("Wrong timeout value!", do_record=False)
            return False

    @EnforceOrder(accepted_states=["S1", "S2"])
    def set_feedback_mode(self, mode, tg_id=None, do_record=False, do_show=True):
        def _set_fbk_mode(tg):
            ok = tg.set_feedback_mode(mode)
            if not ok:
                mode_desc = tg.get_fbk_mode_desc(mode, short=True)
                self.set_error(f"The target does not support the requested feedback mode ({mode_desc})",
                               code=Error.CommandError)
            elif do_show or do_record:
                if tg.fbk_wait_full_time_slot_mode:
                    msg = "Feedback Mode = " + tg.fbk_wait_full_time_slot_msg
                else:
                    msg = "Feedback Mode = " + tg.fbk_wait_until_recv_msg
                self.lg.log_fmk_info(msg, do_record=do_record)

        if tg_id is None:
            for tg in self.targets.values():
                _set_fbk_mode(tg)
        else:
            tg = self.targets[tg_id]
            _set_fbk_mode(tg)

    @EnforceOrder(accepted_states=["S1", "S2"])
    def switch_feedback_mode(self, tg_id, do_record=False, do_show=True):
        if tg_id not in self.targets:
            self.set_error("The selected target is not enabled", code=Error.CommandError)
            return

        tg = self.targets[tg_id]
        if tg.fbk_wait_full_time_slot_mode:
            self.set_feedback_mode(Target.FBK_WAIT_UNTIL_RECV, tg_id=tg_id, do_record=do_record, do_show=do_show)
        else:
            self.set_feedback_mode(Target.FBK_WAIT_FULL_TIME, tg_id=tg_id, do_record=do_record, do_show=do_show)

    # Used to introduce some delay after sending data
    def _delay_sending(self):
        """
        return False if the user want to stop fuzzing (action possible if
        delay is set to -1)
        """
        ret = True
        if self._burst_countdown <= 1:
            self._burst_countdown = self._burst

            if self.__tg_enabled:
                if self._delay == -1.0:
                    try:
                        signal.signal(signal.SIGINT, sig_int_handler)
                        cont = get_user_input(colorize("\n*** Press [ENTER] to continue ('q' to exit) ***\n",
                                                       rgb=Color.PROMPT))
                        if cont == "q":
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

    def _do_before_sending_data(self, data_list: Sequence[Data]) -> Sequence[Data]:
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
        self._recovered_tgs = None
        # _last_sending_date is not as precise as the one stored in Target object. But it is
        # sufficient for its purpose within the plumbing.
        self._last_sending_date = datetime.datetime.now()
        self._handle_data_callbacks(data_list, hook=HOOK.after_sending)

    def _do_sending_and_logging_init(self, data_list):
        for d in data_list:
            if d.sending_delay is not None:
                self.set_sending_delay(d.sending_delay)

            if d.feedback_timeout is not None:
                tg_ids = self._vtg_to_tg(d)
                for tg_id in tg_ids:
                    self.set_feedback_timeout(d.feedback_timeout, tg_id=tg_id)

            if d.feedback_mode is not None:
                tg_ids = self._vtg_to_tg(d)
                for tg_id in tg_ids:
                    self.set_feedback_mode(d.feedback_mode, tg_id=tg_id)

        blocked_data = list(filter(lambda x: x.is_blocked(), data_list))
        data_list = list(filter(lambda x: not x.is_blocked(), data_list))

        if self._burst_countdown == self._burst:
            try:
                max_fbk_timeout = max([tg.feedback_timeout for tg in self._currently_used_targets
                                       if tg.feedback_timeout is not None])
            except ValueError:
                # empty list
                max_fbk_timeout = self._fbk_timeout_default
            user_interrupt, go_on = self._collect_residual_feedback(timeout=max_fbk_timeout)
        else:
            user_interrupt, go_on = False, True

        if blocked_data:
            self._handle_data_callbacks(blocked_data, hook=HOOK.after_fbk)
            self._handle_data_callbacks(blocked_data, hook=HOOK.final)
            self.fmkDB.flush_current_feedback()

        if user_interrupt:
            raise UserInterruption
        elif go_on:
            return data_list
        else:
            raise TargetFeedbackError

    def collect_residual_feedback(self, timeout=0):
        if self._collect_residual_feedback(force_mode=True, timeout=timeout)[0]:
            raise UserInterruption

    def _collect_residual_feedback(self, force_mode=False, timeout=0):
        # If feedback_timeout = 0 then we don't consider residual feedback.
        # We try to avoid unnecessary latency in this case, as well as
        # to avoid retrieving some feedback that could be a trigger for sending the next data
        # (e.g., with a NetworkTarget in server_mode + wait_for_client)
        targets_to_retrieve_fbk = {}
        do_residual_tg_fbk_gathering = False
        for tg_id, tg in self.targets.items():
            cond = True if tg.feedback_timeout is None or force_mode else tg.feedback_timeout > 0
            if cond:
                do_residual_tg_fbk_gathering = True
                targets_to_retrieve_fbk[tg_id] = tg

        tg_ready = True
        log_no_error = True
        fbk_timeout = {}
        user_interrupt = False
        if do_residual_tg_fbk_gathering:
            # log residual just before sending new data to avoid
            # polluting feedback logs of the next emission

            collected = False
            for tg in targets_to_retrieve_fbk.values():
                if tg.collect_unsolicited_feedback(timeout=timeout):
                    self._recovered_tgs = None
                    collected = True

            if collected:
                # We have to make sure the targets are ready for sending data after
                # collecting feedback.
                ftimeout = None if timeout == 0 else timeout
                ret = self.wait_for_target_readiness(forced_feedback_timeout=ftimeout)
                user_interrupt = ret == -2
                tg_ready = ret >= 0

            log_no_error = self.log_target_residual_feedback()

            for tg in targets_to_retrieve_fbk.values():
                tg.cleanup()

        self.monitor_probes(prefix="Probe Status Before Sending Data")

        go_on = tg_ready and log_no_error

        return user_interrupt, go_on

    def _do_after_feedback_retrieval(self, data_list):
        self._handle_data_callbacks(data_list, hook=HOOK.after_fbk)
        self._handle_data_callbacks(data_list, hook=HOOK.final)
        self.fmkDB.flush_current_feedback()

    def _do_after_dmaker_data_retrieval(self, data):
        self._handle_data_callbacks([data], hook=HOOK.after_dmaker_production)

    def handle_data_desc(self, data_desc, resolve_dataprocess=True, original_data=None,
                         save_generator_seed=False, reset_dmakers=False):
        if isinstance(data_desc, Data):
            data = data_desc
            data.generate_info_from_content(data=original_data)

        elif isinstance(data_desc, DataProcess):
            if data_desc.dp_completed:
                # It means we already resolve the dataprocess (as @dp_completed is only set
                # in these code path) and we are called a second time
                # while @dp_completed has not been cleared.
                # Typical of Replace_Data cbkops used in Scenario that could get called twice in
                # HOOK.before_sending_step1 and HOOK.before_sending_step2.
                data_desc.dp_completed = False
                return None

            if isinstance(data_desc.seed, str):
                try:
                    seed_node = self.dm.get_atom(data_desc.seed)
                except:
                    self.set_error(msg="Cannot create the seed from the "
                                       "name {:s}!".format(data_desc.seed),
                                   code=Error.UserCodeError)
                    return None
                else:
                    seed = Data(seed_node)
                    seed.generate_info_from_content(data=original_data)

            elif isinstance(data_desc.seed, Data):
                seed = data_desc.seed
                seed.generate_info_from_content(data=original_data)
            elif data_desc.seed is None:
                seed = None
            else:
                self.set_error(msg="DataProcess object contains an unrecognized seed"
                                   " type {!r}".format(data_desc.seed),
                               code=Error.UserCodeError)
                return None

            if resolve_dataprocess or data_desc.outcomes is None:
                if data_desc.process is None:
                    data = seed
                else:
                    data = self.process_data(data_desc.process, seed=seed,
                                             save_gen_seed=save_generator_seed,
                                             reset_dmakers=reset_dmakers)
                    if data is None:
                        if data_desc.auto_regen:
                            data_desc.auto_regen_cpt += 1

                        while data_desc.next_process() or data_desc.auto_regen:
                            data = self.process_data(data_desc.process, seed=seed,
                                                     save_gen_seed=save_generator_seed,
                                                     reset_dmakers=reset_dmakers)
                            if data is not None:
                                break

                    if data is not None:
                        data.generate_info_from_content(data=original_data)

                data_desc.outcomes = data
                if data is not None and data.tg_ids is None:
                    data.tg_ids = data_desc.tg_ids

            else:
                data = data_desc.outcomes
                # we do not update data with data_desc information because when we reached this case
                # ("else" branch case) we have already done it when .outcomes was computed (which is
                # in the "if" branch case).

            if data is None:
                data_desc.dp_completed = True
                self.set_error(msg="Data creation process has yielded!", code=Error.DPHandOver)
                return None

        elif isinstance(data_desc, str):
            try:
                node = self.dm.get_atom(data_desc)
            except:
                self.set_error(msg="Cannot retrieved a data called {:s}!".format(data_desc), code=Error.UserCodeError)
                return None
            else:
                data = Data(node)
                data.generate_info_from_content(data=original_data)
                if original_data is not None:
                    data.tg_ids = original_data.tg_ids
        else:
            self.set_error(msg="Data descriptor type is not recognized {!s}!".format(type(data_desc)),
                           code=Error.UserCodeError)
            return None

        if original_data is not None:
            data.origin = original_data.origin

        return data

    def _handle_data_callbacks(self, data_list, hook, resolve_dataprocess=True):
        new_data_list = []
        stop_data_list_processing = False

        for data in data_list:
            if stop_data_list_processing:
                break

            try:
                if hook == HOOK.after_fbk:
                    data.run_callbacks(feedback=self.last_feedback_gate, hook=hook)
                else:
                    data.run_callbacks(feedback=None, hook=hook)
            except:
                self._handle_user_code_exception("A Data callback (called at {!r}) has crashed! "
                                                 "(Data object internal ID: {:d})".format(hook, id(data)))
                new_data_list.append(data)
                continue

            if hook == HOOK.final:
                continue

            new_data = data
            data_tg_ids = data.tg_ids if data.tg_ids is not None else [self._tg_ids[0]]

            pending_ops = data.pending_callback_ops(hook=hook)
            if pending_ops:
                for op in pending_ops:
                    # CallBackOps.Set_FbkTimeout is obsolete. Not used by scenario, only used in
                    # tuto_strategy.py as an example. Note that fbk timeout is dealt directly at Data()
                    # level by self._do_sending_and_logging_init()
                    fbk_timeout = op[CallBackOps.Set_FbkTimeout]
                    if fbk_timeout is not None:
                        self.set_feedback_timeout(fbk_timeout)

                    returned_obj = op[CallBackOps.Replace_Data]
                    if returned_obj is not None:
                        # This means that data_list will be replaced by something else, thus ignore
                        # current data_list and start from scratch.
                        # In case of Scenario handling with a multi data step, we skip the remaining
                        # data in the list because they will be regenerated or new ones will prevail.
                        # Indeed, the Replace_Data callback is triggered twice:
                        # in Hook.before_sending_step1 and in Hook.before_sending_step2.
                        stop_data_list_processing = True

                        data_desc, vtg_ids_list = returned_obj
                        if vtg_ids_list is None:
                            vtg_ids_list = itertools.repeat(None)

                        new_data = []
                        first_step = True
                        for d_desc, vtg_ids in zip(data_desc, vtg_ids_list):
                            data_tmp = self.handle_data_desc(d_desc,
                                                             resolve_dataprocess=resolve_dataprocess,
                                                             original_data=data,
                                                             reset_dmakers=data.attrs.is_set(DataAttr.Reset_DMakers))

                            if data_tmp is not None:
                                if first_step:
                                    first_step = False
                                    data_tmp.copy_callback_from(data)
                                data_tmp.tg_ids = data.tg_ids if vtg_ids is None else vtg_ids
                                new_data.append(data_tmp)
                            else:
                                # We mark the data unusable in order to make sending methods
                                # aware of specific events that should stop the sending process.
                                # In this case it is either the normal end of a scenario or an error
                                # within a scenario step.
                                newd = Data()
                                newd.tg_ids = data.tg_ids if vtg_ids is None else vtg_ids
                                newd.set_basic_attributes(from_data=data)
                                if not data.on_error_handover_to_user:
                                    newd.copy_callback_from(data)
                                newd.make_unusable()
                                new_data = [newd]
                                break

                    for idx in op[CallBackOps.Del_PeriodicData]:
                        self._unregister_task(idx)

                    for idx in op[CallBackOps.Stop_Task]:
                        self._unregister_task(idx)

                    final_data_tg_ids = self._vtg_to_tg(data)
                    for idx, obj in op[CallBackOps.Add_PeriodicData].items():
                        task_obj, period = obj
                        data_desc = task_obj.data
                        if task_obj.vtg_ids_list:
                            final_data_tg_ids = self._vtg_to_tg(data, vtg_ids_list=task_obj.vtg_ids_list)

                        if isinstance(data_desc, DataProcess):
                            # In this case each time we send the periodic we walk through the process
                            # (thus, sending a new data each time)
                            periodic_data = data_desc
                            func = partial(self._send_periodic, final_data_tg_ids)
                        else:
                            periodic_data = self.handle_data_desc(data_desc,
                                                                  resolve_dataprocess=resolve_dataprocess,
                                                                  original_data=data)
                            targets = [self.targets[x] for x in final_data_tg_ids]
                            func = [partial(tg.send_data_sync, from_fmk=False) for tg in targets]

                        if periodic_data is not None:
                            task = FmkTask(idx, func, periodic_data, period=period,
                                           error_func=self._handle_user_code_exception,
                                           cleanup_func=partial(self._unregister_task, idx))
                            self._register_task(idx, task)
                            if self.is_ok():
                                self.lg.log_fmk_info("A periodic data sending has been registered (Task ID #{!s})".format(idx))
                        else:
                            self.set_error(msg="Data descriptor is incorrect!",
                                           code=Error.UserCodeError,)

                    for idx, obj in op[CallBackOps.Start_Task].items():
                        task_obj, period = obj
                        self._create_fmktask_from_task(task_obj, task_ref=idx, period=period)

            if isinstance(new_data, list):
                for newd in new_data:
                    new_data_list.append(newd)
            else:
                new_data_list.append(new_data)

        return new_data_list

    def _vtg_to_tg(self, data, vtg_ids_list=None):
        mapping = self.prj.scenario_target_mapping.get(data.scenario_dependence, None)
        vtg_ids = data.tg_ids if vtg_ids_list is None else vtg_ids_list
        if vtg_ids is None:
            tg_ids = mapping.get(None, self._tg_ids[0]) if mapping else self._tg_ids[0]
            tg_ids = [tg_ids]
        else:
            if mapping:
                tg_ids = [mapping.get(tg_id, tg_id) for tg_id in vtg_ids]
            else:
                tg_ids = vtg_ids

        valid_tg_ids = []
        for i in tg_ids:
            if i not in self._tg_ids:
                try:
                    requested_tg_id = self.get_available_targets()[i]
                except IndexError:
                    self.set_error("WARNING: The provided target number '{:d}' does not exist ".format(i),
                                   code=Error.FmkWarning)
                else:
                    self.set_error("WARNING: An access attempt occurs on a disabled target: '({:d}) {!s}' "
                                   "It will be redirected to the first enabled target.".format(i, requested_tg_id),
                                   code=Error.FmkWarning)
                i = self._tg_ids[0]
                if self._debug_mode:
                    raise ValueError("Access attempt occurs on a disabled target")
            valid_tg_ids.append(i)

        return valid_tg_ids

    def _send_periodic(self, tg_ids, data_desc):
        data = self.handle_data_desc(data_desc)
        if data is not None:
            for tg in [self.targets[tg_id] for tg_id in tg_ids]:
                tg.send_data_sync(data, from_fmk=False)
        else:
            self.set_error(msg="Data descriptor handling returned 'None'!", code=Error.UserCodeError)
            raise DataProcessTermination

    def _unregister_task(self, id, ign_error=False):
        with self._task_list_lock:
            if id in self._task_list:
                self._task_list[id].stop()
                del self._task_list[id]
                self.lg.log_fmk_info("Removal of a Task " "(Task ID #{!s})".format(id))
            elif not ign_error:
                self.set_error("ERROR: Task ID #{!s} does not exist. "
                               "Cannot unregister.".format(id), code=Error.UserCodeError)

    def _register_task(self, id, task):
        with self._task_list_lock:
            if id not in self._task_list:
                self._task_list[id] = task
                task.start()
            else:
                self.set_error("WARNING: Task ID #{!s} already exists. "
                               "Task ignored.".format(id), code=Error.UserCodeError)

    def _cleanup_tasks(self):
        for id in self._task_list:
            self._task_list[id].stop()
        self._task_list = {}

    @EnforceOrder(accepted_states=["S2"])
    def stop_all_tasks(self):
        self._cleanup_tasks()

    @EnforceOrder(accepted_states=["S2"])
    def process_data_and_send( self, data_desc=None, id_from_fmkdb=None, id_from_db=None,
                              max_loop=1, tg_ids=None,
                              verbose=False, console_display=True,
                              save_generator_seed=False):
        """
        Send data to the selected targets. These data can follow a specific processing before
        being emitted. The latter depends on what is provided in `data_desc`.


        Args:
            data_desc: Can be either a :class:`framework.data.DataProcess`, a :class:`framework.data.Data`,
              the name (str) of an atom of the loaded data models, or a list of the previous types.
            id_from_fmkdb: Data can be fetched from the FmkDB and send directly to the targets or be
              used as the seed of a DataProcess if such object is provided in `data_desc`.
            id_from_db: Data can be fetched from the Data Bank and send directly to the targets or be
              used as the seed of a DataProcess if such object is provided in `data_desc`.
            max_loop: Maximum number of iteration. -1 one means "infinite" or until some criteria occurs
              (e.g., a disruptor has exhausted, the end-user issued Ctrl-C, ...)
            tg_ids: Target ID or list of the Target IDs on which data will be sent. If provided
              it will supersede the `tg_ids` parameter of any DataProcess provided in `data_desc`
            verbose: Pretty print sent data
            console_display: If `False`, nothing will be displayed on the screen (that could cause latency)
            save_generator_seed: If random Generators are used, the generated data will be internally saved
              and will be reused next time this generator will be called, until
              FmkPlumbing.cleanup_dmaker(... reset_existing_seed=True) is called on this Generator.

        Returns:
            The list of data that have been sent. `None` if nothing was sent due to some error.

        """

        assert data_desc is not None or id_from_fmkdb is not None or id_from_db is not None
        assert id_from_fmkdb is None or id_from_db is None

        if id_from_fmkdb is not None:
            data = self.fmkdb_fetch_data(start_id=id_from_fmkdb, end_id=id_from_fmkdb)
            if data is None:
                return None

        elif id_from_db is not None:
            data = self.get_from_data_bank(id_from_db)
            if data is None:
                return None

        if data_desc is not None:
            if id_from_fmkdb is not None:
                assert isinstance(data_desc, DataProcess)
                data_desc.seed = data
            elif id_from_db is not None:
                assert isinstance(data_desc, DataProcess)
                data_desc.seed = data

            data_desc = data_desc if isinstance(data_desc, list) else [data_desc]
            cpt = 0
            sent_data = []
            while cpt < max_loop or max_loop == -1:
                cpt += 1
                data_list = []
                for d_desc in data_desc:
                    data = self.handle_data_desc(d_desc, resolve_dataprocess=True,
                                                 save_generator_seed=save_generator_seed)
                    if data is None:
                        data = Data()
                        data.make_unusable()
                    if tg_ids:
                        data.tg_ids = tg_ids
                    data_list.append(data)

                go_on, sdata = self.send_data_and_log(data_list, verbose=verbose,
                                                      console_display=console_display)
                if sdata:
                    for d in sdata:
                        sent_data.append(d)

                if not go_on:
                    break

        else:
            cpt = 0
            sent_data = []
            while cpt < max_loop or max_loop == -1:
                cpt += 1
                go_on, sdata = self.send_data_and_log(data, verbose=verbose,
                                                      console_display=console_display)

                if sdata:
                    for d in sdata:
                        sent_data.append(d)

                if not go_on:
                    break

        return sent_data

    @EnforceOrder(accepted_states=["S2"])
    def send_data_and_log(self, data_list, verbose=False, console_display=True):
        if not console_display:
            lg_display_on_term_save = self.lg.display_on_term
            self.lg.display_on_term = False

        if isinstance(data_list, Data):
            data_list = [data_list]

        try:
            data_list = self._do_sending_and_logging_init(data_list)
        except (TargetFeedbackError, UserInterruption):
            return False, None

        # we delay sending after calling self._do_sending_and_logging_init(data_list)
        # as this delay can be changed while data is handled by this method.
        go_on = self._delay_sending()
        if not go_on:
            return False, None

        if not data_list:
            return True, None

        data_list = self._send_data(data_list)

        if self._sending_error or self._stop_sending:
            return False, None

        if data_list is None:
            # In this case:
            # - either some data callbacks have triggered to block the emission of
            #   what was in data_list and we go on because this is a normal behavior (especially
            #   in the context of Scenario() execution).
            # - or the framework is requested to go on even if there are no data to send (e.g., a
            #   DataProcess of a Scenario has completed and it exists a transition for that condition
            #   in the scenario).
            return True, None

        # All feedback entries that are available for relevant framework users (scenario
        # callbacks, operators, ...) are flushed just after sending a new data because it
        # means the previous feedback entries are obsolete.
        self.fmkDB.flush_current_feedback()

        # For loaded Target()s not currently stimulated (i.e., ._send_data() not triggered on them)
        # we also want to get data that may have been sent by the associated real targets. So that
        # after the sending operation we get
        # a full snapshot of the feedback coming from all the loaded Target()s.
        # Note: Feedback retrieved from a real target has to be provided to the framework through
        # the associated Target object either after Target.send_data()
        # is called or when Target.collect_unsolicited_feedback() is called.
        if self._burst_countdown == self._burst:
            try:
                # we compute the max fbk_timeout onl yon the target that have been stimulated
                # as they rule the sequencing
                max_fbk_timeout = max([tg.feedback_timeout for tg in self._currently_used_targets
                                       if tg.feedback_timeout is not None])
            except ValueError:
                # empty list
                max_fbk_timeout = self._fbk_timeout_default
            for tg in self.targets.values():
                if tg not in self._currently_used_targets:
                    tg.collect_unsolicited_feedback(timeout=max_fbk_timeout)

        # the provided data_list can be changed after having called self._send_data()
        multiple_data = len(data_list) > 1

        if self.prj.wkspace_enabled:
            if self.prj.wkspace_size == 1:
                self.__current = [data_list[-1]]
            else:
                for dt in data_list:
                    self.__current.append(dt)
                wkspace_len = len(self.__current)
                if wkspace_len > self.prj.wkspace_size:
                    self.lg.log_fmk_info(f"Workspace is full (size={self.prj.wkspace_size}). Older "
                                         f"entries will be removed (ratio={self.prj.wkspace_free_slot_ratio_when_full*100}%)")
                    fslots = int(self.prj.wkspace_free_slot_ratio_when_full * self.prj.wkspace_size)
                    self.__current = self.__current[wkspace_len - self.prj.wkspace_size + fslots:]

        for dt in data_list:
            dt.make_recordable()

        # When checking target readiness, feedback timeout is taken into account indirectly
        # through the call to Target.is_feedback_received()
        cont0 = self.wait_for_target_readiness() >= 0

        if multiple_data:
            self._log_data(data_list, verbose=verbose)
        else:
            self._log_data(data_list[0], verbose=verbose)

        cont1 = True
        cont2 = True
        # That means this is the end of a burst
        if self._burst_countdown == self._burst:
            cont1 = self.retrieve_and_log_target_feedback()

        self.mon.notify_target_feedback_retrieval()
        self.mon.wait_for_probe_status_retrieval()

        if self._burst_countdown == self._burst:
            # We handle probe feedback if any
            cont2 = self.monitor_probes(force_record=True)
            for tg in self._currently_used_targets:
                tg.cleanup()

        self._do_after_feedback_retrieval(data_list)

        if not console_display:
            self.lg.display_on_term = lg_display_on_term_save

        return cont0 and cont1 and cont2, data_list

    @EnforceOrder(accepted_states=["S2"])
    def _send_data(self, data_list: Sequence[Data]):
        """
        @data_list: either a list of Data() or a Data()
        """

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

            self._stop_sending = False
            if data_list[0].is_unusable():
                self.mon.notify_error()
                if data_list[0].on_error_handover_to_user:
                    # We ask the framework to stop its current sending task and to give the
                    # control back to the end user.
                    self._stop_sending = True
                    self.set_error("_send_data(): A DataProcess has yielded. No more data to send."
                                   " We give control back to the end user.",
                                   code=Error.NoMoreData)
                else:
                    self.set_error("_send_data(): A DataProcess has yielded. No more data to send."
                                   " We are asked to go on silently with the next steps, if any.",
                                   code=Error.NoMoreData)
                    self._handle_data_callbacks(data_list, hook=HOOK.final)

                return None

            self._setup_new_sending()
            self._sending_error = False

            used_targets = []
            for d in data_list:
                self.next_data_id = self.fmkDB.get_next_data_id(prev_id=self.next_data_id)
                d.estimated_data_id = self.next_data_id
                tg_ids = self._vtg_to_tg(d)
                for tg_id in tg_ids:
                    if tg_id not in self.targets:
                        self.mon.notify_error()
                        self.set_error("_send_data(): Invalid Target ID ({:d})".format(tg_id),
                                       code=Error.FmkError)
                        self._sending_error = True
                        return None

                    tg = self.targets[tg_id]
                    tg.add_pending_data(d)
                    if tg not in used_targets:
                        used_targets.append(tg)

            self._currently_used_targets = used_targets

            for tg in self._currently_used_targets:
                try:
                    tg.send_pending_data(from_fmk=True)
                except TargetStuck as e:
                    self.lg.log_target_feedback_from(
                        source=FeedbackSource(self),
                        content="*** WARNING: Unable to send data to the target! [reason: {!s}]".format(e),
                        status_code=-1,
                        timestamp=datetime.datetime.now(),
                    )
                    self.mon.notify_error()
                    self._sending_error = True
                except:
                    self._handle_user_code_exception()
                    self.mon.notify_error()
                    self._sending_error = True
                else:
                    self.mon.notify_data_sending_event()

            self._do_after_sending_data(data_list)

        return data_list

    @EnforceOrder(accepted_states=["S2"])
    def _log_data(self, data_list, verbose=False):
        if self.__tg_enabled:
            if not self._is_data_valid(data_list):
                self.set_error("Data is empty and miss some needed meta-info --> will not be "
                               "logged",
                               code=Error.DataInvalid)
                return

            self.group_id += 1
            self._recovered_tgs = None
            gen = self.__current_gen

            if isinstance(data_list, Data):
                data_list = [data_list]
                multiple_data = False
            elif isinstance(data_list, list):
                multiple_data = True
            else:
                raise ValueError

            if multiple_data:
                self.lg.log_fmk_info("MULTIPLE DATA EMISSION", nl_after=True, delay_recording=True)

            for idx, dt in enumerate(data_list):
                dt_mk_h = dt.get_history()
                if multiple_data:
                    self.lg.log_fmk_info("Data #%d" % (idx + 1), nl_before=True, delay_recording=True)
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

                tg_ids = self._vtg_to_tg(dt)
                for tg_id in tg_ids:
                    tg = self.targets[tg_id]
                    ack_date = tg.get_last_target_ack_date()
                    self.lg.set_target_ack_date(FeedbackSource(tg), date=ack_date)

                if self.fmkDB.enabled:
                    self.last_data_id = self.lg.commit_data_table_entry(self.group_id, self.prj.name)
                    if self.last_data_id is None:
                        self.lg.print_console("### Data not recorded in FmkDB",
                                              rgb=Color.DATAINFO, nl_after=True)
                    else:
                        self.lg.print_console("### FmkDB Data ID: {!r}".format(self.last_data_id),
                                              rgb=Color.DATAINFO, nl_after=True)

                if multiple_data:
                    self.lg.log_fn("--------------------------", rgb=Color.SUBINFO)

                self.lg.log_target_ack_date()

                self.lg.reset_current_state()

    @EnforceOrder(accepted_states=["S2"])
    def _setup_new_sending(self):
        if self._burst > 1 and self._burst_countdown == self._burst:
            p = "\n::[ START BURST ]::\n"
        else:
            p = "\n"
        self._current_sent_date = self.lg.start_new_log_entry(preamble=p)

    @EnforceOrder(accepted_states=["S2"])
    def retrieve_and_log_target_feedback(self, residual=False):
        collected_status, err_detected2 = None, False
        ok = True
        if self.__tg_enabled:
            if residual:
                p = "*** RESIDUAL TARGET FEEDBACK ***"
                e = "********************************"
            else:
                p = "::[ END BURST ]::\n" if self._burst > 1 else None
                e = None
            try:
                collected_status = self.lg.log_collected_feedback(preamble=p, epilogue=e)
            except NotImplementedError:
                pass

            for tg in self.targets.values():
                if collected_status:
                    status = collected_status.get(tg, tg.STATUS_THRESHOLD_FOR_RECOVERY)
                    status = tg.STATUS_THRESHOLD_FOR_RECOVERY if status is None else status
                    err_detected1 = status < tg.STATUS_THRESHOLD_FOR_RECOVERY
                else:
                    err_detected1 = False
                err_detected2 = self._log_directly_retrieved_target_feedback(tg=tg, preamble=p, epilogue=e)
                go_on = self._recover_target(tg) if err_detected1 or err_detected2 else True
                if not go_on:
                    ok = False

        return ok

    @EnforceOrder(accepted_states=["S2"])
    def log_target_residual_feedback(self):
        return self.retrieve_and_log_target_feedback(residual=True)

    def _log_directly_retrieved_target_feedback(self, tg, preamble=None, epilogue=None):
        """
        This method is to be used when the target does not make use
        of Logger.collect_feedback() facility. We thus try to
        access the feedback from Target directly
        """
        err_detected = False

        if not tg.is_feedback_received():
            return err_detected

        tg_fbk = tg.get_feedback()
        if tg_fbk is not None:
            err_code = tg_fbk.get_error_code()
            if err_code is not None and err_code < tg.STATUS_THRESHOLD_FOR_RECOVERY:
                err_detected = True

            if tg_fbk.has_fbk_collector():
                for ref, fbk, status, tstamp in tg_fbk.iter_and_cleanup_collector():
                    if status < tg.STATUS_THRESHOLD_FOR_RECOVERY:
                        err_detected = True
                    self.lg.log_target_feedback_from(source=FeedbackSource(tg, subref=ref,
                                                                           display_feedback=tg.display_feedback),
                                                     content=fbk,
                                                     status_code=status,
                                                     timestamp=tstamp,
                                                     preamble=preamble,
                                                     epilogue=epilogue)

            raw_fbk = tg_fbk.get_bytes()
            if raw_fbk is not None:
                self.lg.log_target_feedback_from(source=FeedbackSource(tg, display_feedback=tg.display_feedback),
                                                 content=raw_fbk,
                                                 status_code=err_code,
                                                 timestamp=tg_fbk.get_timestamp(),
                                                 preamble=preamble,
                                                 epilogue=epilogue)

            tg_fbk.cleanup()

        return err_detected

    @EnforceOrder(accepted_states=["S2"])
    def wait_for_target_readiness(self, forced_feedback_timeout=None):
        """

        Args:
            forced_feedback_timeout: should be an integer >= 0 if only feedback need to be checked

        Returns:

        """

        if self.__tg_enabled:
            t0 = datetime.datetime.now() if self._last_sending_date is None else self._last_sending_date
            signal.signal(signal.SIGINT, sig_int_handler)
            ret = 0
            if forced_feedback_timeout is not None:
                fbk_timeout = forced_feedback_timeout
            elif self._currently_used_targets:
                fbkt_list = [tg.feedback_timeout for tg in self._currently_used_targets
                             if tg.feedback_timeout is not None]
                fbk_timeout = max(fbkt_list) if fbkt_list else self._fbk_timeout_default
            elif self._last_sending_date is None:
                # This case happens when we are waiting for feedback but no data has been sent,
                # It is typical when a NoDataStep() is reached in a Scenario
                fbk_timeout = self._fbk_timeout_default
            else:
                fbk_timeout = self._fbk_timeout_max

            # self.print('\n*** DBG: wait for target - fbk timeout: {!r} - forced fbk timeout: {!r}'.format(fbk_timeout, forced_feedback_timeout))

            tg = None
            try:
                # Wait for potential feedback from enabled targets
                for tg in self.targets.values():
                    while True:
                        # self.print('\n*** wait for target fbk busy loop')
                        if fbk_timeout == 0:
                            # self.print('\n*** DBG exit fast path1')
                            break
                        fbk_received = tg.is_feedback_received()
                        if (tg.fbk_wait_until_recv_mode and fbk_received) or \
                                (forced_feedback_timeout is not None and fbk_received):
                            # self.print('\n*** DBG exit fast path2')
                            break
                        now = datetime.datetime.now()
                        if (now - t0).total_seconds() > fbk_timeout:
                            # if not fbk_received:
                            #     self.lg.log_target_feedback_from(
                            #         source=FeedbackSource(self),
                            #         content='*** No feedback received from target {!s}.'
                            #             .format(self.available_targets_desc[tg]),
                            #         status_code=0,
                            #         timestamp=now
                            #     )
                            break
                        time.sleep(0.005)

                hc_timeout = self._hc_timeout_max
                # Wait until the target is ready to send data or timeout expired
                for tg in self.targets.values():
                    while not tg.is_target_ready_for_new_data():
                        # self.print('\n***DBG wait for target ready busy loop')
                        time.sleep(0.005)
                        now = datetime.datetime.now()
                        if (now - t0).total_seconds() > hc_timeout:
                            self.lg.log_target_feedback_from(
                                source=FeedbackSource(self),
                                content="*** Timeout! The target {!s} does not seem to be ready.".format(self.available_targets_desc[tg]),
                                status_code=-2,
                                timestamp=now
                            )
                            go_on = self._recover_target(tg)
                            ret = 0 if go_on else -1
                            # tg.cleanup()
                            break

            except KeyboardInterrupt:
                self.lg.log_comment("*** Waiting for target readiness has been cancelled by the user!\n")
                self.set_error("Waiting for target readiness has been cancelled by the user!",
                               code=Error.OperationCancelled)
                ret = -2
                if tg:
                    tg.cleanup()
            except:
                self._handle_user_code_exception()
                ret = -3
                if tg:
                    tg.cleanup()
            finally:
                self._last_sending_date = None
                signal.signal(signal.SIGINT, signal.SIG_IGN)

            return ret

        else:
            return 0

    @EnforceOrder(accepted_states=["S2"])
    def show_data(self, data: Data, verbose=True):
        self.lg.print_console("-=[ Data Visualization ]=-\n", rgb=Color.INFO, style=FontStyle.BOLD)
        self.lg.pretty_print_data(data, raw_limit=400)
        self.lg.print_console("\n\n", nl_before=False)

    @EnforceOrder(accepted_states=["S2"])
    def show_scenario(self, sc_name, fmt="pdf"):
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

    @EnforceOrder(accepted_states=["S2"])
    def show_atom_identifiers(self):
        self.lg.print_console("-=[ Atom IDs of the current data model ]=-", nl_after=True, rgb=Color.INFO, style=FontStyle.BOLD)
        for k in self.dm.atom_identifiers():
            self.lg.print_console(k, rgb=Color.SUBINFO)
        self.lg.print_console("\n\n", nl_before=False)

    @EnforceOrder(accepted_states=["S2"])
    def log_comment(self, comments):
        self.lg.log_comment(comments)

    @EnforceOrder(accepted_states=["S2"])
    def register_in_data_bank(self, data):
        if isinstance(data, Data):
            data = [data]
        for d in data:
            self.__db_idx += 1
            self.__data_bank[self.__db_idx] = d

    @EnforceOrder(accepted_states=["S2"])
    def fmkdb_fetch_data(self, start_id=1, end_id=-1):
        data_list = []
        for record in self.fmkDB.fetch_data(start_id=start_id, end_id=end_id):
            data_id, content, dtype, dmk_name, dm_name = record
            data = Data(content)
            data.set_data_id(data_id)
            data.set_initial_dmaker((str(dtype), str(dmk_name), None))
            data.from_fmkdb = True
            if dm_name != Database.DEFAULT_DM_NAME:
                dm = self.get_data_model_by_name(dm_name)
                data.set_data_model(dm)
            data_list.append(data)

        if not data_list:
            data_list = None
        elif len(data_list) == 1:
            data_list = data_list[0]

        return data_list

    def _log_fmk_info(self, msg):
        if self.lg:
            self.lg.log_fmk_info(msg, do_record=False)
        else:
            self.print(colorize("*** [ {:s} ] ***".format(msg), rgb=Color.FMKINFO))

    def enable_fmkdb(self):
        self.fmkDB.enable()
        self._log_fmk_info("Enable FmkDB")

    def disable_fmkdb(self):
        self.fmkDB.disable()
        self._log_fmk_info("Disable FmkDB")

    @EnforceOrder(accepted_states=["S2"])
    def get_last_data(self):
        if not self.prj.wkspace_enabled:
            self.set_error("Workspace is disabled!", code=Error.CommandError)
            return None

        if self.__current:
            entry = self.__current[-1]
            return entry
        else:
            return None

    @EnforceOrder(accepted_states=["S2"])
    def get_from_data_bank(self, i):
        try:
            entry = self.__data_bank[i]
        except KeyError:
            return None

        return entry

    @EnforceOrder(accepted_states=["S2"])
    def iter_data_bank(self):
        for i in self.__data_bank:
            yield self.__data_bank[i]

    def _show_entry(self, data):
        gen = self.__current_gen

        data_id = data.get_data_id()
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
                            self.lg.print_console("   |_ " + msg, rgb=Color.SUBINFO)
        else:
            init_dmaker = data.get_initial_dmaker()
            if init_dmaker is None:
                dtype, dmk_name = Database.DEFAULT_GTYPE_NAME, Database.DEFAULT_GEN_NAME
            else:
                dtype, dmk_name, _ = init_dmaker
            dm = data.get_data_model()
            dm_name = None if dm is None else dm.name
            msg = "|- data id: {!r} | type: {:s} | data model: {!s}".format(data_id, dtype, dm_name
            )
            self.lg.print_console(msg, rgb=Color.SUBINFO)

        self.lg.print_console("|_ OUT > ", rgb=Color.SUBINFO)
        self.lg.print_console(data, nl_before=False)
        self.lg.print_console("=" * 80 + "\n", rgb=Color.INFO)

    @EnforceOrder(accepted_states=["S2"])
    def show_data_bank(self):
        self.lg.print_console("-=[ Data Bank ]=-\n", rgb=Color.INFO, style=FontStyle.BOLD)

        for idx, entry in self.__data_bank.items():
            msg = "===[ {:d} ]===".format(idx)
            msg += "=" * (max(80 - len(msg), 0))
            self.lg.print_console(msg, rgb=Color.INFO)
            self._show_entry(entry)

        self.lg.print_console("\n", nl_before=False)

    @EnforceOrder(accepted_states=["S2"])
    def show_wkspace(self):
        if not self.prj.wkspace_enabled:
            self.set_error("Workspace is disabled!", code=Error.CommandError)
            return

        self.lg.print_console("-=[ Workspace ]=-\n", rgb=Color.INFO, style=FontStyle.BOLD)

        for data in self.__current:
            self._show_entry(data)

        self.lg.print_console("\n", nl_before=False)

    @EnforceOrder(accepted_states=["S2"])
    def empty_data_bank(self):
        self.__data_bank = {}
        self.__db_idx = 0

    @EnforceOrder(accepted_states=["S2"])
    def empty_workspace(self):
        if not self.prj.wkspace_enabled:
            self.set_error("Workspace is disabled!", code=Error.CommandError)
            return

        self.__current = []

    @EnforceOrder(accepted_states=["S2"])
    def register_current_in_data_bank(self):
        if not self.prj.wkspace_enabled:
            self.set_error("Workspace is disabled!", code=Error.CommandError)
            return

        if self.__current:
            for data in self.__current:
                self.register_in_data_bank(data)

    @EnforceOrder(accepted_states=["S2"])
    def register_last_in_data_bank(self):
        if not self.prj.wkspace_enabled:
            self.set_error("Workspace is disabled!", code=Error.CommandError)
            return

        if self.__current:
            self.register_in_data_bank(self.__current[-1])

    @EnforceOrder(accepted_states=["S2"])
    def show_operators(self):
        operators = self.prj.get_operators()
        self.lg.print_console("-=[ Operators ]=-", rgb=Color.INFO, style=FontStyle.BOLD)
        self.lg.print_console("")
        for o in operators:
            self.lg.print_console(o, rgb=Color.SUBINFO)
            desc = self._dmaker_desc_str(self.prj.get_operator(o))
            self.lg.print_console(desc, limit_output=False)

        self.lg.print_console("\n\n", nl_before=False)

    @EnforceOrder(accepted_states=["S2"])
    def get_operator(self, name):
        operator = self.prj.get_operator(name)
        if operator is None:
            self.set_error("Invalid operator", code=Error.InvalidOp)
            return None
        else:
            return operator

    @EnforceOrder(accepted_states=["S2"])
    def launch_operator(self, name, user_input=None, use_existing_seed=True, verbose=False):
        operator = self.prj.get_operator(name)
        if operator is None:
            self.set_error("Invalid operator", code=Error.InvalidOp)
            return False

        self._reset_fmk_internals(reset_existing_seed=(not use_existing_seed))

        try:
            ok = operator._start(self._exportable_fmk_ops, self.dm, self.mon, self.targets, self.lg, user_input)
        except:
            self._handle_user_code_exception("Operator has crashed during its start() method")
            return False
        finally:
            self.mon.wait_for_probe_initialization()  # operator.start() can start probes.

        if not ok:
            self.set_error("The _start() method of Operator '%s' has returned an error!" % name,
                           code=Error.UnrecoverableError)
            return False

        fmk_feedback = FmkFeedback()

        exit_operator = False
        while not exit_operator:
            try:
                operation = operator.plan_next_operation(self._exportable_fmk_ops, self.dm,
                                                         self.mon, self.targets, self.lg, fmk_feedback)
            except:
                self._handle_user_code_exception("Operator has crashed during its plan_next_operation() method")
                return False

            if operation is None:
                self.set_error("An operator shall always return an Operation() object in its plan_next_operation()",
                               code=Error.UserCodeError)
                return False

            if operation.is_flag_set(Operation.CleanupDMakers):
                self.cleanup_all_dmakers(reset_existing_seed=False)

            if operation.is_flag_set(Operation.Stop):
                self.retrieve_and_log_target_feedback()
                break
            else:
                retry = False
                data_list = []
                change_list = []

                instr_list = operation.get_instructions()
                for idx, instruction in enumerate(instr_list):
                    action_list, orig, tg_ids = instruction

                    if action_list is None:
                        data = orig
                    else:
                        data = self.process_data(action_list, seed=orig, save_gen_seed=use_existing_seed)
                    if data:
                        data.tg_ids = tg_ids

                    data_list.append(data)

                    if self.is_not_ok():
                        if fmk_feedback.is_flag_set(FmkFeedback.NeedChange):
                            self.set_error("Operator has not made a choice that allows to produce usable data",
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
                                    self.set_error("Unrecoverable error in process_data() method!",
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

                data_list = self._send_data(data_list)
                if self._sending_error:
                    self.lg.log_fmk_info("Operator will shutdown because of a sending error")
                    break
                elif self._stop_sending:
                    self.lg.log_fmk_info("Operator will shutdown because a DataProcess has yielded")
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
                    linst = operator.do_after_all(self._exportable_fmk_ops, self.dm, self.mon, self.targets, self.lg)
                except:
                    self._handle_user_code_exception("Operator has crashed during its .do_after_all() method")
                    return False

                if linst.is_instruction_set(LastInstruction.RecordData):
                    for dt in data_list:
                        dt.make_recordable()
                        self.register_in_data_bank(dt)

                if multiple_data:
                    self._log_data(data_list, verbose=verbose)
                else:
                    self._log_data(data_list[0], verbose=verbose)

                ret = self.wait_for_target_readiness()
                # Note: the condition (ret = -1) is supposed to be managed by the operator
                if ret < -1:
                    exit_operator = True
                    if ret == -2:
                        self.lg.log_fmk_info("Operator will shutdown because waiting has been cancelled by the user")
                    elif ret == -3:
                        self.lg.log_fmk_info("Operator will shutdown because of exception in user code")

                # Target fbk is logged only at the end of a burst
                if self._burst_countdown == self._burst:
                    cont1 = self.retrieve_and_log_target_feedback()

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
                    self.lg.log_operator_feedback(operator=operator, content=op_feedback,
                                                  status_code=op_status, timestamp=op_tstamp)

                comments = linst.get_comments()
                if comments:
                    self.lg.log_comment(comments)

                if op_status is not None and op_status < 0:
                    exit_operator = True
                    self.lg.log_fmk_info("Operator will shutdown because it returns a negative status")
                    for tg in self.targets.values():
                        self._recover_target(tg)

                if self._burst_countdown == self._burst:
                    for tg in self.targets.values():
                        tg.cleanup()

                # Delay introduced after logging data
                if not self._delay_sending():
                    exit_operator = True
                    self.lg.log_fmk_info("Operator will shutdown because waiting has been cancelled by the user")

        try:
            operator.stop(self._exportable_fmk_ops, self.dm, self.mon, self.targets, self.lg)
        except:
            self._handle_user_code_exception("Operator has crashed during its stop() method")
            return False

        self._reset_fmk_internals(reset_existing_seed=(not use_existing_seed))

        return True

    @EnforceOrder(accepted_states=["S2"])
    def exec_dm_tests(self):
        try:
            self.dm.validation_tests()
        except Exception:
            self._handle_user_code_exception(f"Validation tests has crashed on current data model {self.dm.name}")

    @EnforceOrder(accepted_states=["S2"])
    def process_data(self, action_list, seed=None, valid_gen=False, save_gen_seed=False, reset_dmakers=False):
        """

        Args:
          action_list (list): Shall have a format compatible with what follows
            [(action_1, UserInput_1), ..., (action_n, UserInput_n)]
            [action_1, (action_2, UserInput_2), ... action_n]
            where action_N can be either: dmaker_type_N or (dmaker_type_N, dmaker_name_N)

        """

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

        if seed != None:
            data = copy.copy(seed)
            initial_generator_info = seed.get_initial_dmaker()
            # data.generate_info_from_content(data=seed)
            history = data.get_history()
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

        action_list_sz = len(action_list)
        for idx, full_action in enumerate(action_list):
            if isinstance(full_action, (tuple, list)):
                assert len(full_action) == 2
                action, user_input = full_action
            else:
                action = full_action
                user_input = None

            if first and action == "NOGEN":
                self.lg.log_fmk_info("We are asked to ignore the generator and to go on with disruptors resolution")
                first = False
                continue

            if unrecoverable_error:
                break

            if idx == action_list_sz - 1:
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
                dmaker_ref = "type: " + dmaker_type + ", name: " + provided_dmaker_name
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

                    assert dmaker_obj is not None
                    is_gen = issubclass(dmaker_obj.__class__, Generator)
                    stateful = is_gen or issubclass(dmaker_obj.__class__, StatefulDisruptor)

                    if not ok:
                        self.set_error(err_msg, code=Error.CloneError)
                        return None

                    self.fmkDB.insert_dmaker(self.dm.name, dmaker_type, cloned_dmaker_name,
                                             is_gen, stateful, clone_type=cloned_dmaker_type)

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

            if reset_dmakers:
                dmaker_obj._cleanup()

            get_name = get_generic_dmaker_name if generic else get_dmaker_name
            dmaker_name = get_name(dmaker_type, dmaker_obj)

            if first:  # Generator() case
                if not reset_dmakers and \
                        (dmaker_obj in self.__initialized_dmakers and self.__initialized_dmakers[dmaker_obj][0]):
                    ui = self.__initialized_dmakers[dmaker_obj][1]
                else:
                    if action_list_sz == 1 and isinstance(dmaker_obj, DynGenerator):
                        ui = UI(freeze=True) if user_input is None else user_input.merge_with(UI(freeze=True))
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
                                        "by this disruptor taking over it.".format(idx + 1, dmaker_type, dmaker_name))
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
                        msg = (
                            "A disruptor taking over the data generation is at least present twice! "
                            "The resulting behaviour is certainly not what you want, because it will execute twice the "
                            "disrupt_data() method on this disruptor with the same inputs (user + data). You should avoid "
                            "this situation by cloning first the disruptor you want to use twice."
                        )
                        self.set_error(msg, code=Error.CommandError)
                        for dmobj in current_dmobj_list[:-1]:
                            self.cleanup_dmaker(dmaker_obj=dmobj)
                        return None

            setup_crashed = False
            setup_err = False

            try:
                if dmaker_obj not in self.__initialized_dmakers:
                    self.__initialized_dmakers[dmaker_obj] = (False, None)

                if reset_dmakers or not self.__initialized_dmakers[dmaker_obj][0]:
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
                            data = Data(dmaker_obj.produced_seed.get_content(do_copy=True))
                        else:
                            data = dmaker_obj.generate_data(self.dm, self.mon, self.targets)
                            if data.scenario_dependence:
                                init_dmaker = data.get_initial_dmaker()
                                if init_dmaker[0] != Database.DEFAULT_GTYPE_NAME:
                                    initial_generator_info = data.get_initial_dmaker()
                            if save_gen_seed and dmaker_obj.produced_seed is None:
                                # Usefull to replay from the beginning a modelwalking sequence
                                dmaker_obj.produced_seed = Data(data.get_content(do_copy=True))
                        invalid_data = not self._is_data_valid(data)
                    elif isinstance(dmaker_obj, Disruptor):
                        if not self._is_data_valid(data):
                            invalid_data = True
                        else:
                            data = dmaker_obj.disrupt_data(self.dm, self.targets, data)
                    elif isinstance(dmaker_obj, StatefulDisruptor):
                        # we only check validity in the case the stateful disruptor
                        # has not been seeded
                        if dmaker_obj.is_attr_set(DataMakerAttr.NeedSeed) and not self._is_data_valid(data):
                            invalid_data = True
                        else:
                            ret = dmaker_obj._set_seed(data)
                            if isinstance(ret, Data):
                                data = ret
                                dmaker_obj.set_attr(DataMakerAttr.NeedSeed)
                            else:
                                data = dmaker_obj.disrupt_data(self.dm, self.targets, data)
                    else:
                        raise ValueError

                    self._do_after_dmaker_data_retrieval(data)

                    if invalid_data:
                        unrecoverable_error = True
                        self.set_error("The data maker ({:s}) returned an empty data (probable "
                                       "reason: the left-side data maker is disabled and need"
                                       "to be reset)".format(dmaker_ref),
                                       code=Error.DataInvalid,
                                       context={"dmaker_name": dmaker_name, "dmaker_type": dmaker_type})

                    elif data is None:
                        unrecoverable_error = True
                        self.set_error("A Data maker shall never return None! (guilty: '%s')" % dmaker_ref,
                                       code=Error.UserCodeError)

                    elif data.is_unusable():
                        unrecoverable_error = True
                        self.set_error("The data maker ({:s}) has returned unusable data.".format(dmaker_ref),
                                       code=Error.DataUnusable,
                                       context={"dmaker_name": dmaker_name, "dmaker_type": dmaker_type})

                except Exception:
                    unrecoverable_error = True
                    self._handle_user_code_exception("The generate_data()/disrupt_data()/set_seed() " \
                                                     "method of Data Maker '%s' has crashed!" % dmaker_ref)

                # If a generator need a reset or a ('controller') disruptor has yielded
                if dmaker_obj.is_attr_set(DataMakerAttr.SetupRequired):
                    assert dmaker_obj in self.__initialized_dmakers
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
                        # if save_seed and isinstance(dmobj, Generator):
                        #     dmobj.produced_seed = None
                        if dmobj.is_attr_set(DataMakerAttr.Controller):
                            dmobj.set_attr(DataMakerAttr.Active)
                            if dmobj.is_attr_set(DataMakerAttr.HandOver):
                                _handle_disruptors_handover(dmlist[: dmlist_mangled_size - idx])
                            break
                        else:
                            dmobj.set_attr(DataMakerAttr.Active)

                # Apply to controller disruptor only
                if dmaker_obj.is_attr_set(DataMakerAttr.HandOver):
                    _handle_disruptors_handover(current_dmobj_list)
                    self.set_error("Disruptor '{:s}' ({:s}) has yielded!".format(dmaker_name, dmaker_type),
                                   context={"dmaker_name": dmaker_name, "dmaker_type": dmaker_type},
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
            self.set_error("Data is empty (probable reason: used data maker is disabled and need "
                           "to be reset)",
                           code=Error.DataInvalid)
            return None
        else:
            return data

    @EnforceOrder(accepted_states=["S1", "S2"])
    def cleanup_all_dmakers(self, reset_existing_seed=True):
        return self._cleanup_all_dmakers(reset_existing_seed=reset_existing_seed)

    def _cleanup_all_dmakers(self, reset_existing_seed=True):
        if not self.__initialized_dmakers:
            return

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

    @EnforceOrder(accepted_states=["S1", "S2"])
    def cleanup_dmaker( self, dmaker_type=None, name=None, dmaker_obj=None, reset_existing_seed=True, error_on_init=True):
        if dmaker_obj is not None:
            if reset_existing_seed and isinstance(dmaker_obj, Generator):
                dmaker_obj.produced_seed = None

            if dmaker_obj in self.__initialized_dmakers:
                dmaker_obj._cleanup()
                self.__initialized_dmakers[dmaker_obj] = (False, None)
            else:
                self.set_error("The specified data maker is not initialized!",
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
                        raise ValueError("Implementation Error!")

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
            self.set_error("The specified data maker is not initialized!",
                           code=Error.FmkWarning)

    @EnforceOrder(accepted_states=["S2"])
    def set_disruptor_weight(self, dmaker_type, data_maker_name, weight):
        self._tactics.set_disruptor_weight(dmaker_type, data_maker_name, weight)

    @EnforceOrder(accepted_states=["S2"])
    def set_generator_weight(self, generator_type, data_maker_name, weight):
        self._tactics.set_generator_weight(generator_type, data_maker_name, weight)

    @EnforceOrder(accepted_states=["S2"])
    def show_tasks(self):
        self.lg.print_console("-=[ Running Tasks ]=-", rgb=Color.INFO, style=FontStyle.BOLD)
        self.lg.print_console("")
        if not self._task_list:
            self.lg.print_console("No task is currently running", rgb=Color.SUBINFO)
        else:
            for tk_id, tk in self._task_list.items():
                msg = "Task ID #{!s}".format(tk_id)
                self.lg.print_console(msg, rgb=Color.SUBINFO)
        self.lg.print_console("\n", nl_before=False)

    @EnforceOrder(accepted_states=["S2"])
    def show_probes(self):
        probes = self.prj.get_probes()
        self.lg.print_console("-=[ Probes ]=-", rgb=Color.INFO, style=FontStyle.BOLD)
        self.lg.print_console("")
        for p in probes:
            try:
                status = self.mon.get_probe_status(p).value
            except:
                status = None
            msg = "name: %s (status: %s, delay: %f) --> " % (
                p,
                repr(status),
                self.mon.get_probe_delay(p),
            )

            if self.mon.is_probe_stuck(p):
                msg += "stuck"
            elif self.mon.is_probe_launched(p):
                msg += "launched"
            else:
                msg += "stopped"
            self.lg.print_console(msg, rgb=Color.SUBINFO)

        self.lg.print_console("\n", nl_before=False)

    @EnforceOrder(accepted_states=["S2"])
    def launch_probe(self, name):
        ok = self.mon.start_probe(name)
        if not ok:
            self.set_error("Probe does not exist (or already launched)",
                           code=Error.CommandError)
        self.mon.wait_for_probe_initialization()

        return ok

    @EnforceOrder(accepted_states=["S2"])
    def stop_all_probes(self):
        self.mon.stop_all_probes()

    @EnforceOrder(accepted_states=["S2"])
    def stop_probe(self, name):
        self.mon.stop_probe(name)

    @EnforceOrder(accepted_states=["S2"])
    def get_probe_delay(self, name):
        self.mon.get_probe_delay(name)

    @EnforceOrder(accepted_states=["S2"])
    def set_probe_delay(self, name, delay):
        ok = self.mon.set_probe_delay(name, delay)
        if not ok:
            self.set_error("Probe '%s' does not exist" % name,
                           code=Error.CommandError)
        return ok

    @EnforceOrder(accepted_states=["S2"])
    def show_data_maker_types(self):
        def print_dmaker(dmaker_list, title):
            if not dmaker_list:
                return

            ln = ""
            sep = colorize(", ", rgb=Color.FMKINFO)
            lines = []
            for idx, entry in enumerate(dmaker_list, start=1):
                if idx % 5 != 0:
                    ln += colorize(entry, rgb=Color.FMKSUBINFO) + sep
                else:
                    ln += colorize(entry, rgb=Color.FMKSUBINFO)
                    lines.append(colorize("   | ", rgb=Color.FMKINFO) + ln)
                    ln = ""

            if len(dmaker_list) % 5 != 0:
                lines.append(colorize("   | ", rgb=Color.FMKINFO) + ln[: -len(sep)])

            self.lg.print_console(" [ " + title + " ]", rgb=Color.FMKINFO, nl_before=True, nl_after=False)
            for ln in lines:
                self.lg.print_console(ln)
            self.lg.print_console("")

        self.lg.print_console("===[ Generator Types ]" + "=" * 58, rgb=Color.FMKINFOGROUP, nl_after=True)

        dmakers = {}
        for dt, related_dm in self._tactics.generators_info():
            if related_dm is None:
                continue
            if related_dm not in dmakers:
                dmakers[related_dm] = []
            dmakers[related_dm].append(dt)

        for related_dm, dt_list in dmakers.items():
            print_dmaker(dt_list, "Data Model: {}".format(related_dm.name))

        l2 = []
        for dt in self._generic_tactics.generator_types:
            l2.append(dt)
        l2 = sorted(l2)
        print_dmaker(l2, "Generic")

        self.lg.print_console("===[ Disruptor Types ]" + "=" * 58, rgb=Color.FMKINFOGROUP, nl_after=True)

        dmakers = {}
        for dt, related_dm in self._tactics.disruptors_info():
            if related_dm is None:
                continue
            if related_dm not in dmakers:
                dmakers[related_dm] = []
            dmakers[related_dm].append(dt)

        for related_dm, dt_list in dmakers.items():
            print_dmaker(dt_list, "Data Model: {}".format(related_dm.name))

        l2 = []
        for dmaker_type in self._generic_tactics.disruptor_types:
            l2.append(dmaker_type)
        l2 = sorted(l2)
        print_dmaker(l2, "Generic")

    def _chunk_lines(self, string, length):
        l = string.split(" ")
        chk_list = []
        full_line = ""
        for wd in l:
            full_line += wd + " "
            if len(full_line) > (length - 1):
                chk_list.append(full_line)
                full_line = ""
        if full_line:
            chk_list.append(full_line)
        # remove last space char
        if chk_list:
            chk_list[-1] = (chk_list[-1])[:-1]
        return chk_list

    def _dmaker_desc_str(self, obj):
        def _make_str(k, v):
            desc, default, arg_type = v
            l = self._chunk_lines(desc, 60)
            k_len = len(k)
            prefix_len = len("\n    |_ ") + 3 - len("desc: ")
            prefix = "\n    |_ " + colorize(k, rgb=Color.INFO_ALT) + \
                     "\n    |      | " + colorize("desc: ", rgb=Color.SUBINFO_ALT)
            msg = prefix
            indent = 0
            for chk, cpt in zip(l, range(len(l), 0, -1)):
                msg += "    |" * indent + " " * prefix_len * indent + \
                       " |       " * indent + chk + "\n"
                indent = 1

            if isinstance(arg_type, tuple):
                args_type_desc = ""
                for x in arg_type:
                    args_type_desc += x.__name__ + ", "
                args_type_desc = args_type_desc[:-2]
            elif arg_type is None:
                args_type_desc = "unspecified"
            else:
                args_type_desc = arg_type.__name__
            msg += "    |" + " " * prefix_len + \
                   " | " + colorize("default: ", rgb=Color.SUBINFO_ALT) + \
                   colorize(repr(default), rgb=Color.SUBINFO_ALT_HLIGHT) + " [type: {:s}]".format(args_type_desc)
            return msg

        if obj.__doc__:
            msg = "\n" + colorize(obj.__doc__, rgb=Color.INFO_ALT_HLIGHT)
        else:
            msg = ""
        if obj._args_desc:
            msg += "\n  parameters: "
            for k, v in obj._args_desc.items():
                msg += _make_str(k, v)

        return msg

    @EnforceOrder(accepted_states=["S2"])
    def show_generators(self, dmaker_type=None):
        generators = self._tactics.generator_types
        gen_generators = self._generic_tactics.generator_types
        if dmaker_type:
            if dmaker_type not in generators and dmaker_type not in gen_generators:
                self.set_error("The specified data maker does not exist!", 
                               code=Error.FmkWarning)
                return
            else:
                generators = None if dmaker_type not in generators else [dmaker_type]
                gen_generators = None if dmaker_type not in gen_generators else [dmaker_type]

        if generators:
            self.lg.print_console("\n-=[ SPECIFIC GENERATORS ]=-", rgb=Color.INFO, style=FontStyle.BOLD)
            for dt in sorted(generators):
                msg = "\n*** Available generators of type '%s' ***" % dt
                self.lg.print_console(msg, rgb=Color.INFO)
                generators_list = self._tactics.get_generators_list(dt)
                for name in generators_list:
                    msg = "  name: %s (weight: %d, valid: %r)" % (
                        name,
                        self._tactics.get_generator_weight(dt, name),
                        self._tactics.get_generator_validness(dt, name),
                    )
                    msg += self._dmaker_desc_str(self._tactics.get_generator_obj(dt, name))
                    self.lg.print_console(msg, limit_output=False)

        if gen_generators:
            self.lg.print_console("\n-=[ GENERIC GENERATORS ]=-", rgb=Color.INFO, style=FontStyle.BOLD)
            for dt in sorted(gen_generators):
                msg = "\n*** Generic generators of type '%s' ***" % dt
                self.lg.print_console(msg, rgb=Color.INFO)
                gen_generators_list = self._generic_tactics.get_generators_list(dt)
                for name in gen_generators_list:
                    msg = "  name: %s (weight: %d, valid: %r)" % (
                        name,
                        self._generic_tactics.get_generator_weight(dt, name),
                        self._generic_tactics.get_generator_validness(dt, name),
                    )
                    msg += self._dmaker_desc_str(self._generic_tactics.get_generator_obj(dt, name))
                    self.lg.print_console(msg, limit_output=False)

        self.lg.print_console("\n", nl_before=False)

    @EnforceOrder(accepted_states=["S2"])
    def show_disruptors(self, dmaker_type=None):
        disruptors = self._tactics.disruptor_types
        gen_disruptors = self._generic_tactics.disruptor_types
        if dmaker_type:
            if dmaker_type not in disruptors and dmaker_type not in gen_disruptors:
                self.set_error("The specified data maker does not exist!",
                               code=Error.FmkWarning)
                return
            else:
                disruptors = [] if dmaker_type not in disruptors else [dmaker_type]
                gen_disruptors = [] if dmaker_type not in gen_disruptors else [dmaker_type]

        if disruptors:
            self.lg.print_console("\n-=[ SPECIFIC DISRUPTORS ]=-", rgb=Color.INFO, style=FontStyle.BOLD)
            for dmt in sorted(disruptors):
                msg = "\n*** Specific disruptors of type '%s' ***" % dmt
                self.lg.print_console(msg, rgb=Color.INFO)
                disruptors_list = self._tactics.get_disruptors_list(dmt)
                for name in disruptors_list:
                    dis_obj = self._tactics.get_disruptor_obj(dmt, name)
                    if issubclass(dis_obj.__class__, StatefulDisruptor):
                        dis_type = "stateful disruptor"
                    else:
                        dis_type = "stateless disruptor"
                    msg = "  name: {:s} ".format(name) + \
                          " (weight: {:d}, valid: {!r})".format(
                                  self._tactics.get_disruptor_weight(dmt, name),
                                  self._tactics.get_disruptor_validness(dmt, name))
                    msg += " " + colorize("[{:s}]".format(dis_type), rgb=Color.INFO_ALT)
                    msg += self._dmaker_desc_str(dis_obj)
                    self.lg.print_console(msg, limit_output=False)

        if gen_disruptors:
            self.lg.print_console("\n-=[ GENERIC DISRUPTORS ]=-", rgb=Color.INFO, style=FontStyle.BOLD)
            for dmt in sorted(gen_disruptors):
                msg = "\n*** Generic disruptors of type '%s' ***" % dmt
                self.lg.print_console(msg, rgb=Color.INFO)
                gen_disruptors_list = self._generic_tactics.get_disruptors_list(dmt)
                for name in gen_disruptors_list:
                    dis_obj = self._generic_tactics.get_disruptor_obj(dmt, name)
                    if issubclass(dis_obj.__class__, StatefulDisruptor):
                        dis_type = "stateful disruptor"
                    else:
                        dis_type = "stateless disruptor"
                    msg = "  name: {:s} ".format(name) + \
                          " (weight: {:d}, valid: {!r})".format(
                              self._generic_tactics.get_disruptor_weight(dmt, name),
                              self._generic_tactics.get_disruptor_validness(dmt, name))
                    msg += " " + colorize("[{:s}]".format(dis_type), rgb=Color.INFO_ALT)
                    msg += self._dmaker_desc_str(dis_obj)
                    self.lg.print_console(msg, limit_output=False)

        self.lg.print_console("\n", nl_before=False)

    @EnforceOrder(accepted_states=["20_load_prj", "25_load_dm", "S1", "S2"])
    def display_color_theme(self):
        Color.display()


class FmkShell(cmd.Cmd):
    def __init__(self, title, fmk_plumbing, completekey="tab"):
        cmd.Cmd.__init__(self, completekey, stdin=None, stdout=None)
        self.fz = fmk_plumbing
        self.printer = fmk_plumbing.printer
        self.print = fmk_plumbing.printer.print

        self.intro = colorize(FontStyle.BOLD + "\n-=[ %s ]=- (with Fuddly FmK %s)\n" % (title, fuddly_version), rgb=Color.TITLE)

        self.__allowed_cmd = re.compile(
            "^quit$|^switch_term$|^show_projects$|^show_data_models$|^load_project|^load_data_model"
            "|^load_targets|^show_targets$|^launch$|^run_project|^config|^display_color_theme$"
            "|^disable_fmkdb$|^enable_fmkdb$|^disable_fbk_handlers$|^enable_fbk_handlers$|^help"
        )

        self.dmaker_name_re = re.compile(r'^([#\-\w]+)(\(?[^\(\)]*\)?)$', re.S)
        self.input_params_re = re.compile(r'\((.*)\)', re.S)
        self.input_param_values_re = re.compile(r'(.*)=(.*)', re.S)

        self.config = config(self, path=[config_folder])

        self.available_configs = {
            "framework": self.fz.config,
            "shell": self.config,
            "db": self.fz.fmkDB.config,
        }

        def save_config():
            for conf in self.available_configs.values():
                filename = os.path.join(config_folder, conf.config_name + ".ini")
                with open(filename, "w") as cfile:
                    conf.write(cfile)

        atexit.register(save_config)

        self.prompt = "\n" + self.config.prompt + " "

        self.__error = False
        self.__error_msg = ""
        self.__error_fmk = ""
        self._quit_shell = False

        history_path = os.path.expanduser(
            gr.fuddly_data_folder + "fuddly_shell_history"
        )

        def save_history(history_path=history_path):
            readline.write_history_file(history_path)

        if os.path.exists(history_path):
            readline.read_history_file(history_path)

        atexit.register(save_history)

        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def postcmd(self, stop, line):
        self.prompt = "\n" + self.config.prompt + " "

        if self._quit_shell:
            self._quit_shell = False
            msg = colorize(FontStyle.BOLD + "\nReally Quit? [Y/n]", rgb=Color.WARNING)
            try:
                cont = get_user_input(msg)
                cont = cont.upper()
            except(EOFError):
                cont = 'Y'
            if cont == 'Y' or cont == '':
                self.fz.stop()
                return True
            else:
                return False

        printed_err = False
        self.print("")
        if self.fz.is_not_ok() or self.__error:
            printed_err = True
            msg = "| ERROR / WARNING / INFO |"
            self.print(colorize("-" * len(msg), rgb=Color.WARNING))
            self.print(colorize(msg, rgb=Color.WARNING))
            self.print(colorize("-" * len(msg), rgb=Color.WARNING))

        if self.fz.is_not_ok():
            err_list = self.fz.get_error()
            for e in err_list:
                self.print(colorize("    (_ FMK [#{err!s:s}]: {msg:s} _)".format(err=e, msg=e.msg), rgb=e.color)
                )

        if self.__error:
            self.__error = False
            if self.__error_msg != "":
                self.print(colorize("    (_ SHELL: {:s} _)".format(self.__error_msg), rgb=Color.WARNING)
                )

        if printed_err:
            self.print("")

        self.__error_msg = ""
        self.__error_fmk = ""

        self.printer.wait_for_sync()

        return stop

    def emptyline(self):
        return False

    def cmdloop(self, intro=None):
        try:
            cmd.Cmd.cmdloop(self, intro)
        except BaseException as e:
            color = Error(code=Error.OperationCancelled).color
            sys.stdout.write(colorize(repr(e) + "\n", rgb=color))
            self.fz._handle_fmk_exception(cause="unknown error")
            self.__error = False
            self.__error_msg = ""
            self.intro = None
            self.cmdloop()

    def precmd(self, line):
        if line == "EOF":
            self._quit_shell = True
            return ""

        if self.fz.is_usable():
            return line

        elif self.__allowed_cmd.match(line):
            return line

        else:
            self.__error = True
            self.__error_msg = "You shall first load a project and/or enable all the framework components!"
            return ""

    def do_switch_term(self, line):
        """Display information on another terminal"""
        self.fz.switch_term()

        return False

    def do_show_projects(self, line):
        """Show the available Projects"""
        self.fz.show_projects()

        return False

    def do_show_data_models(self, line):
        """Show the available Data Models"""
        self.fz.show_data_models()

        return False

    def do_display_color_theme(self, line):
        """Display the color theme"""
        self.fz.display_color_theme()

        return False

    def do_logger_switch_format(self, line):
        """
        Change the way the logger display the data which are sent to the targets and retrieved from them.
        (From raw format to interpreted format and reversely.)
        This command modify the current Project's Logger.
        """
        self.fz.lg.export_raw_data = not self.fz.lg.export_raw_data

        return False

    def complete_config(self, text, line, bgidx, endix, target=None):
        init = False
        if target is None:
            init = True

        args = line.split()
        if args[-1] == text:
            args.pop()
        if init:
            if len(args) == 1:
                comp = [k for k in self.available_configs.keys()]
                if text != "":
                    comp = [i for i in comp if i.startswith(text)]
                return comp

            try:
                if text != "":
                    return self.complete_config(
                        text,
                        " ".join(["config"] + args[2:] + [text]),
                        0,
                        0,
                        self.available_configs[args[1]],
                    )
                else:
                    return self.complete_config(
                        "",
                        " ".join(["config"] + args[2:]),
                        0,
                        0,
                        self.available_configs[args[1]],
                    )
            except KeyError:
                pass

            return []

        if len(args) == 1 and isinstance(target, config):
            comp = target.parser.options("global") + target.parser.sections()
            if text != "":
                comp = [i for i in comp if i.startswith(text)]
            comp = [
                i.replace(".", " ")
                for i in comp
                if (i[-4:] != ".doc" and i != "config_name" and i != "global")
            ]
            return comp
        if len(args) > 1 and args[1] == "shell":
            return self.complete_config(
                text, " ".join(args[1:] + [text]), 0, 0, self.config
            )
        if len(args) > 1 and target.parser.has_section(args[1]):
            return self.complete_config(
                    text,
                    " ".join(args[1:] + [text]),
                    0,
                    0,
                    getattr(target, args[1]))
        comp = target.parser.options("global")
        comp = [i for i in comp if i.startswith(args[-1] + ".")]
        comp = [i[len(args[-1]) + 1 :] for i in comp
                if (i[-4:] != ".doc" and i != "config_name" and i != "global")]
        if text != "":
            comp = [i for i in comp if i.startswith(text)]
        return comp

    def do_config(self, line, target=None):
        """Get and set miscellaneous options

        Usage:
         - config
               List all configuration options available.
         - config [name [subname...]]
               Get value associated with <name>.
         - config [name [subname...]] value
               Set value associated with <name>.
        """
        self.__error = True

        level = self.config.config.indent.level
        indent = self.config.config.indent.width
        middle = self.config.config.middle

        args = line.split()
        if target is None:
            if len(args) == 0:
                self.print("Available configurations:")
                for target in self.available_configs:
                    self.print(" - {}".format(target))
                self.print('\n\t > Type "config <name>" to display documentation.')
                self.__error = False
                return False
            else:
                try:
                    target = self.available_configs[args[0]]
                    self.__error = False
                    return self.do_config(" ".join(args[1:]), target)
                except KeyError as e:
                    self.print('Unknown config "{}": '.format(args[0]) + str(e))
                return False

        if len(args) == 0:
            self.print(target.help(None, level, indent, middle))
            self.__error = False
            return False
        elif len(args) == 1:
            self.print(target.help(args[0], level, indent, middle))
            self.__error = False
            return False

        section = args[0]
        try:
            attr = getattr(target, section)
        except:
            self.__error_msg = "'{}' is not a valid config key".format(section)
            return False

        if isinstance(attr, config):
            self.__error = False
            return self.do_config(" ".join(args[1:]), attr)

        if len(args) == 2:
            if isinstance(attr, config_dot_proxy):
                self.__error = False
                key = ".".join(args)
                self.print(target.help(key, level, indent, middle))
                self.__error = False
                return False

            try:
                setattr(target, args[0], args[1])
            except AttributeError as e:
                self.__error_msg = "config: " + str(e)
                return False

            self.print(target.help(args[0], level, indent, middle))
            self.__error = False
            return False

        if isinstance(attr, config_dot_proxy):
            key = ".".join(args[:-1])
            try:
                attr = getattr(target, key)
            except:
                self.__error_msg = "'{}' is not a valid config key".format(key)
                return False

            try:
                setattr(target, key, args[-1])
            except AttributeError as e:
                self.__error_msg = "config: " + str(e)
                return False

            self.print(target.help(key, level, indent, middle))
            self.__error = False
            return False

        self.__error_msg = "'{}' do not have subkeys".format(args[0])
        return False

    def do_exec_dm_tests(self, line):
        """
        Execute the validation tests of current Data Model
        """
        self.fz.exec_dm_tests()
        return False

    def do_load_data_model(self, line):
        """Load a Data Model by name"""
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
        """
        Load a multiple Data Model by name
        |_ syntax: load_multiple_data_model <dm_name_1> <dm_name_2> ... [dm_name_n]
        """
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
        """Load an available Project"""
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
        """
        Load a Project by name & Launch it:
        1. Enable the specified target
        2. Load the default data model of the project file
        3. Launch the project by starting fuddly subsystems

        |_ syntax: run_project <project_name> [target_id1 ... target_idN]
        """

        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len < 1:
            self.__error_msg = "Syntax Error!"
            return False

        prj_name = args[0].strip()
        try:
            tg_id = args[1]
        except IndexError:
            tg_id = None

        if tg_id:
            tg_ids = []
            try:
                for tg_id in args[1:]:
                    tg_ids.append(int(tg_id))
            except ValueError:
                self.__error_msg = "Parameter N (N>=2) shall be an integer!"
                return False
        else:
            tg_ids = None

        ok = False
        for prj in self.fz.projects():
            if prj.name == prj_name:
                ok = True
                break

        self.__error_msg = "Project '%s' is not available" % prj_name
        if not ok:
            return False

        self.__error_msg = "Unable to launch the project '%s'" % prj_name
        if not self.fz.run_project(prj=prj, tg_ids=tg_ids):
            return False

        self.__error = False
        return False

    def do_load_targets(self, line):
        """
        Set the target number to use
        |_ syntax: load_targets <target_id1> [target_id2 ... target_idN]
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len < 1:
            return False

        tg_ids = []
        try:
            for tg_id in args:
                tg_ids.append(int(tg_id))
        except ValueError:
            return False

        self.fz.load_targets(tg_ids)

        self.__error = False
        return False

    def do_show_targets(self, line):
        """Show the available Targets for the current Data Model"""
        self.fz.show_targets()

        return False

    def do_show_fmk_internals(self, line):
        """Show the framework internals"""
        self.fz.show_fmk_internals()

        return False

    def do_show_knowledge(self, line):
        """Show the current status of knowledge"""
        self.fz.show_knowledge()

        return False

    def do_launch(self, line):
        """Launch the loaded project by starting every needed components"""
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
        """
        Launch a probe
        |_ syntax: launch_probe <probe_name>
        """
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
        """
        Stop a probe
        |_ syntax: stop_probe <probe_name>
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False

        self.fz.stop_probe(args[0])

        self.__error = False
        return False

    def do_set_probe_delay(self, line):
        """
        Delay a probe.
        |  syntax: set_probe_delay <name> <delay>
        |  |_ possible values for <delay>:
        |      0  : no delay
        |     x>0 : delay expressed in seconds (fraction is possible)
        """
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
        """
        Show all the disruptors description or the ones of the
        provided type
        |_ syntax: show_disruptors [disruptor_type]
        """
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
        """
        Show all the generators description or the ones of the
        provided type
        |_ syntax: show_generators [generator_type]
        """
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

    def do_show_atoms(self, line):
        """
        Provide the Atoms of the current data model.
        """
        self.fz.show_atom_identifiers()
        return False

    def do_enable_wkspace(self, line):
        self.fz.enable_wkspace()
        return False

    def do_disable_wkspace(self, line):
        self.fz.disable_wkspace()
        return False

    def do_send_loop_keepseed(self, line):
        """
        Execute the 'send' command in a loop and save the seed
        |_ syntax: send_loop_keepseed <#loop> <generator_type> [disruptor_type_1 ... disruptor_type_n]  [targetID1 ... targetIDN]

        Notes:
            - To loop indefinitely use -1 for #loop. To stop the loop use Ctrl+C
            - send_loop_keepseed keep the generator output until a reset is performed on it.
              Thus, in the context of a disruptor chain, if the generator is non-deterministic,
              and even if you clean up the generator, you could still reproduce the exact sequence
              of data production from the beginning
        """
        ret = self.do_send_loop(line, use_existing_seed=True)
        return ret

    def do_set_generator_weight(self, line):
        """
        Set the weight of the given generator
        |_ syntax: set_generator_weight <generator_type> <generator> <weight>
        """
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
        """
        Set the weight of the given disruptor
        |_ syntax: set_disruptor_weight <dmaker_type> <disruptor> <weight>
        """
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

    def do_launch_operator(self, line, use_existing_seed=False, verbose=False):
        """
        Launch the specified operator and use any existing seed
        |_ syntax: launch_operator <op_name>
        """
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
        user_input = t[0][1]

        self.fz.launch_operator(operator, user_input, use_existing_seed=use_existing_seed,
                                verbose=verbose)

        self.__error = False
        return False

    def do_launch_operator_keepseed(self, line):
        """
        Launch the specified operator without using any current seed
        |_ syntax: launch_operator_keepseed  <op_name>
        """
        ret = self.do_launch_operator(line, use_existing_seed=True)
        return ret

    def do_launch_operator_verbose(self, line):
        """
        Launch the specified operator and use any existing seed (pretty print enabled)
        |_ syntax: launch_operator_verbose <op_name>
        """
        ret = self.do_launch_operator(line, use_existing_seed=False, verbose=True)
        return ret

    def do_show_operators(self, line):
        self.fz.show_operators()
        return False

    def __parse_instructions(self, cmdline):
        """
        return a list of the following format:
        [(action_1, [arg_11, ..., arg_1n]), ...,
        (action_n, [arg_n1, ..., arg_nn])]
        """

        def __extract_arg(exp, dico):
            re_obj = self.input_param_values_re.match(exp)
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
                return None

            if allargs_str is not None:
                # Parse arguments
                parsed = self.input_params_re.match(allargs_str)
                if parsed:
                    arg_str = parsed.group(1)
                    args = {}
                    l = arg_str.split(":")
                    for a in l:
                        ok = __extract_arg(a, args)
                        if not ok:
                            return None
                else:
                    args = None

            else:
                args = None

            user_input = UI()
            if args is not None and len(args) > 0:
                user_input.set_user_inputs(args)

            d.append((name, user_input))

        return d if bool(d) else None

    def _retrieve_tg_ids(self, args):
        tg_ids = []
        try:
            for arg in args[::-1]:
                tg_id = int(arg)
                tg_ids.append(tg_id)
            args = []
        except ValueError:
            if tg_ids:
                tg_ids = tg_ids[::-1]
                args = args[: -len(tg_ids)]

        tg_ids = tg_ids if tg_ids else None
        return args, tg_ids

    def do_reload_data_model(self, line):
        """
        Reload the current data model
        |_ syntax: reload_data_model
        """
        self.fz.reload_dm()

        return False

    def do_reload_all(self, line):
        """
        Reload the current data model and all its associated components (target, monitor, logger)
        |_ syntax: reload_all [target_id1 ... target_idN]
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len > 0:
            tg_ids = []
            try:
                for tg_id in args:
                    tg_ids.append(int(tg_id))
            except ValueError:
                return False
        else:
            tg_ids = None

        self.fz.reload_all(tg_ids=tg_ids)

        self.__error = False
        return False

    def do_cleanup_all_dmakers(self, line):
        """
        Clean up all initialized Data Makers
        |_ syntax: cleanup_all_dmakers
        """
        self.fz.cleanup_all_dmakers(reset_existing_seed=False)

        return False

    def do_reset_all_dmakers(self, line):
        """
        Reset all initialized Data Makers
        (Note: like cleanup_all_dmaker but clean also existing seeds)
        |_ syntax: reset_all_dmakers
        """
        self.fz.cleanup_all_dmakers(reset_existing_seed=True)

        return False

    def do_cleanup_dmaker(self, line, reset_existing_seed=False):
        """
        Clean up a specified initialized Data Maker
        |_ syntax: cleanup_dmaker <dmaker_type> [dmaker_name]
        """
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
        """
        Reset a specified initialized Data Maker
        (Note: like cleanup_dmaker but clean also the seed if present)
        |_ syntax: reset_dmaker <dmaker_type> [dmaker_name]
        """
        ret = self.do_cleanup_dmaker(line, reset_existing_seed=True)
        return ret

    def do_flush_feedback(self, line):
        """
        Collect the residual feedback (received by the target and the probes)
        """
        self.fz.collect_residual_feedback(timeout=3)
        return False

    def do_collect_feedback(self, line):
        """
        Collect the residual feedback (received by the target and the probes) indefinitely.
        Only stop with Ctrl+C
        """
        # t0 = datetime.datetime.now()
        # while (datetime.datetime.now() - t0).total_seconds() < 100:
        try:
            while True:
                self.fz.collect_residual_feedback(timeout=0.01)
        except UserInterruption:
            pass

        return False

    def do_send(self, line, verbose=False):
        """
        Carry out multiple fuzzing steps in sequence
        |_ syntax: send <generator_type> [disruptor_type_1 ... disruptor_type_n] [targetID1 ... targetIDN]
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len < 1:
            return False

        args, tg_ids = self._retrieve_tg_ids(args)

        actions = self.__parse_instructions(args)
        if actions is None:
            self.__error_msg = "Syntax Error!"
            return False

        self.__error = (self.fz.process_data_and_send(DataProcess(actions, tg_ids=tg_ids),
                                                      verbose=verbose) is None)
        return False

    def do_send_verbose(self, line):
        """
        Carry out multiple fuzzing steps in sequence (pretty print enabled)
        |_ syntax: send_verbose <generator_type> [disruptor_type_1 ... disruptor_type_n] [targetID1 ... targetIDN]
        """
        ret = self.do_send(line, verbose=True)
        return ret

    def do_send_loop(self, line, use_existing_seed=False, verbose=False):
        """
        Execute the 'send' command in a loop
        |_ syntax: send_loop <#loop> <generator_type> [disruptor_type_1 ... disruptor_type_n] [targetID1 ... targetIDN]

        Notes:
            - To loop indefinitely use -1 for #loop. To stop the loop use Ctrl+C
        """
        args = line.split()
        args_len = len(args)

        self.__error = True

        if args_len < 2:
            return False

        args, tg_ids = self._retrieve_tg_ids(args)

        try:
            max_loop = int(args.pop(0))
            if max_loop < 2 and max_loop != -1:
                return False
        except ValueError:
            return False

        actions = self.__parse_instructions(args)
        if actions is None:
            self.__error_msg = "Syntax Error!"
            return False

        conf = self.config.send_loop.aligned_options
        kwargs = {
            "enabled": self.config.send_loop.aligned,
            "page_head": r"^[^=]+====. [^ ]+ .==. [^=]+={9,}.{4}$",
            "batch_mode": (max_loop == -1) and conf.batch_mode,
            "hide_cursor": conf.hide_cursor,
            "prompt_height": conf.prompt_height,
        }

        with aligned_stdout(**kwargs):
            self.__error = self.fz.process_data_and_send(DataProcess(actions, tg_ids=tg_ids),
                                                         max_loop=max_loop, verbose=verbose,
                                                         save_generator_seed=use_existing_seed) is None

        return False

    def do_send_loop_verbose(self, line):
        """
        Execute the 'send' command in a loop and save the seed
        |_ syntax: send_loopv <#loop> <generator_type> [disruptor_type_1 ... disruptor_type_n]  [targetID1 ... targetIDN]

        Notes:
            - To loop indefinitely use -1 for #loop. To stop the loop use Ctrl+C
        """
        ret = self.do_send_loop(line, use_existing_seed=True, verbose=True)
        return ret

    def do_send_with(self, line):
        """
        Generate data from specific generator
        |_ syntax: send_with <generator_type> <generator_name> [targetID1 ... targetIDN]
        """
        self.__error = True

        args = line.split()

        if len(args) < 2:
            return False

        args, tg_ids = self._retrieve_tg_ids(args)

        t = self.__parse_instructions([args[0]])[0]
        if t is None:
            self.__error_msg = "Syntax Error!"
            return False

        actions = [((t[0], args[1]), t[1])]

        self.__error = (
            self.fz.process_data_and_send(DataProcess(actions, tg_ids=tg_ids)) is None
        )
        return False

    def do_send_loop_with(self, line):
        """
        Loop ( Generate data from specific generator )
        |_ syntax: send_loop_with <#loop> <generator_type> <generator_name> [targetID1 ... targetIDN]
        """
        self.__error = True

        args = line.split()

        if len(args) < 3:
            return False

        args, tg_ids = self._retrieve_tg_ids(args)

        try:
            nb = int(args[0])
        except ValueError:
            return False

        actions = self.__parse_instructions([args[1]])[0]
        if actions is None:
            self.__error_msg = "Syntax Error!"
            return False

        conf = self.config.send_loop.aligned_options
        kwargs = {
            "enabled": self.config.send_loop.aligned,
            "page_head": r"^[^=]+====. [^ ]+ .==. [^=]+={9,}.{4}$",
            "batch_mode": False,
            "hide_cursor": conf.hide_cursor,
            "prompt_height": conf.prompt_height,
        }

        with aligned_stdout(**kwargs):
            self.__error = self.fz.process_data_and_send(DataProcess(actions, tg_ids=tg_ids),
                                                         max_loop=nb) is None

        return False

    def do_multi_send(self, line):
        """
        Send several data to one or more targets. Generation instructions must be provided when
        requested (same format as the command 'send').
        |_ syntax: multi_send [#loop]
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len > 1:
            return False
        try:
            loop_count = int(args[0])
        except:
            loop_count = 1

        dp_list = []

        idx = 0
        while True:
            idx += 1

            msg = "*** Data generation instructions [#{:d}] (type '!' " \
                  "when all instructions are provided):\n# ".format(idx)
            actions_str = get_user_input(colorize(msg, rgb=Color.PROMPT))

            if actions_str == "!":
                self.print("*** Configuration terminated.")
                break

            l = actions_str.split()
            if len(l) < 1:
                return False

            l, tg_ids = self._retrieve_tg_ids(l)
            actions = self.__parse_instructions(l)
            if actions is None:
                self.__error_msg = "Syntax Error!"
                return False

            dp_list.append(DataProcess(actions, tg_ids=tg_ids))

        self.__error = self.fz.process_data_and_send(dp_list, max_loop=loop_count) is None
        return False

        # prev_data_list = None
        # exhausted_data_cpt = 0
        # exhausted_data = {}
        # nb_data = len(dp_list)
        #
        # for i in range(loop_count):
        #     data_list = []
        #
        #     for j in range(nb_data):
        #         if j not in exhausted_data:
        #             exhausted_data[j] = False
        #
        #         if not exhausted_data[j]:
        #             action_seq, tg_ids = dp_list[j]
        #             data = self.fz.process_data(action_seq)
        #             if tg_ids and data is not None:
        #                 data.tg_ids = tg_ids
        #         else:
        #             if prev_data_list is not None:
        #                 data = prev_data_list[j]
        #             else:
        #                 self.__error_msg = 'The loop has terminated too soon! (number of exhausted data: %d)' % exhausted_data_cpt
        #                 return False
        #
        #         if data is None and exhausted_data_cpt < nb_data:
        #             exhausted_data_cpt += 1
        #             if prev_data_list is not None:
        #                 data = prev_data_list[j]
        #                 exhausted_data[j] = True
        #             else:
        #                 self.__error_msg = 'The loop has terminated too soon! (number of exhausted data: %d)' % exhausted_data_cpt
        #                 return False
        #
        #             if exhausted_data[j] and exhausted_data_cpt >= nb_data:
        #                 self.__error_msg = 'The loop has terminated because all data are exhausted ' \
        #                     '(number of exhausted data: %d)' % exhausted_data_cpt
        #                 return False
        #
        #         data_list.append(data)
        #
        #     prev_data_list = data_list
        #
        #     self.fz.send_data_and_log(data_list)
        #
        # if exhausted_data_cpt > 0:
        #     self.print("\nThe loop has terminated normally, but it remains non exhausted " \
        #           "data (number of exhausted data: %d)" % exhausted_data_cpt)

    def do_set_feedback_timeout(self, line):
        """
        Set the time duration for feedback gathering (if supported by the target)
        |  syntax: set_feedback_timeout <arg> [targetID]
        |  |_ possible values for <arg>:
        |      0  : no timeout
        |     x>0 : timeout expressed in seconds (fraction is possible)
        |  |_ if targetID is not provided, the value applies to all enabled targets
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if 3 > args_len < 1:
            return False
        try:
            timeout = float(args[0])
        except:
            return False

        tg_id = None
        if args_len > 1:
            try:
                tg_id = int(args[1])
            except ValueError:
                self.__error_msg = "Parameter 2 shall be an integer!"
                return False

        self.fz.set_feedback_timeout(timeout, tg_id=tg_id)

        self.__error = False
        return False

    def do_switch_feedback_mode(self, line):
        """
        Switch target feedback mode between:
          - wait for the full time slot allocated for feedback retrieval
          - wait until the target has send something back to us

        Syntax: switch_feedback_mode <TargetID>
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False

        try:
            tg_id = int(args[0])
        except ValueError:
            return False

        self.fz.switch_feedback_mode(tg_id, do_record=True, do_show=True)

        self.__error = False
        return False

    def do_set_health_check_timeout(self, line):
        """
        Set the timeout when the FMK checks the target readiness (Default = 10).
        |  syntax: set_health_timeout <arg>
        |  |_ possible values for <arg>:
        |      0  : no timeout
        |     x>0 : timeout expressed in seconds (fraction is possible)
        """
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
        """
        Delay sending. Can be usefull during a loop.
        |  syntax: set_delay <arg>
        |  |_ possible values for <arg>:
        |     -1  : wait for keyboard input after each emission of data
        |      0  : no delay
        |     x>0 : delay expressed in seconds (fraction is possible)
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False
        try:
            delay = float(args[0])
            self.fz.set_sending_delay(delay)
        except:
            return False

        self.__error = False
        return False

    def do_set_burst(self, line):
        """
        Set the burst value. Used by the FMK to decide when delay
        shall be applied (Default = 1).
        |  syntax: set_burst <arg>
        |  |_ possible values for <arg>:
        |      1  : delay is applied to each data emission
        |      N : delay is applied after N data emission
        """
        self.__error = True

        args = line.split()
        args_len = len(args)

        if args_len != 1:
            return False
        try:
            val = float(args[0])
            self.fz.set_sending_burst_counter(val)
        except:
            return False

        self.__error = False
        return False

    def do_show_db(self, line):
        """Show the Data Bank"""
        self.fz.show_data_bank()

        return False

    def do_show_wkspace(self, line):
        """Show the Data Bank"""
        self.fz.show_wkspace()

        return False

    def do_empty_db(self, line):
        """Empty the Data Bank"""
        self.fz.empty_data_bank()

        return False

    def do_empty_wkspace(self, line):
        """Empty the current data in the working space"""
        self.fz.empty_workspace()

        return False

    def do_replay_db(self, line):
        """
        Replay data from the FmkDB or the Data Bank and optionnaly apply new disruptors on it
        |_ syntax for FmkDB: replay_db f<entry_idx> [disruptor_type_1 ... disruptor_type_n] [targetID1 ... targetIDN]
        |_ syntax for DBank: replay_db d<entry_idx> [disruptor_type_1 ... disruptor_type_n] [targetID1 ... targetIDN]
        """

        self.__error = True

        args = line.split()
        args, tg_ids = self._retrieve_tg_ids(args)
        args_len = len(args)

        if args_len < 1:
            return False

        try:
            full_id = args.pop(0)
            idx = int(full_id[1:])
            if full_id[0] == "f":
                id_from_fmkdb = idx
                id_from_db = None
            elif full_id[0] == "d":
                id_from_fmkdb = None
                id_from_db = idx
            else:
                raise ValueError

        except ValueError:
            return False

        if args_len > 1:
            actions = self.__parse_instructions(args)
            if actions is None:
                self.__error_msg = "Syntax Error!"
                return False

        else:
            actions = None

        self.__error = self.fz.process_data_and_send(DataProcess(actions, tg_ids=tg_ids),
                                                     id_from_fmkdb=id_from_fmkdb,
                                                     id_from_db=id_from_db) is None
        return False

    def do_replay_db_loop(self, line):
        """
        Loop ( Replay data from the Data Bank and optionnaly apply new disruptors on it )
        |_ syntax for FmkDB: replay_db_loop <#loop> f<idx_from_db> [disruptor_type_1 ... disruptor_type_n] [targetID1 ... targetIDN]
        |_ syntax for DBank: replay_db_loop <#loop> d<idx_from_db> [disruptor_type_1 ... disruptor_type_n] [targetID1 ... targetIDN]
        """

        self.__error = True

        args = line.split()
        args, tg_ids = self._retrieve_tg_ids(args)

        args_len = len(args)

        if args_len < 2:
            return False

        try:
            nb = int(args.pop(0))
            full_id = args.pop(0)
            idx = int(full_id[1:])
            if full_id[0] == "f":
                id_from_fmkdb = idx
                id_from_db = None
            elif full_id[0] == "d":
                id_from_fmkdb = None
                id_from_db = idx
            else:
                raise ValueError

        except ValueError:
            return False

        if args_len > 2:
            actions = self.__parse_instructions(args)
            if actions is None:
                self.__error_msg = "Syntax Error!"
                return False
        else:
            actions = None

        self.__error = self.fz.process_data_and_send(DataProcess(actions, tg_ids=tg_ids),
                                                     id_from_fmkdb=id_from_fmkdb,
                                                     id_from_db=id_from_db,
                                                     max_loop=nb) is None
        return False

    def do_replay_db_all(self, line):
        """
        Replay all data from the Data Bank
        |_ syntax: replay_db_all [targetID1 ... targetIDN]
        """

        args = line.split()
        args, tg_ids = self._retrieve_tg_ids(args)

        try:
            next(self.fz.iter_data_bank())
        except StopIteration:
            self.__error = True
            self.__error_msg = "the Data Bank is empty"
            return False

        for data in self.fz.iter_data_bank():
            self.fz.process_data_and_send(data, tg_ids=tg_ids)

        return False

    def do_show_data_paths(self, line):
        """
        Show the graph paths of the last generated data.
        Can be used as inputs for some generators or disruptors.
        """
        self.__error = True

        data = self.fz.get_last_data()
        if data is None:
            return False

        self.fz.show_data(data, verbose=False)

        self.__error = False
        return False

    def do_show_data(self, line):
        """
        Show the last generated data.
        """
        self.__error = True

        data = self.fz.get_last_data()
        if data is None:
            return False

        self.fz.show_data(data, verbose=True)

        self.__error = False
        return False

    def do_show_scenario(self, line):
        """
        Show a scenario in the specific format FMT (e.g., xdot, png, pdf, ...)
        |_ syntax: show_scenario SCENARIO_NAME [FMT]

        FMT defaults to 'pdf'
        """

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
            fmt = "pdf"

        self.fz.show_scenario(sc_name=sc_name, fmt=fmt)

        self.__error = False
        return False

    def do_replay_last(self, line):
        """
        Replay last data and optionnaly apply new disruptors on it
        |_ syntax: replay_last [disruptor_type_1 ... disruptor_type_n] [targetID1 ... targetIDN]
        """

        self.__error = True

        data = self.fz.get_last_data()
        if data is None:
            return False

        tg_ids = None

        if line:
            args = line.split()
            args, tg_ids = self._retrieve_tg_ids(args)

            actions = self.__parse_instructions(args)
            if actions is None:
                self.__error_msg = "Syntax Error!"
                return False
        else:
            actions = None

        self.__error = self.fz.process_data_and_send(DataProcess(actions, tg_ids=tg_ids, seed=data)) is None

        return False

    def do_send_raw(self, line):
        """
        Send raw data
        |_ syntax: send_raw [targetID1 ... targetIDN]

        A prompt will then ask you to write your input
        """

        self.__error_msg = "Syntax Error!"
        args = line.split()
        args, tg_ids = self._retrieve_tg_ids(args)
        if args:
            self.__error = True
            return False

        data_str = get_user_input(colorize("*** Data to be sent without interpretation:\n# ",
                                           rgb=Color.PROMPT))

        self.fz.process_data_and_send(Data(data_str), tg_ids=tg_ids)

        return False

    def do_send_eval(self, line):
        """
        Send python-evaluation of the parameter <data>
        |_ syntax: send_eval <data> [targetID1 ... targetIDN]
        """
        self.__error_msg = "Syntax Error!"
        args = line.split()

        args, tg_ids = self._retrieve_tg_ids(args)
        if args:
            self.__error = True
            return False

        data_str = get_user_input(colorize("*** Data to be sent after evaluation:\n# ",
                                           rgb=Color.PROMPT))

        try:
            data = Data(eval(data_str))
        except:
            self.__error = True
            return False

        self.fz.process_data_and_send(data, tg_ids=tg_ids)

        return False

    def do_register_db(self, line):
        """
        Register in the data bank the python-evaluation of the parameter <data>
        This can then be used as a seed in a disruptors chain
        |_ syntax: register_db <data>
        """
        self.__error_msg = "Syntax Error!"
        args = line.split()
        args_len = len(args)

        if args_len < 1:
            self.__error = True
            return False

        line = "".join(args)

        if line:
            try:
                data = Data(eval(line))
            except:
                self.__error = True
                return False

            self.fz.register_in_data_bank(data)
        else:
            self.__error = True

        return False

    def do_register_wkspace(self, line):
        """Register the workspace to the Data Bank"""
        self.fz.register_current_in_data_bank()

        return False

    def do_register_last(self, line):
        """Register last emitted data to the Data Bank"""
        self.fz.register_last_in_data_bank()

        return False

    def do_fmkdb_fetch_data(self, line):
        """
        Fetch the data from the FMKDB and fill the Data Bank with it. If data IDs are given,
        only fetch the data between the two references.
        |_ syntax: fmkdb_fetch_data [first_data_id] [last_data_id]
        """

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

        data_list = self.fz.fmkdb_fetch_data(start_id=sid, end_id=eid)
        self.fz.register_in_data_bank(data_list)

        self.__error = False
        return False

    def do_enable_fmkdb(self, line):
        """Enable FmkDB recording"""
        self.fz.enable_fmkdb()
        return False

    def do_disable_fmkdb(self, line):
        """Enable FmkDB recording"""
        self.fz.disable_fmkdb()
        return False

    def do_enable_fbk_handlers(self, line):
        """Enable Feedback Handlers"""
        self.fz.prj.enable_feedback_handlers()
        return False

    def do_disable_fbk_handlers(self, line):
        """Disable Feedback Handlers"""
        self.fz.prj.disable_feedback_handlers()
        return False

    def do_comment(self, line):
        comments = get_user_input(colorize("*** Write your comments:\n# ",
                                           rgb=Color.PROMPT))
        self.fz.log_comment(comments)
        return False

    def do_quit(self, line):
        self.fz.stop()
        return True
