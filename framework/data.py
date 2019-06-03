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

import collections

from framework.global_resources import *
from framework.node import Node, Env
from framework.database import Database

class DataBackend(object):

    def __init__(self, content=None):
        self._dm = None
        if content is not None:
            self.update_from(content)

    def update_from(self, obj):
        raise NotImplementedError

    @property
    def content(self):
        raise NotImplementedError

    @property
    def data_model(self):
        return self._dm

    @data_model.setter
    def data_model(self, val):
        self._dm = val

    @property
    def data_maker_type(self):
        raise NotImplementedError

    @property
    def data_maker_name(self):
        raise NotImplementedError

    def to_str(self):
        raise NotImplementedError

    def to_bytes(self):
        raise NotImplementedError

    def show(self, raw_limit=200, log_func=sys.stdout.write):
        raise NotImplementedError

    def get_content(self, do_copy=False, materialize=True):
        raise NotImplementedError

    def get_length(self):
        raise NotImplementedError


class NodeBackend(DataBackend):

    def update_from(self, obj):
        self._node = obj
        if obj.env is None:
            obj.set_env(Env())
        else:
            self._dm = obj.env.get_data_model()

    @property
    def content(self):
        return self._node

    @property
    def data_maker_type(self):
        return self._node.name.upper()

    @property
    def data_maker_name(self):
        return 'g_'+self._node.name

    def to_str(self):
        return self._node.to_str()

    def to_bytes(self):
        return self._node.to_bytes()

    def show(self, raw_limit=200, log_func=sys.stdout.write):
        self._node.show(raw_limit=raw_limit, log_func=log_func)

    def get_content(self, do_copy=False, materialize=True):
        if materialize:
            # we freeze the content before exporting it
            self._node.freeze()

        if do_copy:
            content = Node(self._node.name, base_node=self._node, ignore_frozen_state=False,
                           new_env=True)
        else:
            content = self._node

        return content

    def get_length(self):
        return len(self._node.to_bytes())

    def __copy__(self):
        new_databackend = type(self)()
        new_databackend.__dict__.update(self.__dict__)
        n = Node(self._node.name, base_node=self._node, ignore_frozen_state=False, new_env=True)
        if new_databackend._dm is not None:
            new_databackend._dm.update_atom(n)
        new_databackend.update_from(n)
        return new_databackend


class RawBackend(DataBackend):

    def update_from(self, obj):
        self._content = convert_to_internal_repr(obj)

    @property
    def content(self):
        return self._content

    @property
    def data_maker_type(self):
        return Database.DEFAULT_GTYPE_NAME

    @property
    def data_maker_name(self):
        return Database.DEFAULT_GEN_NAME

    def to_str(self):
        return unconvert_from_internal_repr(self._content)

    def to_bytes(self):
        return self._content

    def show(self, raw_limit=200, log_func=sys.stdout.write):
        log_func(unconvert_from_internal_repr(self._content))

    def get_content(self, do_copy=False, materialize=True):
        return copy.copy(self._content) if do_copy else self._content

    def get_length(self):
        return len(self._content)


class EmptyBackend(DataBackend):

    @property
    def content(self):
        return None

    @property
    def data_model(self):
        return None

    @data_model.setter
    def data_model(self, val):
        raise NotImplementedError

    @property
    def data_maker_type(self):
        return None

    @property
    def data_maker_name(self):
        return None

    def to_str(self):
        return 'Empty Backend'

    def to_bytes(self):
        return b'Empty Backend'

    def get_content(self, do_copy=False, materialize=True):
        return None

    def get_length(self):
        return 0


class Data(object):

    _empty_data_backend = EmptyBackend()

    def __init__(self, content=None, altered=False, tg_ids=None):

        self._data_id = None

        self.set_basic_attributes()
        self.altered = altered

        self.info_list = []
        self.info = {}
        self._history = None

        self.tg_ids = tg_ids  # targets ID

        # callback related
        self._callbacks = {}
        self._pending_ops = {}

        if content is None:
            self._backend = self._empty_data_backend
        elif isinstance(content, Node):
            self._backend = NodeBackend(content)
        else:
            self._backend = RawBackend(content)

    def set_basic_attributes(self, from_data=None):
        self._backend = None if from_data is None else from_data._backend
        self._type = None if from_data is None else from_data._type

        self.feedback_timeout = None if from_data is None else from_data.feedback_timeout
        self.feedback_mode = None if from_data is None else from_data.feedback_mode

        self.altered = False if from_data is None else from_data.altered

        self._recordable = False if from_data is None else from_data._recordable
        self._unusable = False if from_data is None else from_data._unusable

        # Used to provide information on the origin of the Data().
        # If it comes from a scenario _origin point to the related scenario.
        self._origin = None if from_data is None else from_data._origin

        self._blocked = False if from_data is None else from_data._blocked

        self.scenario_dependence = None if from_data is None else from_data.scenario_dependence

        # If True, the data will not interrupt the framework while processing
        # the data even if the data is unusable, The framework will just go on
        # to its next task without handing over to the end user.
        # Used especially by the Scenario Infrastructure.
        self.on_error_handover_to_user = True if from_data is None else from_data.on_error_handover_to_user

        # This attribute is set to True when the Data content has been retrieved from the fmkDB
        self.from_fmkdb = False if from_data is None else from_data.from_fmkdb

    @property
    def content(self):
        return self._backend.content

    @property
    def tg_ids(self):
        return self._targets

    @tg_ids.setter
    def tg_ids(self, tg_ids):
        if tg_ids is None:
            self._targets = None
        elif isinstance(tg_ids, list):
            assert len(tg_ids) > 0
            self._targets = tg_ids
        elif isinstance(tg_ids, int):
            self._targets = [tg_ids]
        else:
            raise ValueError

    def is_empty(self):
        return isinstance(self._backend, EmptyBackend)

    def set_data_id(self, data_id):
        self._data_id = data_id

    def get_data_id(self):
        return self._data_id

    def set_initial_dmaker(self, t):
        self._type = t

    def get_initial_dmaker(self):
        return self._type

    def update_from(self, obj):
        if isinstance(obj, Node):
            self._backend = NodeBackend(obj)
        else:
            self._backend = RawBackend(obj)

    def get_data_model(self):
        return self._backend.data_model

    def set_data_model(self, dm):
        self._backend.data_model = dm

    def to_bytes(self):
        return self._backend.to_bytes()

    def to_str(self):
        return self._backend.to_str()

    def make_blocked(self):
        self._blocked = True

    def make_free(self):
        self._blocked = False

    def is_blocked(self):
        return self._blocked

    def make_unusable(self):
        self._unusable = True

    def is_unusable(self):
        return self._unusable

    # Only taken into account if the Logger has been set to
    # record data only when requested (explicit_data_recording == True)
    def make_recordable(self):
        self._recordable = True

    def is_recordable(self):
        return self._recordable

    def generate_info_from_content(self, original_data=None, origin=None, additional_info=None):
        dmaker_type = self._backend.data_maker_type
        dmaker_name = self._backend.data_maker_name

        if original_data is not None:
            self.set_basic_attributes(from_data=original_data)
            if original_data.origin is not None:
                self.add_info("Data instantiated from: {!s}".format(original_data.origin))
            if original_data.info:
                info_bundle_to_remove = []
                for key, info_bundle in original_data.info.items():
                    info_bundle_to_remove.append(key)
                    for chunk in info_bundle:
                        for info in chunk:
                            if not self.info_exists(dmaker_type, dmaker_name, info):
                                self.add_info(info)
                for key in info_bundle_to_remove:
                    self.remove_info_from(*key)

        elif origin is not None:
            self.add_info("Data instantiated from: {!s}".format(origin))
        else:
            pass
        if additional_info is not None:
            for info in additional_info:
                self.add_info(info)
        self.remove_info_from(dmaker_type, dmaker_name)
        self.bind_info(dmaker_type, dmaker_name)
        initial_generator_info = [dmaker_type, dmaker_name, None]
        self.set_initial_dmaker(initial_generator_info)
        self.set_history([initial_generator_info])

    def add_info(self, info_str):
        self.info_list.append(info_str)

    def bind_info(self, dmaker_type, data_maker_name):
        key = (dmaker_type, data_maker_name)
        if key in self.info:
            self.info[key].append(self.info_list)
        else:
            self.info[key] = [self.info_list]

        self.info_list = []

    def info_exists(self, dmaker_type, data_maker_name, info):
        if info in self.info_list:
            return True

        return False

    def has_info(self):
        return bool(self.info)

    def remove_info_from(self, dmaker_type, data_maker_name):
        key = (dmaker_type, data_maker_name)
        if key in self.info:
            self.info[key] = []

    def read_info(self, dmaker_type, data_maker_name):
        key = (dmaker_type, data_maker_name)
        try:
            info_l = self.info[key]
        except KeyError:
            print("\n*** The key " \
                      "({:s}, {:s}) does not exist! ***\n".format(dmaker_type, data_maker_name))
            print("self.info contents: ", self.info)
            return

        for info in info_l:
            yield info

    def set_history(self, hist):
        self._history = hist

    def get_history(self):
        return self._history

    def get_length(self):
        return self._backend.get_length()

    def get_content(self, do_copy=False):
        return self._backend.get_content(do_copy=do_copy)

    def show(self, raw_limit=200, log_func=sys.stdout.write):
        self._backend.show(raw_limit=raw_limit, log_func=log_func)

    pretty_print = show

    def register_callback(self, callback, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        if hook not in self._callbacks:
            self._callbacks[hook] = collections.OrderedDict()
        self._callbacks[hook][id(callback)] = callback

    def cleanup_callbacks(self, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        if hook in self._callbacks:
            del self._callbacks[hook]
        if hook in self._pending_ops:
            del self._pending_ops[hook]

    def cleanup_all_callbacks(self):
        for hook in HOOK:
            if hook in self._callbacks:
                del self._callbacks[hook]
            if hook in self._pending_ops:
                del self._pending_ops[hook]

    def run_callbacks(self, feedback=None, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        if hook not in self._callbacks:
            return

        new_cbks = copy.copy(self._callbacks[hook])
        for cbk_id, cbk in self._callbacks[hook].items():
            if hook == HOOK.after_fbk:
                cbk_ops = cbk(feedback)
            else:
                cbk_ops = cbk()
            if hook not in self._pending_ops:
                self._pending_ops[hook] = []
            if cbk_ops is not None:
                self._pending_ops[hook].append(cbk_ops.get_operations())
                if cbk_ops.is_flag_set(CallBackOps.ForceDataHandling):
                    self.on_error_handover_to_user = False
                if cbk_ops.is_flag_set(CallBackOps.RemoveCB):
                    del new_cbks[cbk_id]
                if cbk_ops.is_flag_set(CallBackOps.StopProcessingCB):
                    break

        self._callbacks[hook] = new_cbks

    def pending_callback_ops(self, hook=HOOK.after_fbk):
        assert isinstance(hook, HOOK)
        if hook in self._pending_ops:
            pops = self._pending_ops[hook]
            del self._pending_ops[hook]
            return pops
        else:
            return None

    def copy_callback_from(self, data):
        self._callbacks = copy.copy(data._callbacks)

    @property
    def origin(self):
        return self._origin

    @origin.setter
    def origin(self, value):
        self._origin = value

    def __copy__(self):
        new_data = type(self)()
        new_data.__dict__.update(self.__dict__)
        new_data.info_list = copy.copy(self.info_list)
        new_data.info = copy.copy(self.info)
        new_data._history = copy.copy(self._history)
        new_data._type = copy.copy(self._type)
        new_data._callbacks = {}
        for hook, cbk_dict in self._callbacks.items():
            new_data._callbacks[hook] = collections.OrderedDict()
            for key, cbk in cbk_dict.items():
                # ncbk = copy.copy(cbk)
                new_data._callbacks[hook][id(cbk)] = cbk
        new_data._pending_ops = {}  # we do not copy pending_ops
        new_data._backend = copy.copy(self._backend)
        new_data._targets = copy.copy(self._targets)
        return new_data

    def __str__(self):
        return self.to_str()

    def __repr__(self):
        return repr(self.to_bytes())


class CallBackOps(object):

    # Flags
    RemoveCB = 1 # If True, remove this callback after execution
    StopProcessingCB = 2 # If True, any callback following this one won't be processed
    ForceDataHandling = 3

    # Instructions
    Add_PeriodicData = 10  # ask for sending periodically a data
    Del_PeriodicData = 11  # ask for stopping a periodic sending
    Set_FbkTimeout = 21  # set the time duration for feedback gathering for the further data sending
    Replace_Data = 30  # replace the data by another one

    def __init__(self, remove_cb=False, stop_process_cb=False, ignore_no_data=False):
        self.instr = {
            CallBackOps.Add_PeriodicData: {},
            CallBackOps.Del_PeriodicData: [],
            CallBackOps.Set_FbkTimeout: None,
            CallBackOps.Replace_Data: None
        }
        self.flags = {
            CallBackOps.RemoveCB: remove_cb,
            CallBackOps.StopProcessingCB: stop_process_cb,
            CallBackOps.ForceDataHandling: ignore_no_data
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

    def add_operation(self, instr_type, id=None, param=None, period=None):
        if instr_type == CallBackOps.Add_PeriodicData:
            assert id is not None and param is not None
            self.instr[instr_type][id] = (param, period)
        elif instr_type == CallBackOps.Del_PeriodicData:
            assert id is not None
            self.instr[instr_type].append(id)
        elif instr_type == CallBackOps.Set_FbkTimeout:
            assert isinstance(param, int)
            self.instr[instr_type] = param
        elif instr_type == CallBackOps.Replace_Data:
            # param is an opaque
            self.instr[instr_type] = param
        else:
            raise ValueError('Unrecognized Instruction Type')

    def get_operations(self):
        return self.instr
