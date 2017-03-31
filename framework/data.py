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
from framework.data_model import Node, Env
from framework.database import Database

class Data(object):

    def __init__(self, data=None):
        self.node = None
        self.raw = None

        self._type = None
        self._dm = None
        self._data_id = None
        self._recordable = False
        self._unusable = False
        self._blocked = False

        self.feedback_timeout = None
        self.feedback_mode = None

        self.info_list = []
        self.info = {}

        # callback related
        self._callbacks = {}
        self._pending_ops = {}

        self._history = None

        # Used to provide information on the origin of the Data().
        # If it comes from a scenario _origin point to the related scenario.
        self._origin = None

        # This attribute is set to True when the Data content has been retrieved from the fmkDB
        self.from_fmkdb = False

        if data is None:
            return

        if isinstance(data, Node):
            self.update_from_node(data)
        else:
            self.update_from_str_or_bytes(data)

    def set_data_id(self, data_id):
        self._data_id = data_id

    def get_data_id(self):
        return self._data_id

    def set_initial_dmaker(self, t):
        self._type = t

    def get_initial_dmaker(self):
        return self._type

    def update_from_str_or_bytes(self, data_str):
        self.raw = convert_to_internal_repr(data_str)
        self.node = None

    def update_from_node(self, node):
        self.node = node
        if node.env is None:
            node.set_env(Env())
        else:
            self._dm = node.env.get_data_model()

    def get_data_model(self):
        return self._dm

    def set_data_model(self, dm):
        self._dm = dm

    def to_bytes(self):
        if self.node:
            val = self.node.to_bytes()
            self.raw = val
        return self.raw

    def to_str(self):
        if self.node:
            val = self.node.to_str()
            return val
        else:
            return unconvert_from_internal_repr(self.raw)

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
        if self.node is None:
            dmaker_type = Database.DEFAULT_GTYPE_NAME
            dmaker_name = Database.DEFAULT_GEN_NAME
        else:
            dmaker_type = self.node.name.upper()
            dmaker_name = 'g_'+self.node.name

        if original_data is not None:
            if original_data.origin is not None:
                self.add_info("Data instantiated from: {!s}".format(original_data.origin))
            if original_data.info:
                info_bundle_to_remove = []
                for key, info_bundle in original_data.info.items():
                    # if key == (dmaker_type, dmaker_name):
                    #     continue
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

    def copy_info_from(self, data):
        print(self.info_list, self.info, self._type, self._history)
        print(data.info_list, data.info, data._type, data._history)
        self.info_list = data.info_list
        self.info = data.info
        self._type = data._type
        self._history = data._history

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
        if self.node:
            self.raw = self.node.to_bytes()
        return len(self.raw)

    def materialize(self):
        if self.node is not None:
            self.node.freeze()

    def get_contents(self, do_copy=False):
        if self.node is not None:
            # we freeze the contents before exporting it
            self.node.freeze()
            if do_copy:
                contents = Node(self.node.name, base_node=self.node, ignore_frozen_state=False,
                                new_env=True)
            else:
                contents = self.node
        else:
             contents = copy.copy(self.raw) if do_copy else self.raw

        return contents

    def show(self, raw_limit=200, log_func=lambda x: x):
        if self.node is not None:
            self.node.show(raw_limit=raw_limit, log_func=log_func)
        else:
            print(self.raw)

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

        if self.node is not None:
            e = Node(self.node.name, base_node=self.node, ignore_frozen_state=False, new_env=True)
            if new_data._dm is not None:
                new_data._dm.update_node_env(e)
            new_data.update_from_node(e)
        return new_data

    def __str__(self):
        return self.to_str()

    def __repr__(self):
        return repr(self.to_bytes())


class CallBackOps(object):

    # Flags
    RemoveCB = 1 # If True, remove this callback after execution
    StopProcessingCB = 2 # If True, any callback following this one won't be processed

    # Instructions
    Add_PeriodicData = 10  # ask for sending periodically a data
    Del_PeriodicData = 11  # ask for stopping a periodic sending
    Set_FbkTimeout = 21  # set the time duration for feedback gathering for the further data sending
    Replace_Data = 30  # replace the data by another one

    def __init__(self, remove_cb=False, stop_process_cb=False):
        self.instr = {
            CallBackOps.Add_PeriodicData: {},
            CallBackOps.Del_PeriodicData: [],
            CallBackOps.Set_FbkTimeout: None,
            CallBackOps.Replace_Data: None
        }
        self.flags = {
            CallBackOps.RemoveCB: remove_cb,
            CallBackOps.StopProcessingCB: stop_process_cb
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
