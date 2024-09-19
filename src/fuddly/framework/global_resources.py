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

import os
import sys
import copy
import inspect
from enum import Enum

xdg_mod_error = False
try:
    from xdg.BaseDirectory import xdg_data_home, xdg_config_home
except ModuleNotFoundError:
    xdg_mod_error = True
    print('WARNING [FMK]: python3-xdg module is not installed!')


# TODO: Taken out of libs.utils, is this the best place for them?
def ensure_dir(f):
    d = os.path.dirname(f)
    if not os.path.exists(d):
        os.makedirs(d)

def ensure_file(f):
    if not os.path.isfile(f):
        open(f, 'a').close()


fuddly_version = '0.30'

framework_folder = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
framework_folder  = '.' if framework_folder == '' else framework_folder

app_folder = os.path.dirname(framework_folder)
app_folder = '.' if app_folder == '' else app_folder
projects_folder = app_folder + os.sep + 'projects' + os.sep
data_models_folder = app_folder + os.sep + 'data_models' + os.sep

fuddly_data_folder = os.path.expanduser('~' + os.sep + 'fuddly_data' + os.sep)
if not xdg_mod_error and not os.path.exists(fuddly_data_folder):
    use_xdg = True
    fuddly_data_folder = xdg_data_home + os.sep + 'fuddly' + os.sep
    if not os.path.exists(fuddly_data_folder):
        new_fuddly_data_folder = True
else:
    use_xdg = False

ep_group_names = {
    "data_models": "fuddly.data_models",
    "strategies":  "fuddly.data_models_strategies",
    "projects":    "fuddly.projects",
}

ensure_dir(fuddly_data_folder)

exported_data_folder = fuddly_data_folder + 'exported_data' + os.sep
ensure_dir(exported_data_folder)
imported_data_folder = fuddly_data_folder + 'imported_data' + os.sep
ensure_dir(imported_data_folder)
logs_folder = fuddly_data_folder + 'logs' + os.sep
ensure_dir(logs_folder)
workspace_folder = fuddly_data_folder + 'workspace' + os.sep
ensure_dir(workspace_folder)
external_libs_folder = fuddly_data_folder + 'external_libs' + os.sep
ensure_dir(external_libs_folder)
external_tools_folder = fuddly_data_folder + 'external_tools' + os.sep
ensure_dir(external_tools_folder)

if not use_xdg:
    config_folder = os.path.join(fuddly_data_folder, 'config') + os.sep
else:
    xdg_fuddly_config_folder = xdg_config_home + os.sep + 'fuddly' + os.sep
    config_folder = xdg_fuddly_config_folder
ensure_dir(config_folder)

user_projects_folder = fuddly_data_folder + 'user_projects' + os.sep
ensure_dir(user_projects_folder)
ensure_file(user_projects_folder + os.sep + '__init__.py')
user_data_models_folder = fuddly_data_folder + 'user_data_models' + os.sep
ensure_dir(user_data_models_folder)
ensure_file(user_data_models_folder + os.sep + '__init__.py')

user_info_folder = fuddly_data_folder + 'user_info' + os.sep
ensure_dir(user_info_folder)
ensure_file(user_info_folder + os.sep + '__init__.py')

user_targets_folder = fuddly_data_folder + 'user_targets' + os.sep
ensure_dir(user_targets_folder)
ensure_file(user_targets_folder + os.sep + '__init__.py')

fmk_folder = app_folder + os.sep + 'framework' + os.sep

internal_repr_codec = 'utf8'
def convert_to_internal_repr(val):
    if val is None:
        val = b''
    elif isinstance(val, int):
        val = str(val).encode(internal_repr_codec)
    elif isinstance(val, (tuple, list)):
        new_val = []
        for v in val:
            new_v = convert_to_internal_repr(v)
            new_val.append(new_v)
        val = new_val
    elif isinstance(val, str):
        val = val.encode(internal_repr_codec)
    else:
        assert isinstance(val, bytes)

    return val

def unconvert_from_internal_repr(val):
    try:
        val = val.decode(internal_repr_codec, 'strict')
    except:
        val = val.decode('latin-1')

    return val

def is_string_compatible(val):
    if isinstance(val, list):
        for v in val:
            if not is_string_compatible(v):
                return False
        else:
            return True
    else:
        return isinstance(val, (str, bytes))

def get_user_input(msg):
    return input(msg)

def _is_running_from_fs():
    from importlib.metadata import (files,PackageNotFoundError)
    try:
        # Get the __init__.py file from the root of an installed fuddly package
        f = [ f for f in files("fuddly") if str(f) in "fuddly/__init__.py"][0]
    except PackageNotFoundError:
        # Fuddly is not installed so we are (almost) certainly running from the sources
        return True
    except:
        print("Unable to properly detect where we are ran from. Assuming sources.")
        return True
    import fuddly
    return fuddly.__path__[0] != str(f.locate().parent)

is_running_from_fs = _is_running_from_fs()

# Generic container for user inputs

class UI(object):
    """
    Once initialized, attributes cannot be modified
    """
    def __init__(self, **kwargs):
        self._inputs = {}
        for k, v in kwargs.items():
            self._inputs[k] = v

    def __bool__(self):
        return bool(self._inputs)

    def get_inputs(self):
        return self._inputs

    def is_attrs_defined(self, *names):
        for n in names:
            if n not in self._inputs:
                return False
        return True

    def set_user_inputs(self, user_inputs):
        assert isinstance(user_inputs, dict)
        self._inputs = user_inputs

    def merge_with(self, user_inputs):
        self._inputs.update(user_inputs._inputs)

    def check_conformity(self, valid_args):
        for arg in self._inputs:
            if arg not in valid_args:
                return False, arg
        return True, None

    def __getattr__(self, name):
        if name in self._inputs:
            return self._inputs[name]
        else:
            return None

    def __str__(self):
        if self._inputs:
            ui = '['
            for k, v in self._inputs.items():
                ui += "{:s}={!r},".format(k, v)
            return ui[:-1]+']'
        else:
            return '[ ]'

    __repr__ = __str__

    def __copy__(self):
        new_ui = type(self)()
        new_ui.__dict__.update(self.__dict__)
        new_ui._inputs = copy.copy(self._inputs)
        return new_ui


### Exports for Node Absorption ###

class AbsorbStatus(Enum):
    Accept = 1
    Reject = 2
    Absorbed = 3
    FullyAbsorbed = 4

# List of constraints that rules blob absorption
class AbsCsts(object):
    Size = 1
    Contents = 2
    Regexp = 3
    Structure = 4
    SimilarContent = 5

    def __init__(self, size=True, content=True, regexp=True, struct=True, similar_content=False):
        self.constraints = {
            AbsCsts.Size: size,
            AbsCsts.Contents: content,
            AbsCsts.Regexp: regexp,
            AbsCsts.Structure: struct,
            AbsCsts.SimilarContent: similar_content  # for String-type nodes it means "case sensitive"
        }

    def __bool__(self):
        return True in self.constraints.values()

    def __nonzero__(self):
        return True in self.constraints.values()

    def set(self, cst):
        if cst in self.constraints:
            self.constraints[cst] = True
        else:
            raise ValueError

    def clear(self, cst):
        if cst in self.constraints:
            self.constraints[cst] = False
        else:
            raise ValueError

    def __copy__(self):
        new_csts = type(self)()
        new_csts.__dict__.update(self.__dict__)
        new_csts.constraints = copy.copy(self.constraints)

        return new_csts

    def __getitem__(self, key):
        return self.constraints[key]

    def __repr__(self):
        return 'AbsCsts()'


class AbsNoCsts(AbsCsts):

    def __init__(self, size=False, content=False, regexp=False, struct=False, similar_content=False):
        AbsCsts.__init__(self, size=size, content=content, regexp=regexp, struct=struct,
                         similar_content=similar_content)

    def __repr__(self):
        return 'AbsNoCsts()'


class AbsFullCsts(AbsCsts):

    def __init__(self, size=True, content=True, regexp=True, struct=True, similar_content=True):
        AbsCsts.__init__(self, size=size, content=content, regexp=regexp, struct=struct,
                         similar_content=similar_content)

    def __repr__(self):
        return 'AbsFullCsts()'

### Error related resources ###

class Error(object):

    Reserved = -1

    # Generic error code
    FmkError = -2
    CommandError = -3
    UserCodeError = -4
    UnrecoverableError = -5
    FmkWarning = -6
    OperationCancelled = -7

    # FmkPlumbing.process_data() error code
    CloneError = -10
    InvalidDmaker = -11
    HandOver = -12
    DataUnusable = -13
    DataInvalid = -14

    # FmkPlumbing.launch_operator() error code
    InvalidOp = -20
    WrongOpPlan = -21

    # FmkPlumbing DataProcess-handling related code
    DPHandOver = -30  # when a data process yields

    # FmkPlumbing._send_data() code
    NoMoreData = -40

    _code_info = {
        Reserved: {'name': 'Reserved', 'color': 0xFFFFFF},

        FmkError: {'name': 'FmkError', 'color': 0xA00000},
        CommandError: {'name': 'CommandError', 'color': 0xB00000},
        UserCodeError: {'name': 'UserCodeError', 'color': 0xE00000},
        UnrecoverableError: {'name': 'UnrecoverableError', 'color': 0xFF0000},
        FmkWarning: {'name': 'FmkWarning', 'color': 0xFFA500},
        OperationCancelled: {'name': 'OperationCancelled', 'color': 0xFC00F4},

        CloneError: {'name': 'CloneError', 'color': 0xA00000},
        InvalidDmaker: {'name': 'InvalidDmaker', 'color': 0xB00000},
        HandOver: {'name': 'HandOver', 'color': 0x00B500},
        DataUnusable: {'name': 'DataUnusable', 'color': 0x009500},
        DataInvalid: {'name': 'DataInvalid', 'color': 0xA00000},

        InvalidOp: {'name': 'InvalidOp', 'color': 0xB00000},
        WrongOpPlan: {'name': 'WrongOpPlan', 'color': 0xE00000},

        DPHandOver: {'name': 'DPHandOver', 'color': 0x00B500},
        NoMoreData: {'name': 'NoMoreData', 'color': 0xCC0099},
        }


    def __init__(self, msg='', context=None, code=Reserved):
        self.__msg = msg
        self.__ctx = context
        self.__code = code

    def set(self, msg, context=None, code=Reserved):
        self.__msg = msg
        self.__ctx = context
        self.__code = code

    def __get_msg(self):
        return self.__msg

    def __get_context(self):
        return self.__ctx

    def __get_code(self):
        return self.__code

    def __get_color(self):
        return self._code_info[self.code]['color']

    msg = property(fget=__get_msg)
    context = property(fget=__get_context)
    code = property(fget=__get_code)
    color = property(fget=__get_color)

    def __str__(self):
        return self._code_info[self.code]['name']

### Hook related resources for Data ###

class HOOK(Enum):
    after_dmaker_production = 1
    before_sending_step1 = 2
    before_sending_step2 = 3
    after_sending = 4
    after_fbk = 5
    final = 6
