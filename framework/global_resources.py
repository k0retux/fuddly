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

import framework
from libs.utils import ensure_dir, ensure_file


fuddly_version = '0.25.1'

framework_folder = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
# framework_folder = os.path.dirname(framework.__file__)
framework_folder  = '.' if framework_folder == '' else framework_folder

app_folder = os.path.dirname(framework_folder)
app_folder = '.' if app_folder == '' else app_folder
projects_folder = app_folder + os.sep + 'projects' + os.sep
data_models_folder = app_folder + os.sep + 'data_models' + os.sep

fuddly_data_folder = os.path.expanduser('~' + os.sep + 'fuddly_data' + os.sep)
if not os.path.exists(fuddly_data_folder):
    new_fuddly_data_folder = True
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

user_projects_folder = fuddly_data_folder + 'user_projects' + os.sep
ensure_dir(user_projects_folder)
ensure_file(user_projects_folder + os.sep + '__init__.py')
user_data_models_folder = fuddly_data_folder + 'user_data_models' + os.sep
ensure_dir(user_data_models_folder)
ensure_file(user_data_models_folder + os.sep + '__init__.py')

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
    elif sys.version_info[0] > 2:
        if isinstance(val, str):
            val = val.encode(internal_repr_codec)
    elif isinstance(val, unicode):  # only for python2
        val = val.encode(internal_repr_codec)
    elif isinstance(val, str):  # only for python2
        pass
    else:
        raise ValueError
    return val

def unconvert_from_internal_repr(val):
    if sys.version_info[0] == 2 and isinstance(val, buffer):
        # This case occurs when reading from the FmkDB
        val = str(val)
    else:
        try:
            val = val.decode(internal_repr_codec, 'strict')
        except:
            val = val.decode('latin-1')
    return val

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

    def __init__(self, size=True, contents=True, regexp=True, struct=True):
        self.constraints = {
            AbsCsts.Size: size,
            AbsCsts.Contents: contents,
            AbsCsts.Regexp: regexp,
            AbsCsts.Structure: struct
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

    def __init__(self, size=False, contents=False, regexp=False, struct=False):
        AbsCsts.__init__(self, size=size, contents=contents, regexp=regexp, struct=struct)

    def __repr__(self):
        return 'AbsNoCsts()'


class AbsFullCsts(AbsCsts):

    def __init__(self, size=True, contents=True, regexp=True, struct=True):
        AbsCsts.__init__(self, size=size, contents=contents, regexp=regexp, struct=struct)

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

    # FmkPlumbing.get_data() error code
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

    # FmkPlumbing.send_data() code
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
    before_sending = 2
    after_sending = 3
    after_fbk = 4
