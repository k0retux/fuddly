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

import os
import fuzzfmk
import sys
import inspect

fuddly_version = '0.22.1'

fuzzfmk_folder = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
# fuzzfmk_folder = os.path.dirname(fuzzfmk.__file__)
fuzzfmk_folder  = '.' if fuzzfmk_folder == '' else fuzzfmk_folder

app_folder = os.path.dirname(fuzzfmk_folder)
app_folder = '.' if app_folder == '' else app_folder

workspace_folder = app_folder + os.sep + 'workspace' + os.sep
external_libs_folder = app_folder + os.sep + 'external_libs' + os.sep
external_tools_folder = app_folder + os.sep + 'external_tools' + os.sep
exported_data_folder = app_folder + os.sep + 'exported_data' + os.sep
logs_folder = app_folder + os.sep + 'logs' + os.sep
fmk_folder = app_folder + os.sep + 'fuzzfmk' + os.sep

class Error(object):

    Reserved = -1

    # Generic error code
    FmkError = -2
    CommandError = -3
    UserCodeError = -4
    UnrecoverableError = -5
    FmkWarning = -6
    OperationCancelled = -7

    # Fuzzer.get_data() error code
    CloneError = -10
    InvalidDmaker = -11
    HandOver = -12
    DataUnusable = -13

    # Fuzzer.launch_operator() error code
    InvalidOp = -20
    WrongOpPlan = -21

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

        InvalidOp: {'name': 'InvalidOp', 'color': 0xB00000},
        WrongOpPlan: {'name': 'WrongOpPlan', 'color': 0xE00000},
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
