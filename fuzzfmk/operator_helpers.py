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

from fuzzfmk.global_resources import *
from fuzzfmk.tactics_helpers import _handle_user_inputs, _user_input_conformity, _restore_dmaker_internals

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
        To be overloaded if specific initialization code is needed.
        Shall return True if setup has succeeded, otherwise shall
        return False.
        '''
        return True

    def stop(self, fmk_ops, dm, monitor, target, logger):
        '''
        To be overloaded if specific termination code is needed.
        '''
        pass

    def plan_next_operation(self, fmk_ops, dm, monitor, target, logger, fmk_feedback):
        '''
        Shall return a Operation object that contains the operations
        that you want fuddly to perform.
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


def operator(prj, gen_args={}, args={}):
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
        prj.register_new_operator(operator.__class__.__name__, operator)
        return operator_cls

    return internal_func
