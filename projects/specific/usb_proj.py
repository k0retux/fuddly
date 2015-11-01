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

import time

from fuzzfmk.project import *
from fuzzfmk.monitor import *
from fuzzfmk.operator import *
from fuzzfmk.plumbing import *
from fuzzfmk.target import *
from fuzzfmk.logger import *
from fuzzfmk.data_model import *
from fuzzfmk.tactics_helper import *
from fuzzfmk.fuzzing_primitives import *

project = Project()
project.default_dm = 'usb'

logger = Logger('bin', data_in_seperate_file=False, explicit_export=True, export_orig=False)

rpyc_module = True
try:
    import rpyc
except ImportError:
    rpyc_module = False
    print('WARNING [USB DM]: rpyc lib not installed, Pandaboard target will not be available')

class Pandaboard(Target):

    def __init__(self, args):
        self.args = args

    def start(self):
        self.cnx = rpyc.connect(self.args.ip, self.args.port, config={'allow_all_attrs':True, 'allow_pickle': True})
        return True

    def stop(self):
        self.cnx.close()
        return False


    def send_multiple_data(self, data_list):

        stringdict = {}
        idx = 1

        dev_desc = None
        conf_desc = []

        for d in data_list:
            if d.node.semantics.match(NodeSemanticsCriteria(mandatory_criteria=['DEV_DESC'])):
                dev_desc = d.to_bytes()
            elif d.node.semantics.match(NodeSemanticsCriteria(mandatory_criteria=['CONF_DESC'])):
                conf_desc.append(d.to_bytes())
            elif d.node.semantics.match(NodeSemanticsCriteria(mandatory_criteria=['LANGID_DESC'])):
                stringdict[0] = (d.to_bytes(), False)
            elif d.node.semantics.match(NodeSemanticsCriteria(mandatory_criteria=['STRING_DESC'])):
                stringdict[idx] = (d.to_bytes(), False)
                idx += 1

        if len(stringdict) == 0:
            stringdict = None

        if len(conf_desc) == 0:
            conf_desc = None

        # print('\n------------------')
        # print('STR_TABLE', stringdict)
        # print('DEV_DESC', dev_desc)
        # print('CONF_DESC', conf_desc)
        # print('------------------\n')

        self.cnx.root.connect(stringdict=stringdict, dev_desc_str=dev_desc, conf_desc_str_list=conf_desc, raw=True)


    def send_data(self, data):
        e = data.node

        if e.semantics.match(NodeSemanticsCriteria(mandatory_criteria=['DEV_DESC'])):
            self.cnx.root.connect(dev_desc_str=data.to_bytes())
        elif e.semantics.match(NodeSemanticsCriteria(mandatory_criteria=['CONF_DESC'])):
            self.cnx.root.connect(conf_desc_str_list=[data.to_bytes()])


    def is_target_ready_for_new_data(self):
        time.sleep(3)
        self.cnx.root.disconnect()
        time.sleep(1)
        return True


class PandaboardArgs(object):
    ip = '192.168.1.5'
    port = 12345

if rpyc_module:
    panda_tg = Pandaboard(args=PandaboardArgs())
    targets = [panda_tg]
else:
    targets = []


@operator(project,
          gen_args={'init': ('make the model walker ignore all the steps until the provided one', 1, int),
                    'max_steps': ("number of test cases to run", 20, int)},
          args={'mode': ('strategy mode: 0, 1 (fuzz DEV), 2 (Mass-Storage) or 666 (BigConf)', 2, int)})
class Op1(Operator):

    def start(self, fmk_ops, dm, monitor, target, logger, user_input):

        self.count = 0

        self.instr_list = []
        self.instr_list.append([('LANGID', UI(finite=True))])
        self.instr_list.append([('STR', UI(finite=True)), ('tALT', UI(init=self.init))])
        self.instr_list.append([('STR#2', UI(finite=True)), ('tALT#2', UI(init=self.init))])
        self.instr_list.append([('STR#3', UI(finite=True)), ('tALT#3', UI(init=self.init))])
        self.instr_list.append([('STR#4', UI(finite=True)), ('tALT#4', UI(init=self.init))])
        self.instr_list.append([('STR#5', UI(finite=True)), ('tALT#5', UI(init=self.init))])
        if self.mode == 1:
            self.instr_list.append([('DEV', UI(finite=True)), ('tTYPE', UI(init=self.init))])
        elif self.mode == 2:
            self.instr_list.append([('DEV_MS', UI(finite=True))])
        else:
            self.instr_list.append([('DEV', UI(finite=True))])

        if self.mode == 666:
            self.instr_list.append([('CONF', UI(finite=True)), ('ALT', None, UI(conf='BIGCONF')),
                                    ('tTYPE#2', UI(init=self.init, clone_node=False), None)])
        elif self.mode == 2:
            self.instr_list.append([('MSD_CONF', UI(finite=True)), ('tTYPE#2', UI(init=self.init))])
        else:
            self.instr_list.append([('CONF', UI(finite=True)), ('tTYPE#2', UI(init=self.init))])
            self.instr_list.append([('CONF#2', UI(finite=True)), ('tTYPE#3', UI(init=self.init))])

        self.nb_data = len(self.instr_list)
        self.orig_data = [None for i in range(self.nb_data)]

        # LANGID never exhausts
        self.exhaustible_data_nb = self.nb_data - 1

        self.exhausted_data_cpt = 0
        self.prev_data_list = None

        self.msg_list = []
        return True

    def stop(self, fmk_ops, dm, monitor, target, logger):
        for msg in self.msg_list:
            logger.print_console(msg)

    def plan_next_operation(self, fmk_ops, dm, monitor, target, logger, fmk_feedback):

        op = Operation()

        if self.max_steps >= 0 and self.count == self.max_steps:
            op.set_flag(Operation.Stop)
            return op

        self.prev_data_list = fmk_feedback.get_produced_data()

        if fmk_feedback.is_flag_set(FmkFeedback.NeedChange):
            change_list = fmk_feedback.get_flag_context(FmkFeedback.NeedChange)
            for dmaker, idx in change_list:
                self.orig_data[idx] = self.prev_data_list[idx]
                self.exhausted_data_cpt += 1
                msg = 'Exhausted data: #%d [idx: %d, type: %s]' % (self.exhausted_data_cpt, idx, dmaker['dmaker_type'])
                self.msg_list.append(msg)

            if self.exhausted_data_cpt >= self.exhaustible_data_nb:
                op.set_flag(Operation.Stop)
                return op

        for instr, idx in zip(self.instr_list, range(len(self.instr_list))):
            if self.orig_data[idx] is None:
                op.add_instruction(instr)
            else:
                op.add_instruction(None, orig_data=self.orig_data[idx])


        self.count += 1

        return op
