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
import random
import array
from copy import *

from fuzzfmk.plumbing import *
from fuzzfmk.target import *
from fuzzfmk.logger import *

from fuzzfmk.data_model import *
from fuzzfmk.tactics_helper import *
from fuzzfmk.fuzzing_primitives import *
from fuzzfmk.basic_primitives import *

tactics = Tactics()

logger = Logger('EX',
                data_in_seperate_file=False,
                explicit_export=True,
                export_orig=False)


# targets = [Target()]


@probe(tactics)
class P1(Probe):

    def start(self, target, logger):
        self.cpt = 10

    def main(self, target, logger):
        self.cpt += 1

        return ProbeStatus(self.cpt)


@probe(tactics)
class P2(Probe):

    def start(self, target, logger):
        self.cpt = 0

    def main(self, target, logger):
        self.cpt -= 1

        return ProbeStatus(self.cpt)


@blocking_probe(tactics)
class health_check(Probe):

    def start(self, target, logger):
        self.cpt = 0

    def stop(self, target, logger):
        pass

    def main(self, target, logger):           
        # time.sleep(0.1)

        self.cpt += 1

        status = 0
        if self.cpt > 10:
            status = -1

        return ProbeStatus(status)



@operator(tactics)
class Op1(Operator):

    def start(self, fmk_ops, dm, monitor, target, logger, user_input):
        monitor.start_probe('P1')
        monitor.set_probe_delay('P1', 0.3)
        monitor.start_probe('P2')
        monitor.set_probe_delay('P2', 0.1)
        monitor.start_probe('health_check')
        self.new = True
        self.cpt = 0

        specific_ui = user_input.get_specific()

        if specific_ui is None:
            self.strategy_mode = 0
        else:
            val = specific_ui.mode
            assert(type(val) == int or val is None)
            self.strategy_mode = 0 if val is None else val

    def stop(self, fmk_ops, dm, monitor, target, logger):
        monitor.stop_probe('P1')
        monitor.stop_probe('P2')
        monitor.stop_probe('health_check')
        self.new = False

    def plan_next_operation(self, fmk_ops, dm, monitor, target, logger, fmk_feedback):

        op = Operation()

        p1_ret = monitor.get_probe_status('P1').get_status()
        p2_ret = monitor.get_probe_status('P2').get_status()

        logger.print_console('*** status: p1: %d / p2: %d ***' % (p1_ret, p2_ret))

        if fmk_feedback.is_flag_set(FmkFeedback.NeedChange):
            change_list = fmk_feedback.get_flag_context(FmkFeedback.NeedChange)
            for dmaker, idx in change_list:
                logger.log_fmk_info('Exhausted data maker [#{:d}]: {:s} ({:s})'.format(idx, dmaker['dmaker_type'], dmaker['dmaker_name']),
                                    nl_before=True, nl_after=False)
            op.set_flag(Operation.Stop)
            return op

        if p1_ret + p2_ret > 0:
            actions = ['TVE', ('TVE/basic', 't_fuzz_tve_01'), ('Cp', None, [1]), ('Cp#1', None, [3])]
        elif -5 < p1_ret + p2_ret <= 0:
            actions = [('TVE_w#specific', 'g_typed_value_example_01'), (('Ce', 'd_corrupt_bits_node'), None, ['EVT1']), ('Cp#2', None, [1])]
        else:
            actions = ['TVE#2', 'tTYPE']

        op.add_instruction(actions)

        if self.strategy_mode == 1:
            actions_sup = ['TVE#2', ('SIZE', None, [10])]
            op.add_instruction(actions_sup)

        self.cpt += 1

        return op


    def do_after_all(self, fmk_ops, dm, monitor, target, logger):
        linst = LastInstruction()

        health_status = monitor.get_probe_status('health_check')

        if health_status.get_status() == -1:
            linst.set_instruction(LastInstruction.ExportData)
            linst.set_comments('This input has crashed the target!')

            # TODO: restart the target

        return linst



@generator(tactics, gtype="EX1", weight=2)
class example_02(Generator):

    def setup(self, dm, user_input):
        self.tux = dm.get_data('TUX')
        self.tux_h = self.tux.get_node_by_path('TUX/h$')
        self.tx = self.tux.get_node_by_path('TUX/TX$')
        self.tc = self.tux.get_node_by_path('TUX/TC$')

        self.delim = Node('DELIM', values=[' [@] '])

        self.tux.set_subnodes_with_csts([
                1, ['u>', [self.delim, 1],
                    'u=+', [self.tux_h, 1, 3], [self.tc, 1],
                    'u>', [self.delim, 1], [self.tx, 1], [self.delim, 1],
                    'u=.', [self.tx, 1], [self.tc, 1]]
                ])
    
        return True

    def generate_data(self, dm, monitor, target):
        exported_node = Node(self.tux.name, base_node=self.tux)
        dm.set_new_env(exported_node)
        return Data(exported_node)



@generator(tactics, gtype="TVE_w", weight=2)
class g_typed_value_example_01(Generator):

    def generate_data(self, dm, monitor, target):
        return Data(dm.get_data('TVE'))


@generator(tactics, gtype="TVE_w", weight=10)
class g_typed_value_example_02(Generator):

    def generate_data(self, dm, monitor, target):
        return Data(dm.get_data('TVE'))


@disruptor(tactics, dtype="TVE/basic", weight=4)
class t_fuzz_tve_01(Disruptor):

    def disrupt_data(self, dm, target, prev_data):

        val = b"NEW_" + rand_string(mini=5, maxi=10, str_set='XYZRVW')

        if prev_data.node:
            prev_data.node.get_node_by_path('TVE.*EVT1$').set_frozen_value(val)

        else:
            print('DONT_PROCESS_THIS_KIND_OF_DATA')

        return prev_data
