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

from fuzzfmk.project import *
from fuzzfmk.monitor import *
from fuzzfmk.operator_helpers import *
from fuzzfmk.plumbing import *
import fuzzfmk.global_resources as gr

project = Project()
project.default_dm = 'mydf'

logger = Logger(export_data=False, explicit_data_recording=False, export_orig=False,
                export_raw_data=False, enable_file_logging=False)

class TutoNetTarget(NetworkTarget):

    def _custom_data_handling_before_emission(self, data_list):
        self.listen_to('localhost', 64001, 'Dynamic server interface')
        # self.connect_to('localhost', 64002, 'Dynamic client interface')
        # self._logger.collect_target_feedback('TEST', status_code=random.randint(-2,2))

    def _feedback_handling(self, fbk, ref):
        # self.remove_all_dynamic_interfaces()
        return fbk, ref

tg = TutoNetTarget(host='localhost', port=12345, data_semantics='TG1', hold_connection=True)
tg.register_new_interface('localhost', 54321, (socket.AF_INET, socket.SOCK_STREAM), 'TG2', server_mode=True, hold_connection=True)
tg.add_additional_feedback_interface('localhost', 7777, (socket.AF_INET, socket.SOCK_STREAM),
                                     fbk_id='My Feedback Source', server_mode=True)
tg.set_timeout(fbk_timeout=5, sending_delay=3)

### PROBE DEFINITION ###

@probe(project)
class P1(Probe):

    def start(self, target, logger):
        self.cpt = 10

    def main(self, target, logger):
        self.cpt += 1

        return ProbeStatus(self.cpt)


@probe(project)
class P2(Probe):

    def start(self, target, logger):
        self.cpt = 5

    def main(self, target, logger):
        self.cpt -= 1

        return ProbeStatus(self.cpt)


@blocking_probe(project)
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


### TARGETS ALLOCATION ###

targets = [(EmptyTarget(), (P1, 2), (P2, 1.4), health_check),
           tg]

### OPERATOR DEFINITION ###

@operator(project,
          args={'mode': ('strategy mode (0 or 1)', 0, int)})
class MyOp(Operator):

    def start(self, fmk_ops, dm, monitor, target, logger, user_input):
        monitor.set_probe_delay('P1', 0.3)
        monitor.set_probe_delay('P2', 0.1)
        if not monitor.is_probe_launched('P1'):
            monitor.start_probe('P1')
        if not monitor.is_probe_launched('P2'):
            monitor.start_probe('P2')

        self.new = True
        self.cpt = 0
        fmk_ops.set_fuzz_delay(0.5)

        return True

    def stop(self, fmk_ops, dm, monitor, target, logger):
        monitor.stop_probe('P1')
        monitor.stop_probe('P2')
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
            actions = [('SEPARATOR', UI(determinist=True)),
                       ('tSTRUCT', None, UI(deep=True)),
                       ('Cp', None, UI(idx=1)), ('Cp#1', None, UI(idx=3))]
        elif -5 < p1_ret + p2_ret <= 0:
            actions = ['SHAPE#specific', ('C', None, UI(path='.*prefix.$')), ('Cp#2', None, UI(idx=1))]
        else:
            actions = ['SHAPE#2', 'tTYPE']

        op.add_instruction(actions)

        if self.mode == 1:
            actions_sup = ['SHAPE#3', ('SIZE', None, UI(idx=10))]
            op.add_instruction(actions_sup)

        self.cpt += 1

        return op


    def do_after_all(self, fmk_ops, dm, monitor, target, logger):
        linst = LastInstruction()

        if not monitor.is_target_ok():
            linst.set_instruction(LastInstruction.ExportData)
            linst.set_comments('This input has crashed the target!')

            # Restart the target

        return linst
