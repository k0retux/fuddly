from .prj import project
from fuddly.framework.operator_helpers import (Operator, operator, Operation, LastInstruction)
from fuddly.framework.plumbing import FmkFeedback
from fuddly.framework.global_resources import UI
from fuddly.framework.comm_backends import Serial_Backend
from fuddly.framework.monitor import (Probe, probe, ProbeStatus, blocking_probe, ProbePID, ProbeMem)
from fuddly.libs.external_modules import serial_module

### PROBE DEFINITION ###

@probe(project)
class P1(Probe):

    def start(self, dm, target, logger):
        self.cpt = 0

    def main(self, dm, target, logger):
        self.cpt += 1

        return ProbeStatus(self.cpt, info='This is a Linux OS!')


@probe(project)
class P2(Probe):

    def start(self, dm, target, logger):
        self.cpt = 10

    def main(self, dm, target, logger):
        self.cpt -= 1
        ps = ProbeStatus(self.cpt)
        ps.set_private_info('always KO!')
        return ps


@blocking_probe(project)
class health_check(Probe):

    def start(self, dm, target, logger):
        self.cpt = 0

    def stop(self, dm, target, logger):
        pass

    def main(self, dm, target, logger):
        self.cpt += 1

        status = 0
        if self.cpt > 10:
            status = -1

        return ProbeStatus(status)

if serial_module:
    serial_backend = Serial_Backend('/dev/ttyUSB0', username='test', password='test', slowness_factor=8)

    @blocking_probe(project)
    class probe_pid(ProbePID):
        backend = serial_backend
        process_name = 'bash'

    @probe(project)
    class probe_mem(ProbeMem):
        backend = serial_backend
        process_name = 'bash'
        tolerance = 1

### OPERATOR DEFINITION ###

@operator(project,
          args={'mode': ('strategy mode (0 or 1)', 0, int),
                'max_steps': ('maximum number of test cases', 10, int)})
class MyOp(Operator):

    def start(self, fmk_ops, dm, monitor, target, logger, user_input):
        monitor.set_probe_delay(P1, 1)
        monitor.set_probe_delay(P2, 0.2)
        if not monitor.is_probe_launched(P1) and self.mode == 0:
            monitor.start_probe(P1)
        if not monitor.is_probe_launched(P2) and self.mode == 0:
            monitor.start_probe(P2)

        self.cpt = 0
        self.detected_error = 0

        if self.mode == 1:
            fmk_ops.set_sending_delay(0)
        else:
            fmk_ops.set_sending_delay(0.5)

        return True

    def stop(self, fmk_ops, dm, monitor, target, logger):
        pass

    def plan_next_operation(self, fmk_ops, dm, monitor, target, logger, fmk_feedback):

        op = Operation()

        p1_ret = monitor.get_probe_status(P1).value
        p2_ret = monitor.get_probe_status(P2).value

        logger.print_console('*** status: p1: %d / p2: %d ***' % (p1_ret, p2_ret))

        if fmk_feedback.is_flag_set(FmkFeedback.NeedChange):
            change_list = fmk_feedback.get_flag_context(FmkFeedback.NeedChange)
            for dmaker, idx in change_list:
                logger.log_fmk_info('Exhausted data maker [#{:d}]: {:s} '
                                    '({:s})'.format(idx, dmaker['dmaker_type'],dmaker['dmaker_name']),
                                    nl_before=True, nl_after=False)
            op.set_flag(Operation.Stop)
            return op

        if p1_ret + p2_ret > 0:
            actions = [('SEPARATOR', UI(determinist=True)),
                       ('tSTRUCT', UI(deep=True)),
                       ('Cp', UI(idx=1)), ('Cp#1', UI(idx=3))]
        elif -5 < p1_ret + p2_ret <= 0:
            actions = ['SHAPE#specific', ('C#2', UI(path='.*prefix.$')), ('Cp#2', UI(idx=1))]
        else:
            actions = ['SHAPE#3', 'tTYPE#3']

        op.add_instruction(actions, tg_ids=[7,8])

        if self.mode == 1:
            actions_sup = ['SEPARATOR#2', ('tSTRUCT#2', UI(deep=True)), ('SIZE', UI(sz=10))]
            op.add_instruction(actions_sup)

        self.cpt += 1

        return op


    def do_after_all(self, fmk_ops, dm, monitor, target, logger):
        linst = LastInstruction()

        if not monitor.is_target_ok():
            self.detected_error += 1
            linst.set_instruction(LastInstruction.RecordData)
            linst.set_operator_feedback('This input has crashed the target!')
            linst.set_operator_status(0)
        if self.cpt > self.max_steps and self.detected_error < 9:
            linst.set_operator_feedback("We have less than 9 data that trigger some problem with the target!"
                                        " You win!")
            linst.set_operator_status(-8)
        elif self.cpt > self.max_steps:
            linst.set_operator_feedback("Too many errors! ... You loose!")
            linst.set_operator_status(-self.detected_error)

        return linst

