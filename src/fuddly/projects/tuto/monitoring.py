from .prj import project
from fuddly.framework.director_helpers import (Director, director, Instruction, LastInstruction)
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

