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

from __future__ import print_function
from fuzzfmk.monitor import *

class Project(object):

    name = None
    default_dm = None

    def __init__(self):
        self.monitor = Monitor()
        self.target = None
        self.dm = None
        self.operators = {}

    #####################
    ### Configuration ###
    #####################

    def set_logger(self, logger):
        self.logger = logger

    def set_target(self, target):
        self.target = target

    def set_monitor(self, monitor):
        self.monitor = monitor

    def set_data_model(self, dm):
        self.dm = dm

    def register_new_operator(self, name, obj):

        if name in self.operators:
            print("\n*** /!\\ ERROR: The operator name '%s' is already used\n" % name)
            raise ValueError

        self.operators[name] = obj

    def register_new_probe(self, probe, blocking=False):
        try:
            self.monitor.add_probe(probe, blocking)
        except AlreadyExistingProbeError:
            print("\n*** /!\\ ERROR: The probe name '%s' is already used\n" % probe.__class__.__name__)
            raise ValueError


    ##########################
    ### Runtime Operations ###
    ##########################

    def start(self):
        pass

    def stop(self):
        pass

    def get_operator(self, name):
        try:
            ret = self.operators[name]
        except KeyError:
            return None

        return ret

    def get_operators(self):
        return self.operators

    def is_probe_launched(self, name):
        return self.monitor.is_probe_launched(name)

    def set_probe_delay(self, name, delay):
        self.monitor.set_probe_delay(name, delay)

    def get_probe_delay(self, name):
        return self.monitor.get_probe_delay(name)

    def get_probe_status(self, name):
        return self.monitor.get_probe_status(name)

    def get_probes(self):
        return self.monitor.get_probes_names()