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

try:
    import queue as queue
except:
    import Queue as queue

from framework.monitor import *
from framework.knowledge.feedback_handler import *
from framework.knowledge.information import InformationCollector
from framework.value_types import VT
from framework.node import Env
from framework.data_model import DataModel
from framework.tactics_helpers import DataMaker
from framework.scenario import ScenarioEnv

class Project(object):

    name = None
    default_dm = None

    feedback_gate = None

    def __init__(self, enable_fbk_processing=True):
        self.monitor = Monitor()
        self._knowledge_source = InformationCollector()
        self._fbk_processing_enabled = enable_fbk_processing
        self._feedback_processing_thread = None
        self._fbk_handlers = []

        self.target = None
        self.dm = None
        self.operators = {}

    ################################
    ### Knowledge Infrastructure ###
    ################################

    @property
    def knowledge_source(self):
        return self._knowledge_source

    def add_knowledge(self, *info):
        self.knowledge_source.add_information(info)

    def reset_knowledge(self):
        self.knowledge_source.reset_information()

    def register_feedback_handler(self, fbk_handler):
        self._fbk_handlers.append(fbk_handler)

    def notify_data_sending(self, data_list, timestamp, target):
        for fh in self._fbk_handlers:
            fh.notify_data_sending(data_list, timestamp, target)

    def trigger_feedback_handlers(self, source, timestamp, content, status, target):
        if not self._fbk_processing_enabled:
            return
        self._feedback_fifo.put((source, timestamp, content, status, target))

    def _feedback_processing(self):
        '''
        core function of the feedback processing thread
        '''
        while self._run_fbk_handling_thread:
            try:
                fbk_tuple = self._feedback_fifo.get(timeout=0.5)
            except queue.Empty:
                continue

            for fh in self._fbk_handlers:
                info = fh.process_feedback(*fbk_tuple)
                if info:
                    self.knowledge_source.add_information(info)

    def estimate_last_data_impact_uniqueness(self):
        similarity = UNIQUE
        if self._fbk_processing_enabled:
            for fh in self._fbk_handlers:
                similarity += fh.estimate_last_data_impact_uniqueness()

        return similarity

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
            print("\n*** /!\\ ERROR: The operator name '{:s}' is already used\n".format(name))
            raise ValueError

        self.operators[name] = obj

    def register_new_probe(self, probe, blocking=False):
        try:
            self.monitor.add_probe(probe, blocking)
        except AddExistingProbeToMonitorError as e:
            print("\n*** /!\\ ERROR: The probe name '{:s}' is already used\n".format(e.probe_name))
            raise ValueError

    ##########################
    ### Runtime Operations ###
    ##########################

    def start(self):
        VT.knowledge_source = self.knowledge_source
        Env.knowledge_source = self.knowledge_source
        DataModel.knowledge_source = self.knowledge_source
        DataMaker.knowledge_source = self.knowledge_source
        ScenarioEnv.knowledge_source = self.knowledge_source

        if self._fbk_processing_enabled:
            self._run_fbk_handling_thread = True
            self._feedback_fifo = queue.Queue()
            self._feedback_processing_thread = threading.Thread(target=self._feedback_processing,
                                                                name='fuddly feedback processing')
            self._feedback_processing_thread.start()

    def stop(self):
        VT.knowledge_source = None
        Env.knowledge_source = None
        DataModel.knowledge_source = None
        DataMaker.knowledge_source = None
        ScenarioEnv.knowledge_source = None

        if self._fbk_processing_enabled:
            self._run_fbk_handling_thread = False
            if self._feedback_processing_thread:
                self._feedback_processing_thread.join()
            self._feedback_fifo = None

    def get_operator(self, name):
        try:
            ret = self.operators[name]
        except KeyError:
            return None

        return ret

    def get_operators(self):
        return self.operators

    def get_probes(self):
        return self.monitor.get_probes_names()
