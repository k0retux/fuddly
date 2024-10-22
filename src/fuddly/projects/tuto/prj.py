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

from fuddly.framework.comm_backends import Serial_Backend
from fuddly.framework.plumbing import *
from fuddly.framework.knowledge.information import *
from fuddly.framework.knowledge.feedback_handler import TestFbkHandler
from fuddly.framework.scenario import *
from fuddly.framework.global_resources import UI
from fuddly.framework.evolutionary_helpers import DefaultPopulation, CrossoverHelper
from fuddly.framework.data import DataProcess

project = Project()
project.default_dm = ['mydf', 'myproto']

project.map_targets_to_scenario('ex1', {0: 7, 1: 8, None: 8})

logger = Logger(record_data=False, explicit_data_recording=False,
                export_raw_data=False, enable_file_logging=False,
                highlight_marked_nodes=True)

### KNOWLEDGE ###

project.add_knowledge(
    Hardware.X86_64,
    Language.C,
    # Test.OnlyInvalidCases
)

project.register_feedback_handler(TestFbkHandler())

### PROJECT SCENARIOS DEFINITION ###

def cbk_print(env, step):
    print(env.user_context)
    print(env.user_context.prj)

open_step = Step('ex', do_before_sending=cbk_print)
open_step.connect_to(FinalStep())

sc_proj1 = Scenario('proj1', anchor=open_step, user_context=UI(prj='proj1'))
sc_proj2 = sc_proj1.clone('proj2')
sc_proj2.user_context = UI(prj='proj2')


step1 = Step(DataProcess(process=['tTYPE'], seed='4tg1'))
step2 = Step(DataProcess(process=['tTYPE#2'], seed='4tg2'))

step1.connect_to(step2, dp_completed_guard=True)
step2.connect_to(FinalStep(), dp_completed_guard=True)

sc_proj3 = Scenario('proj3', anchor=step1)

project.register_scenarios(sc_proj1, sc_proj2, sc_proj3)

### EVOLUTIONNARY PROCESS EXAMPLE ###

init_dp1 = DataProcess([('tTYPE', UI(fuzz_mag=0.2))], seed='exist_cond')
init_dp1.append_new_process([('tSTRUCT', UI(deep=True))])

init_dp2 = DataProcess([('tTYPE#2', UI(fuzz_mag=0.2))], seed='exist_cond')
init_dp2.append_new_process([('tSTRUCT#2', UI(deep=True))])

project.register_evolutionary_processes(
    ('evol1', DefaultPopulation,
     {'init_process': init_dp1,
      'max_size': 80,
      'max_generation_nb': 3,
      'crossover_algo': CrossoverHelper.crossover_algo1}),
    ('evol2', DefaultPopulation,
     {'init_process': init_dp2,
      'max_size': 80,
      'max_generation_nb': 3,
      'crossover_algo': CrossoverHelper.get_configured_crossover_algo2()})
)

