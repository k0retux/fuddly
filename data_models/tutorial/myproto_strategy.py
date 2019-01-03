from framework.tactics_helpers import *
from framework.scenario import *
from framework.data import Data
from framework.value_types import *

tactics = Tactics()

def cbk_check_v3(env, current_step, next_step):
    return current_step.content['.*/header'].get_subfield(2) == 3

def cbk_check_crc_error(env, current_step, next_step, fbk):
    for source, status, timestamp, data in fbk:
        if b'CRC error' in data:
            return True

init_step = Step('init', fbk_timeout=1)
v1v2cmd_step = Step('register', fbk_timeout=2)
v3cmd_step = Step('zregister', fbk_timeout=2)
final_step = FinalStep()

init_step.connect_to(v3cmd_step, cbk_after_sending=cbk_check_v3)
init_step.connect_to(v1v2cmd_step)

v1v2cmd_step.connect_to(init_step, cbk_after_fbk=cbk_check_crc_error)
v3cmd_step.connect_to(init_step, cbk_after_fbk=cbk_check_crc_error)

v1v2cmd_step.connect_to(final_step)
v3cmd_step.connect_to(final_step)

sc_client_req = Scenario('basic', anchor=init_step)

tactics.register_scenarios(sc_client_req)