from framework.tactics_helpers import *
from framework.scenario import *

tactics = Tactics()


def cbk_check_crc_error(env, current_step, next_step, fbk):
    for source, status, timestamp, data in fbk:
        if b'CRC error' in data:
            return True


def set_init_v3(env, step):
    step.content['.*/header'].set_subfield(2, 3)


init_step = Step('init', fbk_timeout=0.5, do_before_data_processing=set_init_v3)
v3cmd_step = Step('zregister', fbk_timeout=1)
final_step = FinalStep()

init_step.connect_to(v3cmd_step)
v3cmd_step.connect_to(init_step, cbk_after_fbk=cbk_check_crc_error)
v3cmd_step.connect_to(final_step)

sc_client_req = Scenario('basic', anchor=init_step)

tactics.register_scenarios(sc_client_req)