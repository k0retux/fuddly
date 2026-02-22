from fuddly.framework.tactics_helpers import *
from fuddly.framework.scenario import *
from fuddly.framework.scenario_bricks import ScenarioBrick

tactics = Tactics()

class MyProto(ScenarioBrick):

    def build(self, user_context: UI = None, **kwargs):

        def cbk_check_crc_error(env, current_step, next_step, fbk):
            for source, status, timestamp, data in fbk:
                if b'CRC error' in data:
                    return True


        def set_init_v3(env, step):
            step.content['.*/header'][0].set_subfield(2, 3)

        init_step = Step('init', fbk_timeout=0.5, do_before_sending=set_init_v3)
        v3cmd_step = Step('zregister', fbk_timeout=1)
        final_step = NoDataStep(step_desc='end')

        init_step.connect_to(v3cmd_step)
        v3cmd_step.connect_to(init_step, cbk_after_fbk=cbk_check_crc_error)
        v3cmd_step.connect_to(final_step)


        starting_step = init_step
        in_connectors = []
        out_connectors = [final_step]

        return starting_step, in_connectors, out_connectors


tactics.register_scenario_bricks(MyProto(name='basic', final=True))
