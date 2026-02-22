from fuddly.framework.scenario import *
from fuddly.framework.scenario_builder import ScenarioBuilder, FragmentationScenarioBuilder
from fuddly.framework.scenario_bricks import ScenarioBrick, FRAG_POL


class BurstSBrick(ScenarioBrick):

    def build(self, user_context: UI = None, **kwargs):

        def check_fbk(env, current_step, next_step, fbk):
            print(f'\n*** Callback After Feedback Retrieval [from: {str(current_step)}] ***')
            return True

        s1 = Step(Data('step1'), fbk_timeout=2, burst_count=3)
        s2 = Step(Data('step2'))
        s3 = Step(Data('step3'))
        s4 = Step(Data('step4'))
        final = NoDataStep(step_desc='Exit burst')

        s1.connect_to(final, cbk_after_fbk=check_fbk)
        s1.connect_to(s2)
        s2.connect_to(final, cbk_after_fbk=check_fbk)
        s2.connect_to(s3)
        s3.connect_to(final, cbk_after_fbk=check_fbk)
        s3.connect_to(s4)
        s4.connect_to(final, cbk_after_fbk=check_fbk)

        starting_step = s1
        in_connectors = []
        out_connectors = [final]

        return starting_step, in_connectors, out_connectors

sbrick_burst = BurstSBrick(name='burst', final=True)

class InitSBrick(ScenarioBrick):

    def build(self, user_context: UI = None, **kwargs):
        dp_init = DataProcess(['C'], seed='init')
        step_init = Step(dp_init, fbk_timeout=0.5, vtg_ids=1)
        # step_out = NoDataStep()
        # step_os.connect_to(step_out)

        starting_step = step_init
        in_connectors = [step_init]
        out_connectors = [step_init]

        return starting_step, in_connectors, out_connectors

sbrick_init = InitSBrick()


class FinalSBrick_1(ScenarioBrick):

    def build(self, user_context: UI = None, **kwargs):
        dp_final = DataProcess(['C'], seed='register')
        step_final = Step(dp_final, fbk_timeout=0.5, vtg_ids=1)

        starting_step = step_final
        in_connectors = [step_final]
        out_connectors = [step_final]

        return starting_step, in_connectors, out_connectors

class FinalSBrick_2(ScenarioBrick):

    def build(self, user_context: UI = None, **kwargs):
        step_final = Step('zregister', fbk_timeout=0.5, vtg_ids=1)

        starting_step = step_final
        in_connectors = [step_final]
        out_connectors = [step_final]

        return starting_step, in_connectors, out_connectors

sbrick_final_1 = FinalSBrick_1()
sbrick_final_2 = FinalSBrick_2()

sbrick_final_1.connect_out_to(sbrick_final_2)

pld_list = ['ABCD', 'OOOOOOOOO', 'MMMMM', 'UUU', 'H'*100]

sb_frag_01 = FragmentationScenarioBuilder()
sb_frag_01.set_scenario_params(name='frag_1', host_name='frag_cmd', fragment_list=pld_list,
                               fragidx_ref='f_idx', fragcount_ref='f_count', pld_ref='pld',
                               pldsz_ref='size',
                               fbk_timeout=0.1)
sb_frag_01.set_starting_sbrick(sbrick_init)
sb_frag_01.set_ending_sbrick(sbrick_final_1)

pld = 'A'*6+'B'*6+'C'*6+'D'*6+'E'*6+'123'

sb_frag_02 = FragmentationScenarioBuilder()
sb_frag_02.set_scenario_params(name='frag_2', host_name='frag_cmd',
                               payload=pld,
                               fragidx_ref='f_idx', fragcount_ref='f_count', pld_ref='pld',
                               pldsz_ref='size',
                               fbk_timeout=0.1)
# sb_frag_02.set_starting_sbrick(sbrick_init.clone())