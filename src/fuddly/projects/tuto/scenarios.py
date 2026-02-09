from fuddly.framework.scenario import *
from fuddly.framework.scenario_builder import ScenarioBuilder, FragmentationScenarioBuilder


def check_fbk(env, current_step, next_step, fbk):
    print(f'\n*** Callback After Feedback Retrieval [from: {str(current_step)}] ***')
    return True

s1 = Step(Data('step1'), fbk_timeout=2, burst_count=3)
s2 = Step(Data('step2'))
s3 = Step(Data('step3'))
s4 = Step(Data('step4'))
final = FinalStep()

s1.connect_to(final, cbk_after_fbk=check_fbk)
s1.connect_to(s2)
s2.connect_to(final, cbk_after_fbk=check_fbk)
s2.connect_to(s3)
s3.connect_to(final, cbk_after_fbk=check_fbk)
s3.connect_to(s4)
s4.connect_to(final, cbk_after_fbk=check_fbk)

sc_burst = Scenario('burst', anchor=s1)


payload = ['ABCD', 'OOOOOOOOO', 'MMMMM', 'UUU', 'H'*100]

sb_frag = FragmentationScenarioBuilder()
sb_frag.set_scenario_params(name='frag', pod_atom_name='frag_cmd', payload=payload,
                            fragidx_ref='f_idx', fragcount_ref='f_count', pld_ref='pld',
                            fbk_timeout=0.1)
