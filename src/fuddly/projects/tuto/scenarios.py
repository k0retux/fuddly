from fuddly.framework.scenario import *

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