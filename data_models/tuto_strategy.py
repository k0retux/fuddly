from fuzzfmk.plumbing import *
from fuzzfmk.tactics_helpers import *
from fuzzfmk.global_resources import *
from fuzzfmk.scenario import *

tactics = Tactics()

def cbk_transition1(env, current_step, next_step):
    return True

def cbk_transition2(env, current_step, next_step, fbk):
    if next_step.node:
        print("\n\n*** The next node named '{:s}' will be modified!".format(next_step.node.name))
        next_step.node['off_gen/prefix'] = '*MODIFIED*'
    else:
        print("\n\n*** The next node won't be modified!")
    return True

def cbk_transition3(env, current_step, next_step):
    if hasattr(env, 'switch'):
        print('\n**test1')
        return False
    else:
        print('\n**test2')
        env.switch = False
        return True

periodic1 = PeriodicData(DataProcess(process=[('C',None,UI(nb=1)),'tTYPE'], seed='enc'),
                         period=5)
periodic2 = PeriodicData(Data('2nd Periodic (3s)\n'), period=3)

step1 = Step('exist_cond', fbk_timeout=2, cbk_before_sending=cbk_transition1,
             set_periodic=[periodic1, periodic2])
step2 = Step('separator', fbk_timeout=5, cbk_after_fbk=cbk_transition2)
step3 = Step('off_gen', fbk_timeout=2, cbk_after_sending=cbk_transition3,
             clear_periodic=[periodic1, periodic2])

sc1 = Scenario('ex1')
sc1.add_steps(step1, step2, step3)

step4 = Step(DataProcess(process=['tTYPE#2'],seed='shape'))
step_final = FinalStep()

sc2 = Scenario('ex2')
sc2.add_steps(step1, step2, step4, step_final)

tactics.register_scenarios(sc1, sc2)


@generator(tactics, gtype="CBK", weight=1)
class g_test_callback_01(Generator):

    def setup(self, dm, user_input):
        self.fbk = None
        self.d = Data()
        self.d.register_callback(self.callback_1)
        self.d.register_callback(self.callback_2)
        self.d.register_callback(self.callback_3)
        self.d.register_callback(self.callback_before_sending_1,
                                 hook=HOOK.before_sending)
        self.d.register_callback(self.callback_before_sending_2,
                                 hook=HOOK.before_sending)
        return True

    def generate_data(self, dm, monitor, target):
        if self.fbk:
            self.d.update_from_str_or_bytes(self.fbk)
        else:
            node = dm.get_data('off_gen')
            self.d.update_from_node(node)
        return self.d

    def callback_1(self, feedback):
        print('\n*** callback 1 ***')
        if feedback:
            self.fbk = 'FEEDBACK from ' + str(feedback.keys())
        else:
            self.fbk = 'NO FEEDBACK'

        cbk = CallBackOps(remove_cb=True)
        cbk.add_operation(CallBackOps.Add_PeriodicData, id=1,
                          param=Data('\nTEST Periodic...'), period=5)
        return cbk

    def callback_2(self, feedback):
        print('\n*** callback 2 ***')
        cbk = CallBackOps(stop_process_cb=True, remove_cb=True)
        cbk.add_operation(CallBackOps.Add_PeriodicData, id=2,
                          param=Data('\nTEST One shot!'))
        return cbk

    def callback_3(self, feedback):
        print('\n*** callback 3 ***')
        cbk = CallBackOps(remove_cb=True)
        cbk.add_operation(CallBackOps.Del_PeriodicData, id=1)
        return cbk

    def callback_before_sending_1(self):
        print('\n*** callback just before sending data 1 ***')
        cbk = CallBackOps(stop_process_cb=True, remove_cb=True)
        cbk.add_operation(CallBackOps.Set_FbkTimeout, param=2)
        return cbk

    def callback_before_sending_2(self):
        print('\n*** callback just before sending data 2 ***')
        cbk = CallBackOps(remove_cb=True)
        cbk.add_operation(CallBackOps.Set_FbkTimeout, param=8)
        return cbk
