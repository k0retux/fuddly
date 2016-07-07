from framework.plumbing import *
from framework.tactics_helpers import *
from framework.global_resources import *
from framework.scenario import *

tactics = Tactics()

def cbk_transition1(env, current_step, next_step):
    return True

def cbk_transition2(env, current_step, next_step, fbk):
    if not fbk:
        print("\n\nNo feedback retrieved. Let's wait for another turn")
        current_step.make_blocked()
        return False
    else:
        print("\n\nFeedback received from {!s}. Let's go on".format(fbk.keys()))
        print(repr(fbk.values()))
        current_step.make_free()
        if next_step.node:
            print("*** The next node named '{:s}' will be modified!".format(next_step.node.name))
            next_step.node['.*/prefix.?'] = '*MODIFIED*'
        else:
            print("*** The next node won't be modified!")
        return True

def cbk_transition3(env, current_step, next_step):
    if hasattr(env, 'switch'):
        return False
    else:
        env.switch = False
        return True

periodic1 = Periodic(DataProcess(process=[('C', None, UI(nb=1)), 'tTYPE'], seed='enc'),
                     period=5)
periodic2 = Periodic(Data('2nd Periodic (3s)\n'), period=3)

### SCENARIO 1 ###
step1 = Step('exist_cond', fbk_timeout=2, set_periodic=[periodic1, periodic2])
step2 = Step('separator', fbk_timeout=5, clear_periodic=[periodic1])
empty = NoDataStep(clear_periodic=[periodic2])
step4 = Step('off_gen', fbk_timeout=2, step_desc='overriding the auto-description!')

step1_copy = copy.copy(step1) # for scenario 2
step2_copy = copy.copy(step2) # for scenario 2

step1.connect_to(step2, cbk_before_sending=cbk_transition1)
step2.connect_to(empty, cbk_after_fbk=cbk_transition2)
empty.connect_to(step4)
step4.connect_to(step1, cbk_after_sending=cbk_transition3)

sc1 = Scenario('ex1')
sc1.set_anchor(step1)

### SCENARIO 2 ###
step4 = Step(DataProcess(process=['tTYPE#2'], seed='shape'))
step_final = FinalStep()

step1_copy.connect_to(step2_copy, cbk_before_sending=cbk_transition1)
step2_copy.connect_to(step4, cbk_after_fbk=cbk_transition2)
step4.connect_to(step_final)

sc2 = Scenario('ex2')
sc2.set_anchor(step1_copy)

### SCENARIO 3 ###
anchor = Step('exist_cond')
option1 = Step(Data('Option 1'))
option2 = Step(Data('Option 2'))

anchor.connect_to(option1, cbk_after_sending=cbk_transition3)
anchor.connect_to(option2)
option1.connect_to(anchor)
option2.connect_to(anchor)

sc3 = Scenario('ex3')
sc3.set_anchor(anchor)

tactics.register_scenarios(sc1, sc2, sc3)


@generator(tactics, gtype="CBK")
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
