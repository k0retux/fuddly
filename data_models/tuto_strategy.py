from framework.plumbing import *
from framework.tactics_helpers import *
from framework.global_resources import *
from framework.scenario import *
from framework.data import Data

tactics = Tactics()

def cbk_transition1(env, current_step, next_step, feedback):
    assert env is not None
    if not feedback:
        print("\n\nNo feedback retrieved. Let's wait for another turn")
        current_step.make_blocked()
        return False
    else:
        print("\n\nFeedback received from {!s}. Let's go on".format(feedback.sources()))
        for source, status, timestamp, data in  feedback:
            if data is not None:
                data = data[:15]
            print('*** Feedback entry:\n'
                  '    source: {:s}\n'
                  '    status: {:d}\n'
                  ' timestamp: {!s}\n'
                  '   content: {!r} ...\n'.format(source, status, timestamp, data))
        current_step.make_free()
        if next_step.node:
            print("*** The next node named '{:s}' will be modified!".format(next_step.node.name))
            next_step.node['.*/prefix.?'] = '*MODIFIED*'
        else:
            print("*** The next node won't be modified!")
        return True

def cbk_transition2(env, current_step, next_step):
    assert env is not None
    if hasattr(env, 'switch'):
        return False
    else:
        env.switch = False
        return True

def before_sending_cbk(env, step):
    assert env is not None
    print('\n--> Action executed before sending any data on step {:d} [desc: {!s}]'.format(id(step), step))
    step.node.show()
    return True

def before_data_processing_cbk(env, step):
    assert env is not None
    print('\n--> Action executed before data processing on step {:d} [desc: {!s}]'.format(id(step), step))
    if step.node is not None:
        step.node.show()
    return True

periodic1 = Periodic(DataProcess(process=[('C', None, UI(nb=1)), 'tTYPE'], seed='enc'),
                     period=5)
periodic2 = Periodic(Data('2nd Periodic (3s)\n'), period=3)

### SCENARIO 1 ###
step1 = Step('exist_cond', fbk_timeout=1, set_periodic=[periodic1, periodic2],
             do_before_sending=before_sending_cbk)
step2 = Step('separator', fbk_timeout=2, clear_periodic=[periodic1])
empty = NoDataStep(clear_periodic=[periodic2])
step4 = Step('off_gen', fbk_timeout=0, step_desc='overriding the auto-description!')

step1_copy = copy.copy(step1) # for scenario 2
step2_copy = copy.copy(step2) # for scenario 2

step1.connect_to(step2)
step2.connect_to(empty, cbk_after_fbk=cbk_transition1)
empty.connect_to(step4)
step4.connect_to(step1, cbk_after_sending=cbk_transition2)

sc1 = Scenario('ex1')
sc1.set_anchor(step1)

### SCENARIO 2 ###
step4 = Step(DataProcess(process=['tTYPE#2'], seed='shape'))
step_final = FinalStep()

step1_copy.connect_to(step2_copy)
step2_copy.connect_to(step4, cbk_after_fbk=cbk_transition1)
step4.connect_to(step_final)

sc2 = Scenario('ex2')
sc2.set_anchor(step1_copy)

### SCENARIO 3 ###
anchor = Step(DataProcess(process=['tTYPE#3'], seed='exist_cond'),
              do_before_data_processing=before_data_processing_cbk,
              do_before_sending=before_sending_cbk)
option1 = Step(Data('Option 1'), step_desc='option 1\ndescription',
               do_before_data_processing=before_data_processing_cbk)
option2 = Step(Data('Option 2'),
               do_before_data_processing=before_data_processing_cbk)

anchor.connect_to(option1, cbk_after_sending=cbk_transition2)
anchor.connect_to(option2)
option1.connect_to(anchor)
option2.connect_to(anchor)

sc3 = Scenario('ex3')
sc3.set_anchor(anchor)

### SCENARIO 4 & 5 ###
dp = DataProcess(['tTYPE#NOREG'], seed='exist_cond', auto_regen=False)
dp.append_new_process([('tSTRUCT#NOREG', None, UI(deep=True))])
unique_step = Step(dp)
unique_step.connect_to(unique_step)
sc4 = Scenario('no_regen')
sc4.set_anchor(unique_step)

dp = DataProcess(['tTYPE#REG'], seed='exist_cond', auto_regen=True)
dp.append_new_process([('tSTRUCT#REG', None, UI(deep=True))])
unique_step = Step(dp)
unique_step.connect_to(unique_step)
sc5 = Scenario('auto_regen')
sc5.set_anchor(unique_step)

### SCENARIO for testing transition selection ###

def cbk_after_fbk_return_true(env, current_step, next_step, fbk):
    if not hasattr(env, 'cbk_true_cpt'):
        env.cbk_true_cpt = 1
    else:
        env.cbk_true_cpt += 1
    # print('\n++ cbk_after_fbk_return_true from step {!s}'.format(current_step))
    return True

def cbk_after_sending_return_true(env, current_step, next_step):
    if not hasattr(env, 'cbk_true_cpt'):
        env.cbk_true_cpt = 1
    else:
        env.cbk_true_cpt += 1
    # print('\n++ cbk_after_sending_return_true from step {!s}'.format(current_step))
    return True

init_step = NoDataStep(step_desc='init')
g1_step = Step('intg')
g11_step = Step('4tg1')
g12_step = Step('4tg2')
g13_step = Step('4default')
final_step = FinalStep()

init_step.connect_to(g1_step)
g1_step.connect_to(g11_step, cbk_after_fbk=cbk_after_fbk_return_true)
g1_step.connect_to(g12_step, cbk_after_sending=cbk_after_sending_return_true)
g1_step.connect_to(g13_step, cbk_after_fbk=cbk_after_fbk_return_true)

g11_step.connect_to(init_step)
g12_step.connect_to(final_step)
g13_step.connect_to(final_step)

reinit_step = Step('enc')
reinit_step.connect_to(init_step)

sc_test = Scenario('test', anchor=init_step, reinit_anchor=reinit_step)

g1_step = Step('intg')
g11_step = Step('4tg1')
g12_step = Step('4tg2')
g13_step = Step('4default')
g1_step.connect_to(g11_step, cbk_after_fbk=cbk_after_fbk_return_true)
g1_step.connect_to(g12_step)
g1_step.connect_to(g13_step, cbk_after_sending=cbk_after_sending_return_true)
sc_test2 = Scenario('test2', anchor=g1_step)

g1_step = Step('intg')
g11_step = Step('4tg1')
g12_step = Step('4tg2')
g13_step = Step('4default')
g1_step.connect_to(g11_step, cbk_after_fbk=cbk_after_fbk_return_true)
g1_step.connect_to(g12_step, cbk_after_sending=cbk_after_sending_return_true,
                   cbk_after_fbk=cbk_after_fbk_return_true)
g1_step.connect_to(g13_step, cbk_after_fbk=cbk_after_fbk_return_true)
sc_test3 = Scenario('test3', anchor=g1_step)

def cbk_after_fbk_return_false(env, current_step, next_step, fbk):
    if not hasattr(env, 'cbk_false_cpt'):
        env.cbk_false_cpt = 1
    else:
        env.cbk_false_cpt += 1
    # print('\n++ cbk_after_fbk_return_false from step {!s}'.format(current_step))
    return False

def cbk_after_sending_return_false(env, current_step, next_step):
    if not hasattr(env, 'cbk_false_cpt'):
        env.cbk_false_cpt = 1
    else:
        env.cbk_false_cpt += 1
    # print('\n++ cbk_after_sending_return_false from step {!s}'.format(current_step))
    return False

g1_step = Step('intg')
g11_step = Step('4tg1')
g12_step = Step('4tg2')
g13_step = Step('4default')
g1_step.connect_to(g11_step, cbk_after_fbk=cbk_after_fbk_return_false)
g1_step.connect_to(g12_step, cbk_after_sending=cbk_after_sending_return_false,
                   cbk_after_fbk=cbk_after_fbk_return_false)
g1_step.connect_to(g13_step, cbk_after_sending=cbk_after_sending_return_false,
                   cbk_after_fbk=cbk_after_fbk_return_true)
sc_test4 = Scenario('test4', anchor=g1_step)

tactics.register_scenarios(sc1, sc2, sc3, sc4, sc5, sc_test, sc_test2, sc_test3, sc_test4)

@generator(tactics, gtype="CBK")
class g_test_callback_01(Generator):

    def setup(self, dm, user_input):
        self.fbk = None
        self.d = Data()
        self.d.register_callback(self.callback_1)
        self.d.register_callback(self.callback_2)
        self.d.register_callback(self.callback_3)
        self.d.register_callback(self.callback_before_sending_1,
                                 hook=HOOK.before_sending_step1)
        self.d.register_callback(self.callback_before_sending_2,
                                 hook=HOOK.before_sending_step1)
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
