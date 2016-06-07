from fuzzfmk.plumbing import *
from fuzzfmk.tactics_helpers import *
from fuzzfmk.global_resources import *

tactics = Tactics()


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
