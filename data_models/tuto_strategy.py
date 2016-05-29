from fuzzfmk.plumbing import *
from fuzzfmk.tactics_helpers import *
from fuzzfmk.global_resources import *

tactics = Tactics()


@generator(tactics, gtype="CB", weight=1)
class g_test_callback_01(Generator):

    def setup(self, dm, user_input):
        self.fbk = None
        return True

    def generate_data(self, dm, monitor, target):
        if self.fbk:
            d = Data(self.fbk)
        else:
            node = dm.get_data('off_gen')
            d = Data(node)
        d.register_callback(self.callback_1)
        d.register_callback(self.callback_2)
        return d

    def callback_1(self, feedback):
        print('*** callback 1 ***')
        if feedback:
            self.fbk = 'FEEDBACK from ' + str(feedback.keys())
        else:
            self.fbk = 'NO FEEDBACK'
        return True

    def callback_2(self, feedback):
        print('*** callback 2 ***')
        return True
