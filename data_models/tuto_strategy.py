from fuzzfmk.plumbing import *
from fuzzfmk.tactics_helper import *
from fuzzfmk.global_resources import *

tactics = Tactics()

logger = Logger('tuto', data_in_seperate_file=False, explicit_export=False, export_orig=True, export_raw_data=False)

class TutoTarget(NetworkTarget):

    def _custom_data_handling_before_emission(self, data_list):
        pass

    def _feedback_handling(self, fbk, ref):
        return fbk, ref

tg = TutoTarget(host='localhost', port=12345, data_semantics='TG1')
tg.register_new_interface('localhost', 54321, (socket.AF_INET, socket.SOCK_STREAM), 'TG2', server_mode=True)
tg.add_additional_feedback_interface('localhost', 7777, (socket.AF_INET, socket.SOCK_STREAM),
                                     fbk_id='My Feedback Source', server_mode=True)
tg.set_timeout(fbk_timeout=5, sending_delay=3)

targets = [tg]
