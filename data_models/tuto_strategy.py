from fuzzfmk.plumbing import *
from fuzzfmk.tactics_helper import *
from fuzzfmk.global_resources import *

tactics = Tactics()

logger = Logger('tuto', data_in_seperate_file=False, explicit_export=False, export_orig=True, export_raw_data=False)

class TutoTarget(NetworkTarget):

    def feedback_handling(self, fbk, ref):
        return fbk, ref

tg = TutoTarget(host='localhost', port=12345, data_semantics='TG1')
tg.register_new_interface('localhost', 54321, (socket.AF_INET, socket.SOCK_STREAM), 'TG2')
tg.add_additional_feedback_interface('localhost', 7777, (socket.AF_INET, socket.SOCK_STREAM),
                                     fbk_id='Another Feedback Source')

targets = [tg]
