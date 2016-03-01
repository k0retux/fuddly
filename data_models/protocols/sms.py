import sys

from fuzzfmk.data_model import *
from fuzzfmk.value_types import *
from fuzzfmk.data_model_helpers import *

class SMS_DataModel(DataModel):

    file_extension = 'sms'

    def absorb(self, data, idx):
        pass

    def build_data_model(self):

        smstxt_desc = \
        {'name': 'smstxt',
         'contents': [
             {'name': 'len',
              'contents': MH.LEN(vt=UINT8, after_encoding=False),
              'node_args': 'user_data'},
             {'name': 'user_data',
              'contents': GSM7bitPacking(val_list=['Hello World!'], max_sz=160)
             }
         ]
        }
        self.register(smstxt_desc)

data_model = SMS_DataModel()
