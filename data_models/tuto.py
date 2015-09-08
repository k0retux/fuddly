from fuzzfmk.data_model import *
from fuzzfmk.value_types import *
from fuzzfmk.data_model_helpers import *

class MyDF_DataModel(DataModel):

    file_extension = 'df'
    name = 'mydf'

    def dissect(self, data, idx):
        pass

    def build_data_model(self):

        test_desc = \
        {'name': 'test',
         'contents': [
             {'name': 'str1',
              'contents': String(val_list=['ABCDEF', 'abcdef'])},
             {'name': 'str2',
              'contents': String(val_list=['GHIJKL', 'ghijkl'])}
         ]}

        self.register(test_desc)



data_model = MyDF_DataModel()
