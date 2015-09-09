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

        test_node_desc = \
        {'name': 'TestNode',
         'contents': [
              # block 1
              {'section_type': MH.Ordered,
               'duplicate_mode': MH.Copy,
               'contents': [

                   {'contents': BitField(subfield_sizes=[21,2,1], endian=VT.BigEndian,
                                         subfield_val_lists=[None, [0b10], [0,1]],
                                         subfield_val_extremums=[[500, 600], None, None]),
                    'name': 'val1',
                    'qty': (1, 5)},

                   {'name': 'val2'},

                   {'name': 'middle',
                    'mode': MH.NotMutableClone,
                    'contents': [{
                        'section_type': MH.Random,
                        'contents': [

                            {'contents': String(val_list=['OK', 'KO'], size=2),
                             'name': 'val2'},

                            {'name': 'val21',
                             'clone': 'val1'},

                            {'name': 'USB_desc',
                             'export_from': 'usb',
                             'data_id': 'STR'},

                            {'type': MH.Generator,
                             'contents': lambda x: Node('cts',
                                                        values=[x[0].get_flatten_value() \
                                                                + x[1].get_flatten_value()]),
                             'name': 'val22',
                             'node_args': [('val21', 2), 'val3']}
                        ]}]},

                   {'contents': String(max_sz = 10),
                    'name': 'val3',
                    'sync_qty_with': 'val1',
                    'alt': [
                        {'conf': 'alt1',
                         'contents': SINT8(int_list=[1,4,8])},
                        {'conf': 'alt2',
                         'contents': UINT16_be(mini=0xeeee, maxi=0xff56),
                         'determinist': True}]}
               ]},

              # block 2
              {'section_type': MH.Pick,
               'weights': (10,5),
               'contents': [
                   {'contents': String(val_list=['PLIP', 'PLOP'], size=4),
                    'name': ('val21', 2)},

                   {'contents': SINT16_be(int_list=[-1, -3, -5, 7]),
                    'name': ('val22', 2)}
               ]}
         ]}


        self.register(test_desc, test_node_desc)



data_model = MyDF_DataModel()
