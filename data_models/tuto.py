import sys
sys.path.append('.')

from framework.plumbing import *

from framework.data_model import *
from framework.value_types import *
from framework.data_model_helpers import *
from framework.encoders import *

class MyDF_DataModel(DataModel):

    file_extension = 'df'
    name = 'mydf'

    def absorb(self, data, idx):
        pass

    def build_data_model(self):

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
                  
                  {'name': 'val22'},

                  {'name': 'val21-qty',
                   'contents': UINT16_be(int_list=[2,4])},
                  
                  {'name': 'middle',
                   'custo_set': MH.Custo.NTerm.FrozenCopy,
                   'custo_clear': MH.Custo.NTerm.MutableClone,
                   'separator': {'contents': {'name': 'sep',
                                              'contents': String(val_list=['\n'], absorb_regexp='\n+'),
                                              'absorb_csts': AbsNoCsts(regexp=True)}},
                   'contents': [{
                       'section_type': MH.Random,
                       'contents': [
                           
                           {'contents': String(val_list=['OK', 'KO'], size=2),
                            'name': 'val2',
                            'qty': (1, 3)},
                           
                           {'name': 'val21',
                            'qty_from': 'val21-qty',
                            'clone': 'val1'},
                           
                           {'name': 'USB_desc',
                            'import_from': 'usb',
                            'data_id': 'STR'},
                           
                           {'type': MH.Generator,
                            'contents': lambda x: Node('cts', values=[x[0].to_bytes() \
                                                                      + x[1].to_bytes()]),
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
                   'name': 'val4'},
                  
                  {'contents': SINT16_be(int_list=[-1, -3, -5, 7]),
                   'name': 'val5'}
              ]},
            
             # block 3
             {'section_type': MH.FullyRandom,
              'contents': [
                  {'contents': String(val_list=['AAA', 'BBBB', 'CCCCC']),
                   'name': ('val21', 2)},
                  
                  {'contents': UINT8(int_list=[2, 4, 6, 8]),
                   'qty': (2, 3),
                   'name': 'val7'}
              ]}
         ]}


        def keycode_helper(blob, constraints, node_internals):
            off = blob.find(b'\xd2')
            if off > -1:
                return AbsorbStatus.Accept, off, None
            else:
                return AbsorbStatus.Reject, 0, None

        abstest_desc = \
        {'name': 'AbsTest',
         'contents': [

             {'name': 'prefix',
              'contents': UINT8(int_list=[0xcc, 0xff, 0xee])},

             {'name': 'variable_string',
              'contents': String(max_sz=20),
              'set_attrs': [NodeInternals.Abs_Postpone]},

             {'name': 'keycode',
              'contents': UINT16_be(int_list=[0xd2d3, 0xd2fe, 0xd2aa]),
              'absorb_helper': keycode_helper},

             {'name': 'variable_suffix',
              'contents': String(val_list=['END', 'THE_END'])}
         ]}


        abstest2_desc = \
        {'name': 'AbsTest2',
         'contents': [

             {'name': 'prefix',
              'contents': UINT8(int_list=[0xcc, 0xff, 0xee])},

             {'name': 'variable_string',
              'contents': String(max_sz=20),
              'set_attrs': [NodeInternals.Abs_Postpone]},

             {'name': 'keycode',
              'contents': UINT16_be(int_list=[0xd2d3, 0xd2fe, 0xd2aa])},

             {'name': 'variable_suffix',
              'contents': String(val_list=['END', 'THE_END'])}
         ]}


        separator_desc = \
        {'name': 'separator',
         'separator': {'contents': {'name': 'sep_nl',
                                    'contents': String(val_list=['\n'], absorb_regexp='[\r\n|\n]+'),
                                    'absorb_csts': AbsNoCsts(regexp=True)},
                       'prefix': False,
                       'suffix': False,
                       'unique': True},
         'contents': [
             {'section_type': MH.FullyRandom,
              'contents': [
                  {'name': 'parameters',
                   'separator': {'contents': {'name': ('sep',2),
                                              'contents': String(val_list=[' '], absorb_regexp=' +'),
                                              'absorb_csts': AbsNoCsts(regexp=True)}},
                   'qty': 3,
                   'contents': [
                       {'section_type': MH.FullyRandom,
                        'contents': [
                            {'name': 'color',
                             'determinist': True,  # used only for test purpose
                             'contents': [
                                 {'name': 'id',
                                  'contents': String(val_list=['color='])},
                                 {'name': 'val',
                                  'contents': String(val_list=['red', 'black'])}
                             ]},
                            {'name': 'type',
                             'contents': [
                                 {'name': ('id', 2),
                                  'contents': String(val_list=['type='])},
                                 {'name': ('val', 2),
                                  'contents': String(val_list=['circle', 'cube', 'rectangle'], determinist=False)}
                            ]},
                        ]}]},
                  {'contents': String(val_list=['AAAA', 'BBBB', 'CCCC'], determinist=False),
                   'qty': (4, 6),
                   'name': 'str'}
              ]}
         ]}


        sync_desc = \
        {'name': 'exist_cond',
         'shape_type': MH.Ordered,
         'contents': [
             {'name': 'opcode',
              'contents': String(val_list=['A1', 'A2', 'A3'], determinist=True)},

             {'name': 'command_A1',
              'contents': String(val_list=['AAA', 'BBBB', 'CCCCC']),
              'exists_if': (RawCondition('A1'), 'opcode'),
              'qty': 3},

             {'name': 'command_A2',
              'contents': UINT32_be(int_list=[0xDEAD, 0xBEEF]),
              'exists_if': (RawCondition('A2'), 'opcode')},

             {'name': 'command_A3',
              'exists_if': (RawCondition('A3'), 'opcode'),
              'contents': [
                  {'name': 'A3_subopcode',
                   'contents': BitField(subfield_sizes=[15,2,4], endian=VT.BigEndian,
                                        subfield_val_lists=[None, [1,2], [5,6,12]],
                                        subfield_val_extremums=[[500, 600], None, None],
                                        determinist=False)},

                  {'name': 'A3_int',
                   'contents': UINT16_be(int_list=[10, 20, 30], determinist=False)},

                  {'name': 'A3_deco1',
                   'exists_if': (IntCondition(10), 'A3_int'),
                   'contents': String(val_list=['*1*0*'])},

                  {'name': 'A3_deco2',
                   'exists_if': (IntCondition(neg_val=[10]), 'A3_int'),
                   'contents': String(val_list=['+2+0+3+0+'])}
              ]},

             {'name': 'A31_payload',
              'contents': String(val_list=['$ A31_OK $', '$ A31_KO $'], determinist=False),
              'exists_if': (BitFieldCondition(sf=2, val=[6,12]), 'A3_subopcode')},

             {'name': 'A32_payload',
              'contents': String(val_list=['$ A32_VALID $', '$ A32_INVALID $'], determinist=False),
              'exists_if': (BitFieldCondition(sf=[0, 1, 2], val=[[500, 501], [1, 2], 5]), 'A3_subopcode')}
         ]}


        len_gen_desc = \
        {'name': 'len_gen',
         'contents': [
             {'name': 'len',
              'type': MH.Generator,
              'contents': MH.LEN(UINT32_be),
              'node_args': 'payload',
              'absorb_csts': AbsNoCsts()},

             {'name': 'payload',
              'contents': String(min_sz=10, max_sz=100, determinist=False)},
         ]}


        offset_gen_desc = \
        {'name': 'off_gen',
         'custo_set': MH.Custo.NTerm.MutableClone,
         'contents': [
             {'name': 'prefix',
              'contents': String(size=10, alphabet='*+')},
              # 'contents': String(max_sz=10, min_sz=1, alphabet='*+')},

             {'name': 'body',
              # 'custo_set': MH.Custo.NTerm.MutableClone,
              'shape_type': MH.FullyRandom,
              'random': True,
              'contents': [
                  {'contents': String(val_list=['AAA']),
                   'qty': 10,
                   'name': 'str'},
                  {'contents': UINT8(int_list=[0x3F]),
                   'name': 'int'}
              ]},

             {'name': 'len',
              'type': MH.Generator,
              'contents': MH.OFFSET(use_current_position=False, vt=UINT8),
              'node_args': ['prefix', 'int', 'body']},
         ]}


        misc_gen_desc = \
        {'name': 'misc_gen',
         'contents': [
             {'name': 'integers',
              'contents': [
                  {'name': 'int16',
                   'qty': (2, 10),
                   'contents': UINT16_be(int_list=[16, 1, 6], determinist=False)},

                  {'name': 'int32',
                   'qty': (3, 8),
                   'contents': UINT32_be(int_list=[32, 3, 2], determinist=False)}
              ]},

             {'name': 'int16_qty',
              'type': MH.Generator,
              'contents': MH.QTY(node_name='int16', vt=UINT8),
              'node_args': 'integers'},

             {'name': 'int32_qty',
              'type': MH.Generator,
              'contents': MH.QTY(node_name='int32', vt=UINT8),
              'node_args': 'integers'},

             {'name': 'tstamp',
              'type': MH.Generator,
              'contents': MH.TIMESTAMP("%H%M%S"),
              'absorb_csts': AbsCsts(contents=False)},

             {'name': 'crc',
              'type': MH.Generator,
              'contents': MH.CRC(UINT32_be),
              'node_args': ['tstamp', 'int32_qty'],
              'absorb_csts': AbsCsts(contents=False)}

         ]}



        shape_desc = \
        {'name': 'shape',
         'separator': {'contents': {'name': 'sep',
                                    'contents': String(val_list=[' [!] '])}},
         'contents': [

             {'weight': 20,
              'contents': [
                  {'name': 'prefix1',
                   'contents': String(size=10, alphabet='+')},

                  {'name': 'body_top',
                   'contents': [

                       {'name': 'body',
                        'separator': {'contents': {'name': 'sep2',
                                                   'contents': String(val_list=['::'])}},
                        'shape_type': MH.Random, # ignored in determnist mode
                        'contents': [
                            {'contents': String(val_list=['AAA']),
                             'qty': (0, 4),
                             'name': 'str'},
                            {'contents': UINT8(int_list=[0x3E]), # chr(0x3E) == '>'
                             'name': 'int'}
                        ]}
                   ]}

              ]},

             {'weight': 20,
              'contents': [
                  {'name': 'prefix2',
                   'contents': String(size=10, alphabet='>')},

                  {'name': 'body'}
              ]}
         ]}

        for_network_tg1 = Node('4tg1', vt=String(val_list=['FOR_TARGET_1']))
        for_network_tg1.set_semantics(['TG1'])

        for_network_tg2 = Node('4tg2', vt=String(val_list=['FOR_TARGET_2']))
        for_network_tg2.set_semantics(['TG2'])

        enc_desc = \
        {'name': 'enc',
         'contents': [
             {'name': 'data0',
              'contents': String(val_list=['Plip', 'Plop']) },
             {'name': 'crc',
              'contents': MH.CRC(vt=UINT32_be, after_encoding=False),
              'node_args': ['enc_data', 'data2'],
              'absorb_csts': AbsFullCsts(contents=False) },
             {'name': 'enc_data',
              'encoder': GZIP_Enc(6),
              'set_attrs': [NodeInternals.Abs_Postpone],
              'contents': [
                 {'name': 'len',
                  'contents': MH.LEN(vt=UINT8, after_encoding=False),
                  'node_args': 'data1',
                  'absorb_csts': AbsFullCsts(contents=False)},
                 {'name': 'data1',
                  'contents': UTF16_LE(val_list=['Test!', 'Hello World!']) },
              ]},
             {'name': 'data2',
              'contents': String(val_list=['Red', 'Green', 'Blue']) },
         ]}



        example_desc = \
        {'name': 'ex',
         'contents': [
             {'name': 'data0',
              'contents': String(val_list=['Plip', 'Plop']) },

             {'name': 'data_group',
              'contents': [

                 {'name': 'len',
                  'mutable': False,
                  'contents': MH.LEN(vt=UINT8, after_encoding=False),
                  'node_args': 'data1',
                  'absorb_csts': AbsFullCsts(contents=False)},

                 {'name': 'data1',
                  'contents': String(val_list=['Test!', 'Hello World!']) },

                 {'name': 'data2',
                  'qty': (1,3),
                  'semantics': ['sem1', 'sem2'],
                  'contents': UINT16_be(mini=10, maxi=0xa0ff),
                  'alt': [
                       {'conf': 'alt1',
                        'contents': SINT8(int_list=[1,4,8])},
                       {'conf': 'alt2',
                        'contents': UINT16_be(mini=0xeeee, maxi=0xff56)} ]},

                 {'name': 'data3',
                  'semantics': ['sem2'],
                  'sync_qty_with': 'data2',
                  'contents': UINT8(int_list=[30,40,50]),
                  'alt': [
                       {'conf': 'alt1',
                        'contents': SINT8(int_list=[1,4,8])}]},
                ]},

             {'name': 'data4',
              'contents': String(val_list=['Red', 'Green', 'Blue']) }
         ]}



        self.register(test_node_desc, abstest_desc, abstest2_desc, separator_desc,
                      sync_desc, len_gen_desc, misc_gen_desc, offset_gen_desc,
                      shape_desc, for_network_tg1, for_network_tg2, enc_desc, example_desc)


data_model = MyDF_DataModel()
