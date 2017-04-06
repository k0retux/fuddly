import sys
sys.path.append('.')

from framework.plumbing import *

from framework.node import *
from framework.value_types import *
from framework.data_model import *
from framework.encoders import *
import framework.dmhelpers.xml as xml

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
                                        subfield_values=[None, [0b10], [0,1]],
                                        subfield_val_extremums=[[500, 600], None, None]),
                   'name': 'val1',
                   'qty': (1, 5)},
                  
                  {'name': 'val22'},

                  {'name': 'val21-qty',
                   'contents': UINT16_be(values=[2,4])},
                  
                  {'name': 'middle',
                   'custo_set': MH.Custo.NTerm.FrozenCopy,
                   'custo_clear': MH.Custo.NTerm.MutableClone,
                   'separator': {'contents': {'name': 'sep',
                                              'contents': String(values=['\n'], absorb_regexp='\n+'),
                                              'absorb_csts': AbsNoCsts(regexp=True)}},
                   'contents': [{
                       'section_type': MH.Random,
                       'contents': [
                           
                           {'contents': String(values=['OK', 'KO'], size=2),
                            'name': 'val2',
                            'qty': (1, 3)},
                           
                           {'name': 'val21',
                            'qty_from': 'val21-qty',
                            'clone': 'val1'},
                           
                           {'name': 'USB_desc',
                            'import_from': 'usb',
                            'data_id': 'STR'},
                           
                           {'contents': lambda x: Node('cts', values=[x[0].to_bytes() \
                                                                      + x[1].to_bytes()]),
                            'name': 'val22',
                            'node_args': [('val21', 2), 'val3']}
                       ]}]},
                  
                  {'contents': String(max_sz = 10),
                   'name': 'val3',
                   'sync_qty_with': 'val1',
                   'alt': [
                       {'conf': 'alt1',
                        'contents': SINT8(values=[1,4,8])},
                       {'conf': 'alt2',
                        'contents': UINT16_be(min=0xeeee, max=0xff56),
                        'determinist': True}]}
              ]},
             
             # block 2
             {'section_type': MH.Pick,
              'weights': (10,5),
              'contents': [
                  {'contents': String(values=['PLIP', 'PLOP'], size=4),
                   'name': 'val4'},
                  
                  {'contents': SINT16_be(values=[-1, -3, -5, 7]),
                   'name': 'val5'}
              ]},
            
             # block 3
             {'section_type': MH.FullyRandom,
              'contents': [
                  {'contents': String(values=['AAA', 'BBBB', 'CCCCC']),
                   'name': ('val21', 2)},
                  
                  {'contents': UINT8(values=[2, 4, 6, 8]),
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
              'contents': UINT8(values=[0xcc, 0xff, 0xee])},

             {'name': 'variable_string',
              'contents': String(max_sz=20),
              'set_attrs': [NodeInternals.Abs_Postpone]},

             {'name': 'keycode',
              'contents': UINT16_be(values=[0xd2d3, 0xd2fe, 0xd2aa]),
              'absorb_helper': keycode_helper},

             {'name': 'variable_suffix',
              'contents': String(values=['END', 'THE_END'])}
         ]}


        abstest2_desc = \
        {'name': 'AbsTest2',
         'contents': [

             {'name': 'prefix',
              'contents': UINT8(values=[0xcc, 0xff, 0xee])},

             {'name': 'variable_string',
              'contents': String(max_sz=20),
              'set_attrs': [NodeInternals.Abs_Postpone]},

             {'name': 'keycode',
              'contents': UINT16_be(values=[0xd2d3, 0xd2fe, 0xd2aa])},

             {'name': 'variable_suffix',
              'contents': String(values=['END', 'THE_END'])}
         ]}


        separator_desc = \
        {'name': 'separator',
         'separator': {'contents': {'name': 'sep_nl',
                                    'contents': String(values=['\n'], absorb_regexp='[\r\n|\n]+'),
                                    'absorb_csts': AbsNoCsts(regexp=True)},
                       'prefix': False,
                       'suffix': False,
                       'unique': True},
         'contents': [
             {'section_type': MH.FullyRandom,
              'contents': [
                  {'name': 'parameters',
                   'separator': {'contents': {'name': ('sep',2),
                                              'contents': String(values=[' '], absorb_regexp=' +'),
                                              'absorb_csts': AbsNoCsts(regexp=True)}},
                   'qty': 3,
                   'contents': [
                       {'section_type': MH.FullyRandom,
                        'contents': [
                            {'name': 'color',
                             'determinist': True,  # used only for test purpose
                             'contents': [
                                 {'name': 'id',
                                  'contents': String(values=['color='])},
                                 {'name': 'val',
                                  'contents': String(values=['red', 'black'])}
                             ]},
                            {'name': 'type',
                             'contents': [
                                 {'name': ('id', 2),
                                  'contents': String(values=['type='])},
                                 {'name': ('val', 2),
                                  'contents': String(values=['circle', 'cube', 'rectangle'], determinist=False)}
                            ]},
                        ]}]},
                  {'contents': String(values=['AAAA', 'BBBB', 'CCCC'], determinist=False),
                   'qty': (4, 6),
                   'name': 'str'}
              ]}
         ]}


        sync_desc = \
        {'name': 'exist_cond',
         'shape_type': MH.Ordered,
         'contents': [
             {'name': 'opcode',
              'contents': String(values=['A1', 'A2', 'A3'], determinist=True)},

             {'name': 'command_A1',
              'contents': String(values=['AAA', 'BBBB', 'CCCCC']),
              'exists_if': (RawCondition('A1'), 'opcode'),
              'qty': 3},

             {'name': 'command_A2',
              'contents': UINT32_be(values=[0xDEAD, 0xBEEF]),
              'exists_if': (RawCondition('A2'), 'opcode')},

             {'name': 'command_A3',
              'exists_if': (RawCondition('A3'), 'opcode'),
              'contents': [
                  {'name': 'A3_subopcode',
                   'contents': BitField(subfield_sizes=[15,2,4], endian=VT.BigEndian,
                                        subfield_values=[None, [1,2], [5,6,12]],
                                        subfield_val_extremums=[[500, 600], None, None],
                                        determinist=False)},

                  {'name': 'A3_int',
                   'contents': UINT16_be(values=[10, 20, 30], determinist=False)},

                  {'name': 'A3_deco1',
                   'exists_if': (IntCondition(10), 'A3_int'),
                   'contents': String(values=['*1*0*'])},

                  {'name': 'A3_deco2',
                   'exists_if': (IntCondition(neg_val=[10]), 'A3_int'),
                   'contents': String(values=['+2+0+3+0+'])}
              ]},

             {'name': 'A31_payload',
              'contents': String(values=['$ A31_OK $', '$ A31_KO $'], determinist=False),
              'exists_if': (BitFieldCondition(sf=2, val=[6,12]), 'A3_subopcode')},

             {'name': 'A32_payload',
              'contents': String(values=['$ A32_VALID $', '$ A32_INVALID $'], determinist=False),
              'exists_if': (BitFieldCondition(sf=[0, 1, 2], val=[[500, 501], [1, 2], 5]), 'A3_subopcode')}
         ]}


        len_gen_desc = \
        {'name': 'len_gen',
         'contents': [
             {'name': 'len',
              'contents': LEN(UINT32_be),
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
                  {'contents': String(values=['AAA']),
                   'qty': 10,
                   'name': 'str'},
                  {'contents': UINT8(values=[0x3F]),
                   'name': 'int'}
              ]},

             {'name': 'len',
              'contents': OFFSET(use_current_position=False, vt=UINT8),
              'node_args': ['prefix', 'int', 'body']},
         ]}


        misc_gen_desc = \
        {'name': 'misc_gen',
         'contents': [
             {'name': 'integers',
              'contents': [
                  {'name': 'int16',
                   'qty': (2, 10),
                   'contents': UINT16_be(values=[16, 1, 6], determinist=False)},

                  {'name': 'int32',
                   'qty': (3, 8),
                   'contents': UINT32_be(values=[32, 3, 2], determinist=False)}
              ]},

             {'name': 'int16_qty',
              'contents': QTY(node_name='int16', vt=UINT8),
              'node_args': 'integers'},

             {'name': 'int32_qty',
              'contents': QTY(node_name='int32', vt=UINT8),
              'node_args': 'integers'},

             {'name': 'tstamp',
              'contents': TIMESTAMP("%H%M%S"),
              'absorb_csts': AbsCsts(contents=False)},

             {'name': 'crc',
              'contents': CRC(UINT32_be),
              'node_args': ['tstamp', 'int32_qty'],
              'absorb_csts': AbsCsts(contents=False)}

         ]}



        shape_desc = \
        {'name': 'shape',
         'separator': {'contents': {'name': 'sep',
                                    'contents': String(values=[' [!] '])}},
         'contents': [

             {'weight': 20,
              'contents': [
                  {'name': 'prefix1',
                   'contents': String(size=10, alphabet='+')},

                  {'name': 'body_top',
                   'contents': [

                       {'name': 'body',
                        'separator': {'contents': {'name': 'sep2',
                                                   'contents': String(values=['::'])}},
                        'shape_type': MH.Random, # ignored in determnist mode
                        'contents': [
                            {'contents': String(values=['AAA', 'BBB']),
                             'qty': (0, 4),
                             'name': 'str'},
                            {'contents': UINT8(values=[0x3E]), # chr(0x3E) == '>'
                             'name': 'int'}
                        ]},

                   ]},

                   {'contents': String(values=['?','!']),
                    'name': 'int3'}
              ]},

             {'weight': 20,
              'contents': [
                  {'name': 'prefix2',
                   'contents': String(size=10, alphabet='>')},

                  {'name': 'body'}
              ]}
         ]}

        for_network_tg1 = Node('4tg1', vt=String(values=['FOR_TARGET_1']))
        for_network_tg1.set_semantics(['TG1'])

        for_network_tg2 = Node('4tg2', vt=String(values=['FOR_TARGET_2']))
        for_network_tg2.set_semantics(['TG2'])

        for_net_default_tg = Node('4default', vt=String(values=['FOR_DEFAULT_TARGET']))

        basic_intg = Node('intg', vt=UINT16_be(values=[10]))

        enc_desc = \
        {'name': 'enc',
         'contents': [
             {'name': 'data0',
              'contents': String(values=['Plip', 'Plop']) },
             {'name': 'crc',
              'contents': CRC(vt=UINT32_be, after_encoding=False),
              'node_args': ['enc_data', 'data2'],
              'absorb_csts': AbsFullCsts(contents=False) },
             {'name': 'enc_data',
              'encoder': GZIP_Enc(6),
              'set_attrs': [NodeInternals.Abs_Postpone],
              'contents': [
                 {'name': 'len',
                  'contents': LEN(vt=UINT8, after_encoding=False),
                  'node_args': 'data1',
                  'absorb_csts': AbsFullCsts(contents=False)},
                 {'name': 'data1',
                  'contents': String(values=['Test!', 'Hello World!'], codec='utf-16-le') },
              ]},
             {'name': 'data2',
              'contents': String(values=['Red', 'Green', 'Blue']) },
         ]}


        example_desc = \
        {'name': 'ex',
         'contents': [
             {'name': 'data0',
              'contents': String(values=['Plip', 'Plop']) },

             {'name': 'data_group',
              'contents': [

                 {'name': 'len',
                  'mutable': False,
                  'contents': LEN(vt=UINT8, after_encoding=False),
                  'node_args': 'data1',
                  'absorb_csts': AbsFullCsts(contents=False)},

                 {'name': 'data1',
                  'contents': String(values=['Test!', 'Hello World!']) },

                 {'name': 'data2',
                  'qty': (1,3),
                  'semantics': ['sem1', 'sem2'],
                  'contents': UINT16_be(min=10, max=0xa0ff),
                  'alt': [
                       {'conf': 'alt1',
                        'contents': SINT8(values=[1,4,8])},
                       {'conf': 'alt2',
                        'contents': UINT16_be(min=0xeeee, max=0xff56)} ]},

                 {'name': 'data3',
                  'semantics': ['sem2'],
                  'sync_qty_with': 'data2',
                  'contents': UINT8(values=[30,40,50]),
                  'alt': [
                       {'conf': 'alt1',
                        'contents': SINT8(values=[1,4,8])}]},
                ]},

             {'name': 'data4',
              'contents': String(values=['Red', 'Green', 'Blue']) }
         ]}

        regex_desc = {'name': 'regex',
                      'contents': '(333|444)|(foo|bar)|\d|[th|is]'}


        xml1_desc = xml.tag_builder('A1', params={'p1':'a', 'p2': ['foo', 'bar'], 'p3': 'c'},
                                    contents=['foo', 'bar'], node_name='xml1')

        xml2_desc = xml.tag_builder('B1', params={'p1':'a', 'p2': ['foo', 'bar'], 'p3': 'c'},
                                    contents=Node('intg',vt=UINT32_be(values=[1,2,3])),
                                    node_name='xml2')

        xml3_desc = xml.tag_builder('C1', params={'p1':'a', 'p2': ['foo', 'bar'], 'p3': 'c'},
                     contents= \
                         {'name': 'intg',
                          'contents': UINT16_be(values=[60,70,80])}, node_name='xml3')

        xml4_desc = \
            {'name': 'xml4',
             'contents': [
                 {'name': 'inside_cpy',
                  'clone': 'i2'},
                 xml.tag_builder('D1', params={'p1':'a', 'p2': ['foo', 'bar'], 'p3': 'c'},
                                 contents= \
                                     {'name': 'inside',
                                      'contents': [
                                          {'name': 'i1',
                                           'clone': 'outside'},
                                          {'name': 'i2',
                                           'contents': String(values=['FOO', 'BAR'])}
                                      ]} ),
                 {'name': 'outside',
                  'contents': UINT16_be(values=[30,40,50])},
             ] }

        self.register(test_node_desc, abstest_desc, abstest2_desc, separator_desc,
                      sync_desc, len_gen_desc, misc_gen_desc, offset_gen_desc,
                      shape_desc, for_network_tg1, for_network_tg2, for_net_default_tg, basic_intg,
                      enc_desc, example_desc,
                      regex_desc, xml1_desc, xml2_desc, xml3_desc, xml4_desc)


data_model = MyDF_DataModel()
