import sys
import z3

from framework.plumbing import *

from framework.node import *
from framework.value_types import *
from framework.data_model import *
from framework.encoders import *
import framework.dmhelpers.xml as xml
from framework.dmhelpers.json import *
from framework.dmhelpers.xml import tag_builder as xtb
from framework.dmhelpers.xml import xml_decl_builder
from framework.constraint_helpers import Constraint, Z3Constraint

class MyDF_DataModel(DataModel):

    file_extension = 'df'
    name = 'mydf'

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
              'contents': String(values=['A1', 'A2', 'A3'], determinist=True, case_sensitive=False)},

             {'name': 'command_A1',
              'contents': String(values=['AAA', 'BBBB', 'CCCCC'], case_sensitive=False),
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
              'contents': String(values=['$ A31_OK $', '$ A31_KO $'], determinist=False, case_sensitive=False),
              'exists_if': (BitFieldCondition(sf=2, val=[6,12]), 'A3_subopcode')},

             {'name': 'A32_payload',
              'contents': String(values=['$ A32_VALID $', '$ A32_INVALID $'], determinist=False, case_sensitive=False),
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
              'absorb_csts': AbsCsts(content=False)},

             {'name': 'crc',
              'contents': CRC(UINT32_be),
              'node_args': ['tstamp', 'int32_qty'],
              'absorb_csts': AbsCsts(content=False)}

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
              'absorb_csts': AbsFullCsts(content=False, similar_content=False)},
             {'name': 'enc_data',
              'encoder': GZIP_Enc(6),
              'set_attrs': [NodeInternals.Abs_Postpone],
              'contents': [
                 {'name': 'len',
                  'contents': LEN(vt=UINT8, after_encoding=False),
                  'node_args': 'data1',
                  'absorb_csts': AbsFullCsts(content=False, similar_content=False)},
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
                  'absorb_csts': AbsFullCsts(content=False, similar_content=False)},

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
                      'contents': r'(333|444)|(foo|bar)|\d|[th|is]'}


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
                                 specific_fuzzy_vals={'p2': ['myfuzzyvalue!']},
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

        xml5_desc = \
            {'name': 'xml5',
             'contents': [
                 xml_decl_builder(determinist=False),
                 xtb('command', params={'name': ['LOGIN', 'CMD_1', 'CMD_2']},
                     nl_prefix=True, refs={'name': 'cmd_val'}, contents= \
                         [xtb('LOGIN', condition=(RawCondition(val=['LOGIN']), 'cmd_val'),
                              params={'auth': ['cert', 'psk'], 'backend': ['ssh', 'serial']},
                              specific_fuzzy_vals={'auth': ['None']}, determinist=False, contents= \
                             [xtb('msg_id', contents=Node('mid', vt=INT_str(min=0))),
                              xtb('username', contents=['MyUser'], absorb_regexp=r'\w*'),
                              xtb('password', contents=['plopi'],
                                  absorb_regexp=r'[^<\s]*')]),
                          xtb('CMD_1', condition=(RawCondition(val=['CMD_1']), 'cmd_val'), contents= \
                              [{'name': 'msg_id'},
                               xtb('counter', contents=Node('counter_val', vt=UINT8()))]),
                          xtb('CMD_2', condition=(RawCondition(val=['CMD_2']), 'cmd_val'), contents= \
                              [{'name': 'msg_id'},
                               {'name': 'counter'},
                               xtb('filename', contents=Node('fln', vt=Filename(values=['/usr/bin/ls'])))])
                          ])
             ]}

        json_sample_1 = \
            {"menu": {
                "id": "file",
                "value": "File",
                "popup": {
                    "menuitem": [
                        {"value": "New", "onclick": "CreateNewDoc()"},
                        {"value": "Open", "onclick": "OpenDoc()"},
                        {"value": "Close", "onclick": "CloseDoc()"}
                    ]
                }
            }}

        json1_desc = json_builder('json1', sample=json_sample_1)

        json_sample_2 = \
            {"glossary": {
                "title": "example glossary",
                "GlossDiv": {
                    "title": "S",
                    "GlossList": {
                        "GlossEntry": {
                            "ID": "SGML",
                            "SortAs": "SGML",
                            "GlossTerm": "Standard Generalized Markup Language",
                            "Acronym": "SGML",
                            "Abbrev": "ISO 8879:1986",
                            "GlossDef": {
                                "para": "A meta-markup language, used to create markup languages such as DocBook.",
                                "GlossSeeAlso": ["GML", "XML"]
                            },
                            "GlossSee": "markup"
                        }
                    }
                }
            }}

        json2_desc = json_builder('json2', sample=json_sample_2)

        file_desc = \
            {'name': 'file',
             'contents': Filename(values=['test.txt']),
             'debug': True
            }


        nested_desc = \
            {'name': 'nested',
             'custo_clear': MH.Custo.NTerm.MutableClone,
             'contents': [
                 {'name' : 'line',
                  'qty': (0,50), 'default_qty': 2,
                  'contents': [
                      {'name': 'sep', 'contents': String(values=['..'])},
                      {'name': 'wrapper',
                       'contents': [
                           {'name': 'point',
                            'contents': [

                                {'weight':50,
                                 'contents': [
                                     {'name': 'lat',
                                      'contents': [
                                          {'name': 'lat_dir',
                                           'contents': String(values=['N', 'S'])},
                                          {'name': 'lat_deg',
                                           'contents': INT_str(min=0, max=90, min_size=2)},
                                          {'name': 'lat_min',
                                           'qty': (0,1),
                                           'contents': INT_str(min=0, max=59, min_size=2)},
                                      ]},
                                 ]},

                                {'weight':40,
                                 'contents': [
                                     {'name': 'lon',
                                      'contents': [
                                          {'name': 'lon_dir',
                                           'contents': String(values=['E', 'W'])},
                                          {'name': 'lon_deg',
                                           'contents': INT_str(min=0, max=180, min_size=3)},
                                          {'name': 'lon_min',
                                           'qty': (0,1),
                                           'contents': INT_str(min=0, max=59, min_size=2)},
                                      ]},
                                 ]}

                            ]}
                       ]}
                  ]}
             ]}


        csp_desc = \
            {'name': 'csp',
             'constraints': [
                 Constraint(relation=lambda d1, d2: d1[1]+1 == d2[0] or d1[1]+2 == d2[0],
                            vars=('delim_1', 'delim_2')),
                 Constraint(relation=lambda x, y, z: x == 3*y + z,
                            vars=('x_val', 'y_val', 'z_val')),
             ],
             'constraints_highlight': True,
             'contents': [
                 {'name': 'equation',
                  'contents': String(values=['x = 3y + z'])},
                 {'name': 'delim_1',
                  'contents': String(values=[' [', ' ('])},
                  # 'default': ' ('},
                 {'name': 'variables',
                  'separator': {'contents': {'name': 'sep', 'contents': String(values=[', '])},
                                'prefix': False, 'suffix': False},
                  'contents': [
                      {'name': 'x',
                       'contents': [
                           {'name': 'x_symbol',
                            'contents': String(values=['x:', 'X:'])},
                           {'name': 'x_val',
                            'contents': INT_str(min=120, max=130)} ]},
                      {'name': 'y',
                       'contents': [
                           {'name': 'y_symbol',
                            'contents': String(values=['y:', 'Y:'])},
                           {'name': 'y_val',
                            'contents': INT_str(min=30, max=40)}]},
                      {'name': 'z',
                       'contents': [
                           {'name': 'z_symbol',
                            'contents': String(values=['z:', 'Z:'])},
                           {'name': 'z_val',
                            'contents': INT_str(min=1, max=3)}]},
                  ]},
                 {'name': 'delim_2', 'contents': String(values=['-', ']', ')'])},
             ]}


        csp_z3_desc = \
            {'name': 'csp_z3',
             'constraints': [
                 Z3Constraint(relation='Or([x_val >=123, x_val <= 100])',
                              vars=('x_val', 'y_val', 'z_val')),
                 Z3Constraint(relation='x_val == 3*y_val + z_val',
                              vars=('x_val', 'y_val', 'z_val')),
             ],
             'constraints_highlight': True,
             'contents': [
                 {'name': 'equation',
                  'contents': String(values=['x = 3y + z'])},
                 {'name': 'delim_1', 'contents': String(values=[' [',])},
                 {'name': 'variables',
                  'separator': {'contents': {'name': 'sep', 'contents': String(values=[', '])},
                                'prefix': False, 'suffix': False},
                  'contents': [
                      {'name': 'x',
                       'contents': [
                           {'name': 'x_symbol',
                            'contents': String(values=['x:', 'X:'])},
                           {'name': 'x_val',
                            'contents': INT_str(min=10, max=300)} ]},
                      {'name': 'y',
                       'contents': [
                           {'name': 'y_symbol',
                            'contents': String(values=['y:', 'Y:'])},
                           {'name': 'y_val',
                            'contents': INT_str(min=30, max=40)}]},
                      {'name': 'z',
                       'contents': [
                           {'name': 'z_symbol',
                            'contents': String(values=['z:', 'Z:'])},
                           {'name': 'z_val',
                            'contents': INT_str(min=1, max=3)}]},
                  ]},
                 {'name': 'delim_2', 'contents': String(values=[']',])},
             ]}


        csp_str_desc = \
            {'name': 'csp_str',
             'constraints': [
                 Z3Constraint(relation='x_val == 3*y_val + z_val',
                              vars=('x_val', 'y_val', 'z_val')),
                 Z3Constraint(
                     relation="Or(["
                              "And([SubSeq(delim_1, 1, 1) == '(', delim_2 == ')']),"
                              "And([SubSeq(delim_1, 1, 1) == '[', delim_2 == ']'])"
                              "])",
                     vars=('delim_1', 'delim_2'),
                     var_types={'delim_1': z3.String, 'delim_2': z3.String},
                 ),
             ],
             'constraints_highlight': True,
             'contents': [
                 {'name': 'equation',
                  'contents': String(values=['x = 3y + z'])},
                 {'name': 'delim_1',
                  'contents': String(values=[' [', ' (']),
                  'default': ' ('},
                 {'name': 'variables',
                  'separator': {'contents': {'name': 'sep', 'contents': String(values=[', '])},
                                'prefix': False, 'suffix': False},
                  'contents': [
                      {'name': 'x',
                       'contents': [
                           {'name': 'x_symbol',
                            'contents': String(values=['x:', 'X:'])},
                           {'name': 'x_val',
                            'contents': INT_str(min=120, max=130)} ]},
                      {'name': 'y',
                       'contents': [
                           {'name': 'y_symbol',
                            'contents': String(values=['y:', 'Y:'])},
                           {'name': 'y_val',
                            'contents': INT_str(min=30, max=40)}]},
                      {'name': 'z',
                       'contents': [
                           {'name': 'z_symbol',
                            'contents': String(values=['z:', 'Z:'])},
                           {'name': 'z_val',
                            'contents': INT_str(min=1, max=3)}]},
                  ]},
                 {'name': 'delim_2', 'contents': String(values=['-', ']', ')'])},
             ]}



        csp_ns_desc = \
            {'name': 'csp_ns',
             'constraints': [Constraint(relation=lambda lat_deg, lon_deg: lat_deg == lon_deg + 1,
                                        vars=('lat_deg', 'lon_deg'),
                                        var_to_varns={'lat_deg': ('deg', 'lat'),
                                                      'lon_deg': ('deg', 'lon')}),
                             Constraint(lambda lat_min, lon_deg: lat_min == lon_deg + 10,
                                        vars=('lat_min', 'lon_deg'),
                                        var_to_varns={'lon_deg': ('deg', 'lon'),
                                                      'lat_min': ('min', 'lat')})],
             'contents': [
                 {'name': 'latitude',
                  'namespace': 'lat',
                  'contents': [
                      {'name': 'dir',
                       'contents': String(values=['N', 'S'])},
                      {'name': 'deg',
                       'contents': INT_str(min=0, max=90, min_size=2)},
                      {'name': 'min',
                       'contents': INT_str(min=0, max=59, min_size=2)},
                  ]},
                 {'name': 'longitude',
                  'namespace': 'lon',
                  'contents': [
                      {'name': 'dir',
                       'contents': String(values=['E', 'W'])},
                      {'name': 'deg',
                       'contents': INT_str(min=0, max=180, min_size=3)},
                      {'name': 'min',
                       'contents': INT_str(min=0, max=59, min_size=2)},
                  ]},
             ]}


        csp_basic_desc = \
            {'name': 'csp_basic',
             'constraints': [
                 Z3Constraint(relation='idx != 100',
                              vars=('idx',)),
             ],
             'constraints_highlight': True,
             'contents': [
                 {'name': 'prefix', 'contents': String(values=['> '])},
                 {'name': 'idx', 'contents': INT_str(values=[1,2,3,100,4,5,6,7,8,100]),
                  'default': 6},
                 {'name': 'suffix', 'contents': String(values=[' <'])},
             ]}

        str_desc = {'name': 'str',
             'contents': [
                 # {'name': 'str1', 'contents': String(values=['a', 'b', 'c'])},
                 # {'name': 'str2',
                 #  'contents': String(values=['x', 'y'], alphabet='xy', min_sz=1, max_sz=3)},
                 {'name': 'str3',
                  'contents': String(values=['OK'], alphabet=String.non_ctrl_char+String.ctrl_char_set,
                                     min_sz=1, max_sz=3)},
                 {'name': 'idx', 'contents': INT_str(values=[1,2,3,4,5])},
             ]}


        self.register(test_node_desc, abstest_desc, abstest2_desc, separator_desc,
                      sync_desc, len_gen_desc, misc_gen_desc, offset_gen_desc,
                      shape_desc, for_network_tg1, for_network_tg2, for_net_default_tg, basic_intg,
                      enc_desc, example_desc,
                      regex_desc, xml1_desc, xml2_desc, xml3_desc, xml4_desc, xml5_desc,
                      json1_desc, json2_desc, file_desc, nested_desc,
                      csp_desc, csp_z3_desc, csp_str_desc, csp_ns_desc, csp_basic_desc,
                      str_desc)


data_model = MyDF_DataModel()
