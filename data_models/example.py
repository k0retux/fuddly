#!/usr/bin/env python

################################################################################
#
#  Copyright 2014-2016 Eric Lacombe <eric.lacombe@security-labs.org>
#
################################################################################
#
#  This file is part of fuddly.
#
#  fuddly is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  fuddly is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with fuddly. If not, see <http://www.gnu.org/licenses/>
#
################################################################################

import sys
import copy
import re
import functools

sys.path.append('.')

from framework.data_model import *
from framework.data_model_helpers import *
from framework.value_types import *

from framework.fuzzing_primitives import *
from framework.basic_primitives import *

class Example_DataModel(DataModel):

    def build_data_model(self):

        tx = Node('TX')
        tx_h = Node('h', values=['/TX'])

        ku = Node('KU')
        kv = Node('KV')

        ku_h = Node('KU_h', values=[':KU:'])
        kv_h = Node('KV_h', values=[':KV:'])

        tux_subparts_1 = ['POWN', 'TAILS', 'WORLD1', 'LAND321']
        tux_subparts_2 = ['YYYY', 'ZZZZ', 'XXXX']
        ku.set_values(tux_subparts_1)
        kv.set_values(tux_subparts_2)


        tux_subparts_3 = ['[<]MARCHONS', '[<]TESTONS']
        kv.add_conf('ALT')
        kv.set_values(tux_subparts_3, conf='ALT')

        tux_subparts_4 = [u'[\u00c2]PLIP', u'[\u00c2]GLOUP']
        ku.add_conf('ALT')
        ku.set_values(value_type=String(values=tux_subparts_4, codec='utf8'), conf='ALT')
        
        idx = Node('IDX')
        idx.set_values(value_type=SINT16_be(mini=4,maxi=40))

        tx.set_subnodes_basic([tx_h, idx, ku_h, ku, kv_h, kv])

        tc = Node('TC')
        tc_h = Node('h', values=['/TC'])

        ku2 = Node('KU', base_node=ku)
        kv2 = Node('KV', base_node=kv)

        ku_h2 = Node('KU_h', base_node=ku_h)
        kv_h2 = Node('KV_h', base_node=kv_h)

        tc.set_subnodes_basic([tc_h, ku_h2, ku2, kv_h2, kv2])
        

        mark3 = Node('MARK3', values=[' ~(X)~ '])
        self.mark3 = mark3

        tc.add_conf('ALT')
        tc.set_subnodes_basic([mark3, tc_h, ku2, kv_h2], conf='ALT')

        mark = Node('MARK', values=[' [#] '])

        idx2 = Node('IDX2', base_node=idx)
        tux = Node('TUX')
        tux_h = Node('h', values=['TUX'])

        # set 'mutable' attribute to False
        tux_h.clear_attr(NodeInternals.Mutable)

        tux.set_subnodes_with_csts([
            100, ['u>', [tux_h, 1], [idx2, 1], [mark, 1],
                  'u=+(1,2)', [tc, 2], [tx, 1, 2],
                  'u>', [mark, 1], [tx, 1], [tc, 1],
                  'u=..', [tux_h, 1], [idx2, 1]],

            1, ['u>', [mark, 1],
                's=..', [tux_h, 1, 3], [tc, 3],
                'u>', [mark, 1], [tx, 1], [idx2, 1]],

            15, ['u>', [mark, 1],
                 'u=.', [tux_h, 1, 3], [tc, 3],
                 'u=.', [mark, 1], [tx, 1], [idx2, 1]]
            ])


        mark2 = Node('MARK2', values=[' ~(..)~ '])

        tux.add_conf('ALT')
        tux.set_subnodes_with_csts(
            [1, ['u>', [mark2, 1],
                 'u=+(4000,1)', [tux_h, 1], [mark, 1],
                 'u>', [mark2, 1],
                 'u=.', [tux_h, 1], [tc, 10],
                 'u>', [mark, 1], [tx, 1], [idx2, 1]]
             ], conf='ALT')

        
        concat = Node('CONCAT')
        length = Node('LEN')
        node_ex1 = Node('EX1')

        fct = lambda x: b' @ ' + x + b' @ '
        concat.set_func(fct, tux)
        
        if sys.version_info[0] > 2:
            fct = lambda x: b'___' + bytes(chr(x[1]), internal_repr_codec) + b'___'
        else:
            fct = lambda x: b'___' + x[1] + b'___'

        concat.add_conf('ALT')
        concat.set_func(fct, tux, conf='ALT')

        fct2 = lambda x: len(x)
        length.set_func(fct2, tux)
        
        node_ex1.set_subnodes_basic([concat, tux, length])


        evt1 = Node('EVT1')
        evt1.set_values(value_type=SINT16_be(values=[-4]))
        evt1.set_fuzz_weight(10)

        evt2 = Node('EVT2')
        evt2.set_values(value_type=UINT16_le(mini=50, maxi=2**16-1))
        # evt2.set_values(value_type=UINT16_le())
        evt2.set_fuzz_weight(9)

        sep1 = Node('sep1', values=["+"])
        sep2 = Node('sep2', values=["*"])

        sub1 = Node('SUB1')
        sub1.set_subnodes_with_csts([
                1, ['u>', [sep1, 3], [evt1, 2], [sep1, 3]]
                ])

        sp = Node('S', values=[' '])

        ssub = Node('SSUB')
        ssub.set_subnodes_basic([sp, evt2, sp])

        sub2 = Node('SUB2')
        sub2.set_subnodes_with_csts([
                1, ['u>', [sep2, 3], [ssub, 1], [sep2, 3]]
                ])

        sep = Node('sep', values=['   -=||=-   '])
        prefix = Node('Pre', values=['[1] ', '[2] ', '[3] ', '[4] '])
        prefix.make_determinist()

        te3 = Node('EVT3')
        te3.set_values(value_type=BitField(subfield_sizes=[4,4], subfield_values=[[0x5, 0x6], [0xF, 0xC]]))
        te3.set_fuzz_weight(8)
        # te3.make_determinist()

        te4 = Node('EVT4')
        te4.set_values(value_type=BitField(subfield_sizes=[4,4], subfield_val_extremums=[[4, 8], [3, 15]]))
        te4.set_fuzz_weight(7)
        # te4.make_determinist()

        te5 = Node('EVT5')
        te5.set_values(value_type=INT_str(values=[9]))
        te5.cc.set_specific_fuzzy_values([666])
        te5.set_fuzz_weight(6)

        te6 = Node('EVT6')
        vt = BitField(subfield_limits=[2,6,8,10], subfield_values=[[4,2,1],[2,15,16,3],[2,3,0],[1]],
                      padding=0, lsb_padding=True, endian=VT.LittleEndian)
        te6.set_values(value_type=vt)
        te6.set_fuzz_weight(5)
        # te6.make_determinist()


        te7 = Node('EVT7')
        vt = BitField(subfield_sizes=[4,4,4],
                      subfield_values=[[4,2,1], None, [2,3,0]],
                      subfield_val_extremums=[None, [3, 15], None],
                      padding=0, lsb_padding=False, endian=VT.BigEndian)
        te7.set_values(value_type=vt)
        te7.set_fuzz_weight(4)
        # te7.make_determinist()

        suffix = Node('suffix', subnodes=[sep, te3, sep, te4, sep, te5, sep, te6, sep, te7])

        typed_node = Node('TVE', subnodes=[prefix, sub1, sep, sub2, suffix])


        e_pre1 = Node('pre1', value_type=UINT32_le(determinist=False))
        e_pre2 = Node('pre2', values=['  [1]  ', '  [2]  ', '  [3]  ', '  [4]  '])
        e_post = Node('post', values=[' [A]', ' [B]', ' [C]', ' [D]'])

        e_jpg = self.get_external_node(dm_name='jpg', data_id='jpg')

        e_mid = Node('mid', subnodes=[e_pre2, e_jpg, e_post])

        e_blend = Node('BLEND')
        e_blend.set_subnodes_basic([e_pre1, e_mid])

        # Simple
        
        tval1_bottom = Node('TV1_bottom')
        vt = UINT16_be(values=[1,2,3,4,5,6])

        # vt = BitField(subfield_sizes=[4,4,4],
        #               subfield_values=[[4,2,1], None, [10,12,13]],
        #               subfield_val_extremums=[None, [14, 15], None],
        #               padding=0, lsb_padding=False, endian=VT.BigEndian)

        tval1_bottom.set_values(value_type=vt)
        tval1_bottom.make_determinist()

        sep_bottom = Node('sep_bottom', values=[' .. '])
        sep_bottom_alt = Node('sep_bottom_alt', values=[' ;; '])

        tval2_bottom = Node('TV2_bottom')
        vt = UINT16_be(values=[0x42,0x43,0x44])
        tval2_bottom.set_values(value_type=vt)

        alt_tag = Node('AltTag', values=[' |AltTag| ', ' +AltTag+ '])

        bottom = Node('Bottom_NT')
        bottom.set_subnodes_with_csts([
                1, ['u>', [sep_bottom, 1], [tval1_bottom, 1], [sep_bottom, 1], [tval2_bottom, 1]]
                ])

        val1_bottom2 = Node('V1_bottom2', values=['=BOTTOM_2=', '**BOTTOM_2**', '~~BOTTOM_2~~'])
        val1_bottom2.add_conf('ALT')
        val1_bottom2.set_values(['=ALT_BOTTOM_2=', '**ALT_BOTTOM_2**', '~~ALT_BOTTOM_2~~', '__ALT_BOTTOM_2__'], conf='ALT')
        val1_bottom2.add_conf('ALT_2')
        val1_bottom2.set_values(['=2ALT2_BOTTOM_2=', '**2ALT2_BOTTOM_2**', '~~2ALT2_BOTTOM_2~~'], conf='ALT_2')
        val1_bottom2.set_fuzz_weight(2)

        bottom2 = Node('Bottom_2_NT')
        bottom2.set_subnodes_with_csts([
                5, ['u>', [sep_bottom, 1], [val1_bottom2, 1]],
                1, ['u>', [sep_bottom_alt, 1], [val1_bottom2, 2], [sep_bottom_alt, 1]]
                ])
        bottom2.add_conf('ALT')
        bottom2.set_subnodes_with_csts([
                5, ['u>', [alt_tag, 1], [val1_bottom2, 1], [alt_tag, 1]],
                1, ['u>', [alt_tag, 2], [val1_bottom2, 2], [alt_tag, 2]]
                ], conf='ALT')

        tval2_bottom3 = Node('TV2_bottom3')
        vt = UINT32_be(values=[0xF, 0x7])
        tval2_bottom3.set_values(value_type=vt)
        bottom3 = Node('Bottom_3_NT')
        bottom3.set_subnodes_with_csts([
                1, ['u>', [sep_bottom, 1], [tval2_bottom3, 1]]
                ])

        val1_middle = Node('V1_middle', values=['=MIDDLE=', '**MIDDLE**', '~~MIDDLE~~'])
        sep_middle = Node('sep_middle', values=[' :: '])
        alt_tag2 = Node('AltTag-Mid', values=[' ||AltTag-Mid|| ', ' ++AltTag-Mid++ '])

        middle = Node('Middle_NT')
        middle.set_subnodes_with_csts([
                5, ['u>', [val1_middle, 1], [sep_middle, 1], [bottom, 1]],
                3, ['u>', [val1_middle, 2], [sep_middle, 1], [bottom2, 1]],
                1, ['u>', [val1_middle, 3], [sep_middle, 1], [bottom3, 1]]
                ])
        middle.add_conf('ALT')
        middle.set_subnodes_with_csts([
                5, ['u>', [alt_tag2, 1], [val1_middle, 1], [sep_middle, 1], [bottom, 1], [alt_tag2, 1]]
                ], conf='ALT')
        # middle.make_determinist()

        val1_top = Node('V1_top', values=['=TOP=', '**TOP**', '~~TOP~~'])
        sep_top = Node('sep_top', values=[' -=|#|=- ', ' -=|@|=- '])

        prefix1 = Node('prefix1', values=[" ('_') ", " (-_-) ", " (o_o) "])
        prefix2 = Node('prefix2', values=[" |X| ", " |Y| ", " |Z| "])

        e_simple = Node('Simple')
        e_simple.set_subnodes_with_csts([
                1, ['u>', [prefix1, 1], [prefix2, 1], [sep_top, 1], [val1_top, 1], [sep_top, 1], [middle, 1]]
                ])

        ### NonTerm

        e = Node('TV2')
        vt = UINT16_be(values=[1,2,3,4,5,6])
        e.set_values(value_type=vt)
        sep3 = Node('sep3', values=[' # '])
        nt = Node('Bottom_NT')
        nt.set_subnodes_with_csts([
                1, ['u>', [e, 1], [sep3, 1], [e, 1]]
                ])

        sep = Node('sep', values=[' # '])
        sep2 = Node('sep2', values=[' -|#|- '])

        e_val1 = Node('V1', values=['A', 'B', 'C'])
        e_typedval1 = Node('TV1', value_type=UINT16_be(values=[1,2,3,4,5,6]))
        e_val2 = Node('V2', values=['X', 'Y', 'Z'])
        e_val3 = Node('V3', values=['<', '>'])

        e_val_random = Node('Rnd', values=['RANDOM'])

        e_nonterm = Node('NonTerm')
        e_nonterm.set_subnodes_with_csts([
                100, ['u>', [e_val1, 1, 6], [sep, 1], [e_typedval1, 1, 6],
                      [sep2, 1],
                      'u=+(2,3,3)', [e_val1, 1], [e_val2, 1, 3], [e_val3, 1],
                      'u>', [sep2, 1],
                      'u=..', [e_val1, 1, 6], [sep, 1], [e_typedval1, 1, 6]],
                50, ['u>', [e_val_random, 0, 1], [sep, 1], [nt, 1]],
                90, ['u>', [e_val_random, 3]]
                ])


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

                   {'name': 'val2'},

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
                             'name': 'val2'},

                            {'name': 'val21',
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
                         'contents': SINT8(values=[1,4,8])},
                        {'conf': 'alt2',
                         'contents': UINT16_be(mini=0xeeee, maxi=0xff56),
                         'determinist': True}]}
               ]},

              # block 2
              {'section_type': MH.Pick,
               'weights': (10,5),
               'contents': [
                   {'contents': String(values=['PLIP', 'PLOP'], size=4),
                    'name': ('val21', 2)},

                   {'contents': SINT16_be(values=[-1, -3, -5, 7]),
                    'name': ('val22', 2)}
               ]}
         ]}

        mh = ModelHelper(dm=self)
        test_node = mh.create_graph_from_desc(test_node_desc)

        self.register_nodes(node_ex1, tux, typed_node, e_blend, e_nonterm, e_simple,
                            val1_middle, middle, e_jpg, test_node)



data_model = Example_DataModel()
