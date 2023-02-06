# -*- coding: utf8 -*-

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
from __future__ import print_function

import sys
import unittest
import ddt

sys.path.append('.')

from framework.value_types import *

from framework.fuzzing_primitives import *
from framework.plumbing import *
from framework.data_model import *
from framework.encoders import *

from test import ignore_data_model_specifics, run_long_tests, exit_on_import_error

def setUpModule():
    global fmk, dm, results, node_nterm, node_simple, node_typed

    fmk = FmkPlumbing(exit_on_error=exit_on_import_error, debug_mode=True)
    fmk.start()
    fmk.run_project(name='tuto', dm_name=['mydf'])
    results = collections.OrderedDict()
    fmk.prj.reset_knowledge()

    ### Node graph: TVE ###

    evt1 = Node('EVT1')
    evt1.set_values(value_type=SINT16_be(values=[-4]))
    evt1.set_fuzz_weight(10)

    evt2 = Node('EVT2')
    evt2.set_values(value_type=UINT16_le(min=50, max=2**16-1))
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
    te3.set_values(value_type=BitField(subfield_sizes=[4,4], endian=VT.LittleEndian,
                                       subfield_values=[[0x5, 0x6], [0xF, 0xC]]))
    te3.set_fuzz_weight(8)

    te4 = Node('EVT4')
    te4.set_values(value_type=BitField(subfield_sizes=[4,4], endian=VT.LittleEndian,
                                       subfield_val_extremums=[[4, 8], [3, 15]]))
    te4.set_fuzz_weight(7)

    te5 = Node('EVT5')
    te5.set_values(value_type=INT_str(values=[9]))
    te5.cc.set_specific_fuzzy_values([666])
    te5.set_fuzz_weight(6)

    te6 = Node('EVT6')
    vt = BitField(subfield_limits=[2,6,8,10], subfield_values=[[2,1],[2,15,3],[2,3,0],[1]],
                  padding=0, lsb_padding=True, endian=VT.LittleEndian)
    te6.set_values(value_type=vt)
    te6.set_fuzz_weight(5)

    te7 = Node('EVT7')
    vt = BitField(subfield_sizes=[4,4,4],
                  subfield_values=[[4,2,1], None, [2,3,0]],
                  subfield_val_extremums=[None, [3, 15], None],
                  padding=0, lsb_padding=False, endian=VT.BigEndian)
    te7.set_values(value_type=vt)
    te7.set_fuzz_weight(4)

    suffix = Node('suffix', subnodes=[sep, te3, sep, te4, sep, te5, sep, te6, sep, te7])

    typed_node = Node('TVE', subnodes=[prefix, sub1, sep, sub2, suffix])

    ### Node Graph: Simple ###

    tval1_bottom = Node('TV1_bottom')
    vt = UINT16_be(values=[1,2,3,4,5,6])

    tval1_bottom.set_values(value_type=vt)
    tval1_bottom.make_determinist()

    sep_bottom = Node('sep_bottom', values=[' .. '])
    sep_bottom_alt = Node('sep_bottom_alt', values=[' ;; '])

    tval2_bottom = Node('TV2_bottom')
    vt = UINT16_be(values=[0x42,0x43,0x44])
    tval2_bottom.set_values(value_type=vt)

    alt_tag = Node('AltTag', values=[' |AltTag| ', ' +AltTag+ '])
    alt_tag_cpy = alt_tag.get_clone('AltTag_cpy')

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

    val1_bottom2_cpy = val1_bottom2.get_clone('V1_bottom2_cpy')

    bottom2 = Node('Bottom_2_NT')
    bottom2.set_subnodes_with_csts([
            5, ['u>', [sep_bottom, 1], [val1_bottom2, 1]],
            1, ['u>', [sep_bottom_alt, 1], [val1_bottom2_cpy, 2], [sep_bottom_alt, 1]]
            ])
    bottom2.add_conf('ALT')
    bottom2.set_subnodes_with_csts([
            5, ['u>', [alt_tag, 1], [val1_bottom2, 1], [alt_tag, 1]],
            1, ['u>', [alt_tag_cpy, 2], [val1_bottom2_cpy, 2], [alt_tag_cpy, 2]]
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

    val1_middle_cpy1 = val1_middle.get_clone('V1_middle_cpy1')
    val1_middle_cpy2 = val1_middle.get_clone('V1_middle_cpy2')

    middle = Node('Middle_NT')
    middle.set_subnodes_with_csts([
            5, ['u>', [val1_middle, 1], [sep_middle, 1], [bottom, 1]],
            3, ['u>', [val1_middle_cpy1, 2], [sep_middle, 1], [bottom2, 1]],
            1, ['u>', [val1_middle_cpy2, 3], [sep_middle, 1], [bottom3, 1]]
            ])
    middle.add_conf('ALT')
    middle.set_subnodes_with_csts([
            5, ['u>', [alt_tag2, 1], [val1_middle, 1], [sep_middle, 1], [bottom, 1], [alt_tag2, 1]]
            ], conf='ALT')

    val1_top = Node('V1_top', values=['=TOP=', '**TOP**', '~~TOP~~'])
    sep_top = Node('sep_top', values=[' -=|#|=- ', ' -=|@|=- '])

    prefix1 = Node('prefix1', values=[" ('_') ", " (-_-) ", " (o_o) "])
    prefix2 = Node('prefix2', values=[" |X| ", " |Y| ", " |Z| "])

    e_simple = Node('Simple')
    e_simple.set_subnodes_with_csts([
            1, ['u>', [prefix1, 1], [prefix2, 1], [sep_top, 1], [val1_top, 1], [sep_top, 1], [middle, 1]]
            ])

    ### Node Graph: NonTerm ###

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
    e_val1_cpy = e_val1.get_clone('V1_cpy')
    e_typedval1 = Node('TV1', value_type=UINT16_be(values=[1,2,3,4,5,6]))
    e_val2 = Node('V2', values=['X', 'Y', 'Z'])
    e_val3 = Node('V3', values=['<', '>'])

    e_val_random = Node('Rnd', values=['RANDOM'])
    e_val_random2 = Node('Rnd2', values=['RANDOM'])

    e_nonterm = Node('NonTerm')
    e_nonterm.set_subnodes_with_csts([
            100, ['u>', [e_val1, 1, 6], [sep, 1], [e_typedval1, 1, 6],
                  [sep2, 1],
                  'u=+(2,3,3)', [e_val1_cpy, 1], [e_val2, 1, 3], [e_val3, 1],
                  'u>', [sep2, 1],
                  'u=..', [e_val1, 1, 6], [sep, 1], [e_typedval1, 1, 6]],
            50, ['u>', [e_val_random, 0, 1], [sep, 1], [nt, 1]],
            90, ['u>', [e_val_random2, 3]]
            ])


    node_simple = e_simple
    node_simple.set_env(Env())
    node_nterm = e_nonterm
    node_nterm.set_env(Env())
    node_typed = typed_node
    node_typed.set_env(Env())

def tearDownModule():
    global fmk
    fmk.stop()


######## Tests cases begins Here ########

# Legacy --> Need to be revamped
class TestBasics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):

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
        idx.set_values(value_type=SINT16_be(min=4,max=40))

        tx.set_subnodes_basic([tx_h, idx, ku_h, ku, kv_h, kv])
        tx_cpy = tx.get_clone('TX_cpy')

        tc = Node('TC')
        tc_h = Node('h', values=['/TC'])

        ku2 = Node('KU', base_node=ku)
        kv2 = Node('KV', base_node=kv)

        ku_h2 = Node('KU_h', base_node=ku_h)
        kv_h2 = Node('KV_h', base_node=kv_h)

        tc.set_subnodes_basic([tc_h, ku_h2, ku2, kv_h2, kv2])


        mark3 = Node('MARK3', values=[' ~(X)~ '])

        tc.add_conf('ALT')
        tc.set_subnodes_basic([mark3, tc_h, ku2, kv_h2], conf='ALT')
        tc_cpy1= tc.get_clone('TC_cpy1')
        tc_cpy2= tc.get_clone('TC_cpy2')

        mark = Node('MARK', values=[' [#] '])

        idx2 = Node('IDX2', base_node=idx)
        tux = Node('TUX')
        tux_h = Node('h', values=['TUX'])

        # set 'mutable' attribute to False
        tux_h.clear_attr(NodeInternals.Mutable)
        tux_h_cpy = tux_h.get_clone('h_cpy')

        tux.set_subnodes_with_csts([
            100, ['u>', [tux_h, 1], [idx2, 1], [mark, 1],
                  'u=+(1,2)', [tc_cpy2, 2], [tx_cpy, 1, 2],
                  'u>', [mark, 1], [tx, 1], [tc_cpy1, 1],
                  'u=..', [tux_h, 1], [idx2, 1]],

            1, ['u>', [mark, 1],
                's=..', [tux_h_cpy, 1, 3], [tc, 3],
                'u>', [mark, 1], [tx, 1], [idx2, 1]],

            15, ['u>', [mark, 1],
                 'u=.', [tux_h_cpy, 1, 3], [tc, 3],
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
        tux.set_attr(MH.Attr.DEBUG, conf='ALT')

        concat = Node('CONCAT')
        length = Node('LEN')
        node_ex1 = Node('EX1')

        fct = lambda x: b' @ ' + x + b' @ '
        concat.set_func(fct, tux)

        fct = lambda x: b'___' + bytes(chr(x[1]), internal_repr_codec) + b'___'

        concat.add_conf('ALT')
        concat.set_func(fct, tux, conf='ALT')

        fct2 = lambda x: len(x)
        length.set_func(fct2, tux)

        node_ex1.set_subnodes_basic([concat, tux, length])
        node_ex1.set_env(Env())

        cls.node_tux = tux.get_clone()
        cls.node_ex1 = node_ex1


    def setUp(self):
        pass

    def test_node_alt_conf(self):

        print('\n### TEST 8: set_current_conf()')

        node_ex1 = self.node_ex1.get_clone()  # fmk.dm.get_atom('EX1')

        node_ex1.show()

        print('\n*** test 8.0:')

        res01 = True
        l = sorted(node_ex1.get_nodes_names())
        for k in l:
            print(k)
            if 'EX1' != k[0][:len('EX1')]:
                res01 = False
                break

        l2 = sorted(node_ex1.get_nodes_names(conf='ALT'))
        for k in l2:
            print(k)
            if 'EX1' != k[0][:len('EX1')]:
                res01 = False
                break

        self.assertTrue(res01)

        res02 = False
        for k in l2:
            if 'MARK2' in k[0]:
                for k in l2:
                    if 'MARK3' in k[0]:
                        res02 = True
                        break
                break

        self.assertTrue(res02)

        print('\n*** test 8.1:')

        res1 = True

        msg = node_ex1.to_bytes(conf='ALT')
        if b' ~(..)~ ' not in msg or b' ~(X)~ ' not in msg:
            res1 = False
        print(msg)
        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes(conf='ALT')
        if b' ~(..)~ ' not in msg or b' ~(X)~ ' not in msg:
            res1 = False
        print(msg)
        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes()
        if b' ~(..)~ ' in msg or b' ~(X)~ ' in msg:
            res1 = False
        print(msg)
        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes(conf='ALT')
        if b' ~(..)~ ' not in msg or b' ~(X)~ ' not in msg:
            res1 = False
        print(msg)
        node_ex1.unfreeze_all()

        self.assertTrue(res1)

        print('\n*** test 8.2:')

        print('\n***** test 8.2.0: subparts:')

        node_ex1 = self.node_ex1.get_clone()

        res2 = True

        print(node_ex1.to_bytes())

        node_ex1.set_current_conf('ALT', root_regexp=None)

        nonascii_test_str = u'\u00c2'.encode(internal_repr_codec)

        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes()
        if b' ~(..)~ ' not in msg or b' ~(X)~ ' not in msg or b'[<]' not in msg or nonascii_test_str not in msg:
            res2 = False
        print(msg)
        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes()
        if b' ~(..)~ ' not in msg or b' ~(X)~ ' not in msg or b'[<]' not in msg or nonascii_test_str not in msg:
            res2 = False
        print(msg)

        node_ex1.set_current_conf('MAIN', reverse=True, root_regexp=None)

        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes()
        if b' ~(..)~ ' in msg or b' ~(X)~ ' in msg or b'[<]' in msg or nonascii_test_str in msg:
            res2 = False
        print(msg)

        node_ex1 = self.node_ex1.get_clone()

        node_ex1.set_current_conf('ALT', root_regexp='(TC)|(TC_.*)/KV')
        node_ex1.set_current_conf('ALT', root_regexp='TUX$')

        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes()
        if b' ~(..)~ ' not in msg or b' ~(X)~ ' not in msg or b'[<]' not in msg or nonascii_test_str not in msg:
            res2 = False
        print(msg)

        self.assertTrue(res2)

        print('\n***** test 8.2.1: subparts equality:')

        val1 = node_ex1.get_first_node_by_path('TUX$').to_bytes()
        val2 = node_ex1.get_first_node_by_path('CONCAT$').to_bytes()
        print(b' @ ' + val1 + b' @ ')
        print(val2)

        res21 = b' @ ' + val1 + b' @ ' == val2

        self.assertTrue(res21)

        print('\n*** test 8.3:')

        node_ex1 = self.node_ex1.get_clone()

        res3 = True
        l = sorted(node_ex1.get_nodes_names(conf='ALT'))
        for k in l:
            print(k)
            if 'EX1' != k[0][:len('EX1')]:
                res3 = False
                break

        self.assertTrue(res3)

        print('\n*** test 8.4:')

        print(node_ex1.to_bytes())
        res4 = True
        l = sorted(node_ex1.get_nodes_names())
        for k in l:
            print(k)
            if 'EX1' != k[0][:len('EX1')]:
                res4 = False
                break

        self.assertTrue(res4)

        print('\n*** test 8.5:')

        node_ex1 = self.node_ex1.get_clone()

        res5 = True
        node_ex1.unfreeze_all()
        msg = node_ex1.get_first_node_by_path('TUX$').to_bytes(conf='ALT', recursive=False)
        if b' ~(..)~ ' not in msg or b' ~(X)~ ' in msg:
            res5 = False
        print(msg)

        node_ex1.unfreeze_all()
        msg = node_ex1.get_first_node_by_path('TUX$').to_bytes(conf='ALT', recursive=True)
        if b' ~(..)~ ' not in msg or b' ~(X)~ ' not in msg:
            res5 = False
        print(msg)

        self.assertTrue(res5)

        print('\n*** test 8.6:')

        node_ex1 = self.node_ex1.get_clone()

        crit = NodeInternalsCriteria(mandatory_attrs=[NodeInternals.Mutable],
                                     node_kinds=[NodeInternals_NonTerm])

        node_ex1.unfreeze_all()

        tux2 = self.node_tux.get_clone()
        l = tux2.get_reachable_nodes(internals_criteria=crit, owned_conf='ALT')

        for e in l:
            print(e.get_path_from(tux2))

        if len(l) == 4:
            res6 = True
        else:
            res6 = False

        self.assertTrue(res6)


    def test_node_paths(self):

        print('\n### TEST 12: get_all_path() test')

        print('\n*** test 12.1:')

        node_ex1 = self.node_ex1.get_clone()
        for i in node_ex1.iter_paths(only_paths=True):
            print(i)

        print('\n******\n')

        node_ex1.get_value()
        for i in node_ex1.iter_paths(only_paths=True):
            print(i)

        print('\n******\n')

        node_ex1.unfreeze_all()
        node_ex1.get_value()
        for i in node_ex1.iter_paths(only_paths=True):
            print(i)


        node_ex1 = self.node_ex1.get_clone()

        print('Flatten 1: ', repr(node_ex1.to_bytes()))
        print('Flatten 1: ', repr(node_ex1.to_bytes()))
        l = node_ex1.get_value()
        hk = list(node_ex1.iter_paths(only_paths=True))

        print('\n### TEST 1: cross check self.node.get_all_paths().keys() and get_nodes_names() ###')

        print('*** Hkeys from self.node.iter_paths(only_paths=True):')
        hk = sorted(hk)
        for k in hk:
            print(k)

        print('*** Hkeys from get_nodes_names():')
        l = sorted(node_ex1.get_nodes_names())
        for k in l:
            print(k)

        self.assertEqual(len(hk), len(l))

        res2 = False
        for i in range(len(hk)):
            if hk[i] != l[i][0]:
                res2 = False
                break
        else:
            res2 = True

        self.assertTrue(res2)

        print('\n### TEST 2: generate two different EX1 ###')

        node_ex1.unfreeze()
        print(node_ex1.get_value())
        val1 = node_ex1.to_bytes()

        node_ex1.unfreeze()
        print(node_ex1.get_value())
        val2 = node_ex1.to_bytes()

        self.assertTrue(val1 != val2)

        print('\n### TEST 3: generate 4 identical TUX (with last one flatten) ###')

        tux = self.node_tux.get_clone()

        val1 = tux.get_value()
        print(val1)
        val2 = tux.get_value()
        print(val2)
        val3 = tux.get_value()
        print(val3)

        print(repr(tux.to_bytes()))

        self.assertTrue(val1 == val2 and val1 == val3)

        print('\n### TEST 4: generate 2 different flatten TUX ###')

        tux.unfreeze()
        val1 = repr(tux.to_bytes())
        print(val1)
        tux.unfreeze()
        val2 = repr(tux.to_bytes())
        print(val2)

        self.assertTrue(val1 != val2)


    def test_node_search_by_path_01(self):

        print('\n### Test get_first_node_by_path() ###')

        tux2 = self.node_tux.get_clone()

        print('\n*** 1: call 3 times get_first_node_by_path()')

        print('name: %s, result: %s' % ('TUX', tux2.get_first_node_by_path('TUX').get_path_from(tux2)))
        print('name: %s, result: %s' % ('TX', tux2.get_first_node_by_path('TX').get_path_from(tux2)))
        print('name: %s, result: %s' % ('KU', tux2.get_first_node_by_path('KU', conf='ALT').get_path_from(tux2)))
        print('name: %s, result: %s' % (
        'MARK3', tux2.get_first_node_by_path('MARK3', conf='ALT').get_path_from(tux2, conf='ALT')))

        print('\n*** 2: call get_first_node_by_path() with real regexp')

        print('--> ' + tux2.get_first_node_by_path('TX.*KU').get_path_from(tux2))

        print('\n*** 3: call get_reachable_nodes()')

        node_ex1 = self.node_ex1.get_clone()
        l = node_ex1.get_reachable_nodes(path_regexp='TUX')
        for i in l:
            print(i.get_path_from(node_ex1))

        print('\n')

        node_ex1 = self.node_ex1.get_clone()
        l = node_ex1.get_reachable_nodes(path_regexp='T[XC]/KU')
        for i in l:
            print(i.get_path_from(node_ex1))

        if len(l) == 4:
            res2 = True
        else:
            res2 = False

        self.assertTrue(res2)

    def test_node_search_misc_01(self):

        print('\n### TEST 6: get_reachable_nodes()')

        node_ex1 = self.node_ex1.get_clone()
        tux2 = self.node_tux.get_clone()

        for e in sorted(tux2.get_nodes_names()):
            print(e)

        c1 = NodeInternalsCriteria(mandatory_attrs=[NodeInternals.Mutable],
                                   node_kinds=[NodeInternals_TypedValue])

        c2 = NodeInternalsCriteria(node_kinds=[NodeInternals_TypedValue])

        print('\n*** test 6.1:')

        l1 = tux2.get_reachable_nodes(internals_criteria=c1)

        l2 = tux2.get_reachable_nodes(internals_criteria=c2)

        self.assertTrue(len(l2) > len(l1))

        print('len(l1): %d, len(l2): %d' % (len(l1), len(l2)))

        print('\n*** test 6.2:')

        res62 = False
        l = tux2.get_reachable_nodes(internals_criteria=c2, conf='ALT')
        for k in l:
            print(k.get_path_from(tux2, conf='ALT'))
            if 'MARK3' in k.get_path_from(tux2, conf='ALT'):
                res62 = True
                break

        self.assertTrue(res62)

        # l = tux2.get_reachable_nodes(node_kinds=[NodeInternals_NonTerm], conf='ALT')
        # for k in l:
        #     print(k.get_path_from(tux2, conf='ALT'))

        print('\n*** test 6.3:')

        c3 = NodeInternalsCriteria(node_kinds=[NodeInternals_Func])

        l3 = node_ex1.get_reachable_nodes(internals_criteria=c3)
        print("*** %d Func Node found" % len(l3))
        print(l3)

        self.assertTrue(len(l3) == 2)


    def test_node_search_and_update(self):

        print('\n### TEST 7: get_reachable_nodes() and change_subnodes_csts()')

        node_ex1 = self.node_ex1.get_clone()
        tux2 = self.node_tux.get_clone()

        print('*** junk test:')

        tux2.get_first_node_by_path('TUX$').cc.change_subnodes_csts([('u=+', 'u>'), ('u=.', 'u>')])
        print(tux2.to_bytes())

        print('\n*** test 7.1:')

        print('> l1:')

        tux2 = self.node_tux.get_clone()
        # attr = Elt_Attributes(defaults=False)
        # attr.conform_to_nonterm_node()

        # node_kind = [NodeInternals_NonTerm]

        crit = NodeInternalsCriteria(node_kinds=[NodeInternals_NonTerm])

        l1 = tux2.get_reachable_nodes(internals_criteria=crit)

        # tux2.cc.get_subnodes_csts_copy()
        # exit()

        res1 = True
        for e in l1:
            print(e.get_path_from(tux2))
            e.cc.change_subnodes_csts([('*', 'u=.')])
            csts1, _ = e.cc.get_subnodes_csts_copy()
            print(csts1)

            e.cc.change_subnodes_csts([('*', 'u=.'), ('u=.', 'u>')])
            csts2, _ = e.cc.get_subnodes_csts_copy()
            print(csts2)

            print('\n')

            #        val = cmp(csts1, csts2)
            val = (csts1 > csts2) - (csts1 < csts2)
            if val != 0:
                res1 = False

        self.assertTrue(res1)

        print('> l2:')

        l2 = tux2.get_reachable_nodes(internals_criteria=crit)
        for e in l2:
            print(e.get_path_from(tux2))

        print('\n*** test 7.2:')

        self.assertEqual(len(l2), len(l1))

        print('\n*** test 7.3:')

        tux = self.node_tux.get_clone()
        l1 = tux.get_reachable_nodes(internals_criteria=crit, respect_order=True)
        c_l1 = []
        for e in l1:
            order, attrs = e.cc.get_subnodes_csts_copy()

            e.cc.change_subnodes_csts([('u=.', 'u>'), ('u>', 'u=.')])
            csts1, _ = e.cc.get_subnodes_csts_copy()
            print(csts1)
            print('\n')
            c_l1.append(csts1)

            e.set_subnodes_full_format(order, attrs)

        l2 = tux.get_reachable_nodes(internals_criteria=crit, respect_order=True)
        c_l2 = []
        for e in l2:
            orig = e.cc.get_subnodes_csts_copy()

            e.cc.change_subnodes_csts([('u>', 'u=.'), ('u=.', 'u>')])
            csts2, _ = e.cc.get_subnodes_csts_copy()
            print(csts2)
            print('\n')
            c_l2.append(csts2)

        self.assertEqual((c_l1 > c_l2) - (c_l1 < c_l2), 0)


    def test_node_alternate_conf(self):

        nonascii_test_str = u'\u00c2'.encode(internal_repr_codec)

        print('\n### TEST 11: test terminal Node alternate conf')

        print('\n*** test 11.1: value type Node')

        node_ex1 = self.node_ex1.get_clone()

        res1 = True
        msg = node_ex1.to_bytes(conf='ALT')
        if b'[<]' not in msg or nonascii_test_str not in msg:
            res1 = False
        print(msg)

        self.assertTrue(res1)

        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes(conf='ALT')
        if b'[<]' not in msg or nonascii_test_str not in msg:
            res1 = False
        print(msg)

        self.assertTrue(res1)

        node_ex1.unfreeze_all()
        msg = node_ex1.get_first_node_by_path('TUX$').to_bytes(conf='ALT', recursive=False)
        if b'[<]' in msg or nonascii_test_str in msg or b' ~(..)~ TUX ~(..)~ ' not in msg:
            res1 = False
        print(msg)

        self.assertTrue(res1)

        print('\n*****\n')

        crit = NodeInternalsCriteria(mandatory_attrs=[NodeInternals.Mutable],
                                     node_kinds=[NodeInternals_TypedValue])

        node_ex1.unfreeze_all()

        l = node_ex1.get_reachable_nodes(internals_criteria=crit, owned_conf='ALT')

        for e in l:
            print(e.get_path_from(node_ex1))

        self.assertEqual(len(l), 10)

        print('\n*** test 11.2: func type Node')

        node_ex1 = self.node_ex1.get_clone()

        res3 = True
        msg = node_ex1.to_bytes(conf='ALT')
        if b'___' not in msg:
            res3 = False
        print(msg)

        node_ex1.unfreeze_all()
        msg = node_ex1.to_bytes(conf='ALT')
        if b'___' not in msg:
            res3 = False
        print(msg)

        node_ex1.unfreeze_all()
        msg = node_ex1.get_first_node_by_path('TUX$').to_bytes(conf='ALT', recursive=False)
        if b'___' in msg:
            res3 = False
        print(msg)

        self.assertTrue(res3)


    def test_fuzzing_primitives(self):
        print('\n### TEST 10: test fuzzing primitives')

        print('\n*** test 10.1: fuzz_data_tree()')

        node_ex1 = self.node_ex1.get_clone()
        node_ex1.show()

        fuzz_data_tree(node_ex1)
        node_ex1.show()


    def test_node_nt_pick_section(self):
        print('\n### TEST 9: test the constraint type: =+(w1,w2,...)\n' \
              '--> can be False in really rare case')

        nonascii_test_str = u'\u00c2'.encode(internal_repr_codec)
        node_ex1 = self.node_ex1.get_clone()

        res = True
        for i in range(20):
            node_ex1.unfreeze_all()
            msg = node_ex1.get_first_node_by_path('TUX$').to_bytes(conf='ALT', recursive=True)
            if b' ~(..)~ TUX ~(..)~ ' not in msg:
                res = False
                break
                # print(msg)

        self.assertTrue(res)




class TestMisc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        pass

    def _loop_nodes(self, node, cpt=20, criteria_func=None, transform=lambda x: x,
                    result_vector=None):
        stop_loop = False
        for i in range(cpt):
            if stop_loop:
                break
            node.unfreeze()
            val = transform(node.to_bytes())
            print("[#%d] %r" % (i, val))
            # node.show()
            if result_vector and i < len(result_vector):
                print('*** Check value with result_vector[{}]'.format(i))
                self.assertEqual(val, result_vector[i])
            if node.env.exhausted_node_exists():
                for e in node.env.get_exhausted_nodes():
                    # criteria_func(e)
                    if criteria_func(e):
                        print('--> exhausted node: ', e.name)
                        stop_loop = True
                        break
                node.env.clear_all_exhausted_nodes()

        return i

    # @unittest.skip("demonstrating skipping")
    def test_Node_unfreeze_dont_change_state(self):
        '''
        unfreeze(dont_change_state)
        '''
        simple = node_simple.get_clone()

        simple.make_determinist(recursive=True)
        for i in range(15):
            simple.unfreeze()
            val1 = simple.to_bytes()
            # print(val1)
            simple.unfreeze(dont_change_state=True)
            val2 = simple.to_bytes()
            # print(val2)
            if val1 != val2:
                res1 = False
                break
        else:
            res1 = True

        self.assertTrue(res1)

    def test_TypedNode_1(self):
        evt = node_typed.get_clone()
        evt.get_value()

        print('=======[ PATHS ]========')

        for i in evt.iter_paths(only_paths=True):
            print(i)

        print('\n=======[ Typed Nodes ]========')

        c = NodeInternalsCriteria(node_kinds=[NodeInternals_TypedValue])

        vt = {}
        l = evt.get_reachable_nodes(internals_criteria=c)
        for e in l:
            print('------------')
            print('  Node.name:           ', e.name)
            print('  Node.env:            ', e.env)
            print('  Node.value_type:     ', e.cc.get_value_type())
            vt[e] = e.cc.get_value_type()
            if issubclass(vt[e].__class__, VT_Alt):
                continue

        print('')

        evt = node_typed.get_clone()
        evt.make_finite(all_conf=True, recursive=True)
        evt.make_determinist(all_conf=True, recursive=True)
        evt.show()
        orig_rnode = evt.to_bytes()
        prev_path = None
        turn_nb_list = []
        tn_consumer = TypedNodeDisruption()
        for rnode, node, orig_node_val, i in ModelWalker(evt, tn_consumer, make_determinist=True, max_steps=300):
            print('=======[ %d ]========' % i)
            print('  orig:    ', orig_rnode)
            print('  ----')
            if node != None:
                print('  fuzzed:  ', rnode.to_bytes())
                print('  ----')
                current_path = node.get_path_from(rnode)
                if current_path != prev_path:
                    turn_nb_list.append(i)
                print('  current fuzzed node:     %s' % current_path)
                prev_path = current_path
                vt = node.cc.get_value_type()
                print('  node value type (changed by disruptor):        ', vt)
                if issubclass(vt.__class__, VT_Alt):
                    print('  |- node fuzzy mode:        ', vt._fuzzy_mode)
                print('  node value type determinist:        ', vt.determinist)
                print('  node determinist:        ', node.cc.is_attr_set(NodeInternals.Determinist))
                print('  node finite:        ', node.cc.is_attr_set(NodeInternals.Finite))
                if not issubclass(vt.__class__, VT_Alt):
                    print('  node vt endian:         ', node.cc.get_value_type().endian)
                print('  node orig value:        (hexlified) {0!s:s}, {0!s:s}'.format(binascii.hexlify(orig_node_val),
                                                                                      orig_node_val))
                print('  node corrupted value:   (hexlified) {0!s:s}, {0!s:s}'.format(binascii.hexlify(node.to_bytes()),
                                                                                      node.to_bytes()))
                # node.show()
            else:
                turn_nb_list.append(i)
                print('\n--> Fuzzing terminated!\n')
                break

        print('\nTurn number when Node has changed: %r, number of test cases: %d' % (turn_nb_list, i))
        good_list = [1, 12, 22, 32, 42, 48, 54, 64, 74, 84, 95, 105, 115, 125, 135, 141, 151, 161, 171, 180, 189, 203, 218]
        msg = "If Fuzzy_<TypedValue>.values have been modified in size, the good_list should be updated.\n" \
              "If BitField are in random mode [currently put in determinist mode], the fuzzy_mode can produce more" \
              " or less value depending on drawn value when .get_value() is called (if the drawn value is" \
              " the max for instance, drawn_value+1 will not be produced)"

        self.assertTrue(turn_nb_list == good_list, msg=msg)


    def test_NonTerm_Attr_01(self):
        '''
        make_determinist()/finite() on NonTerm Node
        '''
        loop_count = 50

        crit_func = lambda x: x.name == 'NonTerm'

        print('\n -=[ determinist & finite (loop count: %d) ]=- \n' % loop_count)

        nt = node_nterm.get_clone()
        nt.make_finite(all_conf=True, recursive=True)
        nt.make_determinist(all_conf=True, recursive=True)
        nb = self._loop_nodes(nt, loop_count, criteria_func=crit_func)

        self.assertEqual(nb, 32)

        print('\n -=[ determinist & infinite (loop count: %d) ]=- \n' % loop_count)

        nt = node_nterm.get_clone()
        nt.make_infinite(all_conf=True, recursive=True)
        nt.make_determinist(all_conf=True, recursive=True)
        self._loop_nodes(nt, loop_count, criteria_func=crit_func)

        print('\n -=[ random & infinite (loop count: %d) ]=- \n' % loop_count)

        nt = node_nterm.get_clone()
        # nt.make_infinite(all_conf=True, recursive=True)
        nt.make_random(all_conf=True, recursive=True)
        self._loop_nodes(nt, loop_count, criteria_func=crit_func)

        print('\n -=[ random & finite (loop count: %d) ]=- \n' % loop_count)

        nt = node_nterm.get_clone()
        nt.make_finite(all_conf=True, recursive=True)
        nt.make_random(all_conf=True, recursive=True)
        nb = self._loop_nodes(nt, loop_count, criteria_func=crit_func)

        self.assertAlmostEqual(nb, 3)

    def test_BitField_Attr_01(self):
        '''
        make_determinist()/finite() on BitField Node
        TODO: need more assertion
        '''

        loop_count = 80

        print('\n -=[ random & infinite (loop count: %d) ]=- \n' % loop_count)

        t = BitField(subfield_limits=[2, 6, 10, 12],
                     subfield_values=[[2, 1], [2, 15, 3], None, [1]],
                     subfield_val_extremums=[None, None, [3, 11], None],
                     padding=0, lsb_padding=True, endian=VT.LittleEndian,
                     determinist=True, show_padding=True)
        node = Node('BF', value_type=t)
        node.set_env(Env())
        node.make_random(all_conf=True, recursive=True)
        self._loop_nodes(node, loop_count, criteria_func=lambda x: True, transform=binascii.b2a_hex)

        print('\n -=[ determinist & infinite (loop count: %d) ]=- \n' % loop_count)

        node_copy = Node('BF_copy', base_node=node, ignore_frozen_state=True)
        node_copy.set_env(Env())
        node_copy.make_determinist(all_conf=True, recursive=True)
        self._loop_nodes(node_copy, loop_count, criteria_func=lambda x: True, transform=binascii.b2a_hex,
                         result_vector=[b'a04c', b'904c', b'e04f'])

        print('\n -=[ determinist & finite (loop count: %d) ]=- \n' % loop_count)

        node_copy2 = Node('BF_copy2', base_node=node, ignore_frozen_state=True)
        node_copy2.set_env(Env())
        node_copy2.make_determinist(all_conf=True, recursive=True)
        node_copy2.make_finite(all_conf=True, recursive=True)
        it_df = self._loop_nodes(node_copy2, loop_count, criteria_func=lambda x: True, transform=binascii.b2a_hex,
                                 result_vector=[b'a04c', b'904c', b'e04f'])

        print('\n -=[ random & finite (loop count: %d) ]=- \n' % loop_count)

        node_copy3 = Node('BF_copy3', base_node=node, ignore_frozen_state=True)
        node_copy3.set_env(Env())
        node_copy3.make_random(all_conf=True, recursive=True)
        node_copy3.make_finite(all_conf=True, recursive=True)
        it_rf = self._loop_nodes(node_copy3, loop_count, criteria_func=lambda x: True, transform=binascii.b2a_hex)

        self.assertEqual(it_df, it_rf)
        self.assertEqual(it_df, 12)

    def test_BitField_Node(self):

        loop_count = 20
        e_bf = Node('BF')
        vt = BitField(subfield_sizes=[4, 4, 4],
                      subfield_values=[[4, 2, 1], None, [10, 13]],
                      subfield_val_extremums=[None, [14, 15], None],
                      padding=0, lsb_padding=False, endian=VT.BigEndian)
        e_bf.set_values(value_type=vt)
        e_bf.set_env(Env())
        e_bf.make_determinist(all_conf=True, recursive=True)
        e_bf.make_finite(all_conf=True, recursive=True)
        self._loop_nodes(e_bf, loop_count, criteria_func=lambda x: True, transform=binascii.b2a_hex)

        print('\n***\n')

        e_bf.cc.value_type.switch_mode()
        self._loop_nodes(e_bf, loop_count, criteria_func=lambda x: True, transform=binascii.b2a_hex)

        print('\n***\n')

        e_bf.cc.value_type.switch_mode()
        self._loop_nodes(e_bf, loop_count, criteria_func=lambda x: True, transform=binascii.b2a_hex)

        print('\n***')
        print('We change the current BitField value:')
        e_bf.unfreeze_all()
        print(binascii.b2a_hex(e_bf.get_value()))
        e_bf.unfreeze_all()
        print(binascii.b2a_hex(e_bf.get_value()), '\n')

        e_bf.cc.value_type.switch_mode()
        self._loop_nodes(e_bf, loop_count, criteria_func=lambda x: True, transform=binascii.b2a_hex)

        print('\n***')
        print('Random & finite: (should result in only 1 possible values)')

        vt = BitField(subfield_sizes=[4, 4], subfield_values=[[0x3], [0xF]])
        e = Node('bf_test', value_type=vt)
        e.set_env(Env())
        e.make_finite()
        e.make_random()
        count = self._loop_nodes(e, loop_count, criteria_func=lambda x: True)

        self.assertEqual(count, 1)

    def test_BitField_basic_features(self):

        print('\n***** [ BitField ] *****\n')

        i = 0
        ok = True
        t = BitField(subfield_limits=[2, 6, 8, 10], subfield_values=[[1], [1], [1], [1]],
                     padding=0, lsb_padding=False, endian=VT.LittleEndian)
        val = binascii.b2a_hex(t.get_value())
        print(t.pretty_print(), t.drawn_val)
        print('*** [%d] ' % i, val)
        i += 1
        self.assertEqual(val, b'4501')

        t = BitField(subfield_limits=[2, 6, 8, 10], subfield_values=[[1], [1], [1], [1]],
                     padding=0, lsb_padding=True, endian=VT.BigEndian)
        val = binascii.b2a_hex(t.get_value())
        print('*** [%d] ' % i, val)
        i += 1
        self.assertEqual(val, b'5140')

        t = BitField(subfield_limits=[2, 6, 8, 10], subfield_values=[[1], [1], [1], [1]],
                     padding=1, lsb_padding=True, endian=VT.BigEndian)
        val = binascii.b2a_hex(t.get_value())
        print('*** [%d] ' % i, val)
        i += 1
        self.assertEqual(val, b'517f')

        t = BitField(subfield_limits=[2, 6, 8, 10], subfield_values=[[1], [1], [1], [1]],
                     padding=0, lsb_padding=False, endian=VT.BigEndian)
        val = binascii.b2a_hex(t.get_value())
        print('*** [%d] ' % i, val)
        i += 1
        self.assertEqual(val, b'0145')

        t = BitField(subfield_limits=[2, 6, 8, 10], subfield_values=[[1], [1], [1], [1]],
                     padding=1, lsb_padding=False, endian=VT.BigEndian)
        val = binascii.b2a_hex(t.get_value())
        print('*** [%d] ' % i, val)
        i += 1
        self.assertEqual(val, b'fd45')

        t = BitField(subfield_sizes=[2, 4, 2, 2], subfield_values=[[1], [1], [1], [1]],
                     padding=1, lsb_padding=False, endian=VT.BigEndian)
        val = binascii.b2a_hex(t.get_value())
        print('*** [%d] ' % i, val)
        i += 1
        self.assertEqual(val, b'fd45')

        print('\n******** subfield_values\n')

        # Note that 4 in subfield 1 and 16 in subfield 2 are ignored
        # --> 6 different values are output before looping
        t = BitField(subfield_limits=[2, 6, 8, 10], subfield_values=[[2, 1], [2, 15, 3], [2, 3, 0], [1]],
                     padding=0, lsb_padding=True, endian=VT.LittleEndian, determinist=True)
        for i in range(30):
            val = binascii.b2a_hex(t.get_value())
            print('*** [%d] ' % i, val)
            print(t.pretty_print(), ' --> ', t.get_current_raw_val())

        print('\n********\n')

        val = collections.OrderedDict()
        t.switch_mode()
        print(t.subfield_vals)
        for i in range(30):
            val[i] = binascii.b2a_hex(t.get_value())
            print(t.pretty_print(), ' --> ', t.get_current_raw_val())
            print('*** [%d] ' % i, val[i])

        print(list(val.values())[:15])
        self.assertEqual(list(val.values())[:15],
                         [b'c042', b'0042', b'4042', b'804f', b'8040', b'8043', b'8041', b'8044',
                          b'804e', b'8072', b'8052', b'80c2', b'8002', b'8082', b'c042'])

        print('\n********\n')

        t.switch_mode()
        for i in range(30):
            val = binascii.b2a_hex(t.get_value())
            print('*** [%d] ' % i, val)

        print('\n******** subfield_val_extremums\n')

        # --> 14 different values are output before looping
        t = BitField(subfield_limits=[2, 6, 8, 10], subfield_val_extremums=[[1, 2], [4, 12], [0, 3], [2, 3]],
                     padding=0, lsb_padding=True, endian=VT.LittleEndian, determinist=True)
        for i in range(30):
            val = binascii.b2a_hex(t.get_value())
            print('*** [%d] ' % i, val)

        print('\n********\n')

        t.switch_mode()
        for i in range(30):
            val = binascii.b2a_hex(t.get_value())
            print('*** [%d] ' % i, val)

        print('\n********\n')

        t.switch_mode()
        for i in range(30):
            val = binascii.b2a_hex(t.get_value())
            print('*** [%d] ' % i, val)

        print('\n******** rewind() tests \n')

        t = BitField(subfield_limits=[2, 6, 8, 10],
                     subfield_val_extremums=[[1, 2], [4, 12], [0, 3], None],
                     subfield_values=[None, None, None, [3]],
                     padding=0, lsb_padding=False, endian=VT.BigEndian, determinist=True)

        val = collections.OrderedDict()
        for i in range(30):
            val[i] = binascii.b2a_hex(t.get_value())
            print('*** [%d] ' % i, val[i])
            print(t.pretty_print(), ' --> ', t.get_current_raw_val())
            if t.is_exhausted():
                break

        print(list(val.values())[:15])
        self.assertEqual(list(val.values())[:15],
                         [b'0311', b'0312', b'0315', b'0319', b'031d', b'0321', b'0325', b'0329',
                          b'032d', b'0331', b'0351', b'0391', b'03d1'])

        print('\n********\n')
        t.reset_state()

        val1 = t.get_value()
        val2 = t.get_value()
        print(binascii.b2a_hex(val1))
        print(binascii.b2a_hex(val2))
        print('--> rewind')
        t.rewind()
        val3 = t.get_value()
        print(binascii.b2a_hex(val3))
        self.assertEqual(val2, val3)
        print('--> rewind')
        t.rewind()
        val4 = t.get_value()
        val5 = t.get_value()
        print(binascii.b2a_hex(val4))
        print(binascii.b2a_hex(val5))
        self.assertEqual(val2, val4)
        self.assertEqual(val5, b'\x03\x15')

        print('\n********\n')

        t.reset_state()

        for i in range(30):
            val = binascii.b2a_hex(t.get_value())
            print('*** [%d] ' % i, val)
            print(t.pretty_print(), ' --> ', t.get_current_raw_val())
            if t.is_exhausted():
                break

        print('\n********\n')
        print('--> rewind when exhausted')
        t.rewind()
        t.rewind()
        t.rewind()
        t.rewind()
        val1 = t.get_value()
        val2 = t.get_value()
        val3 = t.get_value()
        val4 = t.get_value()
        print(binascii.b2a_hex(val1))
        print(binascii.b2a_hex(val2))
        print(binascii.b2a_hex(val3))
        print(binascii.b2a_hex(val4))

        self.assertEqual([val1, val2, val3, val4],
                         [b'\x03\x31', b'\x03\x51', b'\x03\x91', b'\x03\xd1'])

        print('\n******** Fuzzy mode\n')
        t.reset_state()
        t.switch_mode()

        val1 = t.get_value()
        val2 = t.get_value()
        print(binascii.b2a_hex(val1))
        print(binascii.b2a_hex(val2))
        print('--> rewind')
        t.rewind()
        val3 = t.get_value()
        print(binascii.b2a_hex(val3))
        self.assertEqual(val2, val3)
        print('--> rewind')
        t.rewind()
        val4 = t.get_value()
        val5 = t.get_value()
        print(binascii.b2a_hex(val4))
        print(binascii.b2a_hex(val5))
        self.assertEqual(val2, val4)

        print('\n********\n')

        t.reset_state()
        t.switch_mode()

        for i in range(30):
            val = binascii.b2a_hex(t.get_value())
            print('*** [%d] ' % i, val)
            if t.is_exhausted():
                break

        print('\n********\n')

        print('--> rewind when exhausted')
        t.rewind()
        t.rewind()
        t.rewind()
        t.rewind()
        val1 = t.get_value()
        val2 = t.get_value()
        val3 = t.get_value()
        val4 = t.get_value()
        print(binascii.b2a_hex(val1))
        print(binascii.b2a_hex(val2))
        print(binascii.b2a_hex(val3))
        print(binascii.b2a_hex(val4))

        self.assertEqual([val1, val2, val3, val4],
                         [b'\x03\xd1', b'\x03\x51', b'\x00\x11', b'\x02\x11'])

    def test_BitField_various_features(self):

        bf = Node('BF')
        vt1 = BitField(subfield_sizes=[3, 5, 7],
                       subfield_values=[[2, 1], None, [10, 120]],
                       subfield_val_extremums=[None, [6, 15], None],
                       padding=0, lsb_padding=True, endian=VT.BigEndian)
        bf.set_values(value_type=vt1)
        bf.make_determinist(all_conf=True, recursive=True)
        bf.set_env(Env())

        print('\n -=[ .extend_right() method ]=- \n')
        print('*** before extension')

        bf.show()
        # print(bf.get_raw_value())
        # bf.unfreeze()
        # bf.show()

        vt2 = BitField(subfield_sizes=[4, 3, 4, 4, 2],
                       subfield_values=[None, [3, 5], [15], [14], [2]],
                       subfield_val_extremums=[[8, 12], None, None, None, None],
                       padding=0, lsb_padding=False, endian=VT.BigEndian)

        print('*** after extension')

        bf.reset_state()
        bf.value_type.extend_right(vt2)
        bf.show()

        extended_val = 3151759922
        extended_bytes = b'\xbb\xdc\n2'

        vt = bf.value_type
        self.assertEqual(vt.subfield_limits, [3, 8, 15, 19, 22, 26, 30, 32])
        self.assertEqual(vt.get_current_raw_val(), extended_val)
        self.assertEqual(vt.get_current_value(), extended_bytes)

        print('\n -=[ .extend_left() method ]=- \n')

        # vt3 == vt2
        vt3 = BitField(subfield_sizes=[4, 3, 4, 4, 2],
                       subfield_values=[None, [3, 5], [15], [14], [2]],
                       subfield_val_extremums=[[8, 12], None, None, None, None],
                       padding=0, lsb_padding=False, endian=VT.BigEndian)
        bf2 = Node('BF', vt=vt3)
        bf2.make_determinist(all_conf=True, recursive=True)
        bf2.set_env(Env())

        print('*** before extension')
        bf2.show()

        # vt4 == vt1
        vt4 = BitField(subfield_sizes=[3, 5, 7],
                       subfield_values=[[2, 1], None, [10, 120]],
                       subfield_val_extremums=[None, [6, 15], None],
                       padding=0, lsb_padding=True, endian=VT.BigEndian)

        print('*** after extension')

        bf2.reset_state()
        bf2.value_type.extend_left(vt4)
        bf2.show()

        self.assertEqual(bf2.value_type.subfield_limits, [3, 8, 15, 19, 22, 26, 30, 32])
        self.assertEqual(bf2.value_type.get_current_raw_val(), extended_val)
        self.assertEqual(bf2.value_type.get_current_value(), extended_bytes)

        print('\n -=[ .set_subfield() .get_subfield() methods ]=- \n')

        vt.set_subfield(idx=3, val=5)
        vt.set_subfield(idx=0, val=3)
        self.assertEqual(vt.get_subfield(idx=3), 5)
        self.assertEqual(vt.get_subfield(idx=0), 3)

        bf.unfreeze()
        bf.show()

        self.assertEqual(bf.value_type.get_subfield(idx=3), 5)
        self.assertEqual(bf.value_type.get_subfield(idx=0), 3)

    def test_BitField_absorb(self):

        vt = BitField(subfield_sizes=[4, 4, 4],
                      subfield_values=[[3, 2, 0xe, 1], None, [10, 13, 3]],
                      subfield_val_extremums=[None, [14, 15], None],
                      padding=1, endian=VT.BigEndian, lsb_padding=True)
        bfield_1 = Node('bfield_1', value_type=vt)
        bfield_1.set_env(Env())

        vt = BitField(subfield_sizes=[4, 4, 4],
                      subfield_values=[[3, 2, 0xe, 1], None, [10, 13, 3]],
                      subfield_val_extremums=[None, [14, 15], None],
                      padding=0, endian=VT.BigEndian, lsb_padding=True)
        bfield_2 = Node('bfield_2', value_type=vt)
        bfield_2.set_env(Env())

        vt = BitField(subfield_sizes=[4, 4, 4],
                      subfield_values=[[3, 2, 0xe, 1], None, [10, 13, 3]],
                      subfield_val_extremums=[None, [14, 15], None],
                      padding=1, endian=VT.BigEndian, lsb_padding=False)
        bfield_3 = Node('bfield_3', value_type=vt)
        bfield_3.set_env(Env())

        vt = BitField(subfield_sizes=[4, 4, 4],
                      subfield_values=[[3, 2, 0xe, 1], None, [10, 13, 3]],
                      subfield_val_extremums=[None, [14, 15], None],
                      padding=0, endian=VT.BigEndian, lsb_padding=False)
        bfield_4 = Node('bfield_4', value_type=vt)
        bfield_4.set_env(Env())

        # '?\xef' (\x3f\xe0) + padding 0b1111
        msg = struct.pack('>H', 0x3fe0 + 0b1111)
        status, off, size, name = bfield_1.absorb(msg, constraints=AbsFullCsts())

        print('\n ---[message to absorb]---')
        print(repr(msg))
        bfield_1.show()
        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(size, len(msg))

        msg = struct.pack('>H', 0x3fe0)
        status, off, size, name = bfield_2.absorb(msg, constraints=AbsFullCsts())

        print('\n ---[message to absorb]---')
        print(repr(msg))
        bfield_2.show()
        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(size, len(msg))

        msg = struct.pack('>H', 0xf3fe)
        status, off, size, name = bfield_3.absorb(msg, constraints=AbsFullCsts())

        print('\n ---[message to absorb]---')
        print(repr(msg))
        bfield_3.show()
        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(size, len(msg))

        msg = struct.pack('>H', 0x3fe)
        status, off, size, name = bfield_4.absorb(msg, constraints=AbsFullCsts())

        print('\n ---[message to absorb]---')
        print(repr(msg))
        bfield_4.show()
        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(size, len(msg))


class TestModelWalker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        pass

    def test_NodeConsumerStub_1(self):
        nt = node_simple.get_clone()
        default_consumer = NodeConsumerStub()
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(nt, default_consumer, make_determinist=True,
                                                                    max_steps=200):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 49)

    def test_NodeConsumerStub_2(self):
        nt = node_simple.get_clone()
        default_consumer = NodeConsumerStub(max_runs_per_node=-1, min_runs_per_node=2)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(nt, default_consumer, make_determinist=True,
                                                                    max_steps=200):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 35)

    def test_BasicVisitor(self):
        nt = node_simple.get_clone()
        default_consumer = BasicVisitor(respect_order=True, consider_side_effects_on_sibbling=False)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(nt, default_consumer, make_determinist=True,
                                                                    max_steps=200):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 55)

        print('***')
        nt = node_simple.get_clone()
        default_consumer = BasicVisitor(respect_order=False, consider_side_effects_on_sibbling=False)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(nt, default_consumer, make_determinist=True,
                                                                    max_steps=200):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 37)

    def test_NonTermVisitor(self):
        print('***')
        idx = 0
        simple = node_simple.get_clone()
        nonterm_consumer = NonTermVisitor(respect_order=True, consider_side_effects_on_sibbling=False)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(simple, nonterm_consumer, make_determinist=True,
                                                                    max_steps=20):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 4)

        print('***')
        idx = 0
        simple = node_simple.get_clone()
        nonterm_consumer = NonTermVisitor(respect_order=False, consider_side_effects_on_sibbling=False)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(simple, nonterm_consumer, make_determinist=True,
                                                                    max_steps=20):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 4)

        print('***')

        results = [
            b' [!] ++++++++++ [!] ::AAA::AAA::>:: [!] ? [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::AAA::AAA::>:: [!] ? [!] ',
            b' [!] ++++++++++ [!] ::>:: [!] ? [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::>:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::AAA::AAA::>:: [!] ',
            b' [!] >>>>>>>>>> [!] ::>:: [!] ',
        ]

        idx = 0
        data = fmk.dm.get_external_atom(dm_name='mydf', data_id='shape')
        nonterm_consumer = NonTermVisitor(respect_order=True, consider_side_effects_on_sibbling=False)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(data, nonterm_consumer, make_determinist=True,
                                                                    max_steps=50):
            print(colorize('[%d] ' % idx + rnode.to_ascii(), rgb=Color.INFO))
            # print(colorize(repr(rnode.to_bytes()), rgb=Color.INFO))
            self.assertEqual(rnode.to_bytes(), results[idx-1])
        self.assertEqual(idx, 6)

        print('***')
        idx = 0
        data = fmk.dm.get_external_atom(dm_name='mydf', data_id='shape')
        nonterm_consumer = NonTermVisitor(respect_order=False, consider_side_effects_on_sibbling=False)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(data, nonterm_consumer, make_determinist=True,
                                                                    max_steps=50):
            print(colorize('[%d] ' % idx + rnode.to_ascii(), rgb=Color.INFO))
        self.assertEqual(idx, 6)

        print('***')

    def test_basics(self):
        # data = fmk.dm.get_external_atom(dm_name='mydf', data_id='shape')
        shape_desc = \
            {'name': 'shape',
             'custo_set': MH.Custo.NTerm.FrozenCopy,
             'custo_clear': MH.Custo.NTerm.MutableClone,
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
                            'custo_set': MH.Custo.NTerm.FrozenCopy,
                            'custo_clear': MH.Custo.NTerm.MutableClone,
                            'separator': {'contents': {'name': 'sep2',
                                                       'contents': String(values=['::'])}},
                            'shape_type': MH.Random,  # ignored in determnist mode
                            'contents': [
                                {'contents': Filename(values=['AAA']),
                                 'qty': (0, 4),
                                 'name': 'str'},
                                {'contents': UINT8(values=[0x3E]),  # chr(0x3E) == '>'
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

        mb = NodeBuilder(delayed_jobs=True)
        data = mb.create_graph_from_desc(shape_desc)
        bv_data = data.get_clone()
        nt_data = data.get_clone()

        raw_vals = [
            b' [!] ++++++++++ [!] ::AAA::AAA::?:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::=:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::\xff:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::\x00:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::\x01:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::\x80:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::\x7f:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::AAA::AAA::?:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::AAA::AAA::=:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::AAA::AAA::\xff:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::AAA::AAA::\x00:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::AAA::AAA::\x01:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::AAA::AAA::\x80:: [!] ',
            b' [!] ++++++++++ [!] ::AAA::AAA::AAA::AAA::\x7f:: [!] ',
            b' [!] ++++++++++ [!] ::?:: [!] ',
            b' [!] ++++++++++ [!] ::=:: [!] ',
            b' [!] ++++++++++ [!] ::\xff:: [!] ',
            b' [!] ++++++++++ [!] ::\x00:: [!] ',
            b' [!] ++++++++++ [!] ::\x01:: [!] ',
            b' [!] ++++++++++ [!] ::\x80:: [!] ',
            b' [!] ++++++++++ [!] ::\x7f:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::?:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::=:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::\xff:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::\x00:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::\x01:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::\x80:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::\x7f:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::AAA::AAA::?:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::AAA::AAA::=:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::AAA::AAA::\xff:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::AAA::AAA::\x00:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::AAA::AAA::\x01:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::AAA::AAA::\x80:: [!] ',
            b' [!] >>>>>>>>>> [!] ::AAA::AAA::AAA::AAA::\x7f:: [!] ',
            b' [!] >>>>>>>>>> [!] ::?:: [!] ',
            b' [!] >>>>>>>>>> [!] ::=:: [!] ',
            b' [!] >>>>>>>>>> [!] ::\xff:: [!] ',
            b' [!] >>>>>>>>>> [!] ::\x00:: [!] ',
            b' [!] >>>>>>>>>> [!] ::\x01:: [!] ',
            b' [!] >>>>>>>>>> [!] ::\x80:: [!] ',
            b' [!] >>>>>>>>>> [!] ::\x7f:: [!] ',
        ]

        # Note that the result of the TC that performs a random bitflip could collide with the one
        # playing on letter case, resulting in less test cases (at worst 4 less in total)
        # In this case assert won't be validated

        tn_consumer = TypedNodeDisruption(respect_order=True, ignore_separator=True)
        ic = NodeInternalsCriteria(mandatory_attrs=[NodeInternals.Mutable],
                                   negative_attrs=[NodeInternals.Separator],
                                   node_kinds=[NodeInternals_TypedValue],
                                   negative_node_subkinds=[String, Filename])
        tn_consumer.set_node_interest(internals_criteria=ic)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(data, tn_consumer, make_determinist=True,
                                                                    max_steps=200):
            val = rnode.to_bytes()
            # print(colorize('{!r}'.format(val), rgb=Color.INFO))
            print(colorize('[{:d}] {!r}'.format(idx, val), rgb=Color.INFO))
            self.assertEqual(val, raw_vals[idx - 1])

        self.assertEqual(idx, 42)

        print('***')
        idx = 0
        bv_consumer = BasicVisitor(respect_order=True, consider_side_effects_on_sibbling=False)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(bv_data, bv_consumer,
                                                                    make_determinist=True,
                                                                    max_steps=100):
            print(colorize('[%d] ' % idx + rnode.to_ascii(), rgb=Color.INFO))
        self.assertEqual(idx, 6)

        print('***')
        idx = 0
        nt_consumer = NonTermVisitor(respect_order=True, consider_side_effects_on_sibbling=False)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(nt_data, nt_consumer,
                                                                    make_determinist=True,
                                                                    max_steps=100):
            print(colorize('[%d] ' % idx + rnode.to_ascii(), rgb=Color.INFO))
        self.assertEqual(idx, 6)  # shall be equal to the previous test


    def test_TypedNodeDisruption_1(self):
        nt = node_simple.get_clone()
        tn_consumer = TypedNodeDisruption()
        ic = NodeInternalsCriteria(negative_node_subkinds=[String])
        tn_consumer.set_node_interest(internals_criteria=ic)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(nt, tn_consumer, make_determinist=True,
                                                                    max_steps=300):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 21)

    def test_TypedNodeDisruption_2(self):
        nt = node_simple.get_clone()
        tn_consumer = TypedNodeDisruption(max_runs_per_node=3, min_runs_per_node=3)
        ic = NodeInternalsCriteria(negative_node_subkinds=[String])
        tn_consumer.set_node_interest(internals_criteria=ic)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(nt, tn_consumer, make_determinist=True,
                                                                    max_steps=100):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 9)

    def test_TypedNodeDisruption_3(self):
        '''
        Test case similar to test_TermNodeDisruption_1() but with more
        powerfull TypedNodeDisruption.
        '''
        nt = node_simple.get_clone()
        tn_consumer = TypedNodeDisruption(max_runs_per_node=1)
        # ic = NodeInternalsCriteria(negative_node_subkinds=[String])
        # tn_consumer.set_node_interest(internals_criteria=ic)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(nt, tn_consumer, make_determinist=True,
                                                                    max_steps=-1):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertAlmostEqual(idx, 346, delta=2)
        # almostequal because collision in String test cases can lead to less test cases
        # (related to random bitflip test case that could collide with case_sensitive test case)

    def test_TypedNodeDisruption_BitfieldCollapse(self):
        '''
        Test case similar to test_TermNodeDisruption_1() but with more
        powerfull TypedNodeDisruption.
        '''
        data = fmk.dm.get_external_atom(dm_name='sms', data_id='smscmd')
        data.freeze()
        data.show()

        print('\norig value: ' + repr(data['smscmd/TP-DCS'][0].to_bytes()))
        # self.assertEqual(data['smscmd/TP-DCS'][0].to_bytes(), b'\xF6')

        corrupt_table = {
            1: b'\x06',
            2: b'\xE6',
            3: b'\x16',
            4: b'\xF7',
            5: b'\xF4',
            6: b'\xF5',
            7: b'\xF2'
        }

        tn_consumer = TypedNodeDisruption(max_runs_per_node=1)
        tn_consumer.set_node_interest(path_regexp='smscmd/TP-DCS')
        # ic = NodeInternalsCriteria(negative_node_subkinds=[String])
        # tn_consumer.set_node_interest(internals_criteria=ic)
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(data, tn_consumer,
                                                                    make_determinist=True, max_steps=7):
            print(colorize('\n[%d] ' % idx + repr(rnode['smscmd/TP-DCS$'][0].to_bytes()), rgb=Color.INFO))
            print('node name: ' + consumed_node.name)
            print('original value:  {!s} ({!s})'.format(binascii.b2a_hex(orig_node_val),
                                                        bin(struct.unpack('B', orig_node_val)[0])))
            print('corrupted value: {!s} ({!s})'.format(binascii.b2a_hex(consumed_node.to_bytes()),
                                                        bin(struct.unpack('B', consumed_node.to_bytes())[0])))
            print('result: {!s} ({!s})'.format(binascii.b2a_hex(rnode['smscmd/TP-DCS$'][0].to_bytes()),
                                               bin(struct.unpack('B', rnode['smscmd/TP-DCS$'][0].to_bytes())[0])))
            rnode['smscmd/TP-DCS$'][0].show()
            self.assertEqual(rnode['smscmd/TP-DCS'][0].to_bytes(), corrupt_table[idx])

    def test_AltConfConsumer_1(self):
        simple = node_simple.get_clone()
        consumer = AltConfConsumer(max_runs_per_node=-1, min_runs_per_node=-1)
        consumer.set_node_interest(owned_confs=['ALT'])

        for rnode, consumed_node, orig_node_val, idx in ModelWalker(simple, consumer, make_determinist=True,
                                                                    max_steps=100):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 15)

    def test_AltConfConsumer_2(self):
        simple = node_simple.get_clone()
        consumer = AltConfConsumer(max_runs_per_node=2, min_runs_per_node=1)
        consumer.set_node_interest(owned_confs=['ALT'])

        for rnode, consumed_node, orig_node_val, idx in ModelWalker(simple, consumer, make_determinist=True,
                                                                    max_steps=100):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 8)

    def test_AltConfConsumer_3(self):
        simple = node_simple.get_clone()
        consumer = AltConfConsumer(max_runs_per_node=-1, min_runs_per_node=-1)
        consumer.set_node_interest(owned_confs=['ALT', 'ALT_2'])

        for rnode, consumed_node, orig_node_val, idx in ModelWalker(simple, consumer, make_determinist=True,
                                                                    max_steps=100):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 24)

    def test_AltConfConsumer_4(self):
        simple = node_simple.get_clone()
        consumer = AltConfConsumer(max_runs_per_node=-1, min_runs_per_node=-1)
        consumer.set_node_interest(owned_confs=['ALT_2', 'ALT'])

        for rnode, consumed_node, orig_node_val, idx in ModelWalker(simple, consumer, make_determinist=True,
                                                                    max_steps=50):
            print(colorize('[%d] ' % idx + repr(rnode.to_bytes()), rgb=Color.INFO))
        self.assertEqual(idx, 24)

    def test_JPG(self):
        dm = fmk.get_data_model_by_name('jpg')
        dm.build_data_model()

        nt = dm.get_atom('jpg')
        tn_consumer = TypedNodeDisruption()

        walker = iter(ModelWalker(nt, tn_consumer, make_determinist=True))
        while True:
            try:
                rnode, consumed_node, orig_node_val, idx = next(walker)
                # rnode.get_value()
            except StopIteration:
                break

        print(colorize('number of imgs: %d' % idx, rgb=Color.INFO))

        self.assertEqual(idx, 112)

    def test_USB(self):
        dm_usb = fmk.get_data_model_by_name('usb')
        dm_usb.build_data_model()

        data = dm_usb.get_atom('CONF')
        consumer = TypedNodeDisruption()
        consumer.need_reset_when_structure_change = True
        for rnode, consumed_node, orig_node_val, idx in ModelWalker(data, consumer, make_determinist=True,
                                                                    max_steps=600):
            pass
            # print(colorize('[%d] '%idx + repr(rnode.to_bytes()), rgb=Color.INFO))

        print(colorize('number of confs: %d' % idx, rgb=Color.INFO))

        self.assertIn(idx, [479])


@ddt.ddt
class TestNodeFeatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        pass

    def test_djobs(self):
        tag_desc = \
        {'name': 'tag',
         'contents': [
             {'name': 'type',
              'contents': UINT16_be(values=[0x0101,0x0102,0x0103,0x0104, 0]),
              'absorb_csts': AbsFullCsts()},
             {'name': 'len',
              'contents': UINT16_be(),
              'absorb_csts': AbsNoCsts()},
             {'name': 'value',
              'contents': [
                  {'name': 'v000', # Final Tag (optional)
                   'exists_if': (IntCondition(0), 'type'),
                   'sync_enc_size_with': 'len',
                   'contents': String(size=0)},
                  {'name': 'v101', # Service Name
                   'exists_if': (IntCondition(0x0101), 'type'),
                   'sync_enc_size_with': 'len',
                   'contents': String(values=[u'my \u00fcber service'], codec='utf8'),
                   },
                  {'name': 'v102', # AC name
                   'exists_if': (IntCondition(0x0102), 'type'),
                   'sync_enc_size_with': 'len',
                   'contents': String(values=['AC name'], codec='utf8'),
                   },
                  {'name': 'v103', # Host Identifier
                   'exists_if': (IntCondition(0x0103), 'type'),
                   'sync_enc_size_with': 'len',
                   'contents': String(values=['Host Identifier']),
                   },
                  {'name': 'v104', # Cookie
                   'exists_if': (IntCondition(0x0104), 'type'),
                   'sync_enc_size_with': 'len',
                   'contents': String(values=['Cookie'], min_sz=0, max_sz=1000),
                   },
              ]}
        ]}

        mb = NodeBuilder(delayed_jobs=True)
        d = mb.create_graph_from_desc(tag_desc)
        d.make_determinist(recursive=True)
        d2 = d.get_clone()
        d3 = d.get_clone()

        d.freeze()
        d['.*/value$'][0].unfreeze()
        d_raw = d.to_bytes()
        d.show()

        d2.freeze()
        d2['.*/value$'][0].unfreeze()
        d2['.*/value$'][0].freeze()
        d2_raw = d2.to_bytes()
        d2.show()

        d3.freeze()
        d3['.*/value$'][0].unfreeze()
        d3['.*/len$'][0].unfreeze()
        d3_raw = d3.to_bytes()
        d3.show()

        self.assertEqual(d_raw, d2_raw)
        self.assertEqual(d_raw, d3_raw)

    def test_absorb_nonterm_1(self):
        nint_1 = Node('nint1', value_type=UINT16_le(values=[0xabcd]))
        nint_2 = Node('nint2', value_type=UINT8(values=[0xf]))
        nint_3 = Node('nint3', value_type=UINT16_be(values=[0xeffe]))

        nstr_1 = Node('str1', value_type=String(values=['TBD1'], max_sz=5))
        nstr_2 = Node('str2', value_type=String(values=['TBD2'], max_sz=8))

        vt = BitField(subfield_sizes=[4, 4, 4],
                      subfield_values=[[3, 2, 0xe, 1], None, [10, 13, 3]],
                      subfield_val_extremums=[None, [14, 15], None],
                      padding=1, endian=VT.BigEndian, lsb_padding=True)

        bfield = Node('bfield', value_type=vt)
        bfield.enforce_absorb_constraints(AbsCsts())

        top = Node('top')
        top.set_subnodes_with_csts([
            1, ['u>', [nint_1, 1], [nint_2, 2], [nstr_1, 1], [nint_3, 2], [nstr_2, 1], [bfield, 1]]
        ])

        top.set_env(Env())

        # '?\xef' (\x3f\xe0) + padding 0b1111
        msg_tail = struct.pack('>H', 0x3fe0 + 0b1111)

        msg = b'\xe1\xe2\xff\xeeCOOL!\xc1\xc2\x88\x9912345678' + msg_tail
        status, off, size, name = top.absorb(msg, constraints=AbsNoCsts(size=True))

        print('\n ---[message to absorb]---')
        print(repr(msg))
        print('\n ---[absorbed message]---')
        print(top.to_bytes())

        top.show()

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(size, len(msg))

    def test_absorb_nonterm_2(self):
        nint_1 = Node('nint1', value_type=UINT16_le(values=[0xcdab, 0xffee]))
        nint_2 = Node('nint2', value_type=UINT8(values=[0xaf, 0xbf, 0xcf]))
        nint_3 = Node('nint3', value_type=UINT16_be(values=[0xcfab, 0xeffe]))

        nstr_1 = Node('str1', value_type=String(values=['STR1', 'str1'], max_sz=5))
        nstr_2 = Node('str2', value_type=String(values=['STR22', 'str222'], max_sz=8))

        top = Node('top')
        top.set_subnodes_with_csts([
            1, ['u=.', [nint_1, 1], [nint_2, 1, 2], [nstr_1, 1], [nint_3, 2], [nstr_2, 1]]
        ])

        top.set_env(Env())

        # 2*nint_3 + nstr_1 + nstr_2 + 2*nint_2 + nint_1
        msg = b'\xef\xfe\xef\xfeSTR1str222\xcf\xab\xcd'
        status, off, size, name = top.absorb(msg)

        print('\n ---[message to absorb]---')
        print(repr(msg))
        print('\n ---[absobed message]---')
        print(top.get_value())

        top.show(alpha_order=True)

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(size, len(msg))

    def test_absorb_nonterm_3(self):
        nint_1 = Node('nint1', value_type=UINT16_le(values=[0xcdab, 0xffee]))
        nint_2 = Node('nint2', value_type=UINT8(values=[0xaf, 0xbf, 0xcf]))
        nint_3 = Node('nint3', value_type=UINT16_be(values=[0xcfab, 0xeffe]))

        nstr_1 = Node('str1', value_type=String(values=['STR1', 'str1'], max_sz=5))
        nstr_2 = Node('str2', value_type=String(values=['STR22', 'str222'], max_sz=8))

        top = Node('top')
        top.set_subnodes_with_csts([
            1, ['u=+(2,2,1,5,1)', [nint_1, 1], [nint_2, 1], [nstr_1, 1], [nint_3, 2], [nstr_2, 1, 3]]
        ])

        top.set_env(Env())

        msg = 'str222str222'
        status, off, size, name = top.absorb(msg)

        print('\n ---[message to absorb]---')
        print(repr(msg))
        print('\n ---[absobed message]---')
        print(top.get_value())

        top.show(alpha_order=True)

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(size, len(msg))

    def test_absorb_nonterm_fullyrandom(self):

        test_desc = \
            {'name': 'test',
             'contents': [
                 {'section_type': MH.FullyRandom,
                  'contents': [
                      {'contents': String(values=['AAA', 'BBBB', 'CCCCC']),
                       'qty': (2, 3),
                       'name': 'str'},

                      {'contents': UINT8(values=[2, 4, 6, 8]),
                       'qty': (3, 6),
                       'name': 'int'}
                  ]}
             ]}

        for i in range(5):
            mb = NodeBuilder()
            node = mb.create_graph_from_desc(test_desc)
            node_abs = Node('test_abs', base_node=node)

            node.set_env(Env())
            node_abs.set_env(Env())

            node.show()

            data = node.to_bytes()
            status, off, size, name = node_abs.absorb(data, constraints=AbsFullCsts())

            print('Absorb Status:', status, off, size, name)
            print(' \_ length of original data:', len(data))
            print(' \_ remaining:', data[size:])

            node_abs.show()

            self.assertEqual(status, AbsorbStatus.FullyAbsorbed)

    def test_intg_absorb_1(self):

        self.helper1_called = False
        self.helper2_called = False

        def nint_1_helper(blob, constraints, node_internals):
            if blob[:1] in [b'\xe1', b'\xcd']:
                return AbsorbStatus.Accept, 0, None
            else:
                return AbsorbStatus.Reject, 0, None

        def nint_1_alt_helper(blob, constraints, node_internals):
            if blob[:1] == b'\xff':
                return AbsorbStatus.Accept, 0, None
            else:
                self.helper1_called = True
                return AbsorbStatus.Reject, 0, None

        nint_1 = Node('nint1', value_type=UINT16_le(values=[0xabcd, 0xe2e1]))
        nint_1.set_absorb_helper(nint_1_helper)
        nint_1_cpy = nint_1.get_clone('nint1_cpy')

        nint_1_alt = Node('nint1_alt', value_type=UINT16_le(values=[0xabff, 0xe2ff]))
        nint_1_alt.set_absorb_helper(nint_1_alt_helper)
        nint_1_alt_cpy = nint_1_alt.get_clone('nint1_alt_cpy')

        nint_2 = Node('nint2', value_type=UINT8(values=[0xf, 0xff, 0xee]))
        nint_3 = Node('nint3', value_type=UINT16_be(values=[0xeffe, 0xc1c2, 0x8899]))
        nint_3_cpy = nint_3.get_clone('nint3_cpy')

        nstr_1 = Node('cool', value_type=String(values=['TBD1'], size=4, codec='ascii'))
        nstr_1.enforce_absorb_constraints(AbsNoCsts(regexp=True))
        nstr_2 = Node('str2', value_type=String(values=['TBD2TBD2', '12345678'], size=8, codec='ascii'))

        nint_50 = Node('nint50', value_type=UINT8(values=[0xaf, 0xbf, 0xcf]))
        nint_51 = Node('nint51', value_type=UINT16_be(values=[0xcfab, 0xeffe]))
        nstr_50 = Node('str50', value_type=String(values=['HERE', 'IAM'], max_sz=7))

        middle1 = Node('middle1')
        middle1.set_subnodes_with_csts([
            3, ['u>', [nint_1_alt, 2]],
            2, ['u>', [nint_1, 1, 10], [nint_2, 2], [nstr_1, 1], [nint_3, 2], [nstr_2, 1]],
            1, ['u>', [nint_1_alt_cpy, 1], [nint_3_cpy, 1], 'u=+', [nstr_2, 1], [nint_1_cpy, 2], 'u>', [nstr_1, 1],
                'u=.', [nint_50, 1], [nint_51, 1], [nstr_50, 2, 3]]
        ])

        yeah = Node('yeah', value_type=String(values=['TBD', 'YEAH!'], max_sz=10, codec='ascii'))

        splitter = Node('splitter', value_type=String(values=['TBD'], max_sz=10))
        splitter.set_attr(NodeInternals.Abs_Postpone)
        splitter.enforce_absorb_constraints(AbsNoCsts())

        def nint_10_helper(blob, constraints, node_internals):
            off = blob.find(b'\xd2')
            if off > -1:
                self.helper2_called = True
                return AbsorbStatus.Accept, off, None
            else:
                return AbsorbStatus.Reject, 0, None

        nint_10 = Node('nint10', value_type=UINT16_be(values=[0xcbbc, 0xd2d3]))
        nint_10.set_absorb_helper(nint_10_helper)
        nstr_10 = Node('str10', value_type=String(values=['TBD', 'THE_END'], max_sz=7))

        delim = Node('delim', value_type=String(values=[','], size=1))
        nint_20 = Node('nint20', value_type=INT_str(values=[1, 2, 3]))
        nint_21 = Node('nint21', value_type=UINT8(values=[0xbb]))
        bottom = Node('bottom', subnodes=[delim, nint_20, nint_21])

        bottom2 = Node('bottom2', base_node=bottom)

        middle2 = Node('middle2')
        middle2.set_subnodes_with_csts([
            1, ['u>', [splitter, 1], [nint_10, 1], [bottom, 0, 1], [nstr_10, 1], [bottom2, 0, 1]]
        ])

        top = Node('top', subnodes=[middle1, yeah, middle2])
        top2 = Node('top2', base_node=top)

        top.set_env(Env())
        top2.set_env(Env())

        msg = b'\xe1\xe2\xe1\xe2\xff\xeeCOOL!\xc1\xc2\x88\x9912345678YEAH!\xef\xdf\xbf\xd2\xd3,2\xbbTHE_END'

        # middle1: nint_1_alt + nint_3 + 2*nint_1 + nstr_1('ABCD') + nint_51 + 2*nstr_50 + nint_50
        msg2 = b'\xff\xe2\x88\x99\xe1\xe2\xcd\xabABCD\xef\xfeIAMHERE\xbfYEAH!\xef\xdf\xbf\xd2\xd3,2\xbbTHE_END'

        print('\n****** top ******\n')
        status, off, size, name = top.absorb(msg)

        print('\n---[message to absorb: msg]---')
        print(repr(msg))
        print('---[absorbed message]---')
        # print(repr(top))
        print(top.get_value())

        def verif_val_and_print(*arg, **kwargs):
            Node._print_contents(*arg, **kwargs)
            if 'TBD' in arg:
                raise ValueError('Dissection Error!')

        top.show(print_contents_func=verif_val_and_print)
        l = top.get_nodes_names()

        print('\n****** top2 ******\n')
        status2, off2, size2, name2 = top2.absorb(msg2)

        print('\n---[message to absorb: msg2]---')
        print(repr(msg2))
        print('---[absorbed message]---')
        top2.show()

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(len(l), 19)
        self.assertEqual(len(msg), size)
        self.assertTrue(self.helper1_called)
        self.assertTrue(self.helper2_called)
        self.assertEqual(top.get_first_node_by_path("top/middle2/str10").to_bytes(), b'THE_END')

        # Because constraints are untighten on this node, its nominal
        # size of 4 is set to 5 when absorbing b'COOL!'
        self.assertEqual(top.get_first_node_by_path("top/middle1/cool").to_bytes(), b'COOL!')

        self.assertEqual(status2, AbsorbStatus.FullyAbsorbed)

        del self.helper1_called
        del self.helper2_called

        print('\n*** test __getitem__() ***\n')
        print(top["top/middle2"][0])
        print('\n***\n')
        print(repr(top["top/middle2"][0]))

    def test_show(self):

        a = fmk.dm.get_external_atom(dm_name='usb', data_id='DEV')
        b = fmk.dm.get_external_atom(dm_name='png', data_id='PNG_00')

        a.show(raw_limit=400)
        b.show(raw_limit=400)

        b['PNG_00/chunks/chk/height'] = a
        b.show(raw_limit=400)

        b['PNG_00/chunks/chk/height/idProduct'] = a
        b.show(raw_limit=400)

    def test_exist_condition_01(self):
        ''' Test existence condition for generation and absorption
        '''

        d = fmk.dm.get_external_atom(dm_name='mydf', data_id='exist_cond')

        for i in range(10):
            d_abs = fmk.dm.get_external_atom(dm_name='mydf', data_id='exist_cond')

            d.show()
            raw_data = d.to_bytes()

            print('-----------------------')
            print('Original Data:')
            print(repr(raw_data))
            print('-----------------------')

            status, off, size, name = d_abs.absorb(raw_data, constraints=AbsFullCsts())

            raw_data_abs = d_abs.to_bytes()
            print('-----------------------')
            print('Absorbed Data:')
            print(repr(raw_data_abs))
            print('-----------------------')

            print('-----------------------')
            print('Absorb Status: status=%s, off=%d, sz=%d, name=%s' % (status, off, size, name))
            print(' \_ length of original data: %d' % len(raw_data))
            print(' \_ remaining: %r' % raw_data[size:])
            print('-----------------------')

            self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
            self.assertEqual(raw_data, raw_data_abs)

            d.unfreeze()

    def test_exist_condition_02(self):

        cond_desc = \
            {'name': 'exist_cond',
             'shape_type': MH.Ordered,
             'contents': [
                 {'name': 'opcode',
                  'determinist': True,
                  'contents': String(values=['A3', 'A2'])},

                 {'name': 'command_A3',
                  'exists_if': (RawCondition('A3'), 'opcode'),
                  'contents': [
                      {'name': 'A3_subopcode',
                       'contents': BitField(subfield_sizes=[15, 2, 4], endian=VT.BigEndian,
                                            subfield_values=[None, [1, 2], [5, 6, 12]],
                                            subfield_val_extremums=[[500, 600], None, None],
                                            determinist=False)},

                      {'name': 'A3_int',
                       'determinist': True,
                       'contents': UINT16_be(values=[10, 20, 30])},

                      {'name': 'A3_deco1',
                       'exists_if/and': [(IntCondition(val=[10]), 'A3_int'),
                                         (BitFieldCondition(sf=2, val=[5]), 'A3_subopcode')],
                       'contents': String(values=['$ and_OK $'])},

                      {'name': 'A3_deco2',
                       'exists_if/and': [(IntCondition(val=[10]), 'A3_int'),
                                         (BitFieldCondition(sf=2, val=[6]), 'A3_subopcode')],
                       'contents': String(values=['! and_KO !'])}
                  ]},

                 {'name': 'A31_payload1',
                  'contents': String(values=['$ or_OK $']),
                  'exists_if/or': [(IntCondition(val=[20]), 'A3_int'),
                                   (BitFieldCondition(sf=2, val=[5]), 'A3_subopcode')],
                  },

                 {'name': 'A31_payload2',
                  'contents': String(values=['! or_KO !']),
                  'exists_if/or': [(IntCondition(val=[20]), 'A3_int'),
                                   (BitFieldCondition(sf=2, val=[6]), 'A3_subopcode')],
                  },

             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(cond_desc)

        print('***')
        raw = node.to_bytes()
        node.show()
        print(raw, len(raw))

        result = b"A3T\x0f\xa0\x00\n$ and_OK $$ or_OK $"

        self.assertEqual(result, raw)


    @ddt.data(
        # gt_val test cases
        {'opcode_val': [5], 'val': None, 'gt_val': 4, 'result': b'\x05[cond_checked]'},
        {'opcode_val': [5], 'val': None, 'gt_val': 5, 'result': b'\x05[cond_checked]'},
        {'opcode_val': [5], 'val': [5, 6], 'gt_val': 4, 'result': b'\x05[cond_checked]'},
        {'opcode_val': [5], 'val': [6, 7], 'gt_val': 4, 'result': b'\x05'},
        {'opcode_val': [5], 'val': 5, 'gt_val': 6, 'result': b'\x05'},
        # lt_val test cases
        {'opcode_val': [5], 'val': None, 'lt_val': 6, 'result': b'\x05[cond_checked]'},
        {'opcode_val': [5], 'val': None, 'lt_val': 5, 'result': b'\x05[cond_checked]'},
        {'opcode_val': [5], 'val': [4, 5], 'lt_val': 6, 'result': b'\x05[cond_checked]'},
        {'opcode_val': [5], 'val': [3, 4], 'lt_val': 6, 'result': b'\x05'},
        {'opcode_val': [5], 'val': 5, 'lt_val': 4, 'result': b'\x05'},
    )
    def test_exist_intcondition(self, params):
        cond_desc = \
            {'name': 'exist_cond',
             'contents': [
                 {'name': 'opcode',
                  'determinist': True,
                  'contents': UINT8(values=params['opcode_val'])},

                 {'name': 'type',
                  'exists_if': (IntCondition(val=params['val'], gt_val=params.get('gt_val'),
                                             lt_val=params.get('lt_val')),
                                'opcode'),
                  'contents': String(values=['[cond_checked]'])},
             ]}

        node = NodeBuilder().create_graph_from_desc(cond_desc)

        raw = node.to_bytes()
        print('{} (len: {})'.format(raw, len(raw)))

        self.assertEqual(params['result'], raw)

    @ddt.data(
        {'opcode_val': ['Test'], 'val': None, 'cond_func': lambda x: x.startswith(b'Te'),
         'result': b'Test[cond_checked]'},
        {'opcode_val': ['Tst'], 'val': None, 'cond_func': lambda x: x.startswith(b'Te'),
         'result': b'Tst'},
    )
    def test_exist_rawcondition(self, params):
        cond_desc = \
            {'name': 'exist_cond',
             'contents': [
                 {'name': 'opcode',
                  'determinist': True,
                  'contents': String(values=params['opcode_val'])},

                 {'name': 'type',
                  'exists_if': (RawCondition(val=params['val'], cond_func=params.get('cond_func')),
                                'opcode'),
                  'contents': String(values=['[cond_checked]'])},
             ]}

        node = NodeBuilder().create_graph_from_desc(cond_desc)

        raw = node.to_bytes()
        print('{} (len: {})'.format(raw, len(raw)))

        self.assertEqual(params['result'], raw)


    def test_generalized_exist_cond(self):

        gen_exist_desc = \
            {'name': 'gen_exist_cond',
             'separator': {'contents': {'name': 'sep_nl',
                                        'contents': String(values=['\n'], max_sz=100, absorb_regexp='[\r\n|\n]+'),
                                        'absorb_csts': AbsNoCsts(regexp=True)},
                           'prefix': False, 'suffix': False, 'unique': True},
             'contents': [
                 {'name': 'body',
                  'qty': 7,
                  'separator': {'contents': {'name': 'sep_space',
                                             'contents': String(values=[' '], max_sz=100, absorb_regexp=b'\s+'),
                                             'absorb_csts': AbsNoCsts(size=True, regexp=True)},
                                'prefix': False, 'suffix': False, 'unique': True},
                  'contents': [
                      {'name': 'val_blk',
                       'separator': {'contents': {'name': 'sep_quote',
                                                  'contents': String(values=['"'])},
                                     'prefix': False, 'suffix': True, 'unique': True},
                       'contents': [
                           {'name': 'key',
                            'contents': String(values=['value='])},
                           {'name': 'val1',
                            'contents': String(values=['Toulouse', 'Paris', 'Lyon']),
                            'exists_if': (RawCondition('Location'), 'param')},
                           {'name': 'val2',
                            'contents': String(values=['2015/10/08']),
                            'exists_if': (RawCondition('Date'), 'param')},
                           {'name': 'val3',
                            'contents': String(values=['10:40:42']),
                            'exists_if': (RawCondition('Time'), 'param')},
                           {'name': 'val4',
                            'contents': String(values=['NOT_SUPPORTED']),
                            'exists_if': (RawCondition(['NOTSUP1', 'NOTSUP2', 'NOTSUP3']), 'param')}
                       ]},
                      {'name': 'name_blk',
                       'separator': {'contents': {'name': ('sep_quote', 2),
                                                  'contents': String(values=['"'])},
                                     'prefix': False, 'suffix': True, 'unique': True},
                       'contents': [
                           {'name': ('key', 2),
                            'contents': String(values=['name='])},
                           {'name': 'param',
                            'contents': CYCLE(['NOTSUP1', 'Date', 'Time', 'NOTSUP2', 'NOTSUP3', 'Location'],
                                                 depth=2)}
                       ]}
                  ]}
             ]}

        mb = NodeBuilder(delayed_jobs=True)
        node = mb.create_graph_from_desc(gen_exist_desc)

        print('***')
        raw = node.to_bytes()
        print(raw, len(raw))

        result = \
            b'value="NOT_SUPPORTED" name="NOTSUP1"\n' \
            b'value="2015/10/08" name="Date"\n' \
            b'value="10:40:42" name="Time"\n' \
            b'value="NOT_SUPPORTED" name="NOTSUP2"\n' \
            b'value="NOT_SUPPORTED" name="NOTSUP3"\n' \
            b'value="Toulouse" name="Location"\n' \
            b'value="NOT_SUPPORTED" name="NOTSUP1"'

        print('***')
        print(result, len(result))

        self.assertEqual(result, raw)

    def test_pick_and_cond(self):

        pick_cond_desc = \
            {'name': 'pick_cond',
             'shape_type': MH.Ordered,
             'contents': [
                 {'name': 'opcode',
                  'determinist': True,
                  'contents': String(values=['A1', 'A2', 'A3'])},
                 {'name': 'part1',
                  'determinist': True,
                  'shape_type': MH.Pick,
                  'contents': [
                      {'name': 'option2',
                       'exists_if': (RawCondition('A2'), 'opcode'),
                       'contents': String(values=[' 1_KO_A2'])},
                      {'name': 'option3',
                       'exists_if': (RawCondition('A3'), 'opcode'),
                       'contents': String(values=[' 1_KO_A3'])},
                      {'name': 'option1',
                       'exists_if': (RawCondition('A1'), 'opcode'),
                       'contents': String(values=[' 1_OK_A1'])},
                  ]},
                 {'name': 'part2',
                  'determinist': False,
                  'weights': (100, 100, 1),
                  'shape_type': MH.Pick,
                  'contents': [
                      {'name': 'optionB',
                       'exists_if': (RawCondition('A2'), 'opcode'),
                       'contents': String(values=[' 2_KO_A2'])},
                      {'name': 'optionC',
                       'exists_if': (RawCondition('A3'), 'opcode'),
                       'contents': String(values=[' 2_KO_A3'])},
                      {'name': 'optionA',
                       'exists_if': (RawCondition('A1'), 'opcode'),
                       'contents': String(values=[' 2_OK_A1'])},
                  ]},
             ]}

        mb = NodeBuilder(delayed_jobs=True)
        node = mb.create_graph_from_desc(pick_cond_desc)

        print('***')
        raw = node.to_bytes()
        print(raw, len(raw))

        result = b'A1 1_OK_A1 2_OK_A1'

        self.assertEqual(result, raw)

    def test_collapse_padding(self):

        padding_desc = \
            {'name': 'padding',
             'shape_type': MH.Ordered,
             'custo_set': MH.Custo.NTerm.CollapsePadding,
             'contents': [
                 {'name': 'sublevel',
                  'contents': [
                      {'name': 'part2_msb',
                       'exists_if': (BitFieldCondition(sf=0, val=[1]), 'part1_lsb'),
                       'contents': BitField(subfield_sizes=[2, 2], endian=VT.BigEndian,
                                            subfield_values=[[3], [3]])
                       },
                      {'name': 'part2_middle',
                       'exists_if': (BitFieldCondition(sf=0, val=[1]), 'part1_lsb'),
                       'contents': BitField(subfield_sizes=[2, 2, 1], endian=VT.BigEndian,
                                            subfield_values=[[1, 2], [3], [0]])
                       },
                      {'name': 'part2_KO',
                       'exists_if': (BitFieldCondition(sf=0, val=[2]), 'part1_lsb'),
                       'contents': BitField(subfield_sizes=[2, 2], endian=VT.BigEndian,
                                            subfield_values=[[1], [1]])
                       }
                  ]},
                 {'name': 'part1_lsb',
                  'determinist': True,
                  'contents': BitField(subfield_sizes=[3, 1], padding=0, endian=VT.BigEndian,
                                       subfield_values=[None, [1]],
                                       subfield_val_extremums=[[1, 3], None])
                  },

             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(padding_desc)

        print('***')
        raw = node.to_bytes()
        node.show()  # part2_KO should not be displayed
        print(raw, binascii.b2a_hex(raw),
              list(map(lambda x: bin(x), struct.unpack('>' + 'B' * len(raw), raw))),
              len(raw))

        result = b'\xf6\xc8'
        self.assertEqual(result, raw)


        abs_test_desc = \
            {'name': 'test',
             'contents': [
                 {'name': 'prefix',
                  'contents': String(values=['prefix'])},
                 {'name': 'TP-DCS',  # Data Coding Scheme (refer to GSM 03.38)
                  'custo_set': MH.Custo.NTerm.CollapsePadding,
                  'contents': [
                      {'name': '8-bit',
                       'determinist': True,
                       'contents': BitField(subfield_sizes=[8], endian=VT.BigEndian,
                                            subfield_values=[
                                                [0xAA]],
                                            ) },
                      {'name': 'msb',
                       'determinist': True,
                       'contents': BitField(subfield_sizes=[4], endian=VT.BigEndian,
                                            subfield_values=[
                                                [0b1111,0b1101,0b1100,0b0000]],
                                            ) },
                      {'name': 'lsb1',
                       'determinist': True,
                       'exists_if': (BitFieldCondition(sf=0, val=[0b1111]), 'msb'),
                       'contents': BitField(subfield_sizes=[2,1,1,8], endian=VT.BigEndian,
                                            subfield_values=[[0b10,0b11,0b00,0b01],
                                                                [1,0],
                                                                [0],[0xFE]]
                                            ) },
                      {'name': 'lsb2',
                       'determinist': True,
                       'exists_if': (BitFieldCondition(sf=0, val=[0b1101,0b1100]), 'msb'),
                       'contents': BitField(subfield_sizes=[2,1,1], endian=VT.BigEndian,
                                            subfield_values=[[0b10,0b11,0b00,0b01],
                                                                [0],
                                                                [0,1]]
                                            ) },
                      {'name': 'lsb31',
                       'determinist': True,
                       'exists_if': (BitFieldCondition(sf=0, val=[0]), 'msb'),
                       'contents': BitField(subfield_sizes=[3], endian=VT.BigEndian,
                                            subfield_values=[
                                                [0,4]
                                            ]
                                            ) },

                      {'name': 'lsb32',
                       'determinist': True,
                       'exists_if': (BitFieldCondition(sf=0, val=[0]), 'msb'),
                       'contents': BitField(subfield_sizes=[8], endian=VT.BigEndian,
                                            subfield_values=[
                                                [0,0x5c]
                                            ]
                                            ) },

                      {'name': 'lsb33',
                       'determinist': True,
                       'exists_if': (BitFieldCondition(sf=0, val=[0]), 'msb'),
                       'contents': BitField(subfield_sizes=[1], endian=VT.BigEndian,
                                            subfield_values=[
                                                [0,1]
                                            ]
                                            ) },
                 ]},
                {'name': 'suffix',
                 'contents': String(values=['suffix'])}
             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(abs_test_desc)
        node_abs = node.get_clone()

        raw = node.to_bytes()
        node.show()  # part2_KO should not be displayed
        print(raw, binascii.b2a_hex(raw),
              list(map(lambda x: bin(x), struct.unpack('>' + 'B' * len(raw), raw))),
              len(raw))

        result = b'prefix\xaa\xff\xe6suffix'
        self.assertEqual(result, raw)

        print('\n*** Absorption test ***')

        result = b'prefix\xaa\xff\xe2suffix'
        abs_result = node_abs.absorb(result)
        print('\n--> Absorption status: {!r}\n'.format(abs_result))
        self.assertEqual(abs_result[0], AbsorbStatus.FullyAbsorbed)
        raw = node_abs.to_bytes()
        node_abs.show()  # part2_KO should not be displayed
        print(raw, binascii.b2a_hex(raw),
              list(map(lambda x: bin(x), struct.unpack('>' + 'B' * len(raw), raw))),
              len(raw))

        self.assertEqual(result, raw)

        result = b'prefix\xaa\xdasuffix'
        abs_result = node_abs.absorb(result)
        print('\n--> Absorption status: {!r}\n'.format(abs_result))
        self.assertEqual(abs_result[0], AbsorbStatus.FullyAbsorbed)
        raw = node_abs.to_bytes()
        node_abs.show()  # part2_KO should not be displayed
        print(raw, binascii.b2a_hex(raw),
              list(map(lambda x: bin(x), struct.unpack('>' + 'B' * len(raw), raw))),
              len(raw))

        self.assertEqual(result, raw)

        result = b'prefix\xaa\x08\xb9suffix'
        abs_result = node_abs.absorb(result)
        print('\n--> Absorption status: {!r}\n'.format(abs_result))
        self.assertEqual(abs_result[0], AbsorbStatus.FullyAbsorbed)
        raw = node_abs.to_bytes()
        node_abs.show()  # part2_KO should not be displayed
        print(raw, binascii.b2a_hex(raw),
              list(map(lambda x: bin(x), struct.unpack('>' + 'B' * len(raw), raw))),
              len(raw))

        self.assertEqual(result, raw)


    def test_node_search_primitive_01(self):

        data = fmk.dm.get_external_atom(dm_name='mydf', data_id='exist_cond')
        data.freeze()
        data.unfreeze()
        data.freeze()
        data.unfreeze()
        data.freeze()
        # At this step the data should exhibit 'command_A3'

        ic = NodeInternalsCriteria(required_csts=[SyncScope.Existence])

        l1 = data.get_reachable_nodes(internals_criteria=ic)
        print("\n*** {:d} nodes with existence condition found".format(len(l1)))

        res = []
        for n in l1:
            print(' |_ ' + n.name)
            res.append(n.name)

        self.assertEqual(len(res), 3)
        self.assertTrue('command_A3' in res)

        # node_to_corrupt = l1[1]
        # print('\n*** Node that will be corrupted: {:s}'.format(node_to_corrupt.name))

        # data.env.add_node_to_corrupt(node_to_corrupt)
        # corrupted_data = Node(data.name, base_node=data, ignore_frozen_state=False, new_env=True)
        # data.env.remove_node_to_corrupt(node_to_corrupt)

        # corrupted_data.unfreeze(recursive=True, reevaluate_constraints=True)
        # corrupted_data.show()

    def test_node_search_primitive_02(self):

        ex_node = fmk.dm.get_atom('ex')
        ex_node.show()

        n = ex_node.get_first_node_by_path('ex/data_group/data1')
        print('\n*** node', n.name)


        ic = NodeInternalsCriteria(required_csts=[SyncScope.Existence])

        def exec_search(**kwargs):
            l1 = ex_node.get_reachable_nodes(**kwargs)
            print("\n*** Number of node(s) found: {:d} ***".format(len(l1)))

            res = []
            for n in l1:
                print(' |_ ' + n.name)
                res.append(n.name)

            return res

        exec_search(path_regexp='^ex/data_group/data.*')

        l = ex_node['data_group/data1'][0].get_all_paths_from(ex_node)
        print(l)


    def test_node_search_primitive_03(self):
        test_node = fmk.dm.get_atom('TestNode')
        test_node.show()

        rexp = 'TestNode/middle/(USB_desc/|val2$)'

        l = test_node[rexp]
        for n in l:
            print('Node name: {}, value: {}'.format(n.name, n.to_bytes()))

        test_node[rexp] = Node('ignored_name', values=['TEST'])
        test_node.show()

        self.assertEqual(len(l), 4)

        for n in l:
            print('Node name: {}, value: {}'.format(n.name, n.to_bytes()))
            self.assertEqual(n.to_bytes(), b'TEST')

        self.assertEqual(test_node['Unknown path'], None)


    def test_node_search_performance(self):

        ex_node = fmk.dm.get_atom('ex')
        ex_node.show()

        t0 = datetime.datetime.now()
        for _ in range(30):
            l0 = list(ex_node.iter_nodes_by_path(path_regexp='.*', flush_cache=True, resolve_generator=True))
        now = datetime.datetime.now()
        print('\n*** Execution time of .iter_nodes_by_path(flush_cache=True): {}'.format((now - t0).total_seconds()))

        for n in l0:
            print(n.name)

        t0 = datetime.datetime.now()
        for _ in range(30):
            l1 = list(ex_node.iter_nodes_by_path(path_regexp='.*', flush_cache=False, resolve_generator=True))
        now = datetime.datetime.now()
        print('\n*** Execution time of .iter_nodes_by_path(flush_cache=False): {}'.format((now - t0).total_seconds()))

        for n in l1:
            print(n.name)

        t0 = datetime.datetime.now()
        for _ in range(30):
            nd = ex_node.get_first_node_by_path(path_regexp='.*', flush_cache=False, resolve_generator=True)
        now = datetime.datetime.now()
        print('\n*** Execution time of .get_first_node_by_path(flush_cache=False): {}'.format((now - t0).total_seconds()))

        t0 = datetime.datetime.now()
        for _ in range(30):
            l2 = ex_node.get_reachable_nodes(path_regexp='.*', respect_order=True, resolve_generator=True)
        now = datetime.datetime.now()
        print('\n*** Execution time of .get_reachable_nodes: {}'.format((now - t0).total_seconds()))

        for n in l2:
            print(n.name)

        self.assertEqual(l0, l1)
        self.assertEqual(l1, l2)

@ddt.ddt
class TestNode_NonTerm(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        pass

    @ddt.data((True, True),(True,False),(False,True),(False,False))
    @ddt.unpack
    def test_combinatory_1(self, mimick_twalk, full_comb_mode):
        test_desc = \
        {'name': 'test',
         'custo_set': MH.Custo.NTerm.CycleClone,
         'contents': [
             {'name': 'prefix',
              'qty': (0,4),
              'default_qty': 1,
              'contents': String(values=['-', '+'])},

             {'section_type': MH.Pick,
              'weights': (3,2,1),
              'contents': [
                  {'name': 'pre1', 'contents': String(values=['x'])},
                  {'name': 'pre2', 'contents': String(values=['y'])},
                  {'name': 'pre3', 'contents': String(values=['z'])}
              ]},

             {'name': 'digit',
              'qty': (0,10),
              'default_qty': 2,
              'contents': [
                  {'weight': 50,
                   'contents': [
                       {'name': 'n1', 'contents': String(values=['1'])}
                   ]},
                  {'weight': 40,
                   'contents': [
                       {'name': 'n2', 'contents': String(values=['2'])}
                   ]},
                  {'weight': 30,
                   'contents': [
                       {'name': 'n3', 'contents': String(values=['3'])}
                   ]},
                  {'weight': 20,
                   'contents': [
                       {'name': 'n4', 'contents': String(values=['4'])}
                   ]},
              ]},
              {'section_type': MH.Pick,
               'weights': (2,1,3),
               'contents': [
                   {'name': 'suf2', 'contents': String(values=['b'])},
                   {'name': 'suf3', 'contents': String(values=['c'])},
                   {'name': 'suf1', 'contents': String(values=['a'])}
               ]}
         ]}


        mb = NodeBuilder(add_env=True)
        nd = mb.create_graph_from_desc(test_desc)

        data_ref = [
            b'-x12a',
            b'-+-+x12a',
            b'x12a',
            b'-x1234123412a',
            b'-xa',
            b'-y12a',
            b'-+-+y12a',
            b'y12a',
            b'-y1234123412a',
            b'-ya',
            b'-z12a',
            b'-+-+z12a',
            b'z12a',
            b'-z1234123412a',
            b'-za',
            b'-x12b',
            b'-+-+x12b',
            b'x12b',
            b'-x1234123412b',
            b'-xb',
            b'-x12c',
            b'-+-+x12c',
            b'x12c',
            b'-x1234123412c',
            b'-xc',
        ]

        # mimick_twalk = True
        # full_comb_mode = True

        nd.make_finite()
        nd.custo.full_combinatory_mode = full_comb_mode
        for i in range(1, 200):
            print(f'\n###### data #{i}')
            if mimick_twalk: # with fix_all
                nd.unfreeze(recursive=False)
                nd.freeze()
                nd.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
                nd.freeze()
            else:
                nd.walk(recursive=False)
            data = nd.to_bytes()
            print(data)
            if not full_comb_mode:
                self.assertEqual(data, data_ref[i-1], f'i = {i-1}')

            if nd.is_exhausted():
                break

        if full_comb_mode:
            self.assertEqual(i, 45)
        else:
            self.assertEqual(i, 25)



    @ddt.data(
        (True, True, False), (True, False, False), (False, True, False), (False, False, False),
        (True, True, True), (True, False, True), (False, True, True), (False, False, True)
    )
    @ddt.unpack
    def test_combinatory_2(self, mimick_twalk, clone_mode, full_comb_mode):

        test_desc = \
        {'name': 'test',
         'custo_set': MH.Custo.NTerm.CycleClone,
         'custo_clear': MH.Custo.NTerm.MutableClone,
         'contents': [
             {'name': 'scst1', 'qty': 2, 'contents': String(values=['s'])},
             {'name': 'scst2', 'qty': 2, 'contents': String(values=['s'])},

             {'name': 'pre3',
              'qty': (1,4),
              'default_qty': 3,
              'contents': String(values=['-', '+'])},

             {'name': 'mcst1', 'qty': 2, 'contents': String(values=['s'])},
             {'name': 'mcst2', 'qty': 2, 'contents': String(values=['s'])},

             {'name': 'digit1',
              'qty': (0,10),
              'default_qty': 2,
              'contents': String(values=['1']),
              },

             {'name': 'mcst3', 'qty': 2, 'contents': String(values=['s'])},

             {'name': 'digit2',
              'qty': (3,7),
              'default_qty': 5,
              'contents': String(values=['2']),
              },
             {'name': 'digit3',
              'qty': (0,1),
              'default_qty': 0,
              'contents': String(values=['3']),
              },

             {'section_type': MH.Pick,
              'weights': (2,1,3),
              'contents': [
                  {'name': 'suf2', 'contents': String(values=['b'])},
                  {'name': 'suf3', 'contents': String(values=['c'])},
                  {'name': 'suf1', 'contents': String(values=['a'])}
              ]},

             {'name': 'ecst1', 'qty': 2, 'contents': String(values=['s'])},
             {'name': 'ecst2', 'qty': 2, 'contents': String(values=['s'])},

         ]}

        mb = NodeBuilder(add_env=True)
        nd = mb.create_graph_from_desc(test_desc)

        data_ref = [
            b'ssss-+-ssss11ss22222assss',
            b'ssss-+-+ssss11ss22222assss',
            b'ssss-ssss11ss22222assss',
            b'ssss-+-ssss1111111111ss22222assss',
            b'ssss-+-ssssss22222assss',
            b'ssss-+-ssss11ss2222222assss',
            b'ssss-+-ssss11ss222assss',
            b'ssss-+-ssss11ss222223assss',
        ]

        nd.make_finite()
        nd.custo.full_combinatory_mode = full_comb_mode
        for i in range(1, 200):
            if clone_mode:
                nd = nd.get_clone()
            print(f'\n###### data #{i}')
            if mimick_twalk: # with fix_all
                nd.unfreeze(recursive=False)
                nd.freeze()
                nd.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
                nd.freeze()
            else:
                nd.walk(recursive=False)
            data = nd.to_bytes()
            print(data)
            if not full_comb_mode:
                idx = (i-1) % 8
                if i > 16:
                    str_ref = data_ref[idx][:-5] + b'cssss'
                elif i > 8:
                    str_ref = data_ref[idx][:-5] + b'bssss'
                else:
                    str_ref = data_ref[idx]

                self.assertEqual(data, str_ref, f'i = {i-1}')

            if nd.is_exhausted():
                break

        if full_comb_mode:
            self.assertEqual(i, 162)  # 3 x 54
        else:
            self.assertEqual(i, 24)  # 3 x 8


    def test_infinity(self):
        infinity_desc = \
            {'name': 'infinity',
             'contents': [
                 {'name': 'prefix',
                  'contents': String(values=['A']),
                  'qty': (2, -1)},
                 {'name': 'mid',
                  'contents': String(values=['H']),
                  'qty': -1},
                 {'name': 'suffix',
                  'contents': String(values=['Z']),
                  'qty': (2, -1)},
             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(infinity_desc)
        node_abs = Node('infinity_abs', base_node=node)
        node_abs2 = Node('infinity_abs', base_node=node)

        node.set_env(Env())
        node_abs.set_env(Env())
        node_abs2.set_env(Env())

        # node.show()
        raw_data = node.to_bytes()
        print('\n*** Test with generated raw data (infinite is limited to )\n\nOriginal data:')
        print(repr(raw_data), len(raw_data))

        status, off, size, name = node_abs.absorb(raw_data, constraints=AbsFullCsts())

        print('Absorb Status:', status, off, size, name)
        print(' \_ length of original data:', len(raw_data))
        print(' \_ remaining:', raw_data[size:])
        raw_data_abs = node_abs.to_bytes()
        print(' \_ absorbed data:', repr(raw_data_abs), len(raw_data_abs))
        # node_abs.show()

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(raw_data, raw_data_abs)

        print('\n*** Test with big raw data\n\nOriginal data:')
        raw_data2 = b'A' * (NodeInternals_NonTerm.INFINITY_LIMIT + 30) + b'H' * (
        NodeInternals_NonTerm.INFINITY_LIMIT + 1) + \
                    b'Z' * (NodeInternals_NonTerm.INFINITY_LIMIT - 1)
        print(repr(raw_data2), len(raw_data2))

        status, off, size, name = node_abs2.absorb(raw_data2, constraints=AbsFullCsts())

        print('Absorb Status:', status, off, size, name)
        print(' \_ length of original data:', len(raw_data2))
        print(' \_ remaining:', raw_data2[size:])
        raw_data_abs2 = node_abs2.to_bytes()
        print(' \_ absorbed data:', repr(raw_data_abs2), len(raw_data_abs2))

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(raw_data2, raw_data_abs2)

    def test_separator(self):
        test_desc = \
            {'name': 'test',
             'determinist': True,
             'separator': {'contents': {'name': 'SEP',
                                        'contents': String(values=[' ', '  ', '     '],
                                                           absorb_regexp='\s+', determinist=False),
                                        'absorb_csts': AbsNoCsts(regexp=True)},
                           'prefix': True,
                           'suffix': True,
                           'unique': True},
             'contents': [
                 {'section_type': MH.FullyRandom,
                  'contents': [
                      {'contents': String(values=['AAA', 'BBBB', 'CCCCC']),
                       'qty': (3, 5),
                       'name': 'str'},

                      {'contents': String(values=['1', '22', '333']),
                       'qty': (3, 5),
                       'name': 'int'}
                  ]},

                 {'section_type': MH.Random,
                  'contents': [
                      {'contents': String(values=['WW', 'YYY', 'ZZZZ']),
                       'qty': (2, 2),
                       'name': 'str2'},

                      {'contents': UINT16_be(values=[0xFFFF, 0xAAAA, 0xCCCC]),
                       'qty': (3, 3),
                       'name': 'int2'}
                  ]},
                 {'section_type': MH.Pick,
                  'contents': [
                      {'contents': String(values=['LAST', 'END']),
                       'qty': (2, 2),
                       'name': 'str3'},

                      {'contents': UINT16_be(values=[0xDEAD, 0xBEEF]),
                       'qty': (2, 2),
                       'name': 'int3'}
                  ]}
             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(test_desc)
        node.set_env(Env())

        for i in range(5):
            node_abs = Node('test_abs', base_node=node)
            node_abs.set_env(Env())

            node.show()
            raw_data = node.to_bytes()
            print('Original data:')
            print(repr(raw_data), len(raw_data))

            status, off, size, name = node_abs.absorb(raw_data, constraints=AbsFullCsts())

            print('Absorb Status:', status, off, size, name)
            print(' \_ length of original data:', len(raw_data))
            print(' \_ remaining:', raw_data[size:])
            raw_data_abs = node_abs.to_bytes()
            print(' \_ absorbed data:', repr(raw_data_abs), len(raw_data_abs))

            # node_abs.show()

            self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
            self.assertEqual(len(raw_data), len(raw_data_abs))
            self.assertEqual(raw_data, raw_data_abs)

            node.unfreeze()

    def test_encoding_attr(self):
        enc_desc = \
            {'name': 'enc',
             'contents': [
                 {'name': 'data0',
                  'contents': String(values=['Plip', 'Plop'])},
                 {'name': 'crc',
                  'contents': CRC(vt=UINT32_be, after_encoding=False),
                  'node_args': ['enc_data', 'data2'],
                  'absorb_csts': AbsFullCsts(content=False, similar_content=False)},
                 {'name': 'enc_data',
                  'encoder': GZIP_Enc(6),
                  'set_attrs': NodeInternals.Abs_Postpone,
                  'contents': [
                      {'name': 'len',
                       'contents': LEN(vt=UINT8, after_encoding=False),
                       'node_args': 'data1',
                       'absorb_csts': AbsFullCsts(content=False, similar_content=False)},
                      {'name': 'data1',
                       'contents': String(values=['Test!', 'Hello World!'], codec='utf-16-le')},
                  ]},
                 {'name': 'data2',
                  'contents': String(values=['Red', 'Green', 'Blue'])},
             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(enc_desc)
        node.set_env(Env())

        node_abs = Node('abs', base_node=node, new_env=True)
        node_abs.set_env(Env())

        node.show()
        print('\nData:')
        print(node.to_bytes())
        self.assertEqual(struct.unpack('B', node['enc/enc_data/len$'][0].to_bytes())[0],
                         len(node['enc/enc_data/data1$'][0].get_raw_value()))

        raw_data = b'Plop\x8c\xd6/\x06x\x9cc\raHe(f(aPd\x00\x00\x0bv\x01\xc7Blue'
        status, off, size, name = node_abs.absorb(raw_data, constraints=AbsFullCsts())

        print('\nAbsorb Status:', status, off, size, name)
        print(' \_ length of original data:', len(raw_data))
        print(' \_ remaining:', raw_data[size:])
        raw_data_abs = node_abs.to_bytes()
        print(' \_ absorbed data:', repr(raw_data_abs), len(raw_data_abs))
        node_abs.show()

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(raw_data, raw_data_abs)

    def test_node_addition(self):

        # Notes:
        # Current test cases are agnostic to differences between min and max value as the NT nodes are
        # in determinist mode, meaning that we only see the usage of min qty in the current test cases.

        new_node_min_qty = 2
        new_node_max_qty = 2

        print('\n*** Test Case 1 ***\n')

        ex_node = fmk.dm.get_atom('ex')
        ex_node.show()
        new_node = Node('my_node2', values=['New node added!!!!'])
        data2_node = ex_node['ex/data_group/data2'][0]
        ex_node['ex/data_group'][0].add(new_node, after=data2_node, min=new_node_min_qty, max=new_node_max_qty)
        ex_node.show()

        nt_node = ex_node['ex/data_group'][0]
        self.assertEqual(nt_node.get_subnode_idx(new_node),
                         nt_node.get_subnode_idx(ex_node['ex/data_group/data2'][0])+1)

        ex_node.unfreeze()
        ex_node.show()
        self.assertEqual(nt_node.get_subnode_idx(new_node),
                         nt_node.get_subnode_idx(ex_node['ex/data_group/data2:3'][0])+1)

        print('\n*** Test Case 2 ***\n')

        ex_node = fmk.dm.get_atom('ex')
        ex_node.show()
        new_node = Node('my_node2', values=['New node added!!!!'])
        ex_node['ex/data_group'][0].add(new_node, idx=0, min=new_node_min_qty, max=new_node_max_qty)
        ex_node.show()

        nt_node = ex_node['ex/data_group'][0]
        self.assertEqual(nt_node.get_subnode_idx(new_node), 0)

        ex_node.unfreeze()
        ex_node.show()
        self.assertEqual(nt_node.get_subnode_idx(new_node), 0)

        print('\n*** Test Case 3 ***\n')

        ex_node = fmk.dm.get_atom('ex')
        ex_node.show()
        new_node = Node('my_node2', values=['New node added!!!!'])
        ex_node['ex/data_group'][0].add(new_node, idx=None, min=new_node_min_qty, max=new_node_max_qty)
        ex_node.show()

        nt_node = ex_node['ex/data_group'][0]
        self.assertEqual(nt_node.get_subnode_idx(new_node), nt_node.get_subnode_qty()-new_node_min_qty)

        ex_node.unfreeze()
        ex_node.show()
        self.assertEqual(nt_node.get_subnode_idx(new_node), nt_node.get_subnode_qty()-new_node_min_qty)


class TestNode_TypedValue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        pass

    def test_bitfield(self):

        bf = BitField(subfield_sizes=[4, 4, 4],
                      subfield_values=[[4, 2, 1], None, [10, 11, 15]],
                      subfield_val_extremums=[None, [5, 9], None],
                      padding=0, lsb_padding=False, endian=VT.BigEndian,
                      defaults=[2,8,15])
        node = Node('BF', vt=bf)
        node.set_env(Env())

        node_abs = node.get_clone()

        node.show()
        b1 = node.to_bytes()

        node.set_default_value([1,5,11])
        node.show()
        b2 = node.to_bytes()

        self.assertEqual(b1, b'\x0f\x82')
        self.assertEqual(b2, b'\x0b\x51')

        raw_data = b'\x0f\x74'
        status, _, _, _ = node_abs.absorb(raw_data, constraints=AbsFullCsts())
        self.assertTrue(status, AbsorbStatus.FullyAbsorbed)

        node_abs.show()
        b3 = node_abs.to_bytes()
        node_abs.reset_state()
        b4 = node_abs.to_bytes()

        self.assertEqual(b3, b'\x0f\x74')
        self.assertEqual(b4, b'\x0f\x74')

    def test_integer(self):
        node = Node('Int1', vt=UINT8(min=9, max=40, determinist=True, default=21))
        node.set_env(Env())

        node.show()
        i1 = node.get_raw_value()

        node.set_default_value(35)
        i2 = node.get_raw_value()
        node.walk()
        i3 = node.get_raw_value()

        node.reset_state()
        i4 = node.get_raw_value()

        print('\n***', i1, i2, i3, i4)

        self.assertEqual(i1, 21)
        self.assertEqual(i2, 35)
        self.assertNotEqual(i3, 35)
        self.assertEqual(i4, 35)

        node = Node('Int2', vt=UINT8(values=[9,10,21,32,40], determinist=True, default=21))
        node.set_env(Env())

        node_abs = node.get_clone()

        node.show()
        i1 = node.get_raw_value()

        self.assertRaises(DataModelDefinitionError, node.set_default_value, 35)

        node.set_default_value(32)
        i2 = node.get_raw_value()

        print('\n***', i1, i2)

        self.assertEqual(i1, 21)
        self.assertEqual(i2, 32)

        raw_data = b'\x28'  # == 40
        status, _, _, _ = node_abs.absorb(raw_data, constraints=AbsFullCsts())
        self.assertTrue(status, AbsorbStatus.FullyAbsorbed)

        node_abs.show()
        i3 = node_abs.get_raw_value()
        node_abs.reset_state()
        i4 = node_abs.get_raw_value()

        self.assertEqual(i3, 40)
        self.assertEqual(i4, 40)


    def test_str_basics(self):
        node = Node('test', vt=String(min_sz=2, max_sz=100, alphabet='ABCDEFGH', default='CAFE'))
        node.set_env(Env())
        str0 = node.to_str()

        node.set_default_value('BABA')

        str1 = node.to_str()
        node.walk()
        str2 = node.to_str()
        node.reset_state()
        str3 = node.to_str()
        node.walk()
        node.walk()
        node.reset_state()
        str4 = node.to_str()

        print('*** node.to_str():\n{}\n{}\n{}\n{}\n{}'.format(str0, str1, str2, str3, str4))

        self.assertEqual(str0, 'CAFE')
        self.assertEqual(str1, 'BABA')
        self.assertEqual(str3, 'BABA')
        self.assertEqual(str4, 'BABA')
        self.assertNotEqual(str2, 'BABA')

        node = Node('test', vt=String(values=['ABC', 'GAG'], min_sz=2, max_sz=100, alphabet='ABCDEFGH', default='CAFE'))
        node.set_env(Env())

        node_abs = node.get_clone()

        str0 = node.to_str()
        node.walk()
        str1 = node.to_str()

        print('*** node.to_str():\n{}\n{}'.format(str0,str1)) #, str1, str2, str3, str4))

        self.assertEqual(str0, 'CAFE')
        self.assertEqual(str1, 'ABC')

        raw_data = b'FACE'
        status, _, _, _ = node_abs.absorb(raw_data, constraints=AbsFullCsts())
        self.assertTrue(status, AbsorbStatus.FullyAbsorbed)

        node_abs.show()
        str2 = node_abs.to_str()
        node_abs.reset_state()
        str3 = node_abs.to_str()

        self.assertEqual(str2, 'FACE')
        self.assertEqual(str3, 'FACE')


    def test_filename(self):

        node1 = Node('fname', vt=Filename(values=['myfile.txt'], case_sensitive=False))
        node1.set_env(Env())

        node2 = Node('fname', vt=Filename(values=['myfile.txt'], case_sensitive=False, uri_parsing=True))
        node2.set_env(Env())

        node3 = Node('fname', vt=Filename(values=['base/myfile.txt'], case_sensitive=False))
        node3.set_env(Env())

        node4 = Node('fpath', vt=FolderPath(values=['base/myfolder'], case_sensitive=False))
        node4.set_env(Env())

        node_list = [(node1, 28),
                     (node2, 20),
                     (node3, 19),
                     (node4, 19)]

        for node, nb_tc in node_list:
            tn_consumer = TypedNodeDisruption(fuzz_magnitude=1.0)
            for rnode, consumed_node, orig_node_val, idx in ModelWalker(node, tn_consumer, make_determinist=True, max_steps=-1):
                data = rnode.to_bytes()
                sz = len(data)
                print(colorize('[{:d}] ({:04d}) {!r}'.format(idx, sz, data), rgb=Color.INFO))

            self.assertEqual(idx, nb_tc)

    def test_str_alphabet(self):

        alphabet1 = 'ABC'
        alphabet2 = 'NED'

        alpha_desc = \
            {'name': 'top',
             'contents': [
                 {'name': 'alpha1',
                  'contents': String(min_sz=10, max_sz=100, values=['A' * 10], alphabet=alphabet1),
                  'set_attrs': [NodeInternals.Abs_Postpone]},
                 {'name': 'alpha2',
                  'contents': String(min_sz=10, max_sz=100, alphabet=alphabet2)},
                 {'name': 'end',
                  'contents': String(values=['END'])},
             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(alpha_desc)
        node.set_env(Env())

        node_abs = Node('alpha_abs', base_node=node)
        node_abs.set_env(Env())

        node.show()
        raw_data = node.to_bytes()
        print(repr(raw_data), len(raw_data))

        alphabet = alphabet1 + alphabet2
        for l in raw_data:
            l = chr(l)
            self.assertTrue(l in alphabet)

        print('\n*** Test with following  data:')
        raw_data = b'A' * 10 + b'DNE' * 30 + b'E' * 10 + b'END'
        print(repr(raw_data), len(raw_data))

        status, off, size, name = node_abs.absorb(raw_data, constraints=AbsFullCsts())

        print('Absorb Status:', status, off, size, name)
        print(' \_ length of original data:', len(raw_data))
        print(' \_ remaining:', raw_data[size:])
        raw_data_abs = node_abs.to_bytes()
        print(' \_ absorbed data:', repr(raw_data_abs), len(raw_data_abs))
        node_abs.show()

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(raw_data, raw_data_abs)

        node_abs = Node('alpha_abs', base_node=node)
        node_abs.set_env(Env())

        print('\n*** Test with following INVALID data:')
        raw_data = b'A' * 10 + b'DNE' * 20 + b'F' + b'END'
        print(repr(raw_data), len(raw_data))

        status, off, size, name = node_abs.absorb(raw_data, constraints=AbsFullCsts())

        print('Absorb Status:', status, off, size, name)
        print(' \_ length of original data:', len(raw_data))
        print(' \_ remaining:', raw_data[size:])
        raw_data_abs = node_abs.to_bytes()
        print(' \_ absorbed data:', repr(raw_data_abs), len(raw_data_abs))
        node_abs.show()

        self.assertEqual(status, AbsorbStatus.Reject)
        self.assertEqual(raw_data[size:], b'FEND')

    def test_encoded_str_1(self):

        class MyEncoder(Encoder):
            def encode(self, val):
                return val + b'***'

            def decode(self, val):
                return val[:-3]

        @from_encoder(MyEncoder)
        class EncodedStr(String): pass

        data = ['Test!', u'Hell\u00fc World!']
        enc_desc = \
            {'name': 'enc',
             'contents': [
                 {'name': 'len',
                  'contents': LEN(vt=UINT8, after_encoding=False),
                  'node_args': 'user_data',
                  'absorb_csts': AbsFullCsts(content=False, similar_content=False)},
                 {'name': 'user_data',
                  'contents': EncodedStr(values=data, codec='utf8')},
                 {'name': 'compressed_data',
                  'contents': GZIP(values=data, encoding_arg=6)}
             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(enc_desc)
        node.set_env(Env())

        node_abs = Node('enc_abs', base_node=node, new_env=True)
        node_abs.set_env(Env())

        node.show()
        self.assertEqual(struct.unpack('B', node['enc/len$'][0].to_bytes())[0],
                         len(node['enc/user_data$'][0].get_raw_value()))

        raw_data = b'\x0CHell\xC3\xBC World!***' + \
                   b'x\x9c\xf3H\xcd\xc9\xf9\xa3\x10\x9e_\x94\x93\xa2\x08\x00 \xb1\x04\xcb'

        status, off, size, name = node_abs.absorb(raw_data, constraints=AbsFullCsts())

        print('Absorb Status:', status, off, size, name)
        print(' \_ length of original data:', len(raw_data))
        print(' \_ remaining:', raw_data[size:])
        raw_data_abs = node_abs.to_bytes()
        print(' \_ absorbed data:', repr(raw_data_abs), len(raw_data_abs))
        node_abs.show()

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
        self.assertEqual(raw_data, raw_data_abs)

        msg = b'Hello World'
        gsm_t = GSM7bitPacking(max_sz=20)
        gsm_enc = gsm_t.encode(msg)
        gsm_dec = gsm_t.decode(gsm_enc)
        self.assertEqual(msg, gsm_dec)

        msg = b'Hello World!'
        gsm_enc = gsm_t.encode(msg)
        gsm_dec = gsm_t.decode(gsm_enc)
        self.assertEqual(msg, gsm_dec)

        msg = b'H'
        gsm_enc = gsm_t.encode(msg)
        gsm_dec = gsm_t.decode(gsm_enc)
        self.assertEqual(msg, gsm_dec)

        msg = b'Hello World!' * 10
        vtype = GZIP(max_sz=20)
        enc = vtype.encode(msg)
        dec = vtype.decode(enc)
        self.assertEqual(msg, dec)

        msg = b'Hello World!'
        vtype = Wrapper(max_sz=20, encoding_arg=[b'<test>', b'</test>'])
        enc = vtype.encode(msg)
        dec = vtype.decode(enc)
        self.assertEqual(msg, dec)

        vtype = Wrapper(max_sz=20, encoding_arg=[b'<test>', None])
        enc = vtype.encode(msg)
        dec = vtype.decode(enc)
        self.assertEqual(msg, dec)

        vtype = Wrapper(max_sz=20, encoding_arg=[None, b'</test>'])
        enc = vtype.encode(msg)
        dec = vtype.decode(enc)
        self.assertEqual(msg, dec)

    def test_encoded_str_2(self):

        enc_desc = \
            {'name': 'enc',
             'contents': [
                 {'name': 'len',
                  'contents': UINT8()},
                 {'name': 'user_data',
                  'sync_enc_size_with': 'len',
                  'contents': String(values=['TEST'], codec='utf8')},
                 {'name': 'padding',
                  'contents': String(max_sz=0),
                  'absorb_csts': AbsNoCsts()},
             ]}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(enc_desc)
        node.set_env(Env())

        node_abs = Node('enc_abs', base_node=node, new_env=True)
        node_abs.set_env(Env())
        node_abs2 = node_abs.get_clone()

        node_abs.show()

        raw_data = b'\x0C' + b'\xC6\x67' + b'garbage'  # \xC6\x67 --> invalid UTF8
        status, off, size, name = node_abs.absorb(raw_data, constraints=AbsNoCsts(size=True, struct=True))

        self.assertEqual(status, AbsorbStatus.Reject)

        raw_data = b'\x05' + b'\xC3\xBCber' + b'padding'  # \xC3\xBC = ü in UTF8

        status, off, size, name = node_abs2.absorb(raw_data, constraints=AbsNoCsts(size=True, struct=True))

        print('Absorb Status:', status, off, size, name)
        print(' \_ length of original data:', len(raw_data))
        print(' \_ remaining:', raw_data[size:])
        raw_data_abs = node_abs2.to_bytes()
        print(' \_ absorbed data:', repr(raw_data_abs), len(raw_data_abs))
        node_abs2.show()

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)


class TestHLAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        pass

    def test_create_graph(self):
        a = {'name': 'top',
             'contents': [
                 {'weight': 2,
                  'contents': [
                      # block 1
                      {'section_type': MH.Ordered,
                       'duplicate_mode': MH.Copy,
                       'contents': [

                           {'contents': String(max_sz=10),
                            'name': 'val1',
                            'qty': (1, 5)},

                           {'name': 'val2'},

                           {'name': 'middle',
                            'custo_clear': MH.Custo.NTerm.MutableClone,
                            'custo_set': MH.Custo.NTerm.FrozenCopy,
                            'contents': [{
                                'section_type': MH.Ordered,
                                'contents': [

                                    {'contents': String(values=['OK', 'KO'], size=2),
                                     'name': 'val2'},

                                    {'name': 'val21',
                                     'clone': 'val1'},

                                    {'name': 'USB_desc',
                                     'import_from': 'usb',
                                     'data_id': 'STR'},

                                    {'type': MH.Leaf,
                                     'contents': lambda x: x[0] + x[1],
                                     'name': 'val22',
                                     'node_args': ['val1', 'val3'],
                                     'custo_set': MH.Custo.Func.FrozenArgs}
                                ]}]},

                           {'contents': String(max_sz=10),
                            'name': 'val3',
                            'sync_qty_with': 'val1',
                            'alt': [
                                {'conf': 'alt1',
                                 'contents': SINT8(values=[1, 4, 8])},
                                {'conf': 'alt2',
                                 'contents': UINT16_be(min=0xeeee, max=0xff56),
                                 'determinist': True}]}
                       ]},

                      # block 2
                      {'section_type': MH.Pick,
                       'contents': [
                           {'contents': String(values=['PLIP', 'PLOP'], size=4),
                            'name': ('val21', 2)},

                           {'contents': SINT16_be(values=[-1, -3, -5, 7]),
                            'name': ('val22', 2)}
                       ]}
                  ]}
             ]}

        mb = NodeBuilder(fmk.dm)
        node = mb.create_graph_from_desc(a)

        node.set_env(Env())
        node.show()

        node.unfreeze_all()
        node.show()
        node.unfreeze_all()
        node.show()

        node.reset_state(recursive=True)
        node.set_current_conf('alt1', recursive=True)
        node.show()

        node.reset_state(recursive=True)
        node.set_current_conf('alt2', recursive=True)
        node.show()

        print('\nNode Dictionnary (size: {:d}):\n'.format(len(mb.node_dico)))
        for name, node in mb.node_dico.items():
            print(name, ': ', repr(node), node.c)


class TestDataModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        pass

    def test_data_container(self):
        node = fmk.dm.get_external_atom(dm_name='mydf', data_id='exist_cond')
        data = copy.copy(Data(node))
        data = copy.copy(Data('TEST'))

    @unittest.skipIf(not run_long_tests, "Long test case")
    def test_data_makers(self):

        for dm in fmk.dm_list:
            try:
                dm.load_data_model(fmk._name2dm)
            except:
                print("\n*** WARNING: Data Model '{:s}' not tested because" \
                      " the loading process has failed ***\n".format(dm.name))
                raise

            print("Test '%s' Data Model" % dm.name)
            for data_id in dm.atom_identifiers():
                print("Try to get '%s'" % data_id)
                data = dm.get_atom(data_id)
                data.get_value()
                # data.show(raw_limit=200)
                print('Success!')

    @unittest.skipIf(not run_long_tests, "Long test case")
    def test_data_model_specifics(self):

        for dm in fmk.dm_list:
            try:
                dm.load_data_model(fmk._name2dm)
            except:
                print("\n*** WARNING: Data Model '{:s}' not tested because" \
                      " the loading process has failed ***\n".format(dm.name))
                raise

            print("Validating '{:s}' Data Model".format(dm.name))

            ok = dm.validation_tests()
            self.assertTrue(ok)

    def test_generic_generators(self):
        dm = fmk.get_data_model_by_name('mydf')
        dm.load_data_model(fmk._name2dm)

        for i in range(5):
            d = dm.get_atom('off_gen')
            d.show()
            raw = d.to_bytes()
            print(raw)

            retr_off = raw[-1]
            print('\nRetrieved offset is: %d' % retr_off)

            int_idx = d['off_gen/body$'][0].get_subnode_idx(d['off_gen/body/int'][0])
            off = int_idx * 3 + 10  # +10 for 'prefix' delta
            self.assertEqual(off, retr_off)

    @unittest.skipIf(ignore_data_model_specifics, "USB specific test cases")
    def test_usb_specifics(self):

        dm = fmk.get_data_model_by_name('usb')
        dm.build_data_model()

        msd_conf = dm.get_atom('CONF')
        msd_conf.set_current_conf('MSD', recursive=True)
        msd_conf.show()

        self.assertEqual(len(msd_conf.to_bytes()), 32)

    @unittest.skipIf(ignore_data_model_specifics, "PNG specific test cases")
    def test_png_specifics(self):

        dm = fmk.get_data_model_by_name('png')
        dm.build_data_model()

        png_dict = dm.import_file_contents(extension='png')
        for n, png in png_dict.items():

            png_buff = png.to_bytes()
            png.show(raw_limit=400)

            with open(gr.workspace_folder + 'TEST_FUZZING_' + n, 'wb') as f:
                f.write(png_buff)

            filename = os.path.join(dm.get_import_directory_path(), n)
            with open(filename, 'rb') as orig:
                orig_buff = orig.read()

            if png_buff == orig_buff:
                print("\n*** Builded Node ('%s') match the original image" % png.name)
            else:
                print("\n*** ERROR: Builded Node ('%s') does not match the original image!" % png.name)

            self.assertEqual(png_buff, orig_buff)

    @unittest.skipIf(ignore_data_model_specifics, "JPG specific test cases")
    def test_jpg_specifics(self):

        dm = fmk.get_data_model_by_name('jpg')
        dm.build_data_model()

        jpg_dict = dm.import_file_contents(extension='jpg')
        for n, jpg in jpg_dict.items():

            jpg_buff = jpg.to_bytes()

            with open(gr.workspace_folder + 'TEST_FUZZING_' + n, 'wb') as f:
                f.write(jpg_buff)

            filename = os.path.join(dm.get_import_directory_path(), n)
            with open(filename, 'rb') as orig:
                orig_buff = orig.read()

            if jpg_buff == orig_buff:
                print("\n*** Builded Node ('%s') match the original image" % jpg.name)
            else:
                print("\n*** ERROR: Builded Node ('%s') does not match the original image!" % jpg.name)
                print('    [original size={:d}, generated size={:d}]'.format(len(orig_buff), len(jpg_buff)))

            self.assertEqual(jpg_buff, orig_buff)

    @unittest.skipIf(ignore_data_model_specifics, "Tutorial specific test cases, cover various construction")
    def test_tuto_specifics(self):
        '''Tutorial specific test cases, cover various data model patterns and
        absorption.'''

        dm = fmk.get_data_model_by_name('mydf')
        dm.load_data_model(fmk._name2dm)

        data_id_list = ['misc_gen', 'len_gen', 'exist_cond', 'separator', 'AbsTest', 'AbsTest2',
                        'regex']
        loop_cpt = 5

        for data_id in data_id_list:
            d = dm.get_atom(data_id)

            for i in range(loop_cpt):
                d_abs = dm.get_atom(data_id)
                d_abs.set_current_conf('ABS', recursive=True)

                d.show()
                raw_data = d.to_bytes()

                print('-----------------------')
                print('Original Data:')
                print(repr(raw_data))
                print('-----------------------')

                status, off, size, name = d_abs.absorb(raw_data, constraints=AbsFullCsts())

                raw_data_abs = d_abs.to_bytes()
                print('-----------------------')
                print('Absorbed Data:')
                print(repr(raw_data_abs))
                print('-----------------------')

                print('-----------------------')
                print('Absorb Status: status=%s, off=%d, sz=%d, name=%s' % (status, off, size, name))
                print(' \_ length of original data: %d' % len(raw_data))
                print(' \_ remaining: %r' % raw_data[size:])
                print('-----------------------')

                self.assertEqual(status, AbsorbStatus.FullyAbsorbed)
                self.assertEqual(raw_data, raw_data_abs)

                d.unfreeze()

    @unittest.skipIf(ignore_data_model_specifics, "ZIP specific test cases")
    def test_zip_specifics(self):

        dm = fmk.get_data_model_by_name('zip')
        dm.build_data_model()

        abszip = dm.get_atom('ZIP')
        abszip.set_current_conf('ABS', recursive=True)

        # We generate a ZIP file from the model only (no real ZIP file)
        zip_buff = dm.get_atom('ZIP').to_bytes()
        lg = len(zip_buff)

        # dm.pkzip.show(raw_limit=400)
        # dm.pkzip.reset_state(recursive=True)
        status, off, size, name = abszip.absorb(zip_buff, constraints=AbsNoCsts(size=True, struct=True))
        # abszip.show(raw_limit=400)

        print('\n*** Absorb Status:', status, off, size, name)
        print('*** Length of generated ZIP:', lg)

        self.assertEqual(status, AbsorbStatus.FullyAbsorbed)

        abs_buff = abszip.to_bytes()
        if zip_buff == abs_buff:
            print("\n*** Absorption of the generated node has worked!")
        else:
            print("\n*** ERROR: Absorption of the generated node has NOT worked!")

        self.assertEqual(zip_buff, abs_buff)

        # abszip.show()
        flen_before = len(abszip['ZIP/file_list/file/data'][0].to_bytes())
        print('file data len before: ', flen_before)

        off_before = abszip['ZIP/cdir/cdir_hdr:2/file_hdr_off']
        # Needed to avoid generated ZIP files that have less than 2 files.
        if off_before is not None:
            # Make modification of the ZIP and verify that some other ZIP
            # fields are automatically updated
            off_before = off_before[0].to_bytes()
            print('offset before:', off_before)
            csz_before = abszip['ZIP/file_list/file/header/common_attrs/compressed_size'][0].to_bytes()
            print('compressed_size before:', csz_before)

            abszip['ZIP/file_list/file/header/common_attrs/compressed_size'][0].set_current_conf('MAIN')

            NEWVAL = b'TEST'
            print(abszip['ZIP/file_list/file/data'][0].absorb(NEWVAL, constraints=AbsNoCsts()))

            flen_after = len(abszip['ZIP/file_list/file/data'][0].to_bytes())
            print('file data len after: ', flen_after)

            abszip.unfreeze(only_generators=True)
            abszip.get_value()

            # print('\n******\n')
            # abszip.show()

            off_after = abszip['ZIP/cdir/cdir_hdr:2/file_hdr_off'][0].to_bytes()
            print('offset after: ', off_after)
            csz_after = abszip['ZIP/file_list/file/header/common_attrs/compressed_size'][0].to_bytes()
            print('compressed_size after:', csz_after)

            # Should not be equal in the general case
            self.assertNotEqual(off_before, off_after)
            # Should be equal in the general case
            self.assertEqual(struct.unpack('<L', off_before)[0] - struct.unpack('<L', off_after)[0],
                             flen_before - flen_after)
            self.assertEqual(struct.unpack('<L', csz_after)[0], len(NEWVAL))

        zip_dict = dm.import_file_contents(extension='zip')
        for n, pkzip in zip_dict.items():

            zip_buff = pkzip.to_bytes()
            # pkzip.show(raw_limit=400)

            with open(gr.workspace_folder + 'TEST_FUZZING_' + n, 'wb') as f:
                f.write(zip_buff)

            filename = os.path.join(dm.get_import_directory_path(), n)
            with open(filename, 'rb') as orig:
                orig_buff = orig.read()

            err_msg = "Some ZIP are not supported (those that doesn't store compressed_size" \
                      " in the file headers)"
            if zip_buff == orig_buff:
                print("\n*** Builded Node ('%s') match the original image" % pkzip.name)
            else:
                print("\n*** ERROR: Builded Node ('%s') does not match the original image!" % pkzip.name)
                # print(err_msg)

            self.assertEqual(zip_buff, orig_buff, msg=err_msg)


@ddt.ddt
class TestDataModelHelpers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fmk.run_project(name='tuto', tg_ids=0, dm_name='mydf')

    @ddt.data("HTTP_version_regex", ("HTTP_version_regex", 17), ("HTTP_version_regex", "whatever"))
    def test_regex(self, regex_node_name):
        HTTP_version_classic = \
            {'name': 'HTTP_version_classic',
             'contents': [
                 {'name': 'HTTP_name', 'contents': String(values=["HTTP"])},
                 {'name': 'slash', 'contents': String(values=["/"])},
                 {'name': 'major_version_digit', 'contents': String(size=1, values=["0", "1", "2", "3", "4",
                                                                                      "5", "6", "7", "8", "9"])},

                 {'name': '.', 'contents': String(values=["."])},
                 {'name': 'minor_version_digit', 'clone': 'major_version_digit'},
             ]}

        HTTP_version_regex = \
            {'name': regex_node_name, 'contents': "(HTTP)(/)(0|1|2|3|4|5|6|7|8|9)(\.)(0|1|2|3|4|5|6|7|8|9)"}

        mb = NodeBuilder()
        node_classic = mb.create_graph_from_desc(HTTP_version_classic)
        node_classic.make_determinist(recursive=True)

        mb = NodeBuilder()
        node_regex = mb.create_graph_from_desc(HTTP_version_regex)
        node_regex.make_determinist(recursive=True)

        node_regex.show()
        node_classic.show()

        self.assertEqual(node_regex.to_bytes(), node_classic.to_bytes())

    @ddt.data(('(HTTP)/[0-9]\.[0-9]|this|is|it[0123456789]', [5, 1, 2]),
              ('this|.is|it|[0123456789]', [1, 2, 1, 1]),
              ('|this|is|it[0123456789]|\dyes\-', [1, 2, 2]))
    @ddt.unpack
    def test_regex_shape(self, regexp, shapes):
        revisited_HTTP_version = {'name': 'HTTP_version_classic', 'contents': regexp}

        mb = NodeBuilder()
        node = mb.create_graph_from_desc(revisited_HTTP_version)

        excluded_idx = []

        while True:
            node_list, idx = node.cc._get_next_heavier_component(node.subnodes_order, excluded_idx=excluded_idx)
            if len(node_list) == 0:
                break
            excluded_idx.append(idx)
            print(node_list)
            try:
                idx = shapes.index(len(node_list[0][1]))
            except ValueError:
                print(len(node_list[0][1]))
                self.fail()
            else:
                del shapes[idx]

        self.assertEqual(len(shapes), 0)

    def test_xml_helpers(self):

        xml5_samples = [
            '<?xml encoding="UTF-8" version="1.0" standalone="no"?>\n<command name="LOGIN">'
            '\n<LOGIN backend="ssh" auth="cert">\n<msg_id>\n0\n</msg_id>\n<username>\nMyUser'
            '\n</username>\n<password>\nplopi\n</password>\n</LOGIN>\n</command>',
            '<?xml  \t encoding="UTF-16"   standalone="yes"\n version="7.9"?>\n  <command name="LOGIN">'
            '\n<LOGIN backend="ssh" auth="cert">\t \n<msg_id>\n56\n\t\n</msg_id>\n<username>\nMyUser'
            '\n</username>\n<password>\nohohoh!  \n</password>\n</LOGIN>\n</command>']


        for idx, sample in enumerate(xml5_samples):
            xml_atom = fmk.dm.get_atom('xml5')
            status, off, size, name = xml_atom.absorb(sample, constraints=AbsFullCsts())

            print('{:s} Absorb Status: {:d}, {:d}, {:s}'.format(status, off, size, name))
            print(' \_ length of original data: {:d}'.format(len(sample)))
            print(' \_ remaining: {!r}'.format(sample[size:size+1000]))

            xml_atom.show()
            assert status == AbsorbStatus.FullyAbsorbed

        data_sizes = [211, 148, 183]
        for i in range(100):
            # fmk.lg.export_raw_data = True
            data = fmk.process_data(
                ['XML5', ('tWALK', UI(path='xml5/command/start-tag/content/attr1/cmd_val',
                                      consider_sibbling_change=False))])
            if data is None:
                break

            go_on = fmk.send_data_and_log([data])
            bstr_len = len(data.to_bytes())
            assert bstr_len == data_sizes[i], f'i: {i}, len(data.to_bytes()): {bstr_len}'

            if not go_on:
                raise ValueError
        else:
            raise ValueError

        assert i == 3

        raise ValueError

        specific_cases_checked = False
        for i in range(100):
            data = fmk.process_data(
                ['XML5', ('tTYPE', UI(path='xml5/command/LOGIN/start-tag/content/attr1/val'))])
            if data is None:
                break
            node_to_check = data.content['xml5/command/LOGIN/start-tag/content/attr1/val'][0]
            if node_to_check.to_bytes() == b'None':
                # one case should trigger this condition
                specific_cases_checked = True
            go_on = fmk.send_data_and_log([data])
            if not go_on:
                raise ValueError
        else:
            raise ValueError

        # number of test cases
        self.assertEqual(i, 22)
        self.assertTrue(specific_cases_checked)

class TestFMK(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fmk.run_project(name='tuto', tg_ids=0, dm_name='mydf')
        fmk.prj.reset_target_mappings()

    def setUp(self):
        fmk.reload_all(tg_ids=[0])
        fmk.prj.reset_target_mappings()

    def test_generic_disruptors_01(self):
        dmaker_type = 'TESTNODE'
        # fmk.cleanup_dmaker(dmaker_type=dmaker_type, reset_existing_seed=True)

        gen_disruptors = fmk._generic_tactics.disruptor_types
        print('\n-=[ GENERIC DISRUPTORS ]=-\n')
        print(gen_disruptors)

        for dis in gen_disruptors:
            if dis in ['CROSS']:
                continue

            print("\n\n---[ Tested Disruptor %r ]---" % dis)
            if dis == 'EXT':
                act = [dmaker_type, (dis, UI(cmd='/bin/cat', file_mode=True))]
                d = fmk.process_data(act)
            else:
                act = [dmaker_type, dis]
                d = fmk.process_data(act)
            if d is not None:
                fmk._log_data(d)
                print("\n---[ Pretty Print ]---\n")
                d.show()
                fmk.cleanup_dmaker(dmaker_type=dmaker_type, reset_existing_seed=True)
            else:
                raise ValueError("\n***WARNING: the sequence {!r} returns {!r}!".format(act, d))

        fmk.cleanup_all_dmakers(reset_existing_seed=True)

    def test_separator_disruptor(self):
        for i in range(100):
            d = fmk.process_data(['SEPARATOR', 'tSEP'])
            if d is None:
                break
            fmk._setup_new_sending()
            fmk._log_data(d)

        self.assertGreater(i, 2)

    def test_struct_disruptor(self):

        idx = 0
        expected_idx = 6

        expected_outcomes = [b'A1', b'A2', b'A3$ A32_VALID $', b'A3T\x0f\xa0\x00\n$ A32_VALID $',
                             b'A3T\x0f\xa0\x00\n*1*0*', b'A1']
        expected_outcomes_24_alt = [b'A3$ A32_INVALID $', b'A3T\x0f\xa0\x00\n$ A32_INVALID $']

        outcomes = []

        act = [('EXIST_COND', UI(determinist=True)), ('tWALK', UI(consider_sibbling_change=False)), 'tSTRUCT']
        for i in range(4):
            for j in range(10):
                d = fmk.process_data(act)
                if d is None:
                    print('--> Exiting (need new input)')
                    break
                fmk._setup_new_sending()
                fmk._log_data(d)
                outcomes.append(d.to_bytes())
                d.show()
                idx += 1

        self.assertEqual(outcomes[:2], expected_outcomes[:2])
        self.assertTrue(outcomes[2:4] == expected_outcomes[2:4] or outcomes[2:4] == expected_outcomes_24_alt)
        self.assertEqual(outcomes[-2:], expected_outcomes[-2:])
        self.assertEqual(idx, expected_idx)

        print('\n****\n')

        expected_idx = 10
        idx = 0
        act = [('SEPARATOR', UI(determinist=True)), ('tSTRUCT', UI(deep=True))]
        for j in range(10):
            d = fmk.process_data(act)
            if d is None:
                print('--> Exiting (need new input)')
                break
            fmk._setup_new_sending()
            fmk._log_data(d)
            outcomes.append(d.to_bytes())
            d.show()
            idx += 1

        self.assertEqual(idx, expected_idx)

    def test_typednode_disruptor(self):

        idx = 0
        expected_idx = 13

        expected_outcomes = []
        outcomes = []

        act = ['OFF_GEN', ('tTYPE', UI(min_node_tc=1, max_node_tc=4))]
        for j in range(100):
            d = fmk.process_data(act)
            if d is None:
                print('--> Exiting (need new input)')
                break
            fmk._setup_new_sending()
            fmk._log_data(d)
            outcomes.append(d.to_bytes())
            d.show()
            idx += 1

        self.assertEqual(idx, expected_idx)

    def test_operator_1(self):

        fmk.reload_all(tg_ids=[7,8])

        fmk.launch_operator('MyOp', user_input=UI(max_steps=100, mode=1))
        last_data_id = max(fmk.lg._last_data_IDs.values())
        print('\n*** Last data ID: {:d}'.format(last_data_id))
        fmkinfo = fmk.fmkDB.execute_sql_statement(
            "SELECT CONTENT FROM FMKINFO "
            "WHERE DATA_ID == {data_id:d} "
            "ORDER BY ERROR DESC;".format(data_id=last_data_id)
        )
        self.assertTrue(fmkinfo)
        for info in fmkinfo:
            if 'Exhausted data maker' in info[0]:
                break
        else:
            raise ValueError('the data maker should be exhausted and trigger the end of the operator')

    @unittest.skipIf(not run_long_tests, "Long test case")
    def test_operator_2(self):

        fmk.reload_all(tg_ids=[7,8])

        myop = fmk.get_operator(name='MyOp')
        fmk.launch_operator('MyOp')

        fbk = fmk.last_feedback_gate.get_feedback_from(myop)[0]['content']
        print(fbk)
        self.assertIn(b'You win!', fbk)

        fmk.launch_operator('MyOp')
        fbk = fmk.last_feedback_gate.get_feedback_from(myop)[0]['content']
        print(fbk)
        self.assertIn(b'You loose!', fbk)

    def test_scenario_infra_01a(self):

        print('\n*** test scenario SC_NO_REGEN via _send_data()')

        base_qty = 0
        for i in range(100):
            data = fmk.process_data(['SC_NO_REGEN'])
            data_list = fmk._send_data([data])  # needed to make the scenario progress
            if not data_list:
                base_qty = i
                break
        else:
            raise ValueError

        err_list = fmk.get_error()
        code_vector = [str(e) for e in err_list]
        print('\n*** Retrieved error code vector: {!r}'.format(code_vector))

        self.assertEqual(code_vector, ['DataUnusable', 'HandOver', 'DataUnusable', 'HandOver',
                                       'DPHandOver', 'NoMoreData'])
        self.assertEqual(base_qty, 51)

        print('\n*** test scenario SC_AUTO_REGEN via _send_data()')

        for i in range(base_qty * 3):
            data = fmk.process_data(['SC_AUTO_REGEN'])
            data_list = fmk._send_data([data])
            if not data_list:
                raise ValueError

    @unittest.skipIf(not run_long_tests, "Long test case")
    def test_scenario_infra_01b(self):

        print('\n*** test scenario SC_NO_REGEN via send_data_and_log()')
        # send_data_and_log() is used to stimulate the framework in more places.

        base_qty = 0
        for i in range(100):
            data = fmk.process_data(['SC_NO_REGEN'])
            go_on = fmk.send_data_and_log([data])
            if not go_on:
                base_qty = i
                break
        else:
            raise ValueError

        err_list = fmk.get_error()
        code_vector = [str(e) for e in err_list]
        full_code_vector = [(str(e), e.msg) for e in err_list]
        print('\n*** Retrieved error code vector: {!r}'.format(full_code_vector))


        self.assertEqual(code_vector, ['DataUnusable', 'HandOver', 'DataUnusable', 'HandOver',
                                       'DPHandOver', 'NoMoreData'])
        self.assertEqual(base_qty, 51)

        print('\n*** test scenario SC_AUTO_REGEN via send_data_and_log()')

        for i in range(base_qty * 3):
            data = fmk.process_data(['SC_AUTO_REGEN'])
            go_on = fmk.send_data_and_log([data])
            if not go_on:
                raise ValueError


    @unittest.skipIf(not run_long_tests, "Long test case")
    def test_scenario_infra_02(self):

        fmk.reload_all(tg_ids=[1])  # to collect feedback from monitoring probes
        fmk.prj.reset_target_mappings()
        fmk.prj.map_targets_to_scenario('ex1', {0: 1, 1: 1, None: 1})
        fmk.prj.map_targets_to_scenario('ex2', {0: 1, 1: 1, None: 1})

        print('\n*** Test scenario EX1')

        data = None
        prev_data = None
        now = datetime.datetime.now()
        for i in range(10):
            prev_data = data
            data = fmk.process_data(['SC_EX1'])
            ok = fmk.send_data_and_log([data])  # needed to make the scenario progress
            if not ok:
                raise ValueError

        exec_time = (datetime.datetime.now() - now).total_seconds()

        self.assertEqual(prev_data.to_bytes(), data.to_bytes())
        self.assertGreater(exec_time, 5)

        print('\n\n*** Test SCENARIO EX2 ***\n\n')

        data = None
        steps = []
        for i in range(4):
            data = fmk.process_data(['SC_EX2'])
            if i == 3:
                self.assertTrue(data is None)
            if data is not None:
                steps.append(data.origin.current_step)
                ok = fmk.send_data_and_log([data])  # needed to make the scenario progress
                if not ok:
                    raise ValueError
            if i == 0:
                self.assertTrue(bool(fmk._task_list))

        for idx, s in enumerate(steps):
            print('\n[{:d}]-----'.format(idx))
            print(s)
            print('-----')

        self.assertNotEqual(steps[-1], steps[-2])
        self.assertFalse(bool(fmk._task_list))

    def test_scenario_infra_03(self):
        steps = []
        for i in range(6):
            data = fmk.process_data(['SC_EX3'])
            steps.append(data.origin.current_step)
            ok = fmk.send_data_and_log([data])  # needed to make the scenario progress
            if not ok:
                raise ValueError

        for idx, s in enumerate(steps):
            print('\n[{:d}]-----'.format(idx))
            print(s)
            print('-----')

        self.assertEqual(steps[3], steps[5])
        self.assertNotEqual(steps[5], steps[1])
        self.assertEqual(steps[2], steps[4])
        self.assertEqual(steps[0], steps[2])

    def test_scenario_infra_04(self):

        def walk_scenario(name, iter_num):
            print('\n===== run scenario {:s} ======\n'.format(name))
            steps = []
            scenario = None
            for i in range(iter_num):
                data = fmk.process_data([name])
                if i == 1:
                    scenario = data.origin
                steps.append(data.origin.current_step)
                ok = fmk.send_data_and_log([data])  # needed to make the scenario progress
                if not ok:
                    raise ValueError

            for idx, s in enumerate(steps):
                print('\n[{:d}]-----'.format(idx))
                print(s)
                print('-----')

            return scenario, steps

        scenario, steps = walk_scenario('SC_TEST', 4)
        print('\n++++ env.cbk_true_cpt={:d} | env.cbk_false_cpt={:d}'
              .format(scenario.env.cbk_true_cpt, 0))
        self.assertEqual(steps[0], steps[-1])
        self.assertEqual(scenario.env.cbk_true_cpt, 2)
        self.assertEqual(str(steps[-2]), '4TG1')

        scenario, steps = walk_scenario('SC_TEST2', 2)
        print('\n++++ env.cbk_true_cpt={:d} | env.cbk_false_cpt={:d}'
              .format(scenario.env.cbk_true_cpt, 0))
        # self.assertEqual(steps[0], steps[-1])
        self.assertEqual(scenario.env.cbk_true_cpt, 1)
        self.assertEqual(str(steps[-1]), '4TG1')

        scenario, steps = walk_scenario('SC_TEST3', 2)
        print('\n++++ env.cbk_true_cpt={:d} | env.cbk_false_cpt={:d}'
              .format(scenario.env.cbk_true_cpt, 0))
        # self.assertEqual(steps[0], steps[-1])
        self.assertEqual(scenario.env.cbk_true_cpt, 2)
        self.assertEqual(str(steps[-1]), '4TG1')

        scenario, steps = walk_scenario('SC_TEST4', 2)
        print('\n++++ env.cbk_true_cpt={:d} | env.cbk_false_cpt={:d}'
              .format(scenario.env.cbk_true_cpt, scenario.env.cbk_false_cpt))
        # self.assertEqual(steps[0], steps[-1])
        self.assertEqual(scenario.env.cbk_true_cpt, 1)
        self.assertEqual(scenario.env.cbk_false_cpt, 4)
        self.assertEqual(str(steps[-1]), '4DEFAULT')

    @unittest.skipIf(not run_long_tests, "Long test case")
    def test_evolutionary_fuzzing(self):
        fmk.reload_all(tg_ids=[7])
        fmk.process_data_and_send(DataProcess(['SC_EVOL1']), verbose=False, max_loop=-1)
        fmk.process_data_and_send(DataProcess(['SC_EVOL2']), verbose=False, max_loop=-1)


class TestConstBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fmk.run_project(name='tuto', tg_ids=0, dm_name='mydf')
        fmk.prj.reset_target_mappings()
        fmk.disable_fmkdb()

    def setUp(self):
        fmk.reload_all(tg_ids=[0])
        fmk.prj.reset_target_mappings()

    def test_twalkcsp_operator(self):
        idx = 0
        expected_idx = 8
        expected_outcomes = [b'x = 3y + z (x:123, y:40, z:3)',
                             b'x = 3y + z (x:120, y:39, z:3)',
                             b'x = 3y + z (x:122, y:40, z:2)',
                             b'x = 3y + z (x:121, y:40, z:1)',
                             b'x = 3y + z [x:123, y:40, z:3]',
                             b'x = 3y + z [x:120, y:39, z:3]',
                             b'x = 3y + z [x:122, y:40, z:2]',
                             b'x = 3y + z [x:121, y:40, z:1]']
        outcomes = []

        act = [('CSP', UI(determinist=True)), ('tWALKcsp')]
        for j in range(20):
            d = fmk.process_data(act)
            if d is None:
                print('--> Exit (need new input)')
                break
            fmk._setup_new_sending()
            fmk._log_data(d)
            outcomes.append(d.to_bytes())
            # d.show()
            idx += 1

        self.assertEqual(idx, expected_idx)
        self.assertEqual(outcomes, expected_outcomes)

    def test_twalk_operator(self):
        idx = 0
        expected_idx = 13
        expected_outcomes = [b'x = 3y + z (x:123, y:40, z:3)',
                             b'x = 3y + z (X:123, y:40, z:3)',
                             b'x = 3y + z (x:123, y:40, z:3)', # redundancy
                             b'x = 3y + z (x:124, y:40, z:3)',
                             b'x = 3y + z (x:125, y:40, z:3)',
                             b'x = 3y + z (x:126, y:40, z:3)',
                             b'x = 3y + z (x:127, y:40, z:3)',
                             b'x = 3y + z (x:128, y:40, z:3)',
                             b'x = 3y + z (x:129, y:40, z:3)',
                             b'x = 3y + z (x:130, y:40, z:3)',
                             b'x = 3y + z (x:120, y:39, z:3)',
                             b'x = 3y + z (x:121, y:40, z:1)',
                             b'x = 3y + z (x:122, y:40, z:2)']
        outcomes = []

        act = [('CSP', UI(determinist=True)), ('tWALK', UI(path='csp/variables/x'))]
        for j in range(20):
            d = fmk.process_data(act)
            if d is None:
                print('--> Exit (need new input)')
                break
            fmk._setup_new_sending()
            fmk._log_data(d)
            outcomes.append(d.to_bytes())
            # d.show()
            idx += 1

        self.assertEqual(idx, expected_idx)
        self.assertEqual(outcomes, expected_outcomes)

        idx = 0
        expected_idx = 2
        expected_outcomes = [b'x = 3y + z [x:123, y:40, z:3]',
                             b'x = 3y + z (x:123, y:40, z:3)']
        outcomes = []

        act = [('CSP', UI(determinist=True)), ('tWALK', UI(path='csp/delim_1'))]
        for j in range(20):
            d = fmk.process_data(act)
            if d is None:
                print('--> Exit (need new input)')
                break
            fmk._setup_new_sending()
            fmk._log_data(d)
            outcomes.append(d.to_bytes())
            # d.show()
            idx += 1

        self.assertEqual(idx, expected_idx)
        self.assertEqual(outcomes, expected_outcomes)


    def test_tconst_operator(self):
        idx = 0
        expected_idx = 362
        expected_outcomes = [b'x = 3y + z (x:123, y:40, z:3-',
                             b'x = 3y + z [x:123, y:40, z:3)',
                             b'x = 3y + z [x:123, y:40, z:3-',
                             b'x = 3y + z (x:130, y:40, z:3)',
                             b'x = 3y + z (x:130, y:39, z:3)',
                             b'x = 3y + z (x:130, y:38, z:3)']
        outcomes = []

        act = [('CSP', UI(determinist=True)), ('tCONST')]
        for j in range(500):
            d = fmk.process_data(act)
            if d is None:
                print('--> Exit (need new input)')
                break
            fmk._setup_new_sending()
            fmk._log_data(d)
            outcomes.append(d.to_bytes())
            # d.show()
            idx += 1

        self.assertEqual(idx, expected_idx)
        self.assertEqual(outcomes[:6], expected_outcomes)
