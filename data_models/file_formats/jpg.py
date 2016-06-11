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
import os
import copy
import re
import functools
import struct

from framework.plumbing import *
from framework.data_model import *
from framework.data_model_helpers import *
from framework.value_types import *
from framework.fuzzing_primitives import *
from framework.basic_primitives import *


markers = {
    'SOF': {0: struct.pack('>H', 0xFFC0),
            1: struct.pack('>H', 0xFFC1),
            2: struct.pack('>H', 0xFFC2),
            3: struct.pack('>H', 0xFFC3)},
    'DHT': struct.pack('>H', 0xFFC4),
    'DAC': struct.pack('>H', 0xFFCC),
    'SOI': struct.pack('>H', 0xFFD8),
    'SOE': struct.pack('>H', 0xFFD9),
    'SOS': struct.pack('>H', 0xFFDA),
    'DQT': struct.pack('>H', 0xFFDB),
    'DNL': struct.pack('>H', 0xFFDC),
    'JFIF': struct.pack('>H', 0xFFE0),
    'EXIF': struct.pack('>H', 0xFFE1),
    'COM': struct.pack('>H', 0xFFFE),
    }


### NEED TO BE REVAMPED
### BY USING ModelHelper()
class JPG_DataModel(DataModel):

    file_extension = 'jpg'
    name = 'jpg'

    def build_data_model(self):
        
        self.jpg_dict = self.import_file_contents(extension='jpg')
        nodes = list(self.jpg_dict.values())
        self.register_nodes(*nodes)

    def absorb(self, buff, idx):

        for k, sof in markers['SOF'].items():
            if not re.search(sof, buff, re.S):
                continue

            g = re.search(b'(?P<before_sof>.*?)(?P<sof>' + sof + b')(?P<after_sof>.*)', buff, re.S)
            if g:
                e_sof_marker = Node('SOF_marker')
                # e.add_conf(conf)
                e_sof_marker.set_values(value_type=UINT16_be(int_list=[struct.unpack('>H', sof)[0]]))
                break
        else:
            return None

        before_sof = g.group('before_sof')
        sof = g.group('sof')
        after_sof = g.group('after_sof')

        e_before_sof = Node('before_SOF')
        #e_before_sof.add_conf(conf)
        e_before_sof.set_values([before_sof])

        Lf, P, Y, X, Nf = struct.unpack_from('>HBHHB', after_sof, 0)

        sof_start_len = struct.calcsize('>HBHHB')

        e_after_sofhdr = Node('after_SOF')
        e_after_sofhdr.set_values([after_sof[Lf:]])

        e_Lf = Node('Lf')
        e_Lf.set_values(value_type=UINT16_be(int_list=[Lf]))
        e_P = Node('P')
        e_P.set_values(value_type=UINT8(int_list=[P]))
        e_X = Node('X')
        e_X.set_values(value_type=UINT16_be(int_list=[X]))
        # We add the maximum image dimension supported by the
        # 'display' program (maybe a JPG standard constraint)
        e_X.cc.set_specific_fuzzy_values([65500])
        e_Y = Node('Y')
        e_Y.set_values(value_type=UINT16_be(int_list=[Y]))
        e_Y.cc.set_specific_fuzzy_values([65500])
        e_Nf = Node('Nf')
        e_Nf.set_values(value_type=UINT8(int_list=[Nf]))

        e_SOF_C_struct = Node('SOF_C_struct')
        sof_comp_len = 3
        l = []
        for i in range(Nf):
            C = struct.unpack_from('B', after_sof, sof_start_len + i*sof_comp_len)[0]
            HV = struct.unpack_from('B', after_sof, sof_start_len + 1 + i*sof_comp_len)[0]
            H = HV >> 4
            V = HV & 0x0F
            Tq = struct.unpack_from('B', after_sof, sof_start_len + 2 + i*sof_comp_len)[0]

            e_C = Node('C%d' % i)
            e_C.set_values(value_type=UINT8(int_list=[C]))
            e_HV = Node('H&V%d' % i)
            e_HV.set_values(value_type=BitField(subfield_sizes=[4,4], subfield_val_lists=[[V], [H]]))
            e_HV.make_determinist()
            e_Tq = Node('Tq%d' % i)
            e_Tq.set_values(value_type=UINT8(int_list=[Tq]))

            l.extend([e_C, e_HV, e_Tq])

        # c_struct.add_conf(conf) TODO: ajouter conf
        e_SOF_C_struct.set_subnodes_basic(l)

        e_sof_hdr = Node('SOF_hdr')
        # e_sof_hdr.add_conf(conf) TODO: ajouter conf
        e_sof_hdr.set_subnodes_basic([e_sof_marker, e_Lf, e_P, e_Y, e_X, e_Nf, e_SOF_C_struct])


        ##
        ## Dissect SOS segment
        ##
        after_sof_seg = after_sof[Lf:]
        subparts = re.search(b'(?P<between_sof_sos>.*?)(?P<sos>' + markers['SOS'] + b')(?P<after_sos>.*)', after_sof_seg, re.S)
        between_sof_sos = subparts.group('between_sof_sos')
        sos = subparts.group('sos')
        after_sos = subparts.group('after_sos')

        before_sos = before_sof + sof + after_sof[:Lf] + between_sof_sos
        e_before_sos = Node('before_SOS')
        e_before_sos.set_values([before_sos])

        e_between_sof_sos = Node('between_SOF_SOS')
        e_between_sof_sos.set_values([between_sof_sos])


        ## BEGIN DISSECTION: SOS segment ##
        e_sos_marker = Node('SOS_marker')
        e_sos_marker.set_values(value_type=UINT16_be(int_list=[struct.unpack('>H', markers['SOS'])[0]]))

        Ls, Ns = struct.unpack_from('>HB', after_sos, 0)
        sos_start_len = struct.calcsize('>HB')

        e_Ls = Node('Ls')
        e_Ls.set_values(value_type=UINT16_be(int_list=[Ls]))
        e_Ns = Node('Ns')
        e_Ns.set_values(value_type=UINT8(int_list=[Ns]))

        e_SOS_C_struct = Node('Comp_params')
        sos_comp_len = 2
        l = []
        for i in range(Ns):
            Cs_val = struct.unpack_from('B', after_sos, sos_start_len + i*sos_comp_len)[0]
            TdTa = struct.unpack_from('B', after_sos, sos_start_len + 1 + i*sos_comp_len)[0]
            Td_val = TdTa >> 4
            Ta_val = TdTa & 0x0F

            e_Cs = Node('C%d' % i)
            e_Cs.set_values(value_type=UINT8(int_list=[Cs_val]))
            e_TdTa = Node('Td&Ta%d' % i)
            e_TdTa.set_values(value_type=BitField(subfield_sizes=[4,4], subfield_val_lists=[[Ta_val], [Td_val]]))
            e_TdTa.make_determinist()
            l.extend([e_Cs, e_TdTa])

        e_SOS_C_struct.set_subnodes_basic(l)

        sos_comp_struct_len = sos_comp_len * Ns

        Ss, Se, Ahl = struct.unpack_from('>BBB', after_sos, sos_start_len + sos_comp_struct_len)
        Ah = Ahl >> 4
        Al = Ahl & 0x0F

        e_Ss = Node('Ss')
        e_Ss.set_values(value_type=UINT8(int_list=[Ss]))
        e_Se = Node('Se')
        e_Se.set_values(value_type=UINT8(int_list=[Se]))
        e_Ahl = Node('Ah&Al%d' % i)
        e_Ahl.set_values(value_type=BitField(subfield_sizes=[4,4], subfield_val_lists=[[Al], [Ah]]))
        e_Ahl.make_determinist()

        e_sos_hdr = Node('SOS_hdr')
        e_sos_hdr.set_subnodes_basic([e_sos_marker, e_Ls, e_Ns, e_SOS_C_struct, e_Ss, e_Se, e_Ahl])
        ## END DISSECTION: SOS segment ##

        e_after_soshdr = Node('afterSOS')
        e_after_soshdr.set_values([after_sos[Ls:]])

        ##
        ## Top Elts
        ##

        if idx == 0:
            jpg_id = 'JPG'
        else:
            jpg_id = 'JPG_{:0>2d}'.format(idx)

        ## In this Node, SOF & SOS segments are dissected
        e_jpg = Node(jpg_id)
        e_jpg.set_subnodes_basic([e_before_sof, e_sof_hdr, e_between_sof_sos, e_sos_hdr, e_after_soshdr])

        d_priv = {'height':Y, 'width':X}
        e_jpg.set_private(d_priv)

        return e_jpg




data_model = JPG_DataModel()

