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

from fuddly.framework.data_model import *
from fuddly.framework.global_resources import *
from fuddly.framework.node_builder import NodeBuilder
from fuddly.framework.value_types import *

markers = {
    'SOF': {0: 0xFFC0,
            1: 0xFFC1,
            2: 0xFFC2,
            3: 0xFFC3},
    'DHT': 0xFFC4,
    'DAC': 0xFFCC,
    'SOI': 0xFFD8,
    'SOE': 0xFFD9,
    'SOS': 0xFFDA,
    'DQT': 0xFFDB,
    'DNL': 0xFFDC,
    'JFIF': 0xFFE0,
    'EXIF': 0xFFE1,
    'COM': 0xFFFE,
    }


class JPG_DataModel(DataModel):

    file_extension = 'jpg'
    name = 'jpg'

    def _atom_absorption_additional_actions(self, atom):
        x = atom['.*/SOF_hdr/X'][0].get_raw_value()
        y = atom['.*/SOF_hdr/Y'][0].get_raw_value()
        d_priv = {'height':y, 'width':x}
        atom.set_private(d_priv)
        msg = "add private data: size [x:{:d}, y:{:d}]".format(x, y)
        return atom, msg

    def build_data_model(self):

        jpg_desc = \
        {'name': 'jpg',
         'contents': [
             {'name': 'before_SOF',
              'contents': String(size=0),
              'absorb_csts': AbsNoCsts(),
              'set_attrs': MH.Attr.Abs_Postpone,
              'mutable': False},

             {'name': 'SOF_hdr',
              'contents': [
                  {'name': 'F_marker',
                   'contents': UINT16_be(values=[m for m in markers['SOF'].values()])},
                  {'name': 'Lf',
                   'contents': LEN(vt=UINT16_be, base_len=8),
                   'node_args': 'F_CompGroup',
                   'alt': [
                       {'conf': 'ABS',
                        'contents': UINT16_be()}
                   ]},
                  {'name': 'P',
                   'contents': UINT8(values=[8,12])},
                  {'name': 'Y',
                   'contents': UINT16_be(max=65535),
                   'specific_fuzzy_vals': [65500]},
                  {'name': 'X',
                   'contents': UINT16_be(min=1, max=65535)},
                  {'name': 'Nf',
                   'contents': UINT8(min=1, max=255)},
                  {'name': 'F_CompGroup',
                   'custo_clear': MH.Custo.NTerm.MutableClone,
                   'contents': [
                       {'name': 'F_Comp',
                        'qty_from': 'Nf',
                        'contents': [
                           {'name': 'Cf',
                            'contents': UINT8(min=0, max=255)},
                           {'name': 'H&V',
                            'contents': BitField(subfield_sizes=[4,4], endian=VT.BigEndian,
                                                 subfield_val_extremums=[[1,4], [1,4]],
                                                 subfield_descs=['H sampling', 'V sampling'])},
                           {'name': 'Tq',
                            'contents': UINT8(min=0, max=3)},
                       ]}
                   ]},
              ]},

             {'name': 'between_SOF_SOS',
              'contents': String(),
              'random': True,
              'absorb_csts': AbsNoCsts(),
              'set_attrs': MH.Attr.Abs_Postpone,
              'mutable': False},

             {'name': 'SOS_hdr',
              'contents': [
                  {'name': 'S_marker',
                   'contents': UINT16_be(values=[markers['SOS']])},
                  {'name': 'Ls',
                   'contents': LEN(vt=UINT16_be, base_len=6),
                   'node_args': 'S_CompGroup',
                   'alt': [
                       {'conf': 'ABS',
                        'contents': UINT16_be()}
                   ]},
                  {'name': 'Ns',
                   'contents': UINT8(min=1, max=4)},
                  {'name': 'S_CompGroup',
                   'custo_clear': MH.Custo.NTerm.MutableClone,
                   'contents': [
                       {'name': 'S_Comp',
                        'qty_from': 'Ns',
                        'contents': [
                            {'name': 'Cs',
                             'contents': UINT8()},
                            {'name': 'Td&Ta',
                             'contents': BitField(subfield_sizes=[4, 4], endian=VT.BigEndian,
                                                  subfield_val_extremums=[[0, 3], [0, 3]],
                                                  subfield_descs=['DC entropy', 'AC entropy'])},
                        ]}
                   ]},
                  {'name': 'Ss',
                   'contents': UINT8(min=0, max=63)},
                  {'name': 'Se',
                   'contents': UINT8(min=0, max=63)},
                  {'name': 'Ah&Al',
                   'contents': BitField(subfield_sizes=[4, 4], endian=VT.BigEndian,
                                        subfield_val_extremums=[[0, 13], [0, 13]],
                                        subfield_descs=['approx high', 'approx low'])},
              ]},

             {'name': 'afterSOS',
              'mutable': False,
              'contents': String(min_sz=0),
              'absorb_csts': AbsNoCsts()}
         ]}

        mb = NodeBuilder(delayed_jobs=True)
        jpg = mb.create_graph_from_desc(jpg_desc)

        self.register(jpg)

        jpg_abs = jpg.get_clone(new_env=True)
        jpg_abs.set_current_conf('ABS', recursive=True)
        self.register_atom_for_decoding(jpg_abs,
                                        absorb_constraints=AbsNoCsts(size=True, struct=True,
                                                                     content=True))


data_model = JPG_DataModel()

