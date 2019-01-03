################################################################################
#
#  Copyright 2018 Eric Lacombe <eric.lacombe@security-labs.org>
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

from framework.value_types import *
from framework.data_model import *
from framework.encoders import *

class MyProto_DataModel(DataModel):

    name = 'myproto'

    def build_data_model(self):

        req_desc = \
        {'name': 'req',
         'contents': [
             {'name': 'header',
              'contents': BitField(subfield_sizes=[5,7,4], endian=VT.BigEndian,
                                   subfield_values=[[0], [1,10,20], [1,2,3]],
                                   subfield_descs=['reserved', 'cmd', 'version'])},

             {'name': 'init',
              'exists_if': (BitFieldCondition(sf=1, val=[1]), 'header'),
              'contents': TIMESTAMP("%H:%M:%S"),
              'absorb_csts': AbsFullCsts(contents=False)},

             {'name': 'register',
              'custo_clear': MH.Custo.NTerm.FrozenCopy,
              'exists_if': (BitFieldCondition(sf=1, val=10), 'header'),
              'contents': [
                  {'name': 'payload',
                   'contents': [
                       {'name': 'file_qty',
                        'contents': UINT16_be(min=2, max=8)},
                       {'name': 'file_entry',
                        'qty_from': 'file_qty',
                        'contents': [
                            {'name': 'filename',
                             'contents': Filename(min_sz=1, max_sz=15, alphabet='abcdef')},
                            {'name': 'len',
                             'contents': UINT32_be()},
                            {'name': 'content',
                             'sync_size_with': 'len',
                             'contents': String(min_sz=20, max_sz=50, alphabet=string.printable, codec='latin-1')},
                            {'name': 'crc32',
                             'contents': CRC(vt=UINT32_be),
                             'node_args': ['filename', 'content']},
                       ]}
                   ]}
              ]},

             {'name': 'zregister',
              'exists_if/and': [(BitFieldCondition(sf=1, val=20), 'header'),
                                (BitFieldCondition(sf=2, val=3), 'header')],
              'encoder': GZIP_Enc(6),
              'contents': [
                  {'name': 'zpayload', 'clone': 'payload'}
              ]},

         ]}

        req_atom = NodeBuilder(add_env=True).create_graph_from_desc(req_desc)

        init_atom = req_atom.get_clone('init', ignore_frozen_state=True)
        init_atom['.*/header'].set_subfield(idx=1, val=1)
        init_atom.freeze()
        register_atom = req_atom.get_clone('register', ignore_frozen_state=True)
        register_atom['.*/header'].set_subfield(idx=1, val=10)
        register_atom.freeze()
        zregister_atom = req_atom.get_clone('zregister', ignore_frozen_state=True)
        zregister_atom['.*/header'].set_subfield(idx=1, val=20)
        zregister_atom['.*/header'].set_subfield(idx=2, val=3)
        zregister_atom.freeze()

        self.register(req_atom, init_atom, register_atom, zregister_atom)

    def validation_tests(self):

        data = [b'\x10 17:20:47',

                b"\x11@\x00\x02dfbdfabedcabeb\x00\x00\x00\x19%#H>Rsj!8B@{"
                b"N\t<`r]6\tBH%4Y\x172\xec\x81cfeeeddccbdeebd\x00\x00\x00.\nX25P=llMil/L=* "
                b";vV+Gn4]DK]hD O.[o);7'7YoY#% \\>\x95H5",

                b'2\x80x\x9cc`J\x01\x81\xe44\x06\x06\x06\xcd\x1c\x05\xbfH\xdft\rGE\xb7\x02\xb7'
                b'"\xeb\x84\x84\xd4X\xfddg_w\x17/\xe5\xaa\x88p\xf7T\xd5\xc2\xb0J+\x03;['
                b'e\xfd\x95\x93.\x7fMJIIM\x01\xeaRU\x89\x88\xe3\xb2,'
                b'\x0e\xd6\xcdt4\xf7\r-\xf5w\x0c\xe7\xb5\xa9\x0bS56-s\xd3\xe2\xc9pKp\xe2V\xd6\x8e'
                b'\xcexn\xc4\xd5\x05\x00\xae\xc3\x1f\xcf ']

        ok = True

        for d in data:
            atom = self.get_atom('req')
            status, off, size, name = atom.absorb(d, constraints=AbsFullCsts())
            if status != AbsorbStatus.FullyAbsorbed:
                ok = False

            print('Absorb Status: {!r}, {:d}, {:d}, {:s}'.format(status, off, size, name))
            print(' \_ length of original data: {:d}'.format(len(d)))
            print(' \_ remaining: {!r}'.format(d[size:size+1000]))

            atom.show()

        return ok


data_model = MyProto_DataModel()