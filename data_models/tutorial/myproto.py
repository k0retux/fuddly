# -*- coding: utf8 -*-

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
                             'contents': String(min_sz=20, max_sz=50, alphabet=u'éùijklm:;!',
                                                codec='latin-1')},
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
        init_atom.unfreeze(recursive=True)
        register_atom = req_atom.get_clone('register', ignore_frozen_state=True)
        register_atom['.*/header'].set_subfield(idx=1, val=10)
        register_atom.unfreeze(recursive=True)
        zregister_atom = req_atom.get_clone('zregister', ignore_frozen_state=True)
        zregister_atom['.*/header'].set_subfield(idx=1, val=20)
        zregister_atom['.*/header'].set_subfield(idx=2, val=3)
        zregister_atom.unfreeze(recursive=True)

        self.register(req_atom, init_atom, register_atom, zregister_atom)

    def validation_tests(self):

        data = [b'\x10 17:20:47',

                b'!@\x00\x02dffdecbcaab\x00\x00\x00/i\xe9!mkikl!jilmm!\xe9ml\xe9:;;\xe9\xe9'
                b'\xe9kki\xf9!j\xf9j\xf9k\xf9::ji!!m:j:!\xcc\xc0\xc4\xedfab\x00\x00\x00*mmk!i;j'
                b'\xf9\xe9\xe9!il;;m;\xe9!!l;ijklikl!kmlk\xf9!:;;jmmB\x8d8\x11',

                b'2\x80x\x9c%\x8e!\x0e\x02Q\x0cDW`\xf08\xd4\xc7\x82\xc1\xb6\xa7@\xa36\xbbl2\xd36{'
                b',\x8e\xc0\x018\x03\x87\xa8D '
                b'\xea\xf8\x04;y\xf3\xf2\x86\xcd\xbcL\xf3\xb8\x0c\xc3p\xa0jc\x1aQ\xae\xa5\rQ\x91'
                b'\x91"&\x92\xcd\xa3\xcf\xfb;\xfd\xb6\x8c\x1d>1\x85\x9a%\xca\xa4\x1b\n\xe6\xc5,'
                b'U\x83\xabe\x13z\x98"\xcd\x9d\xd7\xe7\x87\xcb\xd4_\xbb\xce\xfd\xd4\xaaR\x9a\x99N'
                b'\xc0\xd7\xed\xeb\xfd\x97\x9e\xa1&*A\xba$M`\x16@R\n\xbd\xa3\xc1\xa2\x05\xe1\x110'
                b'\x96[\xb5\xba<\xd6\xe3\x17\x1c\xe3Sj ']

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