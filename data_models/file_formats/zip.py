################################################################################
#
#  Copyright 2014-2015 Eric Lacombe <eric.lacombe@security-labs.org>
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

from fuzzfmk.data_model import *
from fuzzfmk.value_types import *
from fuzzfmk.data_model_helpers import *

import zlib
import crcmod
import struct

class ZIP_DataModel(DataModel):

    file_extension = 'zip'
    name = 'zip'

    def dissect(self, data, idx):
        
        nm = 'ZIP_{:0>2d}'.format(idx)
        pkzip = self.pkzip.get_clone(nm)
        print("--> Create %s from provided ZIP samples." % nm)
        pkzip.set_current_conf('ABS', recursive=True)
        status, off, size, name = pkzip.absorb(data, constraints=AbsNoCsts(size=True,struct=True))
        # pkzip.show(raw_limit=400)

        print('%s Absorb Status:'%nm, status, off, size, name)
        print(' \_ length of original zip:', len(data))
        print(' \_ remaining:', data[size:])

        return pkzip


    def build_data_model(self):

        crc32_func = crcmod.mkCrcFun(0x104C11DB7, initCrc=0x00000000, xorOut=0xFFFFFFFF)

        def g_crc32(node):
            # crc32 = zlib.crc32(node.get_flatten_value())
            val = crc32_func(node.get_flatten_value()) & 0xFFFFFFFF
            n = Node('cts', value_type=UINT32_le(int_list=[val]))
            n.clear_attr(NodeInternals.Mutable)
            return n


        def g_fhdr_off(nodes, helpers):
            info = helpers.graph_info
            try:
                num, total = info[1]
            except:
                num = 0
            padd_len = len(nodes[0].get_flatten_value())
            off = nodes[1].get_subnode_off(num)
            return Node('cts', value_type=UINT32_le(int_list=[padd_len+off]))

        def g_data_desc(nodes):
            # check 3rd bit of gp_flag
            if nodes[0].get_raw_value() & (1<<2):
                desc = \
                {'name': 'data_desc',
                 'contents': [
                     [nodes[1].get_clone('crc32'), 1],
                     [nodes[2].get_clone('compressed_size'), 1],
                     [nodes[3].get_clone('uncompressed_size'), 1]
                 ]}
                n = ModelHelper().create_graph_from_desc(desc) 
            else:
                n = Node('no_data_desc', value_type=String(size=0))

            return n


        MIN_FILE = 0
        MAX_FILE = 30

        zip_desc = \
        {'name': 'ZIP',
         'contents': [
             {'name': 'start_padding',
              'contents': String(size=0),
              'qty': (0,1),
              'clear_attrs': [NodeInternals.Mutable],
              'alt': [
                  {'conf': 'ABS',
                   'contents': String(size=0),
                   'set_attrs': [NodeInternals.Abs_Postpone],
                   'clear_attrs': [NodeInternals.Mutable],
                   'absorb_csts': AbsNoCsts()}
              ]},
             {'name': 'file_list',
              'contents': [
                  {'name': 'file',
                   'qty': (MIN_FILE,MAX_FILE),
                   'contents': [
                       {'name': 'header',
                        'contents': [
                            {'name': 'sig',
                             'contents': UINT32_le(int_list=[0x04034b50]),
                             'absorb_csts': AbsFullCsts(),
                             'clear_attrs': [NodeInternals.Mutable]},
                            {'name': 'common_attrs',
                             'contents': [
                                 {'name': 'version_needed',
                                  'contents': UINT16_le()},
                                 {'name': 'gp_bit_flag',
                                  'contents': UINT16_le()},
                                 {'name': 'compression_method',
                                  'contents': UINT16_le()},
                                 {'name': 'last_mod_time',
                                  'contents': UINT16_le()},
                                 {'name': 'last_mod_date',
                                  'contents': UINT16_le()},
                                 {'name': 'crc32',
                                  'type': MH.Generator,
                                  'contents': g_crc32,
                                  'node_args': 'data',
                                  'clear_attrs': [NodeInternals.Freezable],
                                  'alt': [
                                      {'conf': 'ABS',
                                       'contents': UINT32_le(maxi=2**10)}
                                  ]},
                                 {'name': 'compressed_size',
                                  'type': MH.Generator,
                                  'contents': lambda x: Node('cts', value_type=\
                                                            UINT32_le(int_list=[len(x.get_flatten_value())])),
                                  'node_args': 'data',
                                  'alt': [
                                      {'conf': 'ABS',
                                       'contents': UINT32_le(maxi=2**10)}
                                  ]},
                                 {'name': 'uncompressed_size',
                                  'contents': UINT32_le(maxi=2**10)}
                             ]},
                            {'name': 'file_name_length',
                             'contents': UINT16_le(maxi=2**10)},
                            {'name': 'extra_field_length',
                             'contents': UINT16_le(maxi=2**10)},
                            {'name': 'file_name',
                             'type': MH.Generator,
                             'clear_attrs': [NodeInternals.Freezable],
                             'contents': lambda x: Node('cts', value_type=\
                                                       String(size=x.get_raw_value())),
                             'node_args': 'file_name_length'},
                            {'name': 'extra_field',
                             'type': MH.Generator,
                             'contents': lambda x: Node('cts', value_type=\
                                                       String(size=x.get_raw_value())),
                             'node_args': 'extra_field_length'}
                        ]},
                       {'name': 'data',
                        'type': MH.Generator,
                        'contents': lambda x: Node('cts', value_type=\
                                                   String(val_list=[zlib.compress(b'a'*x.get_raw_value())])),
                        'node_args': 'uncompressed_size',
                        'alt': [
                            {'conf': 'ABS',
                             'type': MH.Generator,
                             'clear_attrs': [NodeInternals.ResetOnUnfreeze],
                             'contents': lambda x: Node('cts', value_type=\
                                                        String(size=x.get_raw_value())),
                             'node_args': 'compressed_size'}
                        ]},
                       {'name': 'data_desc',
                        'type': MH.Generator,
                        'contents': g_data_desc,
                        'node_args': ['gp_bit_flag', 'crc32', 'compressed_size', 'uncompressed_size']}
                   ]}
              ]},
             {'name': 'archive_desc_header',
              'qty': (0,1),
              'contents': String(size=0),
              'alt': [
                  {'conf': 'ABS',
                   'contents': [
                       {'name': 'archive_extra_data_sig',
                        'contents': UINT32_le(int_list=[0x08064b50]),
                        'absorb_csts': AbsFullCsts(),
                        'clear_attrs': [NodeInternals.Mutable]},
                       {'name': 'extra_enc_field_len',
                        'contents': UINT32_le(maxi=2**5)},
                       {'name': 'extra_enc_field',
                        'type': MH.Generator,
                        'contents': lambda x: Node('cts', value_type=\
                                                  String(size=x.get_raw_value())),
                        'node_args': 'extra_enc_field_len'}
                   ]}
              ]},
             {'name': 'cdir',
              'contents': [
                  {'name': 'cdir_hdr',
                   'qty': (MIN_FILE,MAX_FILE),
                   'sync_qty_with': 'file',
                   'contents': [
                       {'name': 'unsupported_fields',
                        'contents': String(size=0),
                        'alt': [
                            {'conf': 'ABS',
                             'contents': String(size=10),
                             'set_attrs': [NodeInternals.Abs_Postpone],
                             'absorb_csts': AbsNoCsts()}
                        ]},
                       {'name': ('sig', 2),
                        'contents': UINT32_le(int_list=[0x02014b50]),
                        'absorb_csts': AbsFullCsts(),
                        'clear_attrs': [NodeInternals.Mutable]},
                       {'name': 'version_made_by',
                        'contents': UINT16_le()},
                       {'name': ('common_attrs', 2),
                        'clone': 'common_attrs'},
                       {'name': ('file_name_length', 2),
                        'contents': UINT16_le(maxi=2**10)},
                       {'name': ('extra_field_length', 2),
                        'contents': UINT16_le(maxi=2**10)},
                       {'name': 'file_comment_length',
                        'contents': UINT16_le(maxi=2**10)},
                       {'name': 'disk_number_start',
                        'contents': UINT16_le()},
                       {'name': 'internal_file_attr',
                        'contents': UINT16_le()},
                       {'name': 'external_file_attr',
                        'contents': UINT32_le()},
                       {'name': 'file_hdr_off',
                        'fuzz_weight': 10,
                        'type': MH.Generator,
                        'contents': g_fhdr_off,
                        'provide_helpers': True,
                        'node_args': ['start_padding', 'file_list']},
                       {'name': ('file_name', 2),
                        'type': MH.Generator,
                        'clear_attrs': [NodeInternals.Freezable],
                        'contents': lambda x: Node('cts', value_type=\
                                                  String(size=x.get_raw_value())),
                        'node_args': ('file_name_length', 2)},
                       {'name': ('extra_field', 2),
                        'type': MH.Generator,
                        'contents': lambda x: Node('cts', value_type=\
                                                  String(size=x.get_raw_value())),
                        'node_args': ('extra_field_length', 2)},
                       {'name': 'file_comment',
                        'type': MH.Generator,
                        'contents': lambda x: Node('cts', value_type=\
                                                  String(size=x.get_raw_value())),
                        'node_args': 'file_comment_length'}
                  ]}
              ]},
             {'name': 'ZIP64_specifics',
              'contents': [
                  {'weight': 5,
                   'contents': [
                       {'name': 'empty',
                        'contents': String(size=0)},
                   ]},
                  {'weight': 1,
                   'contents': [
                       {'name': 'full',
                        'contents': String(val_list=['PK\x06\x06'+'A'*20+'PK\x06\x07'+'B'*16])},
                   ]},
              ],
              'alt': [
                  {'conf': 'ABS',
                   'contents': [
                       {'section_type': MH.Pick,
                        'duplicate_mode': MH.Copy,
                        'contents': [
                            {'name': 'end_of_cdir',
                             'contents': [
                                 {'name': 'zip64_sig_record',
                                  'contents': UINT32_le(int_list=[0x06064b50]),
                                  'absorb_csts': AbsFullCsts(),
                                  'clear_attrs': [NodeInternals.Mutable]},
                                 {'name': 'record_meta_data',
                                  'contents': String(size=0),
                                  'set_attrs': [NodeInternals.Abs_Postpone],
                                  'absorb_csts': AbsNoCsts()},
                                 {'name': 'zip64_sig_locator',
                                  'contents': UINT32_le(int_list=[0x07064b50]),
                                  'absorb_csts': AbsFullCsts(),
                                  'clear_attrs': [NodeInternals.Mutable]},
                                 {'name': 'locator_meta_data',
                                  'contents': String(size=16)}
                             ]},
                            {'name': 'empty_end_of_cdir',
                             'contents': String(size=0)}
                        ]}
                   ]}
              ]},
             {'name': 'end_central_dir',
              'exists_if_not': 'ZIP64_specifics',
              'contents': [
                  {'name': ('ecd_sig', 3),
                   'contents': UINT32_le(int_list=[0x06054b50]),
                   'absorb_csts': AbsFullCsts(),
                   'clear_attrs': [NodeInternals.Mutable]},
                  {'name': 'disk_number',
                   'contents': UINT16_le()},
                  {'name': 'disk_number_with_cdir_start',
                   'contents': UINT16_le()},
                  {'name': 'total_nb_of_cdir_entries_in_this_disk',
                   'type': MH.Generator,
                   'contents': lambda x: Node('cts', value_type=\
                                              UINT16_le(int_list=[x.get_subnode_qty()])),
                   'node_args': 'cdir'},
                  {'name': 'total_nb_of_cdir_entries',
                   'clone': 'total_nb_of_cdir_entries_in_this_disk'},
                  {'name': 'size_of_cdir',
                   'contents': UINT32_le()},
                  {'name': 'off_of_cdir',
                   'type': MH.Generator,
                   'contents': lambda x: Node('cts', value_type=\
                                              UINT32_le(int_list=[len(x[0].get_flatten_value()) \
                                                                 + len(x[1].get_flatten_value()) \
                                                                 + len(x[2].get_flatten_value())])),
                   'node_args': ['start_padding', 'file_list', 'archive_desc_header']},
                  {'name': 'optional',
                   'qty': (0,1),
                   'contents': [
                       {'name': 'ZIP_comment_len',
                        'contents': UINT32_le(maxi=2**10)},
                       {'name': 'ZIP_comment',
                        'type': MH.Generator,
                        'contents': lambda x: Node('cts', value_type=\
                                                  String(size=x.get_raw_value())),
                        'node_args': 'ZIP_comment_len'}
                   ]}
              ]},
             {'name': 'end_padding',
              'contents': String(size=0),
              'qty': (0,1),
              'alt': [
                  {'conf': 'ABS',
                   'contents': String(size=0),
                   'absorb_csts': AbsNoCsts()}
              ]}
        ]}


        mh = ModelHelper()
        self.pkzip = mh.create_graph_from_desc(zip_desc)

        self.zip_dict = self.import_file_contents(extension='zip')

        self.register_nodes(self.pkzip, *self.zip_dict.values())


data_model = ZIP_DataModel()

