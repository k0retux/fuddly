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

import zlib

from framework.data_model import *
from framework.global_resources import *
from framework.value_types import *


class ZIP_DataModel(DataModel):

    file_extension = 'zip'
    name = 'zip'

    def absorb(self, data, idx):
        
        nm = 'ZIP_{:0>2d}'.format(idx)
        pkzip = self.pkzip.get_clone(nm, new_env=True)
        pkzip.set_current_conf('ABS', recursive=True)
        status, off, size, name = pkzip.absorb(data, constraints=AbsNoCsts(size=True,struct=True))
        # pkzip.show(raw_limit=400)

        print('{:s} Absorb Status: {!r}, {:d}, {:d}, {:s}'.format(nm, status, off, size, name))
        print(' \_ length of original zip: {:d}'.format(len(data)))
        print(' \_ remaining: {!r}'.format(data[size:size+1000]))

        if status == AbsorbStatus.FullyAbsorbed:
            print("--> Create {:s} from provided ZIP samples.".format(nm))
            return pkzip
        else:
            return Node(nm, values=['ZIP ABSORBSION FAILED'])


    def build_data_model(self):

        MIN_FILE = 1
        MAX_FILE = -1

        zip_desc = \
        {'name': 'ZIP',
         'contents': [
             {'name': 'start_padding',
              'contents': String(size=0),
              'qty': (0, 1),
              'clear_attrs': MH.Attr.Mutable,
              'alt': [
                  {'conf': 'ABS',
                   'contents': String(size=0),
                   'set_attrs': MH.Attr.Abs_Postpone,
                   'clear_attrs': MH.Attr.Mutable,
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
                             'contents': UINT32_le(values=[0x04034b50]),
                             'absorb_csts': AbsFullCsts(),
                             'clear_attrs': [MH.Attr.Mutable]},
                            {'name': 'common_attrs',
                             'contents': [
                                 {'name': 'version_needed',
                                  'contents': UINT16_le()},
                                 {'name': 'gp_bit_flag',
                                  'contents': BitField(subfield_sizes=[2,1,13], endian=VT.LittleEndian,
                                                       subfield_values=[None, [0,1], None],
                                                       subfield_val_extremums=[[0,3], None, [0, 8191]])},
                                 {'name': 'compression_method',
                                  'contents': UINT16_le()},
                                 {'name': 'last_mod_time',
                                  'contents': UINT16_le()},
                                 {'name': 'last_mod_date',
                                  'contents': UINT16_le()},
                                 {'name': 'crc32',
                                  'contents': CRC(vt=UINT32_le, clear_attrs=[MH.Attr.Mutable]),
                                  'node_args': 'data',
                                  # 'clear_attrs': [MH.Attr.Freezable],
                                  'alt': [
                                      {'conf': 'ABS',
                                       'contents': UINT32_le(max=2**10)}
                                  ]},
                                 {'name': 'compressed_size',
                                  'type': MH.Generator,
                                  'contents': lambda x: Node('cts', value_type=\
                                                            UINT32_le(values=[len(x.to_bytes())])),
                                  'node_args': 'data',
                                  'alt': [
                                      {'conf': 'ABS',
                                       'contents': UINT32_le(max=2**10)}
                                  ]},
                                 {'name': 'uncompressed_size',
                                  'contents': UINT32_le(max=2**10)}
                             ]},
                            {'name': 'file_name_length',
                             'contents': UINT16_le(max=2**10)},
                            {'name': 'extra_field_length',
                             'contents': UINT16_le(max=2**10)},
                            {'name': 'file_name',
                             'type': MH.Generator,
                             'clear_attrs': [MH.Attr.Freezable],
                             'contents': lambda x: Node('cts', value_type=\
                                                        Filename(size=x.get_raw_value(), alphabet='ABC')),
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
                                                   String(values=[zlib.compress(b'a'*x.get_raw_value())])),
                        'node_args': 'uncompressed_size',
                        'alt': [
                            {'conf': 'ABS',
                             'type': MH.Generator,
                             'custo_clear': MH.Custo.Gen.ResetOnUnfreeze,
                             'contents': lambda x: Node('cts', value_type=\
                                                        String(size=x.get_raw_value())),
                             'node_args': 'compressed_size'}
                        ]},
                       {'name': 'data_desc',
                        'exists_if': (BitFieldCondition(sf=1, val=1), 'gp_bit_flag'), # check 3rd bit of gp_flag
                        'contents': [
                            {'name': ('crc32', 2),
                             'clone': 'crc32'},
                            {'name': ('compressed_size', 2),
                             'clone': 'compressed_size'},
                            {'name': ('uncompressed_size', 2),
                             'clone': 'uncompressed_size'}
                        ]},
                       {'name': 'no_data_desc',
                        'exists_if': (BitFieldCondition(sf=1, val=0), 'gp_bit_flag'),
                        'contents': String(size=0)}
                   ]}
              ]},
             {'name': 'archive_desc_header',
              'qty': (0,1),
              'contents': String(size=0),
              'alt': [
                  {'conf': 'ABS',
                   'contents': [
                       {'name': 'archive_extra_data_sig',
                        'contents': UINT32_le(values=[0x08064b50]),
                        'absorb_csts': AbsFullCsts(),
                        'clear_attrs': [MH.Attr.Mutable]},
                       {'name': 'extra_enc_field_len',
                        'contents': UINT32_le(max=2**5)},
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
                             'set_attrs': [MH.Attr.Abs_Postpone],
                             'absorb_csts': AbsNoCsts()}
                        ]},
                       {'name': ('sig', 2),
                        'contents': UINT32_le(values=[0x02014b50]),
                        'absorb_csts': AbsFullCsts(),
                        'clear_attrs': [MH.Attr.Mutable]},
                       {'name': 'version_made_by',
                        'contents': UINT16_le()},
                       {'name': ('common_attrs', 2),
                        'contents': COPY_VALUE(path='header/common_attrs$', depth=1),
                        'node_args': 'file_list',
                        'clear_attrs': [MH.Attr.Mutable]},
                       {'name': ('file_name_length', 2),
                        'contents': COPY_VALUE(path='header/file_name_length', depth=1),
                        'node_args': 'file_list'},
                       {'name': ('extra_field_length', 2),
                        'contents': COPY_VALUE(path='header/extra_field_length', depth=1),
                        'node_args': 'file_list'},
                       {'name': 'file_comment_length',
                        'contents': UINT16_le(max=2**10)},
                       {'name': 'disk_number_start',
                        'contents': UINT16_le()},
                       {'name': 'internal_file_attr',
                        'contents': UINT16_le()},
                       {'name': 'external_file_attr',
                        'contents': UINT32_le()},
                       {'name': 'file_hdr_off',
                        'fuzz_weight': 10,
                        # 'custo_set': MH.Custo.Gen.ResetOnUnfreeze,
                        'contents': OFFSET(vt=UINT32_le),
                        'node_args': ['start_padding', 'file_list']},
                       {'name': ('file_name', 2),
                        'contents': COPY_VALUE(path='header/file_name/cts$', depth=1),
                        'node_args': 'file_list',
                        'alt': [
                            {'conf': 'ABS',
                             'contents': lambda x: Node('cts', value_type=\
                                                        String(size=x.cc.generated_node.get_raw_value())),
                             'node_args': ('file_name_length', 2)} ]},
                       {'name': ('extra_field', 2),
                        'contents': COPY_VALUE(path='header/extra_field/cts$', depth=1),
                        'node_args': 'file_list',
                        'alt': [
                            {'conf': 'ABS',
                             'contents': lambda x: Node('cts', value_type=\
                                                        String(size=x.cc.generated_node.get_raw_value())),
                             'node_args': ('extra_field_length', 2)} ]},
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
                        'contents': String(values=['PK\x06\x06'+'A'*20+'PK\x06\x07'+'B'*16])},
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
                                  'contents': UINT32_le(values=[0x06064b50]),
                                  'absorb_csts': AbsFullCsts(),
                                  'clear_attrs': [MH.Attr.Mutable]},
                                 {'name': 'record_meta_data',
                                  'contents': String(size=0),
                                  'set_attrs': [MH.Attr.Abs_Postpone],
                                  'absorb_csts': AbsNoCsts()},
                                 {'name': 'zip64_sig_locator',
                                  'contents': UINT32_le(values=[0x07064b50]),
                                  'absorb_csts': AbsFullCsts(),
                                  'clear_attrs': [MH.Attr.Mutable]},
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
                   'contents': UINT32_le(values=[0x06054b50]),
                   'absorb_csts': AbsFullCsts(),
                   'clear_attrs': [MH.Attr.Mutable]},
                  {'name': 'disk_number',
                   'contents': UINT16_le()},
                  {'name': 'disk_number_with_cdir_start',
                   'contents': UINT16_le()},
                  {'name': 'total_nb_of_cdir_entries_in_this_disk',
                   'contents': lambda x: Node('cts', value_type=\
                                              UINT16_le(values=[x.get_subnode_qty()])),
                   'node_args': 'cdir'},
                  {'name': 'total_nb_of_cdir_entries',
                   'clone': 'total_nb_of_cdir_entries_in_this_disk'},
                  {'name': 'size_of_cdir',
                   'contents': UINT32_le()},
                  {'name': 'off_of_cdir',
                   'type': MH.Generator,
                   'contents': lambda x: Node('cts', value_type=\
                                              UINT32_le(values=[len(x[0].to_bytes()) \
                                                                 + len(x[1].to_bytes()) #])),
                                                                 + len(x[2].to_bytes())])),
                   'node_args': ['start_padding', 'file_list', 'archive_desc_header']},
                  {'name': 'optional',
                   'qty': (0,1),
                   'contents': [
                       {'name': 'ZIP_comment_len',
                        'contents': UINT32_le(max=2**10)},
                       {'name': 'ZIP_comment',
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


        mb = NodeBuilder(delayed_jobs=True)
        self.pkzip = mb.create_graph_from_desc(zip_desc)

        self.zip_dict = self.import_file_contents(extension='zip')

        self.register(self.pkzip, *self.zip_dict.values())


data_model = ZIP_DataModel()

