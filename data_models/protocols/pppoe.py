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

from framework.data_model import *
from framework.value_types import *


class PPPOE_DataModel(DataModel):

    file_extension = 'bin'

    def build_data_model(self):

        # refer to RFC 2516

        def cycle_tags(tag):
            tag.freeze()
            if tag['.*/type'][0].get_current_raw_val() == 0x102:
                tag['.*/type'][0].unfreeze()
                tag.freeze()
            tag['.*/type'][0].unfreeze()
            tag.unfreeze(reevaluate_constraints=True)
            return tag

        tag_desc = \
        {'name': 'tag',
         'evolution_func': cycle_tags,
         'contents': [
             {'name': 'type',
              'contents': UINT16_be(values=[0x0101,0x0102,0x0103,0x0104,0x0105,
                                            0x0110,0x201,0x0202,0x0203,0]),
              'absorb_csts': AbsFullCsts()},
             {'name': 'len',
              'contents': UINT16_be(),
              'absorb_csts': AbsNoCsts(),
              },
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
                  {'name': 'v105', # Vendor Specific
                   'exists_if': (IntCondition(0x0105), 'type'),
                   'contents': [
                       {'name': 'vendorID',
                        'contents': BitField(subfield_sizes=[24,8], endian=VT.BigEndian,
                                             subfield_values=[None,[0]],
                                             subfield_descs=['type','version']) },
                       {'name': 'remainder',
                        'sync_enc_size_with': ('len', 4),
                        'contents': String(values=['unspecified...'], min_sz=0, max_sz=1000),
                        },
                   ]},
                  {'name': 'v110', # Relay session ID
                   'exists_if': (IntCondition(0x0110), 'type'),
                   'sync_enc_size_with': 'len',
                   'contents': String(size=12)},
                  {'name': 'v201',
                   'exists_if': (IntCondition([0x201, 0x202]), 'type'),
                   'sync_enc_size_with': 'len',
                   'contents': String(values=['Service Name Error or AC System Error!'], codec='utf8'),
                   },
                  {'name': 'v203', # Generic Error
                   'exists_if': (IntCondition(0x0203), 'type'),
                   'sync_enc_size_with': 'len',
                   'contents': String(values=['Generic Error!'], codec='utf8'),
                   'alt': [
                       {'conf': 'null-terminated',  # RFC2516 says it MUST NOT be null terminated
                        'exists_if': (IntCondition(0x0203), 'type'),
                        'contents': [
                            {'name': 'data',
                             'sync_enc_size_with': ('len', -1),
                             'contents': String(values=['Generic Error!'], codec='utf8')},
                            {'name': 'null',
                             'mutable': False,
                             'contents': UINT8(values=[0])}
                        ]}
                   ]},
              ]}
         ]}

        mb = NodeBuilder(delayed_jobs=True, add_env=False)
        tag_node = mb.create_graph_from_desc(tag_desc)

        tag_service_name = tag_node.get_clone('tag_sn')
        tag_service_name['.*/type'][0].set_values(value_type=UINT16_be(values=[0x0101]))

        tag_host_uniq = tag_node.get_clone('tag_host_uniq')
        tag_host_uniq['.*/type'][0].set_values(value_type=UINT16_be(values=[0x0103]))

        tag_host_uniq_pads = tag_host_uniq.get_clone()

        tag_ac_name = tag_node.get_clone('tag_ac_name') # Access Concentrator Name
        tag_ac_name['.*/type'][0].set_values(value_type=UINT16_be(values=[0x0102]))

        tag_sn_error = tag_node.get_clone('tag_sn_error')  # Service Name Error
        tag_sn_error['.*/type'][0].set_values(value_type=UINT16_be(values=[0x0202]))

        tag_service_name_pads = tag_service_name.get_clone()
        tag_node_pads = tag_node.get_clone()

        pppoe_desc = \
        {'name': 'pppoe',
         'contents': [
             {'name': 'mac_dst',
              'semantics': 'mac_dst',
              'mutable': False,
              'contents': String(size=6)},
             {'name': 'mac_src',
              'semantics': 'mac_src',
              'mutable': False,
              'contents': String(size=6)},
             {'name': 'proto',
              'mutable': False,
              'contents': UINT16_be(values=[0x8863])},
             {'name': 'version-type',
              'contents': BitField(subfield_sizes=[4,4], endian=VT.BigEndian,
                                   subfield_values=[[1],[1]],
                                   subfield_descs=['type','version'])},
             {'name': 'code',
              'mutable': False,
              'contents': UINT8(values=[0x9,0x7,0x19,0x65,0xa7]),
              'absorb_csts': AbsFullCsts()},
             {'name': 'session_id',
              'contents': UINT16_be()},
             {'name': 'length',
              'contents': LEN(vt=UINT16_be),
              'node_args': 'payload',
              'alt': [
                  {'conf': 'ABS',
                   'contents': UINT16_be()}
              ]},
             {'name': 'payload',
              'contents': [
                  {'name': '4padi',
                   'shape_type': MH.FullyRandom,
                   'custo_clear': MH.Custo.NTerm.FrozenCopy,
                   'exists_if': (IntCondition(0x9), 'code'),
                   'contents': [
                       (tag_service_name.get_clone(), 1),
                       (tag_node.get_clone(), 0, 4)
                   ]},
                  {'name': '4pado',
                   'shape_type': MH.FullyRandom,
                   'custo_clear': MH.Custo.NTerm.FrozenCopy,
                   'exists_if': (IntCondition(0x7), 'code'),
                   'contents': [
                       (tag_host_uniq.get_clone(), 1),
                       (tag_ac_name.get_clone(), 1),
                       (tag_service_name.get_clone(), 1),
                   ],
                   'alt': [
                       {'conf': 'fuzz',
                        'shape_type': MH.Ordered,
                        'exists_if': (IntCondition(0x7), 'code'),
                        'contents': [
                            (tag_node.get_clone(), 0, 8),
                            (tag_host_uniq.get_clone(), 1),
                            (tag_ac_name.get_clone(), 1),
                            (tag_service_name.get_clone(), 1),
                        ]}
                   ]},
                  {'name': '4padr',
                   'shape_type': MH.FullyRandom,
                   'custo_clear': MH.Custo.NTerm.FrozenCopy,
                   'exists_if': (IntCondition(0x19), 'code'),
                   'contents': [
                       (tag_service_name.get_clone(), 1),
                       (tag_node.get_clone(), 0, 4)
                   ]},
                  {'name': '4pads',
                   'shape_type': MH.FullyRandom,
                   'custo_clear': MH.Custo.NTerm.FrozenCopy,
                   'exists_if': (IntCondition(0x65), 'code'),
                   'contents': [
                       # Accept PPPoE session Case
                       {'weight': 10,
                        'contents': [
                            (tag_service_name_pads, 1),
                            (tag_host_uniq_pads, 1),
                            (tag_node_pads, 0, 4)
                        ]},
                       # Reject PPPoE session Case
                       {'weight': 2,
                        'contents': [
                            (tag_sn_error, 1),
                            (tag_host_uniq_pads, 1),
                            (tag_node_pads, 0, 4)
                        ]},
                   ],
                   'alt': [
                       {'conf': 'fuzz',
                        'exists_if': (IntCondition(0x65), 'code'),
                        'contents': [
                            (tag_node.get_clone(), 0, 8),
                            (tag_service_name_pads.get_clone(), 1),
                            (tag_host_uniq_pads.get_clone(), 1)
                        ]}
                   ]},
                  {'name': '4padt',
                   'shape_type': MH.FullyRandom,
                   'custo_clear': MH.Custo.NTerm.FrozenCopy,
                   'exists_if': (IntCondition(0xa7), 'code'),
                   'contents': [
                       {'contents': tag_host_uniq.get_clone()},
                       {'contents': tag_node.get_clone(), 'qty': (0, 4)}
                   ]}
              ]},
             {'name': 'padding',
              'contents': String(max_sz=0),
              'absorb_csts': AbsNoCsts(),
              'mutable': False},
         ]}

        mb = NodeBuilder(delayed_jobs=True, add_env=False)
        pppoe_msg = mb.create_graph_from_desc(pppoe_desc)
        # pppoe_msg.make_random(recursive=True)

        padi = pppoe_msg.get_clone('padi')
        padi['.*/mac_dst'][0].set_values(value_type=String(values=[u'\xff\xff\xff\xff\xff\xff']))
        padi['.*/code'][0].set_values(value_type=UINT8(values=[0x9]))

        pado = pppoe_msg.get_clone('pado')
        pado['.*/code'][0].set_values(value_type=UINT8(values=[0x7]))
        # pado['.*/code'][0].clear_attr(MH.Attr.Mutable)

        padr = pppoe_msg.get_clone('padr')
        padr['.*/code'][0].set_values(value_type=UINT8(values=[0x19]))

        pads = pppoe_msg.get_clone('pads')
        pads['.*/code'][0].set_values(value_type=UINT8(values=[0x65]))

        padt = pppoe_msg.get_clone('padt')
        padt['.*/code'][0].set_values(value_type=UINT8(values=[0xa7]))

        self.register(pppoe_msg, padi, pado, padr, pads, padt, tag_host_uniq)


data_model = PPPOE_DataModel()