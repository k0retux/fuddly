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

from framework.data_model import *
from framework.data_model_builder import *
from framework.value_types import *


class USB_DEFS:
    DT_DEVICE = 0x01
    DT_CONFIGURATION = 0x02
    DT_STRING = 0x03
    DT_INTERFACE = 0x04
    DT_ENDPOINT = 0x05
    DT_DEVICE_QUALIFIER = 0x06
    DT_OTHER_SPEED_CONFIGURATION = 0x07
    DT_INTERFACE_POWER = 0x08

    STRINGID_MFR = 1
    STRINGID_PRODUCT = 2
    STRINGID_SERIAL = 3
    STRINGID_CONFIG = 4
    STRINGID_INTERFACE = 5

    USB_CLASS_PER_INTERFACE = 0
    USB_CLASS_AUDIO = 1
    USB_CLASS_COMM = 2
    USB_CLASS_HID = 3
    USB_CLASS_PHYSICAL = 5
    USB_CLASS_STILL_IMAGE = 6
    USB_CLASS_PRINTER = 7
    USB_CLASS_MASS_STORAGE = 8
    USB_CLASS_HUB = 9
    USB_CLASS_CDC_DATA = 0x0a
    USB_CLASS_CSCID = 0x0b
    USB_CLASS_CONTENT_SEC = 0x0d
    USB_CLASS_VIDEO = 0x0e
    USB_CLASS_WIRELESS_CONTROLLER = 0xe0
    USB_CLASS_MISC = 0xef
    USB_CLASS_APP_SPEC = 0xfe
    USB_CLASS_VENDOR_SPEC = 0xff
    
    USB_SUBCLASS_VENDOR_SPEC	= 0xff


class USB_DataModel(DataModel):

    file_extension = 'bin'

    def build_data_model(self):

        ep_desc = \
        {'name': 'EP_desc',
         'contents': [
             {'name': 'bLength',
              'contents': UINT8(values=[7])},
             {'name': 'bDescType',
              'contents': UINT8(values=[USB_DEFS.DT_ENDPOINT])},
             {'name': 'bEndpointAddr',
              'contents': BitField(subfield_limits=[4,7,8],
                                   subfield_val_extremums=[[0,0b1111],None,[0,1]],
                                   subfield_values=[None,[0],None],
                                   endian=VT.LittleEndian),
              'alt': [
                  {'conf': 'BULK-IN',
                   'contents': BitField(subfield_limits=[4,7,8],
                                        subfield_values=[[1],[0],[1]],
                                        endian=VT.LittleEndian)},
                  {'conf': 'BULK-OUT',
                   'contents': BitField(subfield_limits=[4,7,8],
                                        subfield_values=[[2],[0],[0]],
                                        endian=VT.LittleEndian)}]},
             {'name': 'bmAttributes',
              'contents': BitField(subfield_limits=[2,6,8], subfield_values=[[0,2,3],[0],[0]],
                                   endian=VT.LittleEndian),
              'fuzz_weight': 5,
              'alt': [
                  {'conf': 'ISO',
                   'contents': BitField(subfield_limits=[2,4,6,8],
                                        subfield_val_extremums=[None,[0,3],[0,2],None],
                                        subfield_values=[[1],None,None,[0]],
                                        endian=VT.LittleEndian)}
              ]},
             {'name': 'wMaxPacketSize',
              'contents': BitField(subfield_limits=[11,13,16],
                                   subfield_val_extremums=[None,[0,2],[0,0]],
                                   subfield_values=[[2**x for x in range(1,12)],None,[0]],
                                   endian=VT.LittleEndian),
              'random': True,
              'alt': [
                  {'conf': 'MSD',
                   'contents': BitField(subfield_limits=[11,13,16],
                                        subfield_val_extremums=[None,[0,2],[0,0]],
                                        subfield_values=[[0x8, 0x10, 0x20, 0x40],[0],[0]],
                                        endian=VT.LittleEndian)}]},
             {'name': 'bInterval',
              'contents': UINT8(values=[4]),
              'alt': [
                  {'conf': 'MSD',
                   'contents': UINT8(values=[0])}]}
         ]}

        mb = ModelBuilder(add_env=False)
        ep_node = mb.create_graph_from_desc(ep_desc)

        msd_ep_bulkin = ep_node.get_clone('EP_BLKIN')
        msd_ep_bulkin.set_current_conf('MSD', recursive=True)
        msd_ep_bulkin.set_current_conf('BULK-IN', recursive=True)
        msd_ep_bulkout = ep_node.get_clone('EP_BLKOUT')
        msd_ep_bulkout.set_current_conf('MSD', recursive=True)
        msd_ep_bulkout.set_current_conf('BULK-OUT', recursive=True)

        interface_desc = \
        {'name': 'Interface',
         'contents': [
             {'name': ('Ihdr', 2),
              'contents': [
                  {'name': ('bLength', 2),
                   'contents': UINT8(values=[9])},
                  {'name': ('bDescType', 2),
                   'contents': UINT8(values=[USB_DEFS.DT_INTERFACE])},
                  {'name': 'bInterfaceNum',
                   'contents': UINT8(mini=0, maxi=10)},
                  {'name': 'bAlternateSetting',
                   'contents': UINT8(values=[0, 1, 2, 3, 4])},
                  {'name': 'bNumEndpoints',
                   # 'random': True,
                   'contents': UINT8(mini=1, maxi=8, default=4),
                   'alt': [
                       {'conf': 'MSD',
                        'contents': UINT8(values=[2])}
                   ]},
                  {'name': 'bInterfaceClass',
                   'contents': UINT8(values=[
                       USB_DEFS.USB_CLASS_MASS_STORAGE,
                       USB_DEFS.USB_CLASS_PRINTER,
                       USB_DEFS.USB_CLASS_HID,
                       USB_DEFS.USB_CLASS_HUB,
                       USB_DEFS.USB_CLASS_PHYSICAL,
                       USB_DEFS.USB_CLASS_MISC,
                       USB_DEFS.USB_CLASS_VENDOR_SPEC]
                   ),
                   'alt': [
                       {'conf': 'MSD',
                        'contents': UINT8(values=[0x8])}
                   ]
                   },
                  {'name': 'bInterfaceSubClass',
                   'contents': UINT8(values=[0x06, 0, 1, 2, 3, 4, 5, 7, 8]),
                   'alt': [
                       {'conf': 'MSD',
                        'contents': UINT8(values=[0x6])}
                   ]},
                  {'name': 'bInterfaceProtocol',
                   'contents': UINT8(values=[0x80, 0x06, 0, 1, 2]),
                   'alt': [
                       {'conf': 'MSD',
                        'contents': UINT8(values=[0x50])}
                   ]},
                  {'name': 'iInterface',
                   'contents': UINT8(values=[USB_DEFS.STRINGID_INTERFACE])},
              ]},
             {'name': 'EP_Group',
              'custo_clear': MH.Custo.NTerm.MutableClone,
              'contents': [
                  {'qty_from': 'bNumEndpoints',
                   'contents': ep_node}
              ],
              'alt': [
                  {'conf': 'MSD',
                   'contents': [
                       (msd_ep_bulkin, 1),
                       (msd_ep_bulkout, 1),
                   ]}
              ]}
         ]}

        mb = ModelBuilder(add_env=False)
        intf_node = mb.create_graph_from_desc(interface_desc)

        conf_desc = \
        {'name': 'CONF',
         'semantics': 'CONF_DESC',
         'contents': [
             {'name': 'hdr',
              'contents': [
                  {'name': 'bLength',
                   'contents': UINT8(values=[9])},
                  {'name': 'bDescType',
                   'contents': UINT8(values=[USB_DEFS.DT_CONFIGURATION])},
                  {'name': 'wTotalLength',
                   'contents': LEN(vt=UINT16_le, base_len=9),
                   'node_args': 'Intf_Group'},
                  {'name': 'bNumInterfaces',
                   'contents': QTY('Interface', vt=UINT8),
                   'node_args': 'Intf_Group',
                   'alt': [
                       {'conf': 'MSD',
                        'contents': UINT8(values=[1])}
                   ]},
                  {'name': 'bConfValue',
                   'contents': UINT8(mini=1, maxi=50)},
                  {'name': 'iConf',
                   'contents': UINT8(values=[USB_DEFS.STRINGID_CONFIG])},
                  {'name': 'bmAttributes',
                   'contents': BitField(subfield_limits=[5,6,7,8],
                                        subfield_values=[[0],[1],[1],[1]],
                                        endian=VT.LittleEndian)},
                  {'name': 'bMaxPower',
                   'contents': UINT8(values=[50])},
              ]},
             {'name': 'Intf_Group',
              'custo_clear': MH.Custo.NTerm.MutableClone,
              'contents': [
                  {'qty': (1,5),
                   'contents': intf_node} ],
              'alt': [
                  {'conf': 'MSD',
                   'contents': [
                       {'qty': 1,
                        'contents': intf_node.get_clone()}
                  ]},
                  {'conf': 'BIGCONF',
                   'contents': [
                       {'qty': 1700,
                        'contents': intf_node.get_clone()}
                   ]} ]
              },
         ]}

        dev_desc = \
        {'name': 'DEV',
         'semantics': 'DEV_DESC',
         'contents': [
             {'name': 'bLength',
              'contents': UINT8(values=[18])},
             {'name': 'bDescType',
              'contents': UINT8(values=[USB_DEFS.DT_DEVICE])},
             {'name': 'bcdUSB',
              'contents': UINT16_le(values=[0x200, 0x100])},
             {'name': 'bDeviceClass',
              'contents': UINT8(values=[0]),
              'alt': [
                  {'conf': 'MS', # mass-storage
                   'contents': UINT8(values=[0])}
              ]},
             {'name': 'bDeviceSubClass',
              'contents': UINT8(values=[0]),
              'alt': [
                  {'conf': 'MS', # mass-storage
                   'contents': UINT8(values=[0])}
              ]},
             {'name': 'bDeviceProto',
              'contents': UINT8(values=[0]),
              'alt': [
                  {'conf': 'MS', # mass-storage
                   'contents': UINT8(values=[0])}
              ]},
             {'name': 'bMaxPacketSize0',
              'contents': UINT8(values=[64])},
             {'name': 'idVendor',
              'contents': UINT16_le(values=[0x1307])},
             {'name': 'idProduct',
              'contents': UINT16_le(values=[0x0165])},
             {'name': 'bcdDevice',
              'contents': UINT16_le(values=[0x100])},
             {'name': 'iManufacturer',
              'contents': UINT8(values=[USB_DEFS.STRINGID_MFR])},
             {'name': 'iProduct',
              'contents': UINT8(values=[USB_DEFS.STRINGID_PRODUCT])},
             {'name': 'iSerialNumber',
              'contents': UINT8(values=[USB_DEFS.STRINGID_SERIAL])},
             {'name': 'bNumConfigs',
              'contents': UINT8(values=[1])}
         ]}

        langid_desc = \
        {'name': 'LANGID',
         'semantics': 'LANGID_DESC',
         'contents': [
             {'name': 'bLength',
              'contents': LEN(vt=UINT8,base_len=2),
              'node_args': 'contents'},
             {'name': 'bDescType',
              'contents': UINT8(values=[USB_DEFS.DT_STRING])},
             {'name': 'contents',
              'contents': [
                  {'name': 'LangID',
                   'qty': (0,30),
                   'contents': UINT16_le(values=[0x040c, 0x0409])}
              ]},
         ]}

        string_desc = \
        {'name': 'STR',
         'semantics': 'STRING_DESC',
         'contents': [
             {'name': 'bLength',
              'contents': UINT8()},
             {'name': 'bDescType',
              'contents': UINT8(values=[USB_DEFS.DT_STRING])},
             {'name': 'contents',
              'sync_enc_size_with': ('bLength', 2),
              'contents': String(values=[u'\u00fcber string', u'what an interesting string!'],
                                 max_sz=126, max_encoded_sz=253, codec='utf-16-le')},
         ]}


        self.register(conf_desc, dev_desc, langid_desc, string_desc)


data_model = USB_DataModel()
