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
import random
import zlib

from fuzzfmk.plumbing import *
from fuzzfmk.data_model import *
from fuzzfmk.data_model_helpers import *
from fuzzfmk.value_types import *
from fuzzfmk.fuzzing_primitives import *
from fuzzfmk.basic_primitives import *


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


### NEED TO BE REVAMPED
### BY USING ModelHelper()
class USB_DataModel(DataModel):

    file_extension = 'bin'

    def build_data_model(self):

        mh = ModelHelper(dm=self)

        e_intf_contents = Node('contents')
        e_conf_contents = Node('contents')
        
        # CONF DESC

        e_blength = Node('bLength', value_type=UINT8(int_list=[9]))
        e_bdesctype = Node('bDescType', value_type=UINT8(int_list=[USB_DEFS.DT_CONFIGURATION]))
        def conf_len(node):
            intg = min(9 + len(node.to_bytes()), 2 ** 16 - 1)
            e = Node('dyn', value_type=UINT16_le(int_list=[intg]))
            return e
        e_wtotlen_gen = Node('wTotalLength')
        e_wtotlen_gen.set_generator_func(conf_len, func_node_arg=e_conf_contents)
        # e_wtotlen_gen.add_conf('MSD')
        # e_wtotlen_gen.set_generator_func(conf_len, func_node_arg=e_conf_contents, func_arg=1, conf='MSD')

        # This function is called with e_conf_contents as a parameter
        def nb_intf(node):
            # node.get_value()
            # print('QTY: ', node.cc._nodes_drawn_qty)
            try:
                nb = min(node.cc.get_drawn_node_qty('INTF'), 2**8-1)
                e = Node('dyn', value_type=UINT8(int_list=[nb]))
            except:
                e = Node('dyn_default', value_type=UINT8(int_list=[10]))
            return e
        e_bnumintf = Node('bNumInterfaces')
        e_bnumintf.set_generator_func(nb_intf, func_node_arg=e_conf_contents)
        e_bnumintf.add_conf('MSD')
        e_bnumintf.set_values(value_type=UINT8(int_list=[1]), conf='MSD')

        e_bconfval = Node('bConfValue', value_type=UINT8(mini=1, maxi=50))
        e_iconf = Node('iConf', value_type=UINT8(int_list=[USB_DEFS.STRINGID_CONFIG]))
        
        vt = BitField(subfield_limits=[5,6,7,8], subfield_val_lists=[[0],[1],[1],[1]],
                      endian=VT.LittleEndian)
        e_bmattrib_conf = Node('bmAttributes', value_type=vt)
        # e_bmattrib_conf.make_determinist()

        # e_bmattrib_conf = Node('bmAttributes', value_type=UINT8(int_list=[0b1110000]))
        # e_bmattrib_conf.clear_attr(NodeInternals.Mutable)

        e_bmaxpower = Node('bMaxPower', value_type=UINT8(int_list=[50]))
        # e_bmaxpower.clear_attr(NodeInternals.Mutable)

        e_conf_desc = Node('CONF_DESC')
        e_conf_desc.set_subnodes_basic([
                e_blength,
                e_bdesctype,
                e_wtotlen_gen,
                e_bnumintf,
                e_bconfval,
                e_iconf,
                e_bmattrib_conf,
                e_bmaxpower
                ])

        # INTERFACE DESC

        e_blength_intf = Node('bLength', value_type=UINT8(int_list=[9]))
        e_bdesctype_intf = Node('bDescType', value_type=UINT8(int_list=[USB_DEFS.DT_INTERFACE]))
        e_intfnum = Node('bInterfaceNum', value_type=UINT8(mini=0, maxi=10))
        e_intfnum.make_random()
        e_baltset = Node('bAlternateSetting', value_type=UINT8(int_list=[0,1,2,3,4]))

        # This function is called with e_intf as a parameter
        def nb_eps(node):
            # node.get_value()
            # print('QTY: ', node.cc._nodes_drawn_qty)
            nb = min(node.cc.get_drawn_node_qty('EP_DESC'), 2**8-1)
            e = Node('dyn', value_type=UINT8(int_list=[nb]))
            return e
        e_bnumep = Node('bNumEndpoints')
        e_bnumep.set_generator_func(nb_eps, func_node_arg=e_intf_contents)
        e_bnumep.add_conf('MSD')
        e_bnumep.set_values(value_type=UINT8(int_list=[2]), conf='MSD')

        cls_ids = [USB_DEFS.USB_CLASS_MASS_STORAGE,
                   USB_DEFS.USB_CLASS_PRINTER,
                   USB_DEFS.USB_CLASS_HID,
                   USB_DEFS.USB_CLASS_HUB,
                   USB_DEFS.USB_CLASS_PHYSICAL,
                   USB_DEFS.USB_CLASS_MISC,
                   USB_DEFS.USB_CLASS_VENDOR_SPEC]

        e_bintfcls = Node('bInterfaceClass', value_type=UINT8(int_list=cls_ids))
        e_bintfcls.make_random()
        e_bintfcls.add_conf('MSD')
        e_bintfcls.set_values(value_type=UINT8(int_list=[0x08]), conf='MSD')

        subcls_ids = [0x06, 0, 1, 2, 3, 4, 5, 7, 8]
        e_bintfsubcls = Node('bInterfaceSubClass', value_type=UINT8(int_list=subcls_ids))
        e_bintfsubcls.make_random()
        e_bintfsubcls.add_conf('MSD')
        e_bintfsubcls.set_values(value_type=UINT8(int_list=[0x06]), conf='MSD')

        proto_ids = [0x80, 0x06, 0, 1, 2]
        e_bintfproto = Node('bInterfaceProtocol', value_type=UINT8(int_list=proto_ids))
        e_bintfproto.make_random()
        e_bintfproto.add_conf('MSD')
        e_bintfproto.set_values(value_type=UINT8(int_list=[0x50]), conf='MSD')

        e_iintf = Node('iInterface', value_type=UINT8(int_list=[USB_DEFS.STRINGID_INTERFACE]))
        
        e_intf_desc = Node('INTF_DESC')
        e_intf_desc.set_subnodes_basic([
                e_blength_intf,
                e_bdesctype_intf,
                e_intfnum,
                e_baltset,
                e_bnumep,
                e_bintfcls,
                e_bintfsubcls,
                e_bintfproto,
                e_iintf
                ])


        # ENDPOINT DESC

        # e_blength = Node('bLength', value_type=UINT8(int_list=[7]))
        # e_bdesctype = Node('bDescType', value_type=UINT8(int_list=[USB_DEFS.DT_ENDPOINT]))

        # vt = BitField(subfield_limits=[4,7,8],
        #               subfield_val_extremums=[[0,0b1111],None,[0,1]],
        #               subfield_val_lists=[None,[0],None],
        #               endian=VT.LittleEndian)
        # e_epaddr = Node('bEndpointAddr', value_type=vt)
        # # e_epaddr.make_determinist()
        # # old_e_epaddr = Node('bEndpointAddr', value_type=UINT8(int_list=[0b10001111]))
        
        # vt_no_ischron = BitField(subfield_limits=[2,6,8], subfield_val_lists=[[0,2,3],[0],[0]],
        #                          endian=VT.LittleEndian)
        # vt_ischron = BitField(subfield_limits=[2,4,6,8],
        #                       subfield_val_extremums=[None,[0,3],[0,2],None],
        #                       subfield_val_lists=[[1],None,None,[0]],
        #                       endian=VT.LittleEndian)
        # e_bmattrib = Node('bmAttributes', value_type=vt_no_ischron)
        # e_bmattrib.set_fuzz_weight(5)
        # # e_bmattrib.make_determinist()

        # e_bmattrib_iso = Node('bmAttributes_isoch', value_type=vt_ischron)
        # e_bmattrib_iso.set_fuzz_weight(5)
        # # e_bmattrib_iso.make_determinist()
        # # e_bmattrib.add_conf('ISO')
        # # e_bmattrib.set_values(value_type=vt_ischron, conf='ISO')

        # # old_e_bmattrib = Node('bmAttributes', value_type=UINT8(int_list=[0b00000010]))

        # vt = BitField(subfield_limits=[11,13,16],
        #               subfield_val_extremums=[[0,2047],[0,2],[0,0]],
        #               subfield_val_lists=[None,None,[0]],
        #               endian=VT.LittleEndian)
        # e_wmaxpacketsize = Node('wMaxPacketSize', value_type=vt)
        # e_wmaxpacketsize.set_fuzz_weight(4)
        # # e_wmaxpacketsize.make_determinist()

        # # old_e_wmaxpacketsize = Node('wMaxPacketSize', value_type=UINT16_le(int_list=[512, 256, 128]))
        # e_binterval = Node('bInterval', value_type=UINT8(int_list=[4]))
        
        # e_ep_desc = Node('EP_DESC')
        # e_ep_desc.set_subnodes_with_csts([
        #         2, ['u>', [e_blength, 1], [e_bdesctype, 1], [e_epaddr, 1], [e_bmattrib, 1], [e_wmaxpacketsize, 1], [e_binterval, 1]],
        #         1, ['u>', [e_blength, 1], [e_bdesctype, 1], [e_epaddr, 1], [e_bmattrib_iso, 1], [e_wmaxpacketsize, 1], [e_binterval, 1]]
        #         ])

        ep_desc = \
        {'name': 'EP_DESC',
         # 'mode': MH.Mode.ImmutableClone,
         'contents': [
             {'name': 'bLength',
              'contents': UINT8(int_list=[7])},
             {'name': 'bDescType',
              'contents': UINT8(int_list=[USB_DEFS.DT_ENDPOINT])},
             {'name': 'bEndpointAddr',
              'contents': BitField(subfield_limits=[4,7,8],
                                   subfield_val_extremums=[[0,0b1111],None,[0,1]],
                                   subfield_val_lists=[None,[0],None],
                                   endian=VT.LittleEndian),
              'alt': [
                  {'conf': 'BULK-IN',
                   'contents': BitField(subfield_limits=[4,7,8],
                                        subfield_val_lists=[[1],[0],[1]],
                                        endian=VT.LittleEndian)},
                  {'conf': 'BULK-OUT',
                   'contents': BitField(subfield_limits=[4,7,8],
                                        subfield_val_lists=[[2],[0],[0]],
                                        endian=VT.LittleEndian)}]},
             {'name': 'bmAttributes',
              'contents': BitField(subfield_limits=[2,6,8], subfield_val_lists=[[0,2,3],[0],[0]],
                                   endian=VT.LittleEndian),
              'fuzz_weight': 5,
              'alt': [
                  {'conf': 'ISO',
                   'contents': BitField(subfield_limits=[2,4,6,8],
                                        subfield_val_extremums=[None,[0,3],[0,2],None],
                                        subfield_val_lists=[[1],None,None,[0]],
                                        endian=VT.LittleEndian)}
              ]},
             {'name': 'wMaxPacketSize',
              'contents': BitField(subfield_limits=[11,13,16],
                                   subfield_val_extremums=[None,[0,2],[0,0]],
                                   subfield_val_lists=[[2**x for x in range(1,12)],None,[0]],
                                   endian=VT.LittleEndian),
              'random': True,
              'alt': [
                  {'conf': 'MSD',
                   'contents': BitField(subfield_limits=[11,13,16],
                                        subfield_val_extremums=[None,[0,2],[0,0]],
                                        subfield_val_lists=[[0x8, 0x10, 0x20, 0x40],[0],[0]],
                                        endian=VT.LittleEndian)}]},
             {'name': 'bInterval',
              'contents': UINT8(int_list=[4]),
              'alt': [
                  {'conf': 'MSD',
                   'contents': UINT8(int_list=[0])}]}
         ]}

        e_ep_desc = mh.create_graph_from_desc(ep_desc)

        # e_ep_desc.make_random(all_conf=True, recursive=True)

        e_intf_contents.set_subnodes_with_csts([
                1, ['u>', [e_ep_desc, 1, 8]]
                ])
        # e_intf_contents.set_mode(MH.Mode.ImmutableClone)
        # e_intf_contents.cc.set_mode(2)

        e_intf = Node('INTF')
        e_intf.set_subnodes_basic([e_intf_desc, e_intf_contents])
        e_intf_desc.make_random(all_conf=True, recursive=True)

        e_intf.add_conf('MSD')
        msd_intf_desc = e_intf_desc.get_clone('INTF_DESC')
        msd_intf_desc.set_current_conf('MSD', recursive=True)
        msd_ep_bulkin = e_ep_desc.get_clone('EP_BLKIN')
        msd_ep_bulkin.set_current_conf('MSD', recursive=True)
        msd_ep_bulkin.set_current_conf('BULK-IN', recursive=True)
        msd_ep_bulkout = e_ep_desc.get_clone('EP_BLKOUT')
        msd_ep_bulkout.set_current_conf('MSD', recursive=True)
        msd_ep_bulkout.set_current_conf('BULK-OUT', recursive=True)
        e_intf.set_subnodes_basic([msd_intf_desc, msd_ep_bulkin, msd_ep_bulkout], conf='MSD')

        msd_intf = e_intf.get_clone('MSD_INTF')
        msd_intf.set_current_conf('MSD')

        e_conf_contents.set_subnodes_with_csts([
                1, ['u>', [e_intf, 1, 5]]
                ])
        e_conf_contents.set_mode(MH.Mode.ImmutableClone)
        e_conf_contents.add_conf('MSD')
        e_conf_contents.set_subnodes_basic([msd_intf], conf='MSD')

        e_intf_alt = Node('INTF', base_node=e_intf, ignore_frozen_state=True)
        e_conf_contents.add_conf('BIGCONF')
        e_conf_contents.set_subnodes_with_csts([
                1, ['u>', [e_intf_alt, 1700]]
                ], conf='BIGCONF')

        # e_conf_contents.cc.set_mode(2)

        conf = Node('CONF')
        conf.set_subnodes_basic([e_conf_desc, e_conf_contents])
        # conf.set_mode(MH.Mode.ImmutableClone)
        conf.add_conf('MSD')
        msd_conf_desc = e_conf_desc.get_clone('MSD_CONF_DESC')
        msd_conf_desc.set_current_conf('MSD', recursive=True)

        conf.set_subnodes_basic([msd_conf_desc, e_conf_contents], conf='MSD')
        conf.set_semantics(NodeSemantics(['CONF_DESC']))

        msd_conf = conf.get_clone('MSD_CONF')
        msd_conf.set_current_conf('MSD', recursive=True)

        # msd_conf.show()
        # raise ValueError

        # DEVICE DESCRIPTOR

        e_blength = Node('bLength', value_type=UINT8(int_list=[18]))
        e_bdesctype = Node('bDescType', value_type=UINT8(int_list=[USB_DEFS.DT_DEVICE]))
        e_bcdusb = Node('bcdUSB', value_type=UINT16_le(int_list=[0x200, 0x100]))
        e_devclass = Node('bDeviceClass', value_type=UINT8(int_list=[0]))
        e_devsubclass = Node('bDeviceSubClass', value_type=UINT8(int_list=[0]))
        e_bdevproto = Node('bDeviceProto', value_type=UINT8(int_list=[0]))
        e_bmaxpacketsize0 = Node('bMaxPacketSize0', value_type=UINT8(int_list=[64]))
        e_idvendor = Node('idVendor', value_type=UINT16_le(int_list=[0x1307]))
        e_idproduct = Node('idProduct', value_type=UINT16_le(int_list=[0x0165]))
        e_bcddevice = Node('bcdDevice', value_type=UINT16_le(int_list=[0x100]))
        e_imanufacturer = Node('iManufacturer', value_type=UINT8(int_list=[USB_DEFS.STRINGID_MFR]))
        e_iproduct = Node('iProduct', value_type=UINT8(int_list=[USB_DEFS.STRINGID_PRODUCT]))
        e_iserialnum = Node('iSerialNumber', value_type=UINT8(int_list=[USB_DEFS.STRINGID_SERIAL]))
        e_bnumconfs = Node('bNumConfigs', value_type=UINT8(int_list=[1]))

        dev = Node('DEV')
        dev.set_subnodes_basic([
                e_blength,
                e_bdesctype,
                e_bcdusb,
                e_devclass,
                e_devsubclass,
                e_bdevproto,
                e_bmaxpacketsize0,
                e_idvendor,
                e_idproduct,
                e_bcddevice,
                e_imanufacturer,
                e_iproduct,
                e_iserialnum,
                e_bnumconfs
                ])

        dev.set_semantics(NodeSemantics(['DEV_DESC']))

        # Mass-Storage Device

        e_devclass_ms = Node('bDeviceClass', value_type=UINT8(int_list=[0]))
        e_devsubclass_ms = Node('bDeviceSubClass', value_type=UINT8(int_list=[0]))
        e_bdevproto_ms = Node('bDeviceProto', value_type=UINT8(int_list=[0]))

        dev_ms = Node('DEV_MS')
        dev_ms.set_subnodes_basic([
                e_blength,
                e_bdesctype,
                e_bcdusb,
                e_devclass_ms,
                e_devsubclass_ms,
                e_bdevproto_ms,
                e_bmaxpacketsize0,
                e_idvendor,
                e_idproduct,
                e_bcddevice,
                e_imanufacturer,
                e_iproduct,
                e_iserialnum,
                e_bnumconfs
                ])

        dev_ms.set_semantics(NodeSemantics(['DEV_DESC']))

        # LANGID TABLE

        e_langid = Node('LangID', value_type=UINT16_le(int_list=[0x040c, 0x0409]))

        e_langid_tbl_contents = Node('contents')
        def langid_len(node):
            intg = 2+len(node.to_bytes())
            if intg > 255:
                intg = 255
            e = Node('dyn', value_type=UINT8(int_list=[intg]))
            return e

        e_blength = Node('bLength')
        e_blength.set_generator_func(langid_len, func_node_arg=e_langid_tbl_contents)
        e_blength.clear_attr(NodeInternals.Freezable, recursive=False)

        e_bdesctype = Node('bDescType', value_type=UINT8(int_list=[USB_DEFS.DT_STRING]))
        e_langid_tbl_contents.set_subnodes_with_csts([
                1, ['u>', [e_langid, 0, 30]]
                ])

        langid_tbl = Node('LANGID')
        langid_tbl.set_subnodes_basic([
                e_blength,
                e_bdesctype,
                e_langid_tbl_contents
                ])

        langid_tbl.set_semantics(NodeSemantics(['LANGID_DESC']))

        # STRING
        valid_str = ['blabla...', "don't know ;)"]

        # max USB str len is 253, so in utf-16 we may have up to 126 chars (253//2)
        e_str_contents = Node('contents', vt=UTF16_LE(val_list=valid_str, max_sz=126,
                                                      max_encoded_sz=253))
        e_str_contents.set_fuzz_weight(5)
        
        def str_len(node):
            intg = 2+len(node.to_bytes())
            if intg > 255:
                intg = 255
            e = Node('dyn', value_type=UINT8(int_list=[intg]))
            return e

        e_blength = Node('bLength')
        e_blength.set_generator_func(str_len, func_node_arg=e_str_contents)
        e_blength.clear_attr(NodeInternals.Freezable, recursive=True)

        e_bdesctype = Node('bDescType', value_type=UINT8(int_list=[USB_DEFS.DT_STRING]))

        string = Node('STR')
        string.set_subnodes_basic([
                e_blength,
                e_bdesctype,
                e_str_contents
                ])

        string.set_semantics(NodeSemantics(['STRING_DESC']))

        self.register_nodes(conf, msd_conf, dev, langid_tbl, string, dev_ms)


data_model = USB_DataModel()
