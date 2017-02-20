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
from framework.data_model_builder import *

class SMS_DataModel(DataModel):

    file_extension = 'sms'

    def absorb(self, data, idx):
        pass

    def build_data_model(self):


        # Text SMS in PDU mode
        smstxt_desc = \
        {'name': 'smstxt',
         'contents': [
             {'name': 'SMS-SUBMIT',  # refer to TS 100 901 (chapter 9.2.3)
              'mutable': False,
              'contents': BitField(subfield_sizes=[2,1,2,1,1,1], endian=VT.BigEndian,
                                   subfield_values=[
                                       [0b01], # message type indicator,
                                       [0,1],  # reject duplicates
                                       [0b00,0b10,0b01,0b11],   # validity period format
                                       [0,1],  # status report request
                                       [0,1],  # user data header indicator
                                       [0,1],  # reply path
                                       ],
                                   subfield_descs=['mti','rd','vpf','srr','udhi','rp']
                                   ) },
             {'name': 'TP-MR',  # Message Reference (refer to TS 100 901)
              'mutable': False,
              'contents': UINT8(values=[0])},
             {'name': 'TP-DA',  # Destination Address (refer to TS 100 901 - chapter 9.1.2.5)
              'mutable': False,
              'contents': [
                  {'name': 'addr_len',
                   'contents': LEN(vt=UINT8, after_encoding=False),
                   'node_args': 'tel_num'},
                  {'name': 'addr_type',
                   'contents': BitField(subfield_sizes=[4,3,1], endian=VT.BigEndian,
                                        subfield_values=[[0b0001], # numbering-plan-identification
                                                            [0b001],  # type of number
                                                            [1]],     # always set to 1
                                        subfield_val_extremums=[None,
                                                                [0,7],
                                                                None],
                                        subfield_descs=['numbering','type',None]
                                        ) },
                  {'name': 'tel_num',
                   'semantics': ['tel num'],
                   'contents': GSMPhoneNum(values=['33612345678'])}
                ]},
             {'name': 'TP-PID',  # Protocol Identifier (refer to TS 100 901)
              'determinist': True,
              'contents': BitField(subfield_sizes=[5,1,2], endian=VT.BigEndian,
                                   subfield_values=[[0b00000], # implicit
                                                       [0, 1],    # no interworking (default)
                                                       [0b00]]    # kind of opcode
                                   ) },
             {'name': 'TP-DCS',  # Data Coding Scheme (refer to GSM 03.38)
              'determinist': True,
              'contents': BitField(subfield_sizes=[4,4], endian=VT.BigEndian,
                                   subfield_values=[[0b0000],   # default alphabet
                                                       [0b0000]]   # first coding group
                                   ) },
             {'name': 'UDL',
              'contents': LEN(vt=UINT8, after_encoding=False),
              'node_args': 'user_data'},
             {'name': 'user_data',
              'contents': GSM7bitPacking(values=['Hello World!'], max_sz=160)
             }
         ]
        }

        # SIM Toolkit commands
        smscmd_desc = \
        {'name': 'smscmd',   # refer to GSM 03.48
         'contents': [
             {'name': 'SMS-SUBMIT',  # refer to TS 100 901 (chapter 9.2.3)
              'mutable': False,
              'contents': BitField(subfield_sizes=[2,1,2,1,1,1], endian=VT.BigEndian,
                                   subfield_values=[
                                       [0b01], # message type indicator,
                                       [0,1],  # reject duplicates
                                       [0b00,0b10,0b01,0b11],   # validity period format
                                       [0,1],  # status report request
                                       [1,0],  # user data header indicator
                                       [0,1],  # reply path
                                       ],
                                   subfield_descs=['mti','rd','vpf','srr','udhi','rp']
                                   ) },
             {'name': 'TP-MR',  # Message Reference (refer to TS 100 901)
              'mutable': False,
              'contents': UINT8(values=[0])},
             {'name': 'TP-DA',  # Destination Address (refer to TS 100 901 - chapter 9.1.2.5)
              'mutable': False,
              'contents': [
                  {'name': 'addr_len',
                   'contents': LEN(vt=UINT8, after_encoding=False),
                   'node_args': 'tel_num'},
                  {'name': 'addr_type',
                   'contents': BitField(subfield_sizes=[4,3,1], endian=VT.BigEndian,
                                        subfield_values=[[0b0001], # numbering-plan-identification
                                                            [0b001],  # type of number
                                                            [1]],     # always set to 1
                                        subfield_val_extremums=[None,
                                                                [0,7],
                                                                None],
                                        subfield_descs=['numbering','type',None]
                                        ) },
                  {'name': 'tel_num',
                   'semantics': ['tel num'],
                   'contents': GSMPhoneNum(values=['33612345678'])}
                ]},
             {'name': 'TP-PID',  # Protocol Identifier (refer to TS 100 901)
              'determinist': True,
              'contents': BitField(subfield_sizes=[6,2], endian=VT.BigEndian,
                                   subfield_values=[[0b111111], # SIM Data Download
                                                       [0b01]],    # kind of opcode
                                   ) },
             {'name': 'TP-DCS',  # Data Coding Scheme (refer to GSM 03.38)
              'custo_set': MH.Custo.NTerm.CollapsePadding,
              'contents': [
                  {'name': 'lsb1',
                   'determinist': True,
                   'exists_if': (BitFieldCondition(sf=0, val=[0b1111]), 'msb'),
                   'contents': BitField(subfield_sizes=[2,1,1], endian=VT.BigEndian,
                                        subfield_values=[[0b10,0b11,0b00,0b01], # class 2 (default)
                                                            [1,0],    # 8-bit data (default)
                                                            [0]]      # reserved
                                        ) },
                  {'name': 'lsb2',
                   'determinist': True,
                   'exists_if': (BitFieldCondition(sf=0, val=[0b1101,0b1100]), 'msb'),
                   'contents': BitField(subfield_sizes=[2,1,1], endian=VT.BigEndian,
                                        subfield_values=[[0b10,0b11,0b00,0b01], # indication type
                                                            [0],    # reserved
                                                            [0,1]]  # set indication Active/Inactive
                                        ) },
                  {'name': 'lsb3',
                   'determinist': True,
                   'exists_if': (BitFieldCondition(sf=0, val=[0]), 'msb'),
                   'contents': BitField(subfield_sizes=[4], endian=VT.BigEndian,
                                        subfield_values=[
                                            [0b0000]  # Default alphabet
                                        ]
                                        ) },
                  {'name': 'msb',
                   'determinist': True,
                   'contents': BitField(subfield_sizes=[4], endian=VT.BigEndian,
                                        subfield_values=[
                                            [0b1111,0b1101,0b1100,0b0000]],  # last coding group
                                        ) },
             ]},
             {'name': 'UDL',
              'contents': LEN(vt=UINT8),
              'node_args': 'user_data'},
             {'name': 'user_data',
              'contents': [
                  {'name': 'UDHL',
                   'contents': UINT8(values=[2])},
                  {'name': 'IEIa', # 0x70 = command packet identifier
                   'contents': UINT8(values=[0x70], mini=0x70, maxi=0x7F)},
                  {'name': 'IEDLa',
                   'contents': UINT8(values=[0])},
                  {'name': 'CPL',  # command packet length
                   'contents': LEN(vt=UINT16_be),
                   'node_args': 'cmd'},
                  {'name': 'cmd',
                   'contents': [
                       {'name': 'CHL', # command header length
                        'contents': LEN(vt=UINT8),
                        'node_args': 'cmd_hdr'},
                       {'name': 'cmd_hdr',
                        'contents': [
                            {'name': 'SPI_p1',  # Security Parameter Indicator (part 1)
                             'contents': BitField(subfield_sizes=[2,1,2,3], endian=VT.BigEndian,
                                                  subfield_values=[None,None,None,[0b000]],
                                                  subfield_val_extremums=[[0,3],[0,1],[0,3],None],
                                                  defaults = [1, # redundancy check
                                                              0, # no ciphering
                                                              0, # no counter
                                                              None],
                                                  subfield_descs=['chksum', 'ciph', 'count', 'reserved']
                                                  ) },

                            {'name': 'SPI_p2',  # Security Parameter Indicator (part 1)
                             'contents': BitField(subfield_sizes=[2,2,1,1,2], endian=VT.BigEndian,
                                                  subfield_values=[None,None,None,None,[0b00]],
                                                  defaults = [1, # PoR required
                                                              3, # PoR Digital Signature required
                                                              0, # PoR not ciphered
                                                              1, # PoR through SMS-SUBMIT
                                                              None],
                                                  subfield_val_extremums=[[0,2],[0,3],[0,1],[0,1],None],
                                                  subfield_descs=['PoR', 'PoR chk', 'PoR ciph',
                                                                  'delivery', 'reserved']
                                                  ) },

                            {'name': 'KIc',  # Key and algo ID for ciphering
                             'contents': BitField(subfield_sizes=[2,2,4], endian=VT.BigEndian,
                                                  subfield_values=[[1,0,3], # 1 = DES (default)
                                                                      [3],     # ECB mode
                                                                      [0b1010]],
                                                  subfield_val_extremums=[None,[0,3],None],
                                                  subfield_descs=['ciph algo', 'ciph mode', 'key indic']
                                                  ) },

                            {'name': 'KID_RC',  # Key and algo ID for CRC  # TS 102 225 (5.1.3.2)
                             'contents': BitField(subfield_sizes=[2,2,4], endian=VT.BigEndian,
                                                  subfield_values=[[1,0,3], # 1 = CRC (default)
                                                                      [0b01,0b00], # 0b01 = CRC 32
                                                                      [0b1010]],
                                                  subfield_val_extremums=[None,None,
                                                                          [1,3]], # key version number to be use
                                                  subfield_descs=['ciph algo', 'ciph mode', 'key indic']
                                                  ) },

                            {'name': 'TAR',  # Toolkit Application Reference
                             'contents': BitField(subfield_sizes=[24],
                                                  subfield_values=[[0]], # Card Manager
                                                  subfield_val_extremums=[[0,2**24-1]])},

                            {'name': 'CNTR',  # Counter (replay detection and sequence integrity counter)
                             'contents':  BitField(subfield_sizes=[40],
                                                   subfield_val_extremums=[[0,2**40-1]]) },

                            {'name': 'PCNTR',  # padding counter
                             'contents': UINT8() },

                            {'name': 'RC|CC|DS',  # redundancy check, (crypto check, or digital sig)
                             'exists_if': (BitFieldCondition(sf=0,val=1), 'SPI_p1'),  # RC only
                             'contents': CRC(poly=0b100000100110000010001110110110111,  # TS 102 225 (5.1.3.2)
                                                init_crc=0, # init_crc=0xFFFFFFFF match the spec but to
                                                            # match the example of annex B, init_crc should 0.
                                                xor_out=0xFFFFFFFF,
                                                rev=True,
                                                vt=UINT32_be),
                             'node_args': ['SPI_p1','SPI_p2','KIc','KID_RC','TAR','CNTR','PCNTR','SecData']},

                            {'name': 'SecData',
                             'contents': String(min_sz=1, max_sz=100, determinist=False)}
                        ]},

                   ]},

              ]}
         ]}


        self.register(smstxt_desc, smscmd_desc)

data_model = SMS_DataModel()
