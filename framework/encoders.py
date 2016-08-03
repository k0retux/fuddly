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
import struct
import zlib
import copy
import binascii

from framework.global_resources import *

class Encoder(object):
    def __init__(self, encoding_arg):
        self._encoding_arg = encoding_arg
        self.reset()

    def reset(self):
        self.init_encoding_scheme(self._encoding_arg)

    def __copy__(self):
        new_data = type(self)(self._encoding_arg)
        new_data.__dict__.update(self.__dict__)
        new_data.encoding_arg = copy.copy(self._encoding_arg)
        return new_data

    def encode(self, val):
        """
        To be overloaded.
        (Should be stateless.)

        Args:
            val (bytes): the value

        Returns:
            bytes: the encoded value
        """
        raise NotImplementedError

    def decode(self, val):
        """
        To be overloaded.
        (Should be stateless.)

        Args:
            val (bytes): the encoded value

        Returns:
            bytes: the decoded value
        """
        raise NotImplementedError

    def init_encoding_scheme(self, arg):
        """
        To be optionally overloaded by a subclass that deals with encoding,
        if encoding need to be initialized in some way. (called at init and
        in :meth:`String.reset`)

        Args:
            arg: provided through the `encoding_arg` parameter of the `String` constructor
        """
        pass

    @staticmethod
    def to_bytes(val):
        return convert_to_internal_repr(val)


class PythonCodec_Enc(Encoder):
    """
    Encoder enabling the usage of every standard encodings supported by Python.
    """
    def init_encoding_scheme(self, arg=None):
        if arg is None:
            self._codec = internal_repr_codec
        else:
            self._codec = arg

    def encode(self, val):
        enc = val.decode(internal_repr_codec, 'replace').encode(self._codec)
        return enc

    def decode(self, val):
        try:
            dec = val.decode(self._codec, 'strict')
        except:
            dec = b''
        return Encoder.to_bytes(dec)


class GZIP_Enc(Encoder):

    def init_encoding_scheme(self, arg=None):
        self.lvl = 9 if arg is None else arg

    def encode(self, val):
        return zlib.compress(val, self.lvl)

    def decode(self, val):
        try:
            dec = zlib.decompress(val)
        except:
            dec = b''

        return dec

class Wrap_Enc(Encoder):
    """
    Encoder to be used as a mean to wrap a Node with a prefix and/or a suffix,
    without defining specific Nodes for that (meaning you don't need to model
    that part and want to simplify your data description).
    """
    def init_encoding_scheme(self, arg):
        """
        Take a list parameter specifying the prefix and the
        suffix to add to the value to encode, or to remove from
        an encoded value.

        Args:
            arg (list): Prefix and suffix character strings.
              Can be individually set to None
        """
        assert(isinstance(arg, (tuple, list)))
        self.prefix = Encoder.to_bytes(arg[0])
        self.suffix = Encoder.to_bytes(arg[1])
        self.prefix_sz = 0 if self.prefix is None else len(self.prefix)
        self.suffix_sz = 0 if self.suffix is None else len(self.suffix)

    def encode(self, val):
        return self.prefix + val + self.suffix

    def decode(self, val):
        val_sz = len(val)
        if val_sz < self.prefix_sz + self.suffix_sz:
            dec = b''
        else:
            if val[:self.prefix_sz] == self.prefix and \
                            val[val_sz-self.suffix_sz:] == self.suffix:
                dec = val[self.prefix_sz:val_sz-self.suffix_sz]
            else:
                dec = b''

        return dec


class GSM7bitPacking_Enc(Encoder):

    def encode(self, msg):
        if sys.version_info[0] > 2:
            ORD = lambda x: x
        else:
            ORD = ord
        msg_sz = len(msg)
        l = []
        idx = 0
        off_cpt = 0
        while idx < msg_sz:
            off = off_cpt % 7
            c_idx = idx
            if off == 0 and off_cpt > 0:
                c_idx = idx + 1
            if c_idx+1 < msg_sz:
                l.append((ORD(msg[c_idx])>>off)+((ORD(msg[c_idx+1])<<(7-off))&0x00FF))
            elif c_idx < msg_sz:
                l.append(ORD(msg[c_idx])>>off)
            idx = c_idx + 1
            off_cpt += 1

        return b''.join(map(lambda x: struct.pack('B', x), l))

    def decode(self, msg):
        if sys.version_info[0] > 2:
            ORD = lambda x: x
        else:
            ORD = ord
        msg_sz = len(msg)
        l = []
        c_idx = 0
        off_cpt = 0
        lsb = 0
        while c_idx < msg_sz:
            off = off_cpt % 7
            if off == 0 and off_cpt > 0:
                l.append(lsb)
                lsb = 0
            if c_idx < msg_sz:
                l.append(((ORD(msg[c_idx])<<off)&0x007F)+lsb)
                lsb = ORD(msg[c_idx])>>(7-off)
            c_idx += 1
            off_cpt += 1

        return b''.join(map(lambda x: struct.pack('B', x), l))

class GSMPhoneNum_Enc(Encoder):

    def encode(self, msg):
        tel = msg
        tel_sz = len(tel)
        tel_num = b''
        for idx in range(0, tel_sz, 2):
            if idx+1<tel_sz:
                tel_num += tel[idx+1:idx+2]+tel[idx:idx+1]
            else:
                tel_num += b'F'+tel[idx:idx+1]
        return binascii.a2b_hex(tel_num)

    def decode(self, msg):
        tel_num = binascii.b2a_hex(msg)
        zone = tel_num[0:2]
        tel_num = tel_num[2:]
        dec = b''
        tel_sz = len(tel_num)
        for idx in range(0, tel_sz, 2):
            if idx+1<tel_sz:
                dec += tel_num[idx+1:idx+2]+tel_num[idx:idx+1]
        if dec[-1:] == b'f':
            dec = dec[:-1]
        return zone+dec

