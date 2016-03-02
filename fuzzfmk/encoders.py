import sys
import struct
import zlib
import copy

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
        if isinstance(val, str) or isinstance(val, bytes):
            if sys.version_info[0] > 2 and not isinstance(val, bytes):
                new_val = bytes(val, 'latin_1')
            else:
                new_val = val
        elif sys.version_info[0] == 2 and isinstance(val, unicode):
            new_val = val.encode('latin_1')
        elif isinstance(val, list) or isinstance(val, tuple):
            new_val = []
            for v in val:
                if sys.version_info[0] > 2 and not isinstance(v, bytes):
                    new_v = bytes(v, 'latin_1')
                else:
                    new_v = v
                new_val.append(new_v)
        elif val is None:
            new_val = b''
        else:
            raise ValueError

        return new_val


class UTF16LE_Enc(Encoder):

    def encode(self, val):
        enc = val.decode('latin_1').encode('utf_16_le')
        return enc

    def decode(self, val):
        try:
            dec = val.decode('utf_16_le')
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
        assert(isinstance(arg, list) or isinstance(arg, tuple))
        print(arg)
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
