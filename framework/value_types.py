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

from __future__ import print_function

import struct
import random
import sys
import itertools
import copy
import math
import binascii
import collections
import string
import re
import zlib
import codecs

import six
from six import with_metaclass

sys.path.append('.')

import framework.basic_primitives as bp
from framework.data_model import AbsorbStatus, AbsCsts
from framework.encoders import *
from framework.error_handling import *
from framework.global_resources import *

DEBUG = False

class VT(object):
    '''
    Base class for value type classes accepted by value Elts
    '''
    mini = None
    maxi = None

    BigEndian = 1
    LittleEndian = 2
    Native = 3

    enc2struct = {
        BigEndian: '>',
        LittleEndian: '<',
        Native: '='
        }

    def __init__(self, endian=BigEndian):
        self.endian = self.enc2struct[endian]

    def make_private(self, forget_current_state):
        pass

    def make_determinist(self):
        pass

    def make_random(self):
        pass

    def get_value(self):
        raise NotImplementedError('New value type shall impplement this method!')

    def get_current_raw_val(self):
        return None

    def reset_state(self):
        raise NotImplementedError

    def rewind(self):
        raise NotImplementedError

    def is_exhausted(self):
        return False

    def set_size_from_constraints(self, size=None, encoded_size=None):
        raise NotImplementedError

    def pretty_print(self, max_size=None):
        return None


class VT_Alt(VT):

    def __init__(self, *args, **kargs):
        self._fuzzy_mode = False
        self.init_specific(*args, **kargs)

    def init_specific(self):
        raise NotImplementedError

    def switch_mode(self):
        if self._fuzzy_mode:
            self.enable_normal_mode()
        else:
            self.enable_fuzz_mode()

        self._fuzzy_mode = not self._fuzzy_mode
        self.after_enabling_mode()

    def after_enabling_mode(self):
        pass

    def enable_normal_mode(self):
        raise NotImplementedError

    def enable_fuzz_mode(self):
        raise NotImplementedError



class meta_8b(type):

    compatible_class = collections.OrderedDict()
    fuzzy_class = collections.OrderedDict()

    def __init__(cls, name, bases, attrs):
        type.__init__(cls, name, (VT,) + bases, attrs)
        cls.size = 8
        cls.compat_cls = meta_8b.compatible_class
        cls.fuzzy_cls = meta_8b.fuzzy_class

        # avoid adding the class of the 'six' module
        if cls.__module__ != 'six':
            if 'usable' in attrs:
                if cls.usable == False:
                    return
            else:
                cls.usable = True
            meta_8b.compatible_class[name] = cls

        if "Fuzzy" in name:
            meta_8b.fuzzy_class[name] = cls



class meta_16b(type):

    compatible_class = collections.OrderedDict()
    fuzzy_class = collections.OrderedDict()

    def __init__(cls, name, bases, attrs):
        type.__init__(cls, name, (VT,) + bases, attrs)
        cls.size = 16
        cls.compat_cls = meta_16b.compatible_class
        cls.fuzzy_cls = meta_16b.fuzzy_class

        # avoid adding the class of the 'six' module
        if cls.__module__ != 'six':
            if 'usable' in attrs:
                if cls.usable == False:
                    return
            else:
                cls.usable = True
            meta_16b.compatible_class[name] = cls

        if "Fuzzy" in name:
            meta_16b.fuzzy_class[name] = cls



class meta_32b(type):

    compatible_class = collections.OrderedDict()
    fuzzy_class = collections.OrderedDict()

    def __init__(cls, name, bases, attrs):
        type.__init__(cls, name, (VT,) + bases, attrs)
        cls.size = 32
        cls.compat_cls = meta_32b.compatible_class
        cls.fuzzy_cls = meta_32b.fuzzy_class

        # avoid adding the class of the 'six' module
        if cls.__module__ != 'six':
            if 'usable' in attrs:
                if cls.usable == False:
                    return
            else:
                cls.usable = True
            meta_32b.compatible_class[name] = cls

        if "Fuzzy" in name:
            meta_32b.fuzzy_class[name] = cls


class meta_64b(type):

    compatible_class = collections.OrderedDict()
    fuzzy_class = collections.OrderedDict()

    def __init__(cls, name, bases, attrs):
        type.__init__(cls, name, (VT,) + bases, attrs)
        cls.size = 64
        cls.compat_cls = meta_64b.compatible_class
        cls.fuzzy_cls = meta_64b.fuzzy_class

        # avoid adding the class of the 'six' module
        if cls.__module__ != 'six':
            if 'usable' in attrs:
                if cls.usable == False:
                    return
            else:
                cls.usable = True
            meta_64b.compatible_class[name] = cls

        if "Fuzzy" in name:
            meta_64b.fuzzy_class[name] = cls


class meta_int_str(type):

    compatible_class = collections.OrderedDict()
    fuzzy_class = collections.OrderedDict()

    def __init__(cls, name, bases, attrs):
        type.__init__(cls, name, (VT,) + bases, attrs)
        cls.compat_cls = meta_int_str.compatible_class
        cls.fuzzy_cls = meta_int_str.fuzzy_class

        # avoid adding the class of the 'six' module
        if cls.__module__ != 'six':
            if 'usable' in attrs:
                if cls.usable == False:
                    return
            else:
                cls.usable = True
            meta_int_str.compatible_class[name] = cls

        if "Fuzzy" in name:
            meta_int_str.fuzzy_class[name] = cls


class String(VT_Alt):
    """
    Value type that represents a character string.

    Attributes:
        encoded_string (bool): shall be set to True by any subclass that deals
          with encoding
        specific_fuzzing_list (list): attribute to be added by subclasses that provide
          specific test cases.
    """

    DEFAULT_MAX_SZ = 10000
    encoded_string = False

    def encode(self, val):
        """
        To be overloaded by a subclass that deals with encoding.
        (Should be stateless.)

        Args:
            val (bytes): the value

        Returns:
            bytes: the encoded value
        """
        return val

    def decode(self, val):
        """
        To be overloaded by a subclass that deals with encoding.
        (Should be stateless.)

        Args:
            val (bytes): the encoded value

        Returns:
            bytes: the decoded value
        """
        return val

    def init_encoding_scheme(self, arg):
        """
        To be optionally overloaded by a subclass that deals with encoding,
        if encoding need to be initialized in some way. (called at init and
        in :meth:`String.reset`)

        Args:
            arg: provided through the `encoding_arg` parameter of the `String` constructor

        """
        return

    def encoding_test_cases(self, current_val, max_sz, min_sz, min_encoded__sz, max_encoded_sz):
        """
        To be optionally overloaded by a subclass that deals with encoding
        in order to provide specific test cases on encoding scheme.

        Args:
            current_val: the current value (not encoded)
            max_sz: maximum size for a not encoded string
            min_sz: minimum size for a not encoded string
            min_encoded_sz: minimum encoded size for a string
            max_encoded_sz: maximum encoded size for a string

        Returns:
            list: the list of encoded test cases
        """
        return None

    def __repr__(self):
        if DEBUG:
            return VT_Alt.__repr__(self)[:-1] + ' contents:' + str(self.val_list) + '>'
        else:
            return VT_Alt.__repr__(self)

    def _str2bytes(self, val):
        if val is None:
            return b''
        elif isinstance(val, (list, tuple)):
            b = []
            for v in val:
                b.append(self._str2bytes(v))
        else:
            if sys.version_info[0] > 2:
                b = val if isinstance(val, bytes) else val.encode(self.codec)
            else:
                try:
                    b = val.encode(self.codec)
                except:
                    err_msg = "\n*** WARNING: Encoding issue. With python2 'str' or 'bytes' means " \
                              "ASCII, prefix the string {:s} with 'u'".format(repr(val[:30]))
                    print(err_msg)
                    b = val
        return b

    def _bytes2str(self, val):
        if isinstance(val, (list, tuple)):
            b = [v.decode(self.codec) for v in val]
        else:
            b = val.decode(self.codec)
        return b

    UTF16LE = codecs.lookup('utf-16-le').name
    UTF16BE = codecs.lookup('utf-16-be').name
    ASCII = codecs.lookup('ascii').name
    LATIN_1 = codecs.lookup('latin-1').name

    def init_specific(self, val_list=None, size=None, min_sz=None,
                      max_sz=None, determinist=True, codec='latin-1', ascii_mode=False,
                      extra_fuzzy_list=None, absorb_regexp=None,
                      alphabet=None, min_encoded_sz=None, max_encoded_sz=None, encoding_arg=None):

        """
        Initialize the String

        Args:
            val_list: List of the character strings that are considered valid for the node
              backed by this *String object*.
            size: Valid character string size for the node backed by this *String object*.
            min_sz: Minimum valid size for the character strings for the node backed by
              this *String object*. If not set, this parameter will be
              automatically inferred by looking at the parameter ``val_list``
              whether this latter is provided.
            max_sz: Maximum valid size for the character strings for the node backed by this
              *String object*. If not set, this parameter will be
              automatically inferred by looking at the parameter ``val_list``
              whether this latter is provided.
            determinist: If set to ``True`` generated values will be in a deterministic
              order, otherwise in a random order.
            codec: codec to use for encoding the string (e.g., 'latin-1', 'utf8')
            ascii_mode: If set to ``True``, it will enforce the string to comply with ASCII
              7 bits.
            extra_fuzzy_list: During data generation, if this parameter is specified with some
              specific values, they will be part of the test cases generated by
              the generic disruptor tTYPE.
            absorb_regexp (str): You can specify a regular expression in this parameter as a
              supplementary constraint for data absorption operation.
            alphabet: The alphabet to use for generating data, in case no `val_list` is
              provided. Also use during absorption to validate the contents. It is
              checked if there is no `val_list`.
            min_encoded_sz: Only relevant for subclasses that leverage the encoding infrastructure.
              Enable to provide the minimum legitimate size for an encoded string.
            max_encoded_sz: Only relevant for subclasses that leverage the encoding infrastructure.
              Enable to provide the maximum legitimate size for an encoded string.
            encoding_arg: Only relevant for subclasses that leverage the encoding infrastructure
              and that allow their encoding scheme to be configured. This parameter is directly
              provided to :meth:`String.init_encoding_scheme`. Any object that go through this
              parameter should support the ``__copy__`` method.
        """

        self.drawn_val = None

        self.val_list = None
        self.val_list_copy = None
        self.val_list_fuzzy = None
        self.val_list_save = None

        self.is_val_list_provided = None

        self.min_sz = None
        self.max_sz = None

        if self.__class__.encode != String.encode:
            self.encoded_string = True
            if not hasattr(self, 'encoding_arg'):
                self.encoding_arg = encoding_arg
            self.init_encoding_scheme(self.encoding_arg)

        self.set_description(val_list=val_list, size=size, min_sz=min_sz,
                             max_sz=max_sz, determinist=determinist, codec=codec,
                             ascii_mode=ascii_mode, extra_fuzzy_list=extra_fuzzy_list,
                             absorb_regexp=absorb_regexp, alphabet=alphabet,
                             min_encoded_sz=min_encoded_sz, max_encoded_sz=max_encoded_sz)

    def make_private(self, forget_current_state):
        if forget_current_state:
            if self.is_val_list_provided:
                self.val_list = copy.copy(self.val_list)
            else:
                self._populate_val_list()
            self.reset_state()
        else:
            self.val_list = copy.copy(self.val_list)
            self.val_list_copy = copy.copy(self.val_list_copy)
            if self.encoded_string:
                self.encoding_arg = copy.copy(self.encoding_arg)

    def make_determinist(self):
        self.determinist = True

    def make_random(self):
        if not self._fuzzy_mode:
            self.determinist = False

    def absorb_auto_helper(self, blob, constraints):
        off = 0
        size = self.max_encoded_sz
        # If 'Contents' constraint is set, we seek for string within
        # val_list or conforming to the alphabet.
        # If 'Regexp' constraint is set, we seek for string matching
        # the regexp.
        # If no such constraints are provided, we assume off==0
        # and let do_absorb() decide if it's OK (via size constraints
        # for instance).
        blob_dec = self.decode(blob)
        if constraints[AbsCsts.Contents] and self.val_list is not None and self.alphabet is None:
            for v in self.val_list:
                if blob_dec.startswith(v):
                    break
            else:
                for v in self.val_list:
                    if self.encoded_string:
                        v = self.encode(v)
                    off = blob.find(v)
                    if off > -1:
                        size = len(v)
                        break

        elif constraints[AbsCsts.Contents] and self.alphabet is not None:
            size = None
            blob_str = self._bytes2str(blob_dec)
            alp = self._bytes2str(self.alphabet)
            for l in alp:
                if blob_str.startswith(l):
                    break
            else:
                sup_sz = len(blob)+1
                off = sup_sz
                for l in alp:
                    l = self.encode(self._str2bytes(l))
                    new_off = blob.find(l)
                    if new_off < off and new_off > -1:
                        off = new_off
                if off == sup_sz:
                    off = -1

        elif constraints[AbsCsts.Regexp] and self.regexp is not None:
            g = re.search(self.regexp, self._bytes2str(blob_dec), re.S)
            if g is not None:
                pattern_enc = self.encode(self._str2bytes(g.group(0)))
                off = blob.find(pattern_enc)
                size = len(pattern_enc)
            else:
                off = -1

        if off < 0:
            return AbsorbStatus.Reject, off, size
        else:
            return AbsorbStatus.Accept, off, size


    def do_absorb(self, blob, constraints, off=0, size=None):
        """
        Core function for absorption.

        Args:
            blob: binary string on which to perform absorption
            constraints: constraints to comply with
            off: absorption should start at offset `off` from blob
            size: if provided, `size` relates to the string to be absorbed (which can be encoded)

        Returns:
            value, off, size
        """
        self.orig_max_sz = self.max_sz
        self.orig_min_encoded_sz = self.min_encoded_sz
        self.orig_max_encoded_sz = self.max_encoded_sz
        self.orig_min_sz = self.min_sz
        self.orig_val_list = copy.copy(self.val_list)
        self.orig_val_list_copy = copy.copy(self.val_list_copy)
        self.orig_drawn_val = self.drawn_val

        if constraints[AbsCsts.Size]:
            sz = size if size is not None and size < self.max_encoded_sz else self.max_encoded_sz

            # if encoded string, val is returned decoded
            val = self._read_value_from(blob[off:sz+off], constraints)

            val_enc_sz = len(self.encode(val)) # maybe different from sz if blob is smaller
            if val_enc_sz < self.min_encoded_sz:
                raise ValueError('min_encoded_sz constraint not respected!')
            if not self.encoded_string:
                val_sz = val_enc_sz
        else:
            blob = blob[off:] #blob[off:size+off] if size is not None else blob[off:]
            val = self._read_value_from(blob, constraints)
            val_sz = len(val)

        if constraints[AbsCsts.Contents] and self.is_val_list_provided:
            for v in self.val_list:
                if val.startswith(v):
                    val = v
                    val_sz = len(val)
                    break
            else:
                if self.alphabet is not None:
                    val, val_sz = self._check_alphabet(val, constraints)
                else:
                    raise ValueError('contents not valid!')
        elif constraints[AbsCsts.Contents] and self.alphabet is not None:
            val, val_sz = self._check_alphabet(val, constraints)

        if self.encoded_string:
            val_enc = self.encode(val)
            val_enc_sz = len(val_enc)

        # If we reach this point that means that val is accepted. Thus
        # update max and min if necessary.
        if not constraints[AbsCsts.Size]:
            if val_sz > self.max_sz:
                self.max_sz = val_sz
            elif val_sz < self.min_sz:
                self.min_sz = val_sz
            if self.encoded_string:
                if val_enc_sz > self.max_encoded_sz:
                    self.max_encoded_sz = val_enc_sz
                elif val_enc_sz < self.min_encoded_sz:
                    self.min_encoded_sz = val_enc_sz

        if self.val_list is None:
            self.val_list = []

        self.val_list.insert(0, val)

        self.reset_state()

        if self.encoded_string:
            # off is still valid here (not modified by this method)
            return val_enc, off, val_enc_sz
        else:
            return val, off, val_sz


    def _check_alphabet(self, val, constraints):
        i = -1  # to cover case where val is ''
        for i, l in enumerate(val):
            if l not in self.alphabet:
                sz = i
                break
        else:
            sz = i+1

        if sz > 0:
            val_sz = sz
        else:
            raise ValueError('contents not valid!')
        if constraints[AbsCsts.Size]:
            if val_sz > self.max_sz:
                val_sz = self.max_sz
                val = val[:val_sz]
            elif val_sz < self.min_sz:
                raise ValueError('contents not valid!')
            else:
                val = val[:sz]
        else:
            val = val[:sz]

        return val, val_sz


    def do_revert_absorb(self):
        '''
        If needed should be called just after self.do_absorb().
        (safe to recall it more than once)
        '''
        if hasattr(self, 'orig_drawn_val'):
            self.val_list = self.orig_val_list
            self.val_list_copy = self.orig_val_list_copy
            self.min_sz = self.orig_min_sz
            self.max_sz = self.orig_max_sz
            self.min_encoded_sz = self.orig_min_encoded_sz
            self.max_encoded_sz = self.orig_max_encoded_sz
            self.drawn_val = self.orig_drawn_val

    def do_cleanup_absorb(self):
        '''
        To be called after self.do_absorb() or self.do_revert_absorb()
        '''
        if hasattr(self, 'orig_drawn_val'):
            del self.orig_val_list
            del self.orig_val_list_copy
            del self.orig_min_sz
            del self.orig_max_sz
            del self.orig_max_encoded_sz
            del self.orig_drawn_val

    def _read_value_from(self, blob, constraints):
        if self.encoded_string:
            blob = self.decode(blob)
        if constraints[AbsCsts.Regexp]:
            g = re.match(self.regexp, self._bytes2str(blob), re.S)
            if g is None:
                raise ValueError('regexp not valid!')
            else:
                return self._str2bytes(g.group(0))
        else:
            return blob

    def reset_state(self):
        self.val_list_copy = copy.copy(self.val_list)
        self.drawn_val = None
        if self.encoded_string:
            self.encoding_arg = copy.copy(self.encoding_arg)
            self.init_encoding_scheme(self.encoding_arg)

    def rewind(self):
        sz_vlist_copy = len(self.val_list_copy)
        sz_vlist = len(self.val_list)
        if self.val_list_copy is not None and \
           sz_vlist_copy < sz_vlist:
            val = self.val_list[sz_vlist - sz_vlist_copy - 1]
            self.val_list_copy.insert(0, val)

        self.drawn_val = None

    def _check_sizes(self, val_list):
        if val_list is not None:
            for v in val_list:
                sz = len(v)
                if self.max_sz is not None:
                    assert(self.max_sz >= sz >= self.min_sz)
                else:
                    assert(sz >= self.min_sz)


    def set_description(self, val_list=None, size=None, min_sz=None,
                        max_sz=None, determinist=True, codec='latin-1',
                        ascii_mode=False, extra_fuzzy_list=None,
                        absorb_regexp=None, alphabet=None,
                        min_encoded_sz=None, max_encoded_sz=None):
        '''
        @size take precedence over @min_sz and @max_sz
        '''
        self.codec = codecs.lookup(codec).name # normalize
        self.max_encoded_sz = max_encoded_sz
        self.min_encoded_sz = min_encoded_sz

        if alphabet is not None:
            self.alphabet = self._str2bytes(alphabet)
        else:
            self.alphabet = None
        self.ascii_mode = ascii_mode

        if absorb_regexp is None:
            if self.ascii_mode:
                self.regexp = '[\x00-\x7f]*'
            else:
                self.regexp = '.*'
        else:
            self.regexp = absorb_regexp

        if extra_fuzzy_list is not None:
            self.extra_fuzzy_list = self._str2bytes(extra_fuzzy_list)
        elif hasattr(self, 'specific_fuzzing_list'):
            self.extra_fuzzy_list = self.specific_fuzzing_list
        else:
            self.extra_fuzzy_list = None

        if val_list is not None:
            assert isinstance(val_list, list)
            self.val_list = self._str2bytes(val_list)
            for val in self.val_list:
                if not self._check_compliance(val, force_max_enc_sz=max_encoded_sz is not None,
                                              force_min_enc_sz=min_encoded_sz is not None,
                                              update_list=False):
                    raise DataModelDefinitionError

                if self.alphabet is not None:
                    for l in val:
                        if l not in self.alphabet:
                            raise ValueError("The value '%s' does not conform to the alphabet!" % val)

            self.val_list_copy = copy.copy(self.val_list)
            self.is_val_list_provided = True  # distinguish cases where
                                           # val_list is provided or
                                           # created based on size
            self.user_provided_list = copy.copy(self.val_list)
        else:
            self.is_val_list_provided = False
            self.user_provided_list = None

        if size is not None:
            self.min_sz = size
            self.max_sz = size
        elif min_sz is not None and max_sz is not None:
            assert(max_sz >= 0 and min_sz >= 0 and max_sz - min_sz >= 0)
            self.min_sz = min_sz
            self.max_sz = max_sz
        elif min_sz is not None:
            self.min_sz = min_sz
            # for string with no size limit, we set a threshold to
            # DEFAULT_MAX_SZ chars
            self.max_sz = self.DEFAULT_MAX_SZ
        elif max_sz is not None:
            self.max_sz = max_sz
            self.min_sz = 0
        elif val_list is not None:
            sz = 0
            for v in val_list:
                length = len(v)
                if length > sz:
                    sz = length
            self.max_sz = sz
            self.min_sz = 0
        elif max_encoded_sz is not None:
            # If we reach this condition, that means no size has been provided, we thus decide
            # an arbitrary default value for max_sz. Regarding absorption, this arbitrary choice will
            # have no influence, as only max_encoded_sz will be used.
            self.min_sz = 0
            self.max_sz = max_encoded_sz
        else:
            self.min_sz = 0
            self.max_sz = self.DEFAULT_MAX_SZ

        self._check_sizes(val_list)

        if val_list is None:
            self._populate_val_list(force_max_enc_sz=max_encoded_sz is not None,
                                    force_min_enc_sz=min_encoded_sz is not None)

        self.determinist = determinist

        if not self.encoded_string:
            # For a non-Encoding type, the size of the string is always lesser or equal than the size
            # of the encoded string. Hence the byte string size is still >= to the string size.
            if self.max_encoded_sz is None or self.max_encoded_sz < self.max_sz:
                self.max_encoded_sz = self.max_sz
            if self.min_encoded_sz is None or self.min_encoded_sz < self.min_sz:
                self.min_encoded_sz = self.min_sz

    def _check_compliance(self, value, force_max_enc_sz, force_min_enc_sz, update_list=True):
        if self.encoded_string:
            try:
                enc_val = self.encode(value)
            except:
                return False
            val_sz = len(enc_val)
            if not force_max_enc_sz and not force_min_enc_sz:
                if self.max_encoded_sz is None or val_sz > self.max_encoded_sz:
                    self.max_encoded_sz = val_sz
                if self.min_encoded_sz is None or val_sz < self.min_encoded_sz:
                    self.min_encoded_sz = val_sz
                if update_list:
                    self.val_list.append(value)
                return True
            elif force_max_enc_sz and not force_min_enc_sz:
                if val_sz <= self.max_encoded_sz:
                    if self.min_encoded_sz is None or val_sz < self.min_encoded_sz:
                        self.min_encoded_sz = val_sz
                    if update_list:
                        self.val_list.append(value)
                    return True
                else:
                    return False
            elif not force_max_enc_sz and force_min_enc_sz:
                if val_sz >= self.min_encoded_sz:
                    if self.max_encoded_sz is None or val_sz > self.max_encoded_sz:
                        self.max_encoded_sz = val_sz
                    if update_list:
                        self.val_list.append(value)
                    return True
                else:
                    return False
            else:
                if val_sz <= self.max_encoded_sz and val_sz >= self.min_encoded_sz:
                    if update_list:
                        self.val_list.append(value)
                    return True
                else:
                    return False
        else:
            val_sz = len(value)
            if self.max_encoded_sz is None or val_sz > self.max_encoded_sz:
                self.max_encoded_sz = val_sz
            if self.min_encoded_sz is None or val_sz < self.min_encoded_sz:
                self.min_encoded_sz = val_sz
            if update_list:
                self.val_list.append(value)
            return True

    def _populate_val_list(self, force_max_enc_sz=False, force_min_enc_sz=False):
        self.val_list = []
        alpbt = string.printable if self.alphabet is None else self._bytes2str(self.alphabet)
        if self.min_sz < self.max_sz:
            self._check_compliance(self._str2bytes(bp.rand_string(size=self.max_sz, str_set=alpbt)),
                                   force_max_enc_sz=force_max_enc_sz, force_min_enc_sz=force_min_enc_sz)
            self._check_compliance(self._str2bytes(bp.rand_string(size=self.min_sz, str_set=alpbt)),
                                   force_max_enc_sz=force_max_enc_sz, force_min_enc_sz=force_min_enc_sz)
        else:
            self._check_compliance(self._str2bytes(bp.rand_string(size=self.max_sz, str_set=alpbt)),
                                   force_max_enc_sz=force_max_enc_sz, force_min_enc_sz=force_min_enc_sz)
        if self.min_sz+1 < self.max_sz:
            NB_VALS_MAX = 3
            for idx in range(NB_VALS_MAX):
                nb_vals = 0
                retry_cpt = 0
                while nb_vals < NB_VALS_MAX and retry_cpt < 5:
                    val = bp.rand_string(mini=self.min_sz+1, maxi=self.max_sz-1, str_set=alpbt)
                    if self._check_compliance(self._str2bytes(val), force_max_enc_sz=force_max_enc_sz,
                                              force_min_enc_sz=force_min_enc_sz):
                        nb_vals += 1
                    else:
                        retry_cpt += 1

        if len(self.val_list) == 0:
            raise DataModelDefinitionError

    def get_current_raw_val(self):
        if self.drawn_val is None:
            self.get_value()
        return self.drawn_val
    
    def enable_normal_mode(self):
        self.val_list = self.val_list_save
        self.val_list_copy = copy.copy(self.val_list)
        self.val_list_fuzzy = None

        self.drawn_val = None

    def enable_fuzz_mode(self):
        self.val_list_fuzzy = []

        if self.drawn_val is not None:
            orig_val = self.drawn_val
        else:
            if self.determinist:
                orig_val = self.val_list_copy[0]
            else:
                orig_val = random.choice(self.val_list_copy)

        sz = len(orig_val)
        sz_delta_with_max = self.max_sz - sz

        try:
            val = bp.corrupt_bits(orig_val, n=1, ascii=self.ascii_mode)
            self.val_list_fuzzy.append(val)
        except:
            print("\n*** Value is empty! --> skipping bitflip test case ***")

        val = orig_val + b"A"*(sz_delta_with_max + 1)
        self.val_list_fuzzy.append(val)

        self.val_list_fuzzy.append(b'')
        if sz > 0:
            sz_delta_with_min = sz - self.min_sz
            val = orig_val[:-sz_delta_with_min-1]
            if val != b'':
                self.val_list_fuzzy.append(val)

        val = orig_val + b"X"*(self.max_sz*8)
        self.val_list_fuzzy.append(val)

        self.val_list_fuzzy.append(b'\x00'*sz if sz>0 else b'\x00')

        if sz > 1:
            is_even = sz % 2 == 0
            cpt = sz // 2
            if is_even:
                self.val_list_fuzzy.append(b'%n' * cpt)
                self.val_list_fuzzy.append(b'%s' * cpt)
                self.val_list_fuzzy.append(b'\r\n' * cpt)
            else:
                self.val_list_fuzzy.append(orig_val[:1] + b'%n' * cpt)
                self.val_list_fuzzy.append(orig_val[:1] + b'%s' * cpt)
                self.val_list_fuzzy.append(orig_val[:1] + b'\r\n' * cpt)
        else:
            self.val_list_fuzzy.append(b'%n%n%n')
            self.val_list_fuzzy.append(b'%s%s%s')
            self.val_list_fuzzy.append(b'\r\n')

        if self.extra_fuzzy_list:
            for v in self.extra_fuzzy_list:
                if v not in self.val_list_fuzzy:
                    self.val_list_fuzzy.append(v)

        if self.codec == self.ASCII:
            val = bytearray(orig_val)
            if len(val) > 0:
                val[0] |= 0x80
                val = bytes(val)
            else:
                val = b'\xe9'
            if val not in self.val_list_fuzzy:
                self.val_list_fuzzy.append(val)
        elif self.codec == self.UTF16BE or self.codec == self.UTF16LE:
            if self.max_sz > 0:
                if self.max_encoded_sz % 2 == 1:
                    nb = self.max_sz // 2
                    # euro character at the end that 'fully' use the 2 bytes of utf-16
                    val = ('A' * nb).encode(self.codec) + b'\xac\x20'
                    if val not in self.val_list_fuzzy:
                        self.val_list_fuzzy.append(val)

        enc_cases = self.encoding_test_cases(orig_val, self.max_sz, self.min_sz,
                                             self.min_encoded_sz, self.max_encoded_sz)
        if enc_cases:
            if self.ascii_mode:
                new_enc_cases = []
                for v in enc_cases:
                    s = ''
                    for i in bytearray(v):
                        s += chr(i & 0x7f)
                    new_enc_cases.append(bytes(s))
                enc_cases = new_enc_cases

            self.val_list_fuzzy += enc_cases

        self.val_list_save = self.val_list
        self.val_list = self.val_list_fuzzy
        self.val_list_copy = copy.copy(self.val_list)

        self.drawn_val = None

    def get_value(self):
        if not self.val_list_copy:
            self.val_list_copy = copy.copy(self.val_list)
        if self.determinist:
            ret = self.val_list_copy.pop(0)
        else:
            ret = random.choice(self.val_list_copy)
            self.val_list_copy.remove(ret)

        self.drawn_val = ret
        if self.encoded_string:
            ret = self.encode(ret)
        return ret

    def is_exhausted(self):
        if self.val_list_copy:
            return False
        else:
            return True

    def set_size_from_constraints(self, size=None, encoded_size=None):
        # This method is used only for absorption purpose, thus no modification
        # is performed on self.val_list. To be reconsidered in the case the method
        # has to be used for an another purpose.

        assert size is not None or encoded_size is not None
        if encoded_size is not None:
            if encoded_size == self.max_encoded_sz:
                return
            self.max_encoded_sz = encoded_size
            self.min_encoded_sz = self.max_encoded_sz
        elif size is not None:
            if size == self.max_sz and size == self.min_sz:
                return
            self.min_sz = self.max_sz = size
        else:
            raise ValueError

    def pretty_print(self, max_size=None):
        if self.drawn_val is None:
            self.get_value()

        if self.encoded_string or self.codec not in [self.ASCII, self.LATIN_1]:
            dec = self.drawn_val
            sz = len(dec)
            if max_size is not None and sz > max_size:
                dec = dec[:max_size]
            dec = dec.decode(self.codec, 'replace')
            if sys.version_info[0] == 2:
                dec = dec.encode('ascii', 'replace')
            return dec + ' [decoded, sz={!s}, codec={!s}]'.format(len(dec), self.codec)
        else:
            return 'codec={!s}'.format(self.codec)


class INT(VT):
    '''
    Base class to be inherited and not used directly
    '''
    mini = None
    maxi = None
    cformat = None
    endian = None
    determinist = True

    mini_gen = None  # automatically set and only used for generation (not absorption)
    maxi_gen = None  # automatically set and only used for generation (not absorption)
    GEN_MAX_INT = 2**32  # 'maxi_gen' is set to this when the INT subclass does not define 'maxi'
                         # and that maxi is not specified by the user
    GEN_MIN_INT = -2**32  # 'mini_gen' is set to this when the INT subclass does not define 'mini'
                          # and that mini is not specified by the user


    def __init__(self, int_list=None, mini=None, maxi=None, default=None, determinist=True):
        self.idx = 0
        self.determinist = determinist
        self.exhausted = False
        self.drawn_val = None
        self.default = None

        if int_list:
            assert default is None
            self.int_list = list(int_list)
            self.int_list_copy = list(self.int_list)

        else:
            if mini is not None and maxi is not None:
                assert maxi >= mini

            if mini is not None and maxi is not None and abs(maxi - mini) < 200:
                self.int_list = list(range(mini, maxi+1))
                # we keep min/max information as it may be valuable for fuzzing
                self.mini = self.mini_gen = mini
                self.maxi = self.maxi_gen = maxi
                if default is not None:
                    assert mini <= default <= maxi
                    self.int_list.remove(default)
                    self.int_list.insert(0,default)
                    # Once inserted at this place, its position is preserved, especially with reset_state()
                    # (assuming do_absorb() is not called), so we do not save 'default' value in this case
                self.int_list_copy = copy.copy(self.int_list)

            else:
                self.int_list = None
                self.int_list_copy = None
                if self.mini is not None:
                    self.mini = max(mini, self.mini) if mini is not None else self.mini
                    self.mini_gen = self.mini
                else:
                    # case where no size constraints exist (e.g., INT_str)
                    if mini is None:
                        self.mini = None
                        self.mini_gen = INT.GEN_MIN_INT
                    else:
                        self.mini = self.mini_gen = mini

                if self.maxi is not None:
                    self.maxi = min(maxi, self.maxi) if maxi is not None else self.maxi
                    self.maxi_gen = self.maxi
                else:
                    # case where no size constraints exist (e.g., INT_str)
                    if maxi is None:
                        self.maxi = None
                        self.maxi_gen = INT.GEN_MAX_INT
                    else:
                        self.maxi = self.maxi_gen = maxi

                if default is not None:
                    assert self.mini_gen <= default <= self.maxi_gen
                    self.default = default
                    self.idx = default - self.mini_gen

    def make_private(self, forget_current_state):
        # no need to copy self.default (that should not be modified)
        if forget_current_state:
            self.int_list_copy = copy.copy(self.int_list)
            self.idx = 0
            self.exhausted = False
            self.drawn_val = None
        else:
            self.int_list_copy = copy.copy(self.int_list_copy)


    def absorb_auto_helper(self, blob, constraints):
        off = 0
        # If 'Contents' constraint is set, we seek for int within
        # int_list.
        # If INT() does not have int_list, we assume off==0
        # and let do_absorb() decide if it's OK.
        if constraints[AbsCsts.Contents] and self.int_list is not None:
            for v in self.int_list:
                if blob.startswith(self._convert_value(v)):
                    break
            else:
                for v in self.int_list:
                    off = blob.find(self._convert_value(v))
                    if off > -1:
                        break

        if off < 0:
            return AbsorbStatus.Reject, off, None
        else:
            return AbsorbStatus.Accept, off, None


    def do_absorb(self, blob, constraints, off=0, size=None):

        self.orig_int_list = copy.copy(self.int_list)
        self.orig_int_list_copy = copy.copy(self.int_list_copy)
        self.orig_drawn_val = self.drawn_val

        blob = blob[off:]

        val, sz = self._read_value_from(blob, size)
        orig_val = self._unconvert_value(val)

        if self.int_list is not None:
            if constraints[AbsCsts.Contents]:
                if orig_val not in self.int_list:
                    raise ValueError('contents not valid!')
            self.int_list.insert(0, orig_val)
            self.int_list_copy = copy.copy(self.int_list)
        else:
            if constraints[AbsCsts.Contents]:
                if self.maxi is not None and orig_val > self.maxi:
                    raise ValueError('contents not valid! (max limit)')
                if self.mini is not None and orig_val < self.mini:
                    raise ValueError('contents not valid! (min limit)')
            # self.int_list = [orig_val]
            self.idx = orig_val - self.mini

        # self.reset_state()
        self.exhausted = False
        self.drawn_val = orig_val

        return val, off, sz


    def do_revert_absorb(self):
        '''
        If needed should be called just after self.do_absorb().
        '''
        if hasattr(self, 'orig_drawn_val'):
            self.int_list = self.orig_int_list
            self.int_list_copy = self.orig_int_list_copy
            self.drawn_val = self.orig_drawn_val

    def do_cleanup_absorb(self):
        if hasattr(self, 'orig_drawn_val'):
            del self.orig_int_list
            del self.orig_int_list_copy
            del self.orig_drawn_val

    def make_determinist(self):
        self.determinist = True

    def make_random(self):
        self.determinist = False

    def get_value_list(self):
        return self.int_list

    def get_current_raw_val(self):
        if self.drawn_val is None:
            self.get_value()
        return self.drawn_val

    def is_compatible(self, integer):
        if self.mini <= integer <= self.maxi:
            return True
        else:
            return False

    def set_value_list(self, new_list):
        ret = False
        if self.int_list:
            l = list(filter(self.is_compatible, new_list))
            if l:
                self.int_list = l
                self.int_list_copy = copy.copy(self.int_list)
                self.idx = 0
                ret = True

        return ret

    def extend_value_list(self, new_list):
        if self.int_list is not None:
            l = list(filter(self.is_compatible, new_list))
            if l:
                int_list_enc = list(map(self._convert_value, self.int_list))

                # We copy the list as it is a class attribute in
                # Fuzzy_* classes, and we don't want to change the classes
                # (as we modify the list contents and not the list itself)
                self.int_list = list(self.int_list)

                # we don't use a set to preserve the order
                for v in l:
                    # we check the converted value to avoid duplicated
                    # values (negative and positive value coded the
                    # same) --> especially usefull for the Fuzzy_INT class
                    if self._convert_value(v) not in int_list_enc:
                        self.int_list.insert(0, v)

                self.idx = 0
                self.int_list_copy = copy.copy(self.int_list)


    def remove_value_list(self, value_list):
        if self.int_list is not None:
            l = list(filter(self.is_compatible, value_list))
            if l:
                # We copy the list as it is a class attribute in
                # Fuzzy_* classes, and we don't want to change the classes
                # (as we modify the list contents and not the list itself)
                self.int_list = list(self.int_list)

                for v in l:
                    try:
                        self.int_list.remove(v)
                    except ValueError:
                        pass

                self.idx = 0
                self.int_list_copy = copy.copy(self.int_list)

    def get_value(self):
        if self.int_list is not None:
            if not self.int_list_copy:
                self.int_list_copy = copy.copy(self.int_list)

            if self.determinist:
                val = self.int_list_copy.pop(0)
            else:
                val = random.choice(self.int_list_copy)
                self.int_list_copy.remove(val)
            if not self.int_list_copy:
                self.int_list_copy = copy.copy(self.int_list)
                self.exhausted = True
            else:
                self.exhausted = False
        else:
            if self.determinist:
                val = self.mini_gen + self.idx
                self.idx += 1
                if self.mini_gen + self.idx > self.maxi_gen:
                    self.exhausted = True
                    self.idx = 0
                else:
                    self.exhausted = False
            else:
                # Finite mode is implemented in this way when 'max -
                # min' is considered too big to be transformed as an
                # 'int_list'. It avoids cunsuming too much memory and
                # provide an end result that seems sufficient for such
                # situation
                val = random.randint(self.mini_gen, self.maxi_gen)
                self.idx += 1
                if self.idx > abs(self.maxi_gen - self.mini_gen):
                    self.idx = 0
                    self.exhausted = True
                else:
                    self.exhausted = False

        self.drawn_val = val
        return self._convert_value(val)

    def get_current_encoded_value(self):
        if self.drawn_val is None:
            self.get_value()
        return self._convert_value(self.drawn_val)

    def set_size_from_constraints(self, size=None, encoded_size=None):
        raise DataModelDefinitionError

    def pretty_print(self, max_size=None):
        if self.drawn_val is None:
            self.get_value()

        if self.drawn_val < 0:
            formatted_val = '-0x' + hex(self.drawn_val)[3:].upper()
        else:
            formatted_val = '0x' + hex(self.drawn_val)[2:].upper()

        return str(self.drawn_val) + ' (' + formatted_val + ')'


    def rewind(self):
        if self.exhausted:
            self.exhausted = False

        if self.int_list is not None:
            if self.int_list_copy is not None and self.drawn_val is not None:
                self.int_list_copy.insert(0, self.drawn_val)
        else:
            if self.idx > 0:
                self.idx -= 1

        self.drawn_val = None

    def _unconvert_value(self, val):
        return struct.unpack(self.cformat, val)[0]

    def _convert_value(self, val):
        return struct.pack(self.cformat, val)

    def _read_value_from(self, blob, size):
        sz = struct.calcsize(self.cformat)
        if size is not None:
            assert(sz == size)

        blob = blob[:sz]

        assert(len(blob) == sz)

        val = struct.unpack(self.cformat, blob)[0]
        return struct.pack(self.cformat, val), sz

    def reset_state(self):
        if self.default is not None:
            self.idx = self.default - self.mini_gen
        else:
            self.idx = 0
        if self.int_list is not None:
            self.int_list_copy = copy.copy(self.int_list)
        self.exhausted = False
        self.drawn_val = None

    def update_raw_value(self, val):
        if isinstance(val, int):
            if self.int_list is not None:
                self.int_list.append(val)
                self.int_list_copy = copy.copy(self.int_list)
            else:
                self.idx = val - self.mini
        else:
            raise TypeError

        self.drawn_val = val
        self.exhausted = False

    # To be used after calling get_value()
    def is_exhausted(self):
        return self.exhausted


class Filename(String):
    specific_fuzzing_list = [
        b'../../../../../../etc/password',
        b'../../../../../../Windows/system.ini',
        b'file%n%n%n%nname.txt',
    ]


def from_encoder(encoder_cls, encoding_arg=None):
    def internal_func(string_subclass):
        def new_meth(meth):
            return meth if sys.version_info[0] > 2 else meth.im_func
        string_subclass.encode = new_meth(encoder_cls.encode)
        string_subclass.decode = new_meth(encoder_cls.decode)
        string_subclass.init_encoding_scheme = new_meth(encoder_cls.init_encoding_scheme)
        if encoding_arg is not None:
            string_subclass.encoding_arg = encoding_arg
        return string_subclass
    return internal_func


@from_encoder(GZIP_Enc)
class GZIP(String): pass

@from_encoder(GSM7bitPacking_Enc)
class GSM7bitPacking(String): pass

@from_encoder(GSMPhoneNum_Enc)
class GSMPhoneNum(String): pass

@from_encoder(Wrap_Enc)
class Wrapper(String): pass


class Fuzzy_INT(INT):
    '''
    Base class to be inherited and not used directly
    '''
    int_list = None
    short_cformat = None

    def __init__(self, endian=VT.BigEndian, supp_list=None):
        self.endian = endian
        if supp_list:
            self.extend_value_list(supp_list)

        assert(self.int_list is not None)
        INT.__init__(self, int_list=self.int_list, determinist=True)

    def make_private(self, forget_current_state):
        self.int_list = copy.copy(self.int_list)

    def is_compatible(self, integer):
        if self.mini <= integer <= self.maxi:
            return True
        elif -((self.maxi + 1) // 2) <= integer <= ((self.maxi + 1) // 2) - 1:
            return True
        else:
            return False

    def _convert_value(self, val):
        try:
            string = struct.pack(VT.enc2struct[self.endian] + self.short_cformat, val)
        except:
            string = struct.pack(VT.enc2struct[self.endian] + self.alt_short_cformat, val)

        return string



#class INT_str(VT, metaclass=meta_int_str):
class INT_str(with_metaclass(meta_int_str, INT)):
    endian = VT.Native

    def is_compatible(self, integer):
        return True

    def _read_value_from(self, blob, size):
        g = re.match(b'-?\d+', blob)
        if g is None:
            raise ValueError
        else:
            return g.group(0), len(g.group(0))

    def _unconvert_value(self, val):
        return int(val)

    def _convert_value(self, val):
        return self._str2bytes(str(val))

    def pretty_print(self, max_size=None):
        if self.drawn_val is None:
            self.get_value()

        return str(self.drawn_val)

    def _str2bytes(self, val):
        if isinstance(val, (list, tuple)):
            b = [v.encode('utf8') for v in val]
        else:
            b = val.encode('utf8')
        return b


#class Fuzzy_INT_str(Fuzzy_INT, metaclass=meta_int_str):
class Fuzzy_INT_str(with_metaclass(meta_int_str, Fuzzy_INT)):
    int_list = [0, 2**32-1, 2**32]

    def is_compatible(self, integer):
        return True

    def _convert_value(self, val):
        return str(val)



class BitField(VT_Alt):
    '''
    Provide:
    - either @subfield_limits or @subfield_sizes
    - either @subfield_val_lists or @subfield_val_extremums

    '''
    padding_one = [0, 1, 0b11, 0b111, 0b1111, 0b11111, 0b111111, 0b1111111]

    def init_specific(self, subfield_limits=None, subfield_sizes=None,
                      subfield_val_lists=None, subfield_val_extremums=None,
                      padding=0, lsb_padding=True,
                      endian=VT.LittleEndian, determinist=True,
                      subfield_descs=None, defaults=None):

        self.drawn_val = None
        self.exhausted = False
        self.exhaustion_cpt = 0
        self.__count_of_possible_values = None

        self.current_val_update_pending = False
        
        self.determinist = determinist
        self.determinist_save = None
        self.endian = endian
        self.padding = padding
        self.lsb_padding = lsb_padding

        self.subfield_descs = None
        self.subfield_limits = []
        self.subfield_sizes = []
        self.subfield_vals = None
        self.subfield_vals_save = None
        self.subfield_extrems = None
        self.subfield_extrems_save = None
        self.subfield_fuzzy_vals = []
        self.current_idx = None
        self.idx = None
        self.idx_inuse = None
        self.set_bitfield(sf_val_lists=subfield_val_lists, sf_val_extremums=subfield_val_extremums,
                          sf_limits=subfield_limits, sf_sizes=subfield_sizes, sf_descs=subfield_descs,
                          sf_defaults=defaults)

    def make_private(self, forget_current_state):
        # no need to copy self.default (that should not be modified)
        self.subfield_limits = copy.copy(self.subfield_limits)
        self.subfield_sizes = copy.copy(self.subfield_sizes)
        self.subfield_vals = copy.copy(self.subfield_vals)
        self.subfield_vals_save = copy.copy(self.subfield_vals_save)
        self.subfield_extrems = copy.copy(self.subfield_extrems)
        self.subfield_extrems_save = copy.copy(self.subfield_extrems_save)
        if forget_current_state:
            self.reset_state()
        else:
            self.idx = copy.copy(self.idx)
            self.idx_inuse = copy.copy(self.idx_inuse)
            self.subfield_fuzzy_vals = copy.copy(self.subfield_fuzzy_vals)

    def reset_state(self):
        self._reset_idx()
        for i, default in enumerate(self.subfield_defaults):
            if default is not None:
                mini, _ = self.subfield_extrems[i]
                self.idx[i] = default - mini
        self.drawn_val = None
        self.__count_of_possible_values = None
        self.exhausted = False
        self.exhaustion_cpt = 0
        self.current_val_update_pending = False
        if self._fuzzy_mode:
            # needed, because some fuzzy values are computed from current values before switching
            self.switch_mode()

    def _reset_idx(self, reset_idx_inuse=True):
        self.current_idx = 0
        self.idx = [1 for i in self.subfield_limits]
        if not self._fuzzy_mode:
            self.idx[0] = 0
        # initially we don't make copy, as it will be copied anyway
        # during .get_value()
        if reset_idx_inuse:
            self.idx_inuse = self.idx
        
    def set_subfield(self, idx, val):
        '''
        Args:
          idx (int): subfield index, from 0 (low significant subfield) to nb_subfields-1
            (specific index -1 is used to choose the last subfield).
          val (int): new value for the subfield
        '''
        if idx == -1:
            idx = len(self.subfield_sizes) - 1
        assert(self.is_compatible(val, self.subfield_sizes[idx]))
        if self.subfield_vals[idx] is None:
            mini, maxi = self.subfield_extrems[idx]
            if val < mini:
                self.subfield_extrems[idx][0] = mini = min(mini, val)
            elif val > maxi:
                self.subfield_extrems[idx][1] = max(maxi, val)
            self.idx_inuse[idx] = self.idx[idx] = val - mini
        else:
            # Note that the case "self.idx[idx]==1" has not to be
            # specifically handled here (for preventing overflow),
            # because even if len(val_list)==1, we add a new element
            # within, making a val_list always >= 2.
            self.subfield_vals[idx].insert(self.idx[idx], val)
            self.idx_inuse[idx] = self.idx[idx]

        self.current_val_update_pending = True


    def get_subfield(self, idx):
        if idx == -1:
            idx = len(self.subfield_sizes) - 1
        if self.subfield_vals[idx] is None:
            mini, maxi = self.subfield_extrems[idx]
            ret = mini + self.idx_inuse[idx]
        else:
            val_list = self.subfield_vals[idx]
            index = 0 if len(val_list) == 1 else self.idx_inuse[idx]
            ret = val_list[index]
            
        return ret

        
    def set_bitfield(self, sf_val_lists=None, sf_val_extremums=None, sf_limits=None, sf_sizes=None,
                     sf_descs=None, sf_defaults=None):

        if sf_limits is not None:
            self.subfield_limits = copy.copy(sf_limits)
        elif sf_sizes is not None:
            lim = 0
            for s in sf_sizes:
                lim += s
                self.subfield_limits.append(lim)
        else:
            raise DataModelDefinitionError

        if sf_val_lists is None:
            sf_val_lists = [None for i in range(len(self.subfield_limits))]
        elif len(sf_val_lists) != len(self.subfield_limits):
            raise DataModelDefinitionError

        if sf_val_extremums is None:
            sf_val_extremums = [None for i in range(len(self.subfield_limits))]
        elif len(sf_val_extremums) != len(self.subfield_limits):
            raise DataModelDefinitionError

        if sf_descs is not None:
            assert(len(self.subfield_limits) == len(sf_descs))
            self.subfield_descs = copy.copy(sf_descs)

        if sf_defaults is not None:
            assert len(sf_defaults) == len(self.subfield_limits)
            self.subfield_defaults = copy.copy(sf_defaults)
        else:
            self.subfield_defaults = [None for i in range(len(self.subfield_limits))]

        self.size = self.subfield_limits[-1]
        self.nb_bytes = int(math.ceil(self.size / 8.0))

        if self.size % 8 == 0:
            self.padding_size = 0
        else:
            self.padding_size = 8 - (self.size % 8)

        self._reset_idx()

        self.subfield_vals = []
        self.subfield_extrems = []

        prev_lim = 0
        # provided limits are not included in the subfields
        for idx, lim in enumerate(self.subfield_limits):

            val_list = sf_val_lists[idx]
            extrems = sf_val_extremums[idx]

            size = lim - prev_lim
            self.subfield_sizes.append(size)

            if val_list is not None:
                default = self.subfield_defaults[idx]
                assert default is None
                l = []
                for v in val_list:
                    if self.is_compatible(v, size):
                        l.append(v)
                self.subfield_vals.append(l)
                self.subfield_extrems.append(None)
            else:
                if extrems is not None:
                    mini, maxi = extrems
                    if self.is_compatible(mini, size) and self.is_compatible(maxi, size):
                        assert(mini != maxi)
                        self.subfield_extrems.append([mini, maxi])
                    else:
                        s = '*** ERROR: min({:d}) / max({:d}) values are out of range!'.format(mini, maxi)
                        raise ValueError(s)
                    self.subfield_vals.append(None)
                else:
                    mini, maxi = 0, (1 << size) - 1
                    self.subfield_extrems.append([mini, maxi])
                    self.subfield_vals.append(None)

                default = self.subfield_defaults[idx]
                if default is not None:
                    self.idx[idx] = default - mini

            self.subfield_fuzzy_vals.append(None)
            prev_lim = lim

    def extend_right(self, bitfield):

        if self.drawn_val is None:
            self.get_current_value()
        if bitfield.drawn_val is None:
            bitfield.get_current_value()

        if self.exhausted and bitfield.exhausted:
            self.exhausted = True
            self.exhaustion_cpt = 0
        else:
            if bitfield.exhausted:
                bitfield.rewind() # side_effect clear 'drawn_val'
                bitfield.get_current_value() # to set 'drawn_val'
            if self.exhausted:
                self.rewind()
                self.get_current_value()

            self.exhausted = False
            self.exhaustion_cpt += bitfield.exhaustion_cpt

        self.__count_of_possible_values = None

        if self.lsb_padding:
            term1 = (self.drawn_val>>self.padding_size)
        else:
            term1 = self.drawn_val

        if bitfield.lsb_padding:
            term2 = (bitfield.drawn_val >> bitfield.padding_size)
        else:
            term2 = bitfield.drawn_val

        self.drawn_val = (term2 << self.size) + term1
        sz_mod = (self.size + bitfield.size) % 8
        new_padding_sz = 8 - sz_mod if sz_mod != 0 else 0

        if self.lsb_padding:
            self.drawn_val <<= new_padding_sz


        self.current_val_update_pending = False
        self.idx += bitfield.idx
        self.idx_inuse += bitfield.idx_inuse

        if self.subfield_descs is not None or bitfield.subfield_descs is not None:
            if self.subfield_descs is None and bitfield.subfield_descs is not None:
                self.subfield_descs = [None for i in self.subfield_limits]
                desc_extension = bitfield.subfield_descs
            elif self.subfield_descs is not None and bitfield.subfield_descs is None:
                desc_extension = [None for i in bitfield.subfield_limits]
            self.subfield_descs += desc_extension
        
        self.subfield_sizes += bitfield.subfield_sizes
        self.subfield_vals += bitfield.subfield_vals
        self.subfield_extrems += bitfield.subfield_extrems
        self.subfield_defaults += bitfield.subfield_defaults

        for l in bitfield.subfield_limits:
            self.subfield_limits.append(self.size + l)

        self.subfield_fuzzy_vals += bitfield.subfield_fuzzy_vals
            
        self.size = self.subfield_limits[-1]
        self.nb_bytes = int(math.ceil(self.size / 8.0))

        if self.size % 8 == 0:
            self.padding_size = 0
        else:
            self.padding_size = 8 - (self.size % 8)


    def set_size_from_constraints(self, size=None, encoded_size=None):
        raise DataModelDefinitionError


    def pretty_print(self, max_size=None):

        first_pass = True
        for lim, sz, val_list, extrems, i in zip(self.subfield_limits[::-1],
                                                 self.subfield_sizes[::-1],
                                                 self.subfield_vals[::-1],
                                                 self.subfield_extrems[::-1],
                                                 range(len(self.subfield_limits))[::-1]):

            if self.subfield_descs is not None and self.subfield_descs[i] is not None:
                prefix = '|{:d}({:s}): '.format(i,self.subfield_descs[i])
            else:
                prefix = '|{:d}: '.format(i)
                
            if first_pass:
                first_pass = False
                string = '(+' + prefix
            else:
                string += ' ' + prefix

            if val_list is None:
                mini, maxi = extrems
                string += bin(mini+self.idx_inuse[i])[2:].zfill(sz)
            else:
                index = 0 if len(val_list) == 1 else self.idx_inuse[i]
                string += bin(val_list[index])[2:].zfill(sz)

        if self.padding_size != 0:
            if self.padding == 1:
                pad = '1'*self.padding_size
            else:
                pad = '0'*self.padding_size
            if self.lsb_padding:
                string += ' |padding: ' + pad + ' |-)'
            else:
                string = '(+|padding: ' + pad + ' ' + string[2:] + ' |-)'

        else:
            string += ' |-)'

        return string + ' ' + str(self.get_current_raw_val())


    def is_compatible(self, integer, size):
        return 0 <= integer <= (1 << size) - 1

    def after_enabling_mode(self):
        self.drawn_val = None
        self.__count_of_possible_values = None
        self._reset_idx()

    def enable_normal_mode(self):
        if self.determinist_save is not None:
            self.determinist = self.determinist_save

        self.subfield_extrems = self.subfield_extrems_save
        self.subfield_extrems_save = None
        self.subfield_vals = self.subfield_vals_save
        self.subfield_vals_save = None
        self.subfield_fuzzy_vals = [None for i in range(len(self.subfield_sizes))]
        self.exhausted = False

    def enable_fuzz_mode(self):

        for idx in range(len(self.subfield_fuzzy_vals)):
            sz = self.subfield_sizes[idx]
            l = []
            self.subfield_fuzzy_vals[idx] = l

            # we substract 1 because after a get_value() call idx is incremented in advance
            # max is needed because self.idx[0] is equal to 0 in this case
            curr_idx = max(self.idx[idx]-1, 0)

            curr_val_list = self.subfield_vals[idx]
            if curr_val_list is not None:
                current = curr_val_list[curr_idx]
            else:
                mini, maxi = self.subfield_extrems[idx]
                current = mini + curr_idx

            # append first a normal value, as it will be used as a
            # reference when the other fields are fuzzed
            l.append(current)

            if self.subfield_extrems[idx] is not None:
                mini, maxi = self.subfield_extrems[idx]
                MM = maxi + 1
                mm = mini - 1
                if MM not in l and self.is_compatible(MM, sz):
                    l.append(MM)
                if mm not in l and self.is_compatible(mm, sz):
                    l.append(mm)

            M = (1 << sz) - 1
            m = 0
            a = l[0] + 1
            b = l[0] - 1
            if M not in l and self.is_compatible(M, sz):
                l.append(M)
            if m not in l and self.is_compatible(m, sz):
                l.append(m)
            if a not in l and self.is_compatible(a, sz):
                l.append(a)
            if b not in l and self.is_compatible(b, sz):
                l.append(b)

            if curr_val_list is not None:
                orig_set = set(curr_val_list)
                max_oset = max(orig_set)
                min_oset = min(orig_set)
                if min_oset != max_oset:
                    diff_sorted = sorted(set(range(min_oset, max_oset+1)) - orig_set)
                    if diff_sorted:
                        item1 = diff_sorted[0]
                        item2 = diff_sorted[-1]
                        if item1 not in l and self.is_compatible(item1, sz):
                            l.append(item1)
                        if item2 not in l and self.is_compatible(item2, sz):
                            l.append(item2)
                    beyond_max_oset = max_oset+1
                    if beyond_max_oset not in l and self.is_compatible(beyond_max_oset, sz):
                        l.append(beyond_max_oset)
                    below_min_oset = min_oset-1
                    if below_min_oset not in l and self.is_compatible(below_min_oset, sz):
                        l.append(below_min_oset)

        self.determinist_save = self.determinist
        self.determinist = True
        
        self.subfield_vals_save = self.subfield_vals
        self.subfield_vals = self.subfield_fuzzy_vals
        self.subfield_extrems_save = self.subfield_extrems
        self.subfield_extrems = [None for i in range(len(self.subfield_fuzzy_vals))]
        self.exhausted = False

    def make_determinist(self):
        self.determinist = True

    def make_random(self):
        if not self._fuzzy_mode:
            self.determinist = False

    def __compute_total_possible_values(self):
        '''
        the returned number correspond to the total number of values
        that can be returned by the BitField in determinist mode. This
        number does not cover all the values such a BitField should be
        able to generate. Refer to get_value() comments for more
        information.
        '''
        if self.__count_of_possible_values is not None:
            return self.__count_of_possible_values

        s = 1
        for val_list, extrems in zip(self.subfield_vals, self.subfield_extrems):
            if val_list is None:
                mini, maxi = extrems
                s += maxi - mini
            else:
                s += len(val_list) - 1

        self.__count_of_possible_values = s
        return self.__count_of_possible_values

    count_of_possible_values = property(fget=__compute_total_possible_values)

    def rewind(self):
        if self.current_idx > 0 and not self.exhausted:
            if self.idx[self.current_idx] > 1:
                self.idx[self.current_idx] -= 1
            elif self.idx[self.current_idx] == 1:
                self.current_idx -= 1
            else:
                ValueError

        elif self.exhausted:
            assert(self.current_idx == 0)
            for i in range(len(self.subfield_limits)):
                if self.subfield_vals[i] is None:
                    last = self.subfield_extrems[i][1] - self.subfield_extrems[i][0]
                else:
                    last = len(self.subfield_vals[i]) - 1
                self.idx[i] = last

            self.current_idx = len(self.subfield_limits) - 1

        elif self.current_idx == 0:
            if self.idx[self.current_idx] > 1:
                self.idx[self.current_idx] -= 1
            elif self.idx[self.current_idx] == 1:
                if not self._fuzzy_mode:
                    self.idx[self.current_idx] = 0
            else:
                pass

        else:
            pass

        self.drawn_val = None
        
        if self.exhausted:
            self.exhausted = False
            self.exhaustion_cpt = 0


    def _read_value_from(self, blob, size, endian, constraints):
        val_list = list(struct.unpack('B'*size, blob))

        if endian == VT.BigEndian:
            val_list = val_list[::-1]

        # val_list from LSB to MSB

        if self.padding_size != 0:
            if self.lsb_padding:
                if constraints[AbsCsts.Contents]:
                    mask = self.padding_one[self.padding_size]
                    if self.padding == 1 and val_list[0] & mask != mask:
                        raise ValueError('contents not valid! (padding should be 1s)')
                    elif self.padding == 0 and val_list[0] & self.padding_one[self.padding_size] != 0:
                        raise ValueError('contents not valid! (padding should be 0s)')
            else:
                if constraints[AbsCsts.Contents]:
                    mask = self.padding_one[self.padding_size]<<(8-self.padding_size)
                    if self.padding == 1 and val_list[-1] & mask != mask:
                        raise ValueError('contents not valid! (padding should be 1s)')
                    elif self.padding == 0 and val_list[-1] & mask != 0:
                        raise ValueError('contents not valid! (padding should be 0s)')

        val_list_sz = len(val_list)
        result = 0
        for v, i in zip(val_list,range(val_list_sz)):
            result += v<<(i*8)

        decoded_val = result

        if self.padding_size != 0:
            if self.lsb_padding:
                result >>= self.padding_size
            else:
                shift = (val_list_sz-1)*8
                result &= (((1<<(8-self.padding_size))-1)<<shift) + (1<<shift)-1

        # We return the decoded integer
        # (1: taking padding into consideration, 2: ignoring padding)
        return decoded_val, result


    def absorb_auto_helper(self, blob, constraints):
        if len(blob) < self.nb_bytes:
            return AbsorbStatus.Reject, 0, None
        else:
            return AbsorbStatus.Accept, 0, None

    def do_absorb(self, blob, constraints, off=0, size=None):

        self.orig_idx = copy.deepcopy(self.idx)
        self.orig_subfield_vals = copy.deepcopy(self.subfield_vals)
        self.orig_drawn_val = self.drawn_val

        self.reset_state()

        blob = blob[off:self.nb_bytes]

        self.drawn_val, orig_val = self._read_value_from(blob, self.nb_bytes, self.endian, constraints)

        insert_idx = 0
        first_pass = True
        limits = self.subfield_limits[:-1]
        limits.insert(0, 0)
        for lim, sz, val_list, extrems, i in zip(limits, self.subfield_sizes, self.subfield_vals, self.subfield_extrems,
                                             range(len(self.subfield_limits))):

            val = (orig_val >> lim) & ((1<<sz)-1)

            if val_list is None:
                mini, maxi = extrems
                if constraints[AbsCsts.Contents] and (mini > val or maxi < val):
                    raise ValueError("Value for subfield number {:d} does not match the constraints!".format(i+1))
                self.idx[i] = val - mini
                if not constraints[AbsCsts.Contents]: # update extremums if necessary
                    extrems[0] = min(extrems[0], val)
                    extrems[1] = max(extrems[1], val)
            else:
                if constraints[AbsCsts.Contents] and val not in val_list:
                    raise ValueError("Value for subfield number {:d} does not match the constraints!".format(i+1))
                val_list.insert(insert_idx, val)                

            if first_pass:
                first_pass = False
                insert_idx = 1

        return blob, off, self.nb_bytes


    def do_revert_absorb(self):
        '''
        If needed should be called just after self.do_absorb().
        '''
        if hasattr(self, 'orig_drawn_val'):
            self.idx = self.orig_idx
            self.subfield_vals = self.orig_subfield_vals
            self.drawn_val = self.orig_drawn_val

    def do_cleanup_absorb(self):
        '''
        To be called after self.do_absorb() or self.do_revert_absorb()
        '''
        if hasattr(self, 'orig_drawn_val'):
            del self.orig_idx
            del self.orig_subfield_vals
            del self.orig_drawn_val

    def get_value(self):
        '''
        In determinist mode, all the values such a BitField should
        be able to generate are not covered but only a subset of them
        (i.e., all combinations are not computed). It has been chosen
        to only keep the value based on the following algorithm:
        "exhaust each subfield one at a time".

        Rationale: In most cases, computing all combinations does not
        make sense for fuzzing purpose.
        '''
        
        if self.current_val_update_pending:
            self.current_val_update_pending = False
            return self.get_current_value()

        self.exhausted = False

        val = 0
        prev_lim = 0
        update_current_idx = False

        self.idx_inuse = copy.copy(self.idx)

        for lim, val_list, extrems, i in zip(self.subfield_limits, self.subfield_vals, self.subfield_extrems,
                                             range(len(self.subfield_limits))):
            if self.determinist:
                if i == self.current_idx:
                    if val_list is None:
                        mini, maxi = extrems
                        v = mini + self.idx[self.current_idx]
                        if v >= maxi:
                            update_current_idx = True
                        else:
                            self.idx[self.current_idx] += 1
                        val += v << prev_lim
                    else:
                        if len(val_list) == 1:
                            index = 0
                        else:
                            index = self.idx[self.current_idx]
                        if index >= len(val_list) - 1:
                            update_current_idx = True
                        else:
                            self.idx[self.current_idx] += 1
                        self.idx_inuse[self.current_idx] = index
                        val += val_list[index] << prev_lim
                else:
                    if self._fuzzy_mode:
                        cursor = 0
                    else:
                        if val_list is not None and len(val_list) == 1:
                            cursor = 0
                        else:
                            if i > self.current_idx and self.subfield_defaults[i] is None:
                                # Note on the use of max(): in the
                                # case of val_list, idx is always > 1,
                                # whereas when it is extrems, idx can
                                # be 0.
                                cursor = max(self.idx[i] - 1, 0)
                            else:
                                cursor = self.idx[i]
                    self.idx_inuse[i] = cursor
                    if val_list is None:
                        mini, maxi = extrems
                        val += (mini + cursor) << prev_lim
                    else:
                        val += (val_list[cursor]) << prev_lim
            else:
                if val_list is None:
                    mini, maxi = extrems
                    drawn_val = random.randint(mini, maxi)
                    self.idx[i] = self.idx_inuse[i] = drawn_val - mini
                else:
                    drawn_val = random.choice(val_list)
                    self.idx[i] = self.idx_inuse[i] = val_list.index(drawn_val)

                val += drawn_val << prev_lim
                
            prev_lim = lim

        if not self.determinist:
            # We make an artificial count to trigger exhaustion in
            # case the BitField is in Finite & Random mode. An exact
            # implementation (like the INT() one) does not seem to be
            # worth the memory cost. We use the same count as if the
            # BitField is in determinist mode
            self.exhaustion_cpt += 1
            if self.exhaustion_cpt >= self.count_of_possible_values:
                self.exhausted = True
                self.exhaustion_cpt = 0
            else:
                self.exhausted = False


        if update_current_idx:
            self.exhausted = False

            self.current_idx += 1
            if self.current_idx >= len(self.idx):
                self._reset_idx(reset_idx_inuse=False)
                self.exhausted = True
            else:
                while True:
                    if self.subfield_vals[self.current_idx] is None:
                        last = self.subfield_extrems[self.current_idx][1] - self.subfield_extrems[self.current_idx][0]
                    else:
                        last = len(self.subfield_vals[self.current_idx]) - 1

                    if self.idx[self.current_idx] > last:
                        self.current_idx += 1
                        if self.current_idx >= len(self.idx):
                            self._reset_idx(reset_idx_inuse=False)
                            self.exhausted = True
                            break
                    else:
                        break

        return self._encode_bitfield(val)
                    

    # Does not affect the state of the BitField
    def get_current_value(self):
        
        val = 0
        prev_lim = 0

        for lim, val_list, extrems, i in zip(self.subfield_limits, self.subfield_vals, self.subfield_extrems,
                                             range(len(self.subfield_limits))):
            if val_list is None:
                mini, maxi = extrems
                v = mini + self.idx_inuse[i]
                val += v << prev_lim
            else:
                if len(val_list) == 1:
                    index = 0
                else:
                    index = self.idx_inuse[i]
                val += val_list[index] << prev_lim

            prev_lim = lim

        return self._encode_bitfield(val)
    
    def _encode_bitfield(self, val):
        
        if self.padding_size != 0:
            if self.lsb_padding:
                val = val << self.padding_size
                if self.padding == 1:
                    val += self.padding_one[self.padding_size]
            else:
                if self.padding == 1:
                    val = val + (self.padding_one[self.padding_size] << self.size)

        self.drawn_val = val

        # bigendian-encoded
        l = []
        for i in range(self.nb_bytes - 1, -1, -1):
            result = val // (1 << i*8)
            val = val % (1 << i*8)  # remainder
            l.append(result)

        # littleendian-encoded
        if self.endian == VT.LittleEndian:
            l = l[::-1]
           
        if sys.version_info[0] > 2:
            return struct.pack('{:d}s'.format(self.nb_bytes), bytes(l))
        else:
            return struct.pack('{:d}s'.format(self.nb_bytes), str(bytearray(l)))

    def get_current_raw_val(self):
        if self.drawn_val is None:
            self.get_value()
        return self.drawn_val
    
    def is_exhausted(self):
        return self.exhausted


#class INT8(INT, metaclass=meta_8b):
class INT8(with_metaclass(meta_8b, INT)):
    usable = False

class SINT8(INT8):
    mini = -2**7
    maxi = 2**7-1
    cformat = 'b'
    endian = VT.Native

class UINT8(INT8):
    mini = 0
    maxi = 2**8-1
    cformat = 'B'
    endian = VT.Native

#class Fuzzy_INT8(Fuzzy_INT, metaclass=meta_8b):
class Fuzzy_INT8(with_metaclass(meta_8b, Fuzzy_INT)):
    mini = 0
    maxi = 2**8-1
    int_list = [0xFF, 0, 0x01, 0x80, 0x7F]
    short_cformat = 'B'
    alt_short_cformat = 'b'


#class INT16(VT, metaclass=meta_16b):
class INT16(with_metaclass(meta_16b, INT)):
    usable = False


class SINT16_be(INT16):
    mini = -2**15
    maxi = 2**15-1
    cformat = '>h'
    endian = VT.BigEndian

class SINT16_le(INT16):
    mini = -2**15
    maxi = 2**15-1
    cformat = '<h'
    endian = VT.LittleEndian

class UINT16_be(INT16):
    mini = 0
    maxi = 2**16-1
    cformat = '>H'
    endian = VT.BigEndian

class UINT16_le(INT16):
    mini = 0
    maxi = 2**16-1
    cformat = '<H'
    endian = VT.LittleEndian


#class Fuzzy_INT16(Fuzzy_INT, metaclass=meta_16b):
class Fuzzy_INT16(with_metaclass(meta_16b, Fuzzy_INT)):
    mini = 0
    maxi = 2**16-1
    int_list = [0xFFFF, 0, 0x8000, 0x7FFF]
    short_cformat = 'H'
    alt_short_cformat = 'h'

# class Other_Fuzzy_INT16(Fuzzy_INT16):
#     mini = 0
#     maxi = 2**16-1
#     int_list = [0xDEAD, 0xBEEF, 0xCAFE]
#     short_cformat = 'H'
#     alt_short_cformat = 'h'


#class INT32(INT, metaclass=meta_32b):
class INT32(with_metaclass(meta_32b, INT)):
    usable = False

class SINT32_be(INT32):
    mini = -2**31
    maxi = 2**31-1
    cformat = '>l'
    endian = VT.BigEndian

class SINT32_le(INT32):
    mini = -2**31
    maxi = 2**31-1
    cformat = '<l'
    endian = VT.LittleEndian

class UINT32_be(INT32):
    mini = 0
    maxi = 2**32-1
    cformat = '>L'
    endian = VT.BigEndian

class UINT32_le(INT32):
    mini = 0
    maxi = 2**32-1
    cformat = '<L'
    endian = VT.LittleEndian


#class Fuzzy_INT32(Fuzzy_INT, metaclass=meta_32b):
class Fuzzy_INT32(with_metaclass(meta_32b, Fuzzy_INT)):
    mini = 0
    maxi = 2**32-1
    int_list = [0xFFFFFFFF, 0, 0x80000000, 0x7FFFFFFF]
    short_cformat = 'L'
    alt_short_cformat = 'l'

# class Other_Fuzzy_INT32(Fuzzy_INT32):
#     mini = 0
#     maxi = 2**32-1
#     int_list = [0xDEADBEEF, 0xAAAAAAAA]
#     short_cformat = 'L'
#     alt_short_cformat = 'l'


#class INT64(INT, metaclass=meta_64b)
class INT64(with_metaclass(meta_64b, INT)):
    usable = False

class SINT64_be(INT64):
    mini = -2**63
    maxi = 2**63-1
    cformat = '>q'
    endian = VT.BigEndian

class SINT64_le(INT64):
    mini = -2**63
    maxi = 2**63-1
    cformat = '<q'
    endian = VT.LittleEndian

class UINT64_be(INT64):
    mini = 0
    maxi = 2**64-1
    cformat = '>Q'
    endian = VT.BigEndian

class UINT64_le(INT64):
    mini = 0
    maxi = 2**64-1
    cformat = '<Q'
    endian = VT.LittleEndian


#class Fuzzy_INT64(Fuzzy_INT, metaclass=meta_64b):
class Fuzzy_INT64(with_metaclass(meta_64b, Fuzzy_INT)):
    mini = 0
    maxi = 2**64-1
    int_list = [0xFFFFFFFFFFFFFFFF, 0, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0x1111111111111111]
    short_cformat = 'Q'
    alt_short_cformat = 'q'

# class Other_Fuzzy_INT64(Fuzzy_INT64):
#     mini = 0
#     maxi = 2**64-1
#     int_list = [0xDEADBEEFDEADBEEF, 0xAAAAAAAAAAAAAAAA]
#     short_cformat = 'Q'
#     alt_short_cformat = 'q'




if __name__ == "__main__":

    import copy

    d = copy.copy(meta_8b.compatible_class)
    d.update(meta_16b.compatible_class)
    d.update(meta_32b.compatible_class)
    d.update(meta_64b.compatible_class)
    d.update(meta_int_str.compatible_class)
    print(d)
    
    obj = {}
    for k, v in d.items():
        print('\n***** [ %s ] *****\n' % k)

        if issubclass(v, INT_str):
            obj[k] = v(mini=1, maxi=10)
        else:
            obj[k] = v()
        obj[k].get_value()

        try:
            obj[k] = v(int_list=[0x11,0x12,0x13])
        except TypeError:
            obj[k] = v()

        for i in range(8):
            print(obj[k].get_value())

        print('\n********\n')

        try:
            obj[k] = v(int_list=[0x11,0x12,0x13], determinist=False)
        except TypeError:
            print(v().__class__)
            obj[k] = v()

        for i in range(8):
            print(obj[k].get_value())

        print('\n********\n')

        try:
            obj[k] = v(mini=0, maxi=2**7-1, determinist=False)
        except TypeError:
            print(v().__class__)
            obj[k] = v()

        for i in range(8):
            print(obj[k].get_value())



    print('\n*******************************\n')


    t = SINT16_be()
    t.is_exhausted()

    print('size: ', t.size)
    print('class: ', t.__class__)
    print('compatible classes: ')
    for c in t.compat_cls.values():
        if c != t.__class__:
            print(c, c().get_value())
    print('fuzzy classes: ')
    for c in t.fuzzy_cls.values():
        print(c, c().get_value())
    print('---')        
    print('val: ', t.get_value())

    print('\n***\n')

    t = UINT16_le(int_list = range(100,400,4))
    print('size: ', t.size)
    print('class: ', t.__class__)
    print('compatible classes: ')
    for c in t.compat_cls.values():
        if c != t.__class__:
            print(c)
    print('fuzzy classes: ')
    for c in t.fuzzy_cls.values():
        print(c, c().get_value())
    print('---')
    for i in range(5):
        print(i, t.get_value())
    
    print('\n***\n')

    t = Fuzzy_INT16()
    for i in range(5):
        print(i, t.get_value())
        if t.is_exhausted():
            print('fin iteration')

    for i in range(5):
        print(i, t.get_value())
        if t.is_exhausted():
            print('fin iteration')


    print('\n***** [ String ] *****\n')

    t = String(val_list=['AA', 'BBB', 'CCCC'], min_sz=1, max_sz=10,
               extra_fuzzy_list=['XTRA_1', '', 'XTRA_2'])

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n********\n')

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n********\n')

    t.reset_state()
    t.switch_mode()

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n====> New String\n')

    t = String(val_list=['AAA', 'BBBB', 'CCCCC'], min_sz=3, max_sz=10)

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n********\n')
    t.reset_state()
    t.switch_mode()

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n********\n')
    t.reset_state()
    t.switch_mode()

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n********\n')

    t.reset_state()
    t.get_value()
    t.get_value()
    t.switch_mode()

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n====> New String\n')

    t = String(val_list=['AAA', 'BBBB', 'CCCCC'], max_sz=10)

    print(t.get_value())
    print(t.get_value())

    print('\n********\n')

    t.rewind()
    print(t.get_value())
    print(t.get_value())

    print('\n********\n')

    t.reset_state()
    print(t.get_value())
    print(t.get_value())

    print('\n********\n')

    t.rewind()
    t.rewind()
    print(t.get_value())
    print(t.get_value())

    print('\n********\n')

    t.rewind()
    t.rewind()
    t.rewind()
    t.rewind()
    print(t.get_value())
    print(t.get_value())

    print('\n====> New String\n')

    t = String(min_sz=1, max_sz=10)

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n********\n')
    t.reset_state()
    t.switch_mode()

    for i in range(30):
        print(t.get_value())
        if t.is_exhausted():
            break

    print('\n********\n')

    t.rewind()
    t.rewind()
    print(t.get_value())
    print(t.get_value())
