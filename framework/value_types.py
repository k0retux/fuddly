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

if sys.version_info[0] > 2:
    # python3
    import builtins
    CHR_compat = chr
else:
    # python2.7
    import __builtin__ as builtins
    CHR_compat = unichr

import framework.basic_primitives as bp
from framework.encoders import *
from framework.error_handling import *
from framework.global_resources import *
from framework.knowledge.information import *

import libs.debug_facility as dbg

DEBUG = dbg.VT_DEBUG

class VT(object):
    '''
    Base class for value type classes accepted by value Elts
    '''
    mini = None
    maxi = None
    knowledge_source = None

    BigEndian = 1
    LittleEndian = 2
    Native = 3

    enc2struct = {
        BigEndian: '>',
        LittleEndian: '<',
        Native: '='
        }

    endian = None

    # def __init__(self, endian=BigEndian):
    #     self.endian = self.enc2struct[endian]

    def make_private(self, forget_current_state):
        pass

    def make_determinist(self):
        pass

    def make_random(self):
        pass

    def get_value(self):
        """
        Walk other the values of the object on a per-call basis.

        Returns: bytes

        """
        raise NotImplementedError('New value type shall implement this method!')

    def get_current_value(self):
        """
        Provide the current value of the object.
        Should not change the state of the object except if no current values.

        Returns: bytes

        """
        raise NotImplementedError('New value type shall implement this method!')

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

    def copy_attrs_from(self, vt):
        pass

    def add_specific_fuzzy_vals(self, vals):
        raise NotImplementedError

    def get_specific_fuzzy_vals(self):
        raise NotImplementedError

    def get_fuzzed_vt_list(self):
        return None


class VT_Alt(VT):

    def __init__(self):
        self._fuzzy_mode = False
        self._specific_fuzzy_vals = None

    def switch_mode(self):
        if self._fuzzy_mode:
            self._enable_normal_mode()
        else:
            self._enable_fuzz_mode()

        self._fuzzy_mode = not self._fuzzy_mode
        self.after_enabling_mode()

    def after_enabling_mode(self):
        pass

    def enable_fuzz_mode(self, fuzz_magnitude=1.0):
        if not self._fuzzy_mode:
            self._enable_fuzz_mode(fuzz_magnitude=fuzz_magnitude)
            self._fuzzy_mode = True
            self.after_enabling_mode()

    def enable_normal_mode(self):
        if self._fuzzy_mode:
            self._enable_normal_mode()
            self._fuzzy_mode = False
            self.after_enabling_mode()

    def _enable_normal_mode(self):
        raise NotImplementedError

    def _enable_fuzz_mode(self, fuzz_magnitude=1.0):
        raise NotImplementedError

    def add_specific_fuzzy_vals(self, vals):
        if self._specific_fuzzy_vals is None:
            self._specific_fuzzy_vals = []
        self._specific_fuzzy_vals += convert_to_internal_repr(vals)

    def get_specific_fuzzy_vals(self):
        return self._specific_fuzzy_vals


class String(VT_Alt):
    """
    Value type that represents a character string.

    Attributes:
        encoded_string (bool): shall be set to True by any subclass that deals
          with encoding
        subclass_fuzzing_list (list): attribute to be added by subclasses that provide
          specific test cases.
    """

    DEFAULT_MAX_SZ = 10000
    encoded_string = False

    ctrl_char_set = ''.join([chr(i) for i in range(0, 0x20)])+'\x7f'
    printable_char_set = ''.join([chr(i) for i in range(0x20, 0x7F)])
    extended_char_set = ''.join([CHR_compat(i) for i in range(0x80, 0x100)])
    non_ctrl_char = printable_char_set + extended_char_set

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
            return VT_Alt.__repr__(self)[:-1] + ' contents:' + str(self.values) + '>'
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
                    if len(val) > 30:
                        val = val[:30] + ' ...'
                    err_msg = "\n*** WARNING: Encoding issue. With python2 'str' or 'bytes' means " \
                              "ASCII, prefix the string {:s} with 'u'".format(repr(val))
                    print(err_msg)
                    b = val
        return b

    def _bytes2str(self, val):
        if isinstance(val, (list, tuple)):
            b = [v.decode(self.codec, 'replace') for v in val]
        else:
            b = val.decode(self.codec, 'replace')
        return b

    UTF16LE = codecs.lookup('utf-16-le').name
    UTF16BE = codecs.lookup('utf-16-be').name
    ASCII = codecs.lookup('ascii').name
    LATIN_1 = codecs.lookup('latin-1').name

    def __init__(self, values=None, size=None, min_sz=None,
                 max_sz=None, determinist=True, codec='latin-1',
                 extra_fuzzy_list=None, absorb_regexp=None,
                 alphabet=None, min_encoded_sz=None, max_encoded_sz=None, encoding_arg=None,
                 values_desc=None):

        """
        Initialize the String

        Args:
            values: List of the character strings that are considered valid for the node
              backed by this *String object*.
            size: Valid character string size for the node backed by this *String object*.
            min_sz: Minimum valid size for the character strings for the node backed by
              this *String object*. If not set, this parameter will be
              automatically inferred by looking at the parameter ``values``
              whether this latter is provided.
            max_sz: Maximum valid size for the character strings for the node backed by this
              *String object*. If not set, this parameter will be
              automatically inferred by looking at the parameter ``values``
              whether this latter is provided.
            determinist: If set to ``True`` generated values will be in a deterministic
              order, otherwise in a random order.
            codec: codec to use for encoding the string (e.g., 'latin-1', 'utf8')
            extra_fuzzy_list: During data generation, if this parameter is specified with some
              specific values, they will be part of the test cases generated by
              the generic disruptor tTYPE.
            absorb_regexp (str): You can specify a regular expression in this parameter as a
              supplementary constraint for data absorption operation.
            alphabet: The alphabet to use for generating data, in case no ``values`` is
              provided. Also use during absorption to validate the contents. It is
              checked if there is no ``values``.
            values_desc (dict): Dictionary that maps string values to their descriptions (character
              strings). Leveraged for display purpose. Even if provided, all values do not need to
              be described.
            min_encoded_sz: Only relevant for subclasses that leverage the encoding infrastructure.
              Enable to provide the minimum legitimate size for an encoded string.
            max_encoded_sz: Only relevant for subclasses that leverage the encoding infrastructure.
              Enable to provide the maximum legitimate size for an encoded string.
            encoding_arg: Only relevant for subclasses that leverage the encoding infrastructure
              and that allow their encoding scheme to be configured. This parameter is directly
              provided to :meth:`String.init_encoding_scheme`. Any object that go through this
              parameter should support the ``__copy__`` method.
        """

        VT_Alt.__init__(self)

        self.drawn_val = None

        self.values = None
        self.values_copy = None
        self.values_fuzzy = None
        self.values_save = None

        self.values_desc = values_desc
        if self.values_desc and not isinstance(self.values_desc, dict):
            raise ValueError('@values_desc should be a dictionary')

        self.is_values_provided = None

        self.min_sz = None
        self.max_sz = None

        if self.__class__.encode != String.encode:
            self.encoded_string = True
            if not hasattr(self, 'encoding_arg'):
                self.encoding_arg = encoding_arg
            self.init_encoding_scheme(self.encoding_arg)

        self.set_description(values=values, size=size, min_sz=min_sz,
                             max_sz=max_sz, determinist=determinist, codec=codec,
                             extra_fuzzy_list=extra_fuzzy_list,
                             absorb_regexp=absorb_regexp, alphabet=alphabet,
                             min_encoded_sz=min_encoded_sz, max_encoded_sz=max_encoded_sz)

    def make_private(self, forget_current_state):
        if forget_current_state:
            if self.is_values_provided:
                self.values = copy.copy(self.values)
            else:
                self._populate_values(force_max_enc_sz=self.max_enc_sz_provided,
                                      force_min_enc_sz=self.min_enc_sz_provided)
                self._ensure_enc_sizes_consistency()
            self.reset_state()
        else:
            self.values = copy.copy(self.values)
            self.values_copy = copy.copy(self.values_copy)
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
        # values or conforming to the alphabet.
        # If 'Regexp' constraint is set, we seek for string matching
        # the regexp.
        # If no such constraints are provided, we assume off==0
        # and let do_absorb() decide if it's OK (via size constraints
        # for instance).
        blob_dec = self.decode(blob)
        if constraints[AbsCsts.Contents] and self.is_values_provided and self.alphabet is None:
            for v in self.values:
                if blob_dec.startswith(v):
                    break
            else:
                for v in self.values:
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
        self.orig_values = copy.copy(self.values)
        self.orig_values_copy = copy.copy(self.values_copy)
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

        if constraints[AbsCsts.Contents] and self.is_values_provided:
            for v in self.values:
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

        if self.values is None:
            self.values = []

        if val in self.values:
            self.values.remove(val)
        self.values.insert(0, val)

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
            self.values = self.orig_values
            self.values_copy = self.orig_values_copy
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
            del self.orig_values
            del self.orig_values_copy
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
        self.values_copy = copy.copy(self.values)
        self.drawn_val = None
        if self.encoded_string:
            self.encoding_arg = copy.copy(self.encoding_arg)
            self.init_encoding_scheme(self.encoding_arg)

    def rewind(self):
        sz_vlist_copy = len(self.values_copy)
        sz_vlist = len(self.values)
        if self.values_copy is not None and \
           sz_vlist_copy < sz_vlist:
            val = self.values[sz_vlist - sz_vlist_copy - 1]
            self.values_copy.insert(0, val)

        self.drawn_val = None

    def _check_sizes(self, values):
        if values is not None:
            for v in values:
                sz = len(v)
                if self.max_sz is not None:
                    assert(self.max_sz >= sz >= self.min_sz)
                else:
                    assert(sz >= self.min_sz)

    def set_description(self, values=None, size=None, min_sz=None,
                        max_sz=None, determinist=True, codec='latin-1',
                        extra_fuzzy_list=None,
                        absorb_regexp=None, alphabet=None,
                        min_encoded_sz=None, max_encoded_sz=None):
        '''
        @size take precedence over @min_sz and @max_sz
        '''
        self.codec = codecs.lookup(codec).name # normalize
        self.max_encoded_sz = max_encoded_sz
        self.min_encoded_sz = min_encoded_sz
        self.max_enc_sz_provided = max_encoded_sz is not None
        self.min_enc_sz_provided = min_encoded_sz is not None

        if alphabet is not None:
            self.alphabet = self._str2bytes(alphabet)
        else:
            self.alphabet = None

        if absorb_regexp is None:
            if self.codec == self.ASCII:
                self.regexp = '[\x00-\x7f]*'
            else:
                self.regexp = '.*'
        else:
            self.regexp = absorb_regexp

        if extra_fuzzy_list is not None:
            self.add_specific_fuzzy_vals(extra_fuzzy_list)

        if values is not None:
            assert isinstance(values, list)
            self.values = self._str2bytes(values)
            for val in self.values:
                if not self._check_compliance(val, force_max_enc_sz=self.max_enc_sz_provided,
                                              force_min_enc_sz=self.min_enc_sz_provided,
                                              update_list=False):
                    raise DataModelDefinitionError

                if self.alphabet is not None:
                    for l in val:
                        if l not in self.alphabet:
                            raise ValueError("The value '%s' does not conform to the alphabet!" % val)

            self.values_copy = copy.copy(self.values)
            self.is_values_provided = True  # distinguish cases where
                                              # values is provided or
                                              # created based on size
            self.user_provided_list = copy.copy(self.values)
        else:
            self.is_values_provided = False
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
        elif values is not None:
            sz = 0
            for v in values:
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

        self._check_sizes(values)

        self.determinist = determinist

        self._ensure_enc_sizes_consistency()

    def _ensure_enc_sizes_consistency(self):
        if not self.encoded_string:
            # For a non-Encoding type, the size of the string is always lesser or equal than the size
            # of the encoded string (utf8, ...). Hence the byte string size is still >= to the string size.
            # As self.max_encoded_sz is needed for absorption, we do the following heuristic (when
            # information is missing).
            if self.max_encoded_sz is None or \
                    (not self.max_enc_sz_provided and self.max_encoded_sz < self.max_sz):
                self.max_encoded_sz = self.max_sz
            if self.min_encoded_sz is None or \
                    (not self.min_enc_sz_provided and self.min_encoded_sz > self.min_sz):
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
                    self.values.append(value)
                return True
            elif force_max_enc_sz and not force_min_enc_sz:
                if val_sz <= self.max_encoded_sz:
                    if self.min_encoded_sz is None or val_sz < self.min_encoded_sz:
                        self.min_encoded_sz = val_sz
                    if update_list:
                        self.values.append(value)
                    return True
                else:
                    return False
            elif not force_max_enc_sz and force_min_enc_sz:
                if val_sz >= self.min_encoded_sz:
                    if self.max_encoded_sz is None or val_sz > self.max_encoded_sz:
                        self.max_encoded_sz = val_sz
                    if update_list:
                        self.values.append(value)
                    return True
                else:
                    return False
            else:
                if val_sz <= self.max_encoded_sz and val_sz >= self.min_encoded_sz:
                    if update_list:
                        self.values.append(value)
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
                self.values.append(value)
            return True

    def _populate_values(self, force_max_enc_sz=False, force_min_enc_sz=False):
        self.values = []
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
                    val = bp.rand_string(min=self.min_sz+1, max=self.max_sz-1, str_set=alpbt)
                    if self._check_compliance(self._str2bytes(val), force_max_enc_sz=force_max_enc_sz,
                                              force_min_enc_sz=force_min_enc_sz):
                        nb_vals += 1
                    else:
                        retry_cpt += 1

        if len(self.values) == 0:
            raise DataModelDefinitionError

    def _enable_normal_mode(self):
        self.values = self.values_save
        self.values_copy = copy.copy(self.values)
        self.values_fuzzy = None

        self.drawn_val = None

    def _enable_fuzz_mode(self, fuzz_magnitude=1.0):
        self.values_fuzzy = []

        def add_to_fuzz_list(flist):
            for v in flist:
                if v not in self.values_fuzzy:
                    self.values_fuzzy.append(v)

        if self.knowledge_source is None \
                or not self.knowledge_source.is_info_class_represented(Language) \
                or self.knowledge_source.is_assumption_valid(Language.C):
            C_strings_enabled = True
        else:
            C_strings_enabled = False

        if self.knowledge_source \
                and self.knowledge_source.is_info_class_represented(InputHandling) \
                and self.knowledge_source.is_assumption_valid(InputHandling.Ctrl_Char_Set):
            CTRL_char_enabled = True
        else:
            CTRL_char_enabled = False

        if self.drawn_val is not None:
            orig_val = self.drawn_val
        else:
            if self.determinist:
                orig_val = self.values_copy[0]
            else:
                orig_val = random.choice(self.values_copy)

        sz = len(orig_val)
        sz_delta_with_max = self.max_encoded_sz - sz

        if sz > 0:
            val = bp.corrupt_bits(orig_val, n=1)
            self.values_fuzzy.append(val)

        val = orig_val + b"A"*(sz_delta_with_max + 1)
        self.values_fuzzy.append(val)

        if len(self.encode(orig_val)) > 0:
            self.values_fuzzy.append(b'')

        if sz > 0:
            sz_delta_with_min = sz - self.min_sz
            val = orig_val[:-sz_delta_with_min-1]
            if val != b'':
                self.values_fuzzy.append(val)

        if self.max_sz > 0:
            val = orig_val + b"X"*(self.max_sz*int(100*fuzz_magnitude))
            self.values_fuzzy.append(val)

        self.values_fuzzy.append(b'\x00' * sz if sz > 0 else b'\x00')

        if self.alphabet is not None and sz > 0:
            if self.codec == self.ASCII:
                base_char_set = set(self.printable_char_set)
            else:
                base_char_set = set(self.non_ctrl_char)

            unsupported_chars = base_char_set - set(self._bytes2str(self.alphabet))
            if unsupported_chars:
                sample = random.sample(unsupported_chars, 1)[0]
                test_case = orig_val[:-1] + sample.encode(self.codec)
                self.values_fuzzy.append(test_case)

        self.values_fuzzy += String.fuzz_cases_ctrl_chars(self.knowledge_source, orig_val, sz,
                                                          self.max_sz, self.codec)
        self.values_fuzzy += String.fuzz_cases_c_strings(self.knowledge_source, orig_val, sz,
                                                         fuzz_magnitude)

        self.values_fuzzy.append(orig_val + b'\r\n' * int(100*fuzz_magnitude))

        if self.codec == self.ASCII:
            val = bytearray(orig_val)
            if len(val) > 0:
                val[0] |= 0x80
                val = bytes(val)
            else:
                val = b'\xe9'
            if val not in self.values_fuzzy:
                self.values_fuzzy.append(val)
        elif self.codec == self.UTF16BE or self.codec == self.UTF16LE:
            if self.max_sz > 0:
                if self.max_encoded_sz % 2 == 1:
                    nb = self.max_sz // 2
                    # euro character at the end that 'fully' use the 2 bytes of utf-16
                    val = ('A' * nb).encode(self.codec) + b'\xac\x20'
                    if val not in self.values_fuzzy:
                        self.values_fuzzy.append(val)

        enc_cases = self.encoding_test_cases(orig_val, self.max_sz, self.min_sz,
                                             self.min_encoded_sz, self.max_encoded_sz)
        if enc_cases:
            self.values_fuzzy += enc_cases

        specif = self.get_specific_fuzzy_vals()
        if specif:
            add_to_fuzz_list(specif)
        if hasattr(self, 'subclass_fuzzing_list'):
            add_to_fuzz_list(self.subclass_fuzzing_list)

        self.values_save = self.values
        self.values = self.values_fuzzy
        self.values_copy = copy.copy(self.values)

        self.drawn_val = None

    @staticmethod
    def fuzz_cases_c_strings(knowledge, orig_val, sz, fuzz_magnitude):
        if knowledge is None \
                or not knowledge.is_info_class_represented(Language) \
                or knowledge.is_assumption_valid(Language.C):

            fuzzy_values = []

            if sz > 1:
                is_even = sz % 2 == 0
                cpt = sz // 2
                if is_even:
                    fuzzy_values.append(b'%n' * cpt)
                    fuzzy_values.append(b'%s' * cpt)
                else:
                    fuzzy_values.append(orig_val[:1] + b'%n' * cpt)
                    fuzzy_values.append(orig_val[:1] + b'%s' * cpt)
            else:
                fuzzy_values.append(b'%n')
                fuzzy_values.append(b'%s')

            fuzzy_values.append(orig_val + b'%n' * int(400*fuzz_magnitude))
            fuzzy_values.append(orig_val + b'%s' * int(400*fuzz_magnitude))
            fuzzy_values.append(orig_val + b'\"%n\"' * int(400*fuzz_magnitude))
            fuzzy_values.append(orig_val + b'\"%s\"' * int(400*fuzz_magnitude))

            return fuzzy_values

        else:
            return []


    @staticmethod
    def fuzz_cases_ctrl_chars(knowledge, orig_val, sz, max_sz, codec):
        if knowledge \
                and knowledge.is_info_class_represented(InputHandling) \
                and knowledge.is_assumption_valid(InputHandling.Ctrl_Char_Set):

            fuzzy_values = []

            if sz > 0:
                fuzzy_values.append(b'\x08'*max_sz) # backspace characters
            if sz == max_sz:
                # also include fixed size string i.e., self.min_sz == self.max_sz
                for c in String.ctrl_char_set:
                    test_case = orig_val[:-1]+c.encode(codec)
                    fuzzy_values.append(test_case)
            else:
                for c in String.ctrl_char_set:
                    test_case = orig_val+c.encode(codec)
                    fuzzy_values.append(test_case)

            return fuzzy_values

        else:
            return []

    def get_value(self):
        if not self.values:
            self._populate_values(force_max_enc_sz=self.max_enc_sz_provided,
                                  force_min_enc_sz=self.min_enc_sz_provided)
            self._ensure_enc_sizes_consistency()
        if not self.values_copy:
            self.values_copy = copy.copy(self.values)
        if self.determinist:
            ret = self.values_copy.pop(0)
        else:
            ret = random.choice(self.values_copy)
            self.values_copy.remove(ret)

        self.drawn_val = ret
        if self.encoded_string:
            ret = self.encode(ret)
        return ret

    def get_current_raw_val(self, str_form=False):
        if self.drawn_val is None:
            self.get_value()
        val = self._bytes2str(self.drawn_val) if str_form else self.drawn_val
        return val

    def get_current_value(self):
        if self.drawn_val is None:
            self.get_value()
        return self.encode(self.drawn_val) if self.encoded_string else self.drawn_val

    def is_exhausted(self):
        if self.values_copy:
            return False
        else:
            return True

    def set_size_from_constraints(self, size=None, encoded_size=None):
        # This method is used only for absorption purpose, thus no modification
        # is performed on self.values. To be reconsidered in the case the method
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

        if self.values_desc:
            desc = self.values_desc.get(self.drawn_val)
            desc = '' if desc is None else ", desc='" + desc + "'"
        else:
            desc = ''

        if self.encoded_string or self.codec not in [self.ASCII, self.LATIN_1]:
            dec = self.drawn_val
            sz = len(dec)
            if max_size is not None and sz > max_size:
                dec = dec[:max_size]
            dec = dec.decode(self.codec, 'replace')
            if sys.version_info[0] == 2:
                dec = dec.encode('latin-1')
            return dec + ' [decoded, sz={!s}, codec={!s}{:s}]'.format(len(dec), self.codec, desc)
        else:
            return 'codec={!s}{:s}'.format(self.codec, desc)


class INT(VT):
    '''
    Base class to be inherited and not used directly
    '''
    usable = False

    mini = None
    maxi = None
    cformat = None
    alt_cformat = None
    endian = None
    determinist = True

    mini_gen = None  # automatically set and only used for generation (not absorption)
    maxi_gen = None  # automatically set and only used for generation (not absorption)
    GEN_MAX_INT = 2**32  # 'maxi_gen' is set to this when the INT subclass does not define 'maxi'
                         # and that maxi is not specified by the user
    GEN_MIN_INT = -2**32  # 'mini_gen' is set to this when the INT subclass does not define 'mini'
                          # and that mini is not specified by the user

    fuzzy_values = None
    value_space_size = None
    size = None

    def __init__(self, values=None, min=None, max=None, default=None, determinist=True,
                 force_mode=False, fuzz_mode=False, values_desc=None):
        self.idx = 0
        self.determinist = determinist
        self.exhausted = False
        self.drawn_val = None
        self.default = None
        self._specific_fuzzy_vals = None
        self.values_desc = values_desc

        if self.values_desc and not isinstance(self.values_desc, dict):
            raise ValueError('@values_desc should be a dictionary')

        if not self.usable:
            raise DataModelDefinitionError("ERROR: {!r} is not usable! (use a subclass of it)"
                                           .format(self.__class__))

        if values:
            if force_mode:
                new_values = []
                for v in values:
                    if not self.is_compatible(v):
                        if v > self.__class__.maxi:
                            v = self.__class__.maxi
                    new_values.append(v)
                values = new_values
            elif fuzz_mode:
                for v in values:
                    if not self.is_size_compatible(v):
                        raise DataModelDefinitionError("Incompatible value ({!r}) regarding possible"
                                                       " encoding size for {!s}".format(v, self.__class__))
            else:
                for v in values:
                    if not self.is_compatible(v):
                        raise DataModelDefinitionError("Incompatible value ({!r}) with {!s}".format(v, self.__class__))

            self.values = list(values)
            if default is not None:
                assert default in self.values
                self.values.remove(default)
                self.values.insert(0, default)
            self.values_copy = list(self.values)

        else:
            if min is not None and max is not None:
                assert max >= min

            if min is not None and max is not None and abs(max - min) < 200:
                self.values = list(range(min, max + 1))
                # we keep min/max information as it may be valuable for fuzzing
                self.mini = self.mini_gen = min
                self.maxi = self.maxi_gen = max
                if default is not None:
                    assert min <= default <= max
                    self.values.remove(default)
                    self.values.insert(0, default)
                    # Once inserted at this place, its position is preserved, especially with reset_state()
                    # (assuming do_absorb() is not called), so we do not save 'default' value in this case
                self.values_copy = copy.copy(self.values)

            else:
                self.values = None
                self.values_copy = None
                if self.mini is not None:
                    self.mini = builtins.max(min, self.mini) if min is not None else self.mini
                    self.mini_gen = self.mini
                else:
                    # case where no size constraints exist (e.g., INT_str)
                    if min is None:
                        self.mini = None
                        self.mini_gen = INT.GEN_MIN_INT
                    else:
                        self.mini = self.mini_gen = min

                if self.maxi is not None:
                    self.maxi = builtins.min(max, self.maxi) if max is not None else self.maxi
                    self.maxi_gen = self.maxi
                else:
                    # case where no size constraints exist (e.g., INT_str)
                    if max is None:
                        self.maxi = None
                        self.maxi_gen = INT.GEN_MAX_INT
                    else:
                        self.maxi = self.maxi_gen = max

                if default is not None:
                    assert self.mini_gen <= default <= self.maxi_gen
                    self.default = default
                    self.idx = default - self.mini_gen

    def make_private(self, forget_current_state):
        # no need to copy self.default (that should not be modified)
        if forget_current_state:
            self.values_copy = copy.copy(self.values)
            self.idx = 0
            self.exhausted = False
            self.drawn_val = None
        else:
            self.values_copy = copy.copy(self.values_copy)

    def copy_attrs_from(self, vt):
        self.endian = vt.endian

    def get_fuzzed_vt_list(self):

        specific_fuzzy_values = self.get_specific_fuzzy_vals()
        supp_list = specific_fuzzy_values if specific_fuzzy_values is not None else []

        val = self.get_current_raw_val()
        if val is not None:
            # don't use a set to preserve determinism if needed
            if val-1 not in supp_list:
                supp_list.append(val+1)
            if val-1 not in supp_list:
                supp_list.append(val-1)

            if self.values is not None:
                orig_set = set(self.values)
                max_oset = max(orig_set)
                min_oset = min(orig_set)
                if min_oset != max_oset:
                    diff_sorted = sorted(set(range(min_oset, max_oset+1)) - orig_set)
                    if diff_sorted:
                        item1 = diff_sorted[0]
                        item2 = diff_sorted[-1]
                        if item1 not in supp_list:
                            supp_list.append(item1)
                        if item2 not in supp_list:
                            supp_list.append(item2)
                    if max_oset+1 not in supp_list:
                        supp_list.append(max_oset+1)
                    if min_oset-1 not in supp_list:
                        supp_list.append(min_oset-1)

            if self.mini is not None:
                cond1 = False
                if self.value_space_size != -1:  # meaning not an INT_str
                    cond1 = (self.mini != 0 or self.maxi != ((1 << self.size) - 1)) and \
                       (self.mini != -(1 << (self.size-1)) or self.maxi != ((1 << (self.size-1)) - 1))
                else:
                    cond1 = True

                if cond1:
                    # we avoid using vt.mini or vt.maxi has they could be undefined (e.g., INT_str)
                    if self.mini_gen-1 not in supp_list:
                        supp_list.append(self.mini_gen-1)
                    if self.maxi_gen+1 not in supp_list:
                        supp_list.append(self.maxi_gen+1)

        if self.fuzzy_values:
            for v in self.fuzzy_values:
                if v not in supp_list:
                    supp_list.append(v)

        if supp_list:
            supp_list = list(filter(self.is_size_compatible, supp_list))
            fuzzed_vt = self.__class__(values=supp_list, fuzz_mode=True)
            return [fuzzed_vt]

        else:
            return None


    def add_specific_fuzzy_vals(self, vals):
        if self._specific_fuzzy_vals is None:
            self._specific_fuzzy_vals = []
        self._specific_fuzzy_vals += vals

    def get_specific_fuzzy_vals(self):
        return self._specific_fuzzy_vals

    def absorb_auto_helper(self, blob, constraints):
        off = 0
        # If 'Contents' constraint is set, we seek for int within
        # values.
        # If INT() does not have values, we assume off==0
        # and let do_absorb() decide if it's OK.
        if constraints[AbsCsts.Contents] and self.values is not None:
            for v in self.values:
                if blob.startswith(self._convert_value(v)):
                    break
            else:
                for v in self.values:
                    off = blob.find(self._convert_value(v))
                    if off > -1:
                        break

        if off < 0:
            return AbsorbStatus.Reject, off, None
        else:
            return AbsorbStatus.Accept, off, None


    def do_absorb(self, blob, constraints, off=0, size=None):

        self.orig_values = copy.copy(self.values)
        self.orig_values_copy = copy.copy(self.values_copy)
        self.orig_drawn_val = self.drawn_val

        blob = blob[off:]

        val, sz = self._read_value_from(blob, size)
        orig_val = self._unconvert_value(val)

        if self.values is not None:
            if constraints[AbsCsts.Contents]:
                if orig_val not in self.values:
                    raise ValueError('contents not valid!')
            if orig_val in self.values:
                self.values.remove(orig_val)
            self.values.insert(0, orig_val)
            self.values_copy = copy.copy(self.values)
        elif self.maxi is None and self.mini is None:
            # this case means 'self' is an unlimited INT (like INT_str subclass) where no constraints
            # have been provided to the constructor, like INT_str().
            self.values = [orig_val]
            self.values_copy = [orig_val]
        else:
            if constraints[AbsCsts.Contents]:
                if self.maxi is not None and orig_val > self.maxi:
                    raise ValueError('contents not valid! (max limit)')
                if self.mini is not None and orig_val < self.mini:
                    raise ValueError('contents not valid! (min limit)')
            else:
                # mini_gen and maxi_gen are always defined
                if orig_val < self.mini_gen:
                    if self.__class__.mini is not None and orig_val < self.__class__.mini:
                        raise ValueError('The type {!s} is not able to represent the value {:d}'
                                         .format(self.__class__, orig_val))
                    self.mini = self.mini_gen = orig_val
                if orig_val > self.maxi_gen:
                    if self.__class__.maxi is not None and orig_val > self.__class__.maxi:
                        raise ValueError('The type {!s} is not able to represent the value {:d}'
                                         .format(self.__class__, orig_val))
                    self.maxi = self.maxi_gen = orig_val

            self.idx = orig_val - self.mini_gen

        # self.reset_state()
        self.exhausted = False
        self.drawn_val = orig_val

        return val, off, sz


    def do_revert_absorb(self):
        '''
        If needed should be called just after self.do_absorb().
        '''
        if hasattr(self, 'orig_drawn_val'):
            self.values = self.orig_values
            self.values_copy = self.orig_values_copy
            self.drawn_val = self.orig_drawn_val

    def do_cleanup_absorb(self):
        if hasattr(self, 'orig_drawn_val'):
            del self.orig_values
            del self.orig_values_copy
            del self.orig_drawn_val

    def make_determinist(self):
        self.determinist = True

    def make_random(self):
        self.determinist = False

    def get_value_list(self):
        return self.values

    def get_current_raw_val(self):
        if self.drawn_val is None:
            self.get_value()
        return self.drawn_val

    def is_compatible(self, integer):
        return self.mini <= integer <= self.maxi

    def is_size_compatible(self, integer):
        if self.value_space_size == -1:
            return True
        elif -((self.value_space_size + 1) // 2) <= integer <= self.value_space_size:
            return True
        else:
            return False

    def set_value_list(self, new_list):
        ret = False
        if self.values:
            l = list(filter(self.is_compatible, new_list))
            if l:
                self.values = l
                self.values_copy = copy.copy(self.values)
                self.idx = 0
                ret = True

        return ret

    def extend_value_list(self, new_list):
        if self.values is not None:
            l = list(filter(self.is_compatible, new_list))
            if l:
                values_enc = list(map(self._convert_value, self.values))

                # We copy the list as it is a class attribute in
                # Fuzzy_* classes, and we don't want to change the classes
                # (as we modify the list contents and not the list itself)
                self.values = list(self.values)

                # we don't use a set to preserve the order
                for v in l:
                    # we check the converted value to avoid duplicated
                    # values (negative and positive value coded the
                    # same) --> especially usefull for the Fuzzy_INT class
                    if self._convert_value(v) not in values_enc:
                        self.values.insert(0, v)

                self.idx = 0
                self.values_copy = copy.copy(self.values)


    def remove_value_list(self, value_list):
        if self.values is not None:
            l = list(filter(self.is_compatible, value_list))
            if l:
                # We copy the list as it is a class attribute in
                # Fuzzy_* classes, and we don't want to change the classes
                # (as we modify the list contents and not the list itself)
                self.values = list(self.values)

                for v in l:
                    try:
                        self.values.remove(v)
                    except ValueError:
                        pass

                self.idx = 0
                self.values_copy = copy.copy(self.values)

    def get_value(self):
        if self.values is not None:
            if not self.values_copy:
                self.values_copy = copy.copy(self.values)

            if self.determinist:
                val = self.values_copy.pop(0)
            else:
                val = random.choice(self.values_copy)
                self.values_copy.remove(val)
            if not self.values_copy:
                self.values_copy = copy.copy(self.values)
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
                # 'values'. It avoids cunsuming too much memory and
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

    def get_current_value(self):
        if self.drawn_val is None:
            self.get_value()
        return self._convert_value(self.drawn_val)

    def set_size_from_constraints(self, size=None, encoded_size=None):
        raise DataModelDefinitionError

    def pretty_print(self, max_size=None):
        if self.drawn_val is None:
            self.get_value()

        if self.values_desc:
            desc = self.values_desc.get(self.drawn_val)
            desc = '' if desc is None else ' [' + desc + ']'
        else:
            desc = ''

        if self.drawn_val < 0:
            formatted_val = '-0x' + hex(self.drawn_val)[3:].upper()
        else:
            formatted_val = '0x' + hex(self.drawn_val)[2:].upper()

        return str(self.drawn_val) + ' (' + formatted_val + ')' + desc


    def rewind(self):
        if self.exhausted:
            self.exhausted = False

        if self.values is not None:
            if self.values_copy is not None and self.drawn_val is not None:
                self.values_copy.insert(0, self.drawn_val)
        else:
            if self.idx > 0:
                self.idx -= 1

        self.drawn_val = None

    def _unconvert_value(self, val):
        return struct.unpack(self.cformat, val)[0]

    def _convert_value(self, val):
        try:
            string = struct.pack(self.cformat, val)
        except:
            # this case can trigger with values that have been added for fuzzing
            string = struct.pack(self.alt_cformat, val)

        return string

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
        if self.values is not None:
            self.values_copy = copy.copy(self.values)
        self.exhausted = False
        self.drawn_val = None

    def update_raw_value(self, val):
        ok = True
        if isinstance(val, int):
            if val > self.__class__.maxi:
                val = self.__class__.maxi
                ok = False
            if self.values is not None:
                self.values.append(val)
                self.values_copy = copy.copy(self.values)
            else:
                self.idx = val - self.mini_gen
        else:
            raise TypeError

        self.drawn_val = val
        self.exhausted = False

        return ok

    # To be used after calling get_value()
    def is_exhausted(self):
        return self.exhausted


class Filename(String):
    @property
    def subclass_fuzzing_list(self):
        linux_spe = [b'../../../../../../etc/password']
        windows_spe = [b'..\\..\\..\\..\\..\\..\\Windows\\system.ini']
        c_spe = [b'file%n%n%n%nname.txt']


        if self.knowledge_source is None:
            flist = linux_spe+windows_spe+c_spe
        else:
            flist = []
            if self.knowledge_source.is_info_class_represented(OS):
                if self.knowledge_source.is_assumption_valid(OS.Linux):
                    flist += linux_spe
                if self.knowledge_source.is_assumption_valid(OS.Windows):
                    flist += windows_spe
            else:
                flist = linux_spe+windows_spe
            if self.knowledge_source.is_info_class_represented(Language):
                if self.knowledge_source.is_assumption_valid(Language.C):
                    flist += c_spe
            else:
                flist += c_spe

        return flist

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


class INT_str(INT):
    endian = VT.Native
    usable = True

    regex_decimal = b'-?\d+'

    regex_upper_hex = b'-?[0123456789ABCDEF]+'
    regex_lower_hex = b'-?[0123456789abcdef]+'

    regex_octal = b'-?[01234567]+'

    regex_bin = b'-?[01]+'

    fuzzy_values = [0, -1, -2**32, 2 ** 32 - 1, 2 ** 32]
    value_space_size = -1  # means infinite

    def __init__(self, values=None, min=None, max=None, default=None, determinist=True,
                 force_mode=False, fuzz_mode=False, base=10, letter_case='upper', min_size=None, reverse=False):
        INT.__init__(self, values=values, min=min, max=max, default=default, determinist=determinist,
                     force_mode=force_mode, fuzz_mode=fuzz_mode)
        assert base in [10, 16, 8, 2]
        assert letter_case in ['upper', 'lower']
        assert min_size is None or isinstance(min_size, int)

        self._base = base
        self._reverse = reverse
        self._min_size = min_size
        self._letter_case = letter_case

        self._format_str, self._regex = self._prepare_format_str(self._min_size, self._base,
                                                                 self._letter_case)

    def copy_attrs_from(self, vt):
        INT.copy_attrs_from(self, vt)
        self._base = vt._base
        self._letter_case = vt._letter_case
        self._min_size = vt._min_size
        self._reverse = vt._reverse
        self._format_str = vt._format_str
        self._regex = vt._regex

    def _prepare_format_str(self, min_size, base, letter_case):
        if min_size is not None:
            format_str = '{:0' + str(min_size)
        else:
            format_str = '{:'

        if base == 10:
            format_str += '}'
            regex = self.regex_decimal
        elif base == 16:
            if letter_case == 'upper':
                format_str += 'X}'
                regex = self.regex_upper_hex
            else:
                format_str += 'x}'
                regex = self.regex_lower_hex
        elif base == 8:
            format_str += 'o}'
            regex = self.regex_octal
        elif base == 2:
            format_str += 'b}'
            regex = self.regex_bin
        else:
            raise ValueError(self._base)

        return (format_str, regex)


    def get_fuzzed_vt_list(self):
        vt_list = INT.get_fuzzed_vt_list(self)
        fuzzed_vals = []

        def handle_size(self, v):
            sz = 1 if v == 0 else math.ceil(math.log(abs(v), self._base))
            if sz <= new_min_size:
                format_str, _ = self._prepare_format_str(new_min_size,
                                                         self._base, self._letter_case)
                fuzzed_vals.append(format_str.format(v))
                return True
            else:
                return False

        if self._min_size is not None and self._min_size > 1:
            new_min_size = self._min_size - 1

            if self.values:
                for v in self.values:
                    if handle_size(self, v):
                        break
            elif self.mini is None:
                handle_size(self, 5)
            elif self.mini >= 0:
                ok = handle_size(self, self.mini)
                if not ok:
                    for v in range(0, self.mini):
                        if handle_size(self, v):
                            break

        qty = self._min_size if self._min_size is not None else 1
        if self._base <= 10:
            fuzzed_vals.append('A'*qty)
        else:
            if self._letter_case == 'upper':
                fuzzed_vals.append('a'*qty)
            else:
                fuzzed_vals.append('A'*qty)
        if self._base <= 8:
            fuzzed_vals.append('8'*qty)
        if self._base <= 2:
            fuzzed_vals.append('2'*qty)

        orig_val = self.get_current_value()
        sz = len(orig_val)
        if self._min_size and self._min_size > sz:
            max_sz = self._min_size
        else:
            max_sz = sz

        fuzzed_vals += String.fuzz_cases_ctrl_chars(self.knowledge_source, orig_val, sz,
                                                    max_sz, codec=String.ASCII)
        fuzzed_vals += String.fuzz_cases_c_strings(self.knowledge_source, orig_val, sz,
                                                   fuzz_magnitude=0.3)

        fuzzed_vals.append(orig_val + b'\r\n' * 100)

        if fuzzed_vals:
            if vt_list is None:
                vt_list = []
            vt_list.insert(0, String(values=fuzzed_vals))

        return vt_list

    def is_compatible(self, integer):
        return True

    def pretty_print(self, max_size=None):
        if self.drawn_val is None:
            self.get_value()

        return str(self.drawn_val)

    def _read_value_from(self, blob, size):
        g = re.match(self._regex, blob)
        if g is None:
            raise ValueError
        else:
            return g.group(0), len(g.group(0))

    def _unconvert_value(self, val):
        if self._reverse:
            val = val[::-1]
        return int(val, base=self._base)

    def _convert_value(self, val):
        if isinstance(val, int):
            ret = self._format_str.format(val).encode('utf8')
            if self._reverse:
                ret = ret[::-1]
            return ret
        else:
            # for some fuzzing case
            assert isinstance(val, bytes)
            return val

class BitField(VT_Alt):
    '''
    Provide:
    - either @subfield_limits or @subfield_sizes
    - either @subfield_values or @subfield_val_extremums

    '''
    padding_one = [0, 1, 0b11, 0b111, 0b1111, 0b11111, 0b111111, 0b1111111]

    def __init__(self, subfield_limits=None, subfield_sizes=None,
                 subfield_values=None, subfield_val_extremums=None,
                 padding=0, lsb_padding=True,
                 endian=VT.BigEndian, determinist=True,
                 subfield_descs=None, defaults=None):

        VT_Alt.__init__(self)

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
        self.set_bitfield(sf_values=subfield_values, sf_val_extremums=subfield_val_extremums,
                          sf_limits=subfield_limits, sf_sizes=subfield_sizes,
                          sf_descs=subfield_descs, sf_defaults=defaults)

    def make_private(self, forget_current_state):
        # no need to copy self.default (that should not be modified)
        self.subfield_limits = copy.deepcopy(self.subfield_limits)
        self.subfield_sizes = copy.deepcopy(self.subfield_sizes)
        self.subfield_vals = copy.deepcopy(self.subfield_vals)
        self.subfield_vals_save = copy.deepcopy(self.subfield_vals_save)
        self.subfield_extrems = copy.deepcopy(self.subfield_extrems)
        self.subfield_extrems_save = copy.deepcopy(self.subfield_extrems_save)
        if forget_current_state:
            self.reset_state()
        else:
            self.idx = copy.deepcopy(self.idx)
            self.idx_inuse = copy.deepcopy(self.idx_inuse)
            self.subfield_fuzzy_vals = copy.deepcopy(self.subfield_fuzzy_vals)

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
                self.subfield_extrems[idx][0] = mini = builtins.min(mini, val)
            elif val > maxi:
                self.subfield_extrems[idx][1] = builtins.max(maxi, val)
            self.idx_inuse[idx] = self.idx[idx] = val - mini
        else:
            try:
                self.subfield_vals[idx].remove(val)
            except:
                pass
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
            values = self.subfield_vals[idx]
            index = 0 if len(values) == 1 else self.idx_inuse[idx]
            ret = values[index]
            
        return ret

        
    def set_bitfield(self, sf_values=None, sf_val_extremums=None, sf_limits=None, sf_sizes=None,
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

        if sf_values is None:
            sf_values = [None for i in range(len(self.subfield_limits))]
        elif len(sf_values) != len(self.subfield_limits):
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

            values = sf_values[idx]
            extrems = sf_val_extremums[idx]

            size = lim - prev_lim
            self.subfield_sizes.append(size)

            if values is not None:
                l = []
                for v in values:
                    if self.is_compatible(v, size):
                        l.append(v)
                default = self.subfield_defaults[idx]
                if default is not None:
                    assert default in l
                    l.remove(default)
                    l.insert(self.idx[idx], default)
                self.subfield_vals.append(l)
                self.subfield_extrems.append(None)
            else:
                if extrems is not None:
                    mini, maxi = extrems
                    if self.is_compatible(mini, size) and self.is_compatible(maxi, size):
                        assert(mini != maxi)
                        self.subfield_extrems.append([mini, maxi])
                    else:
                        s = '*** ERROR: builtins.min({:d}) / builtins.max({:d}) values are out of range!'.format(mini, maxi)
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


    @property
    def bit_length(self):
        return self.size

    @property
    def byte_length(self):
        return self.nb_bytes

    def extend(self, bitfield, rightside=True):

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

        if rightside:
            self.drawn_val = (term2 << self.size) + term1
        else:
            self.drawn_val = (term1 << bitfield.size) + term2
        sz_mod = (self.size + bitfield.size) % 8
        new_padding_sz = 8 - sz_mod if sz_mod != 0 else 0

        if self.lsb_padding:
            self.drawn_val <<= new_padding_sz

        self.current_val_update_pending = False
        if rightside:
            self.idx += bitfield.idx
            self.idx_inuse += bitfield.idx_inuse
        else:
            self.idx = bitfield.idx + self.idx
            self.idx_inuse = bitfield.idx_inuse + self.idx_inuse

        if self.subfield_descs is not None or bitfield.subfield_descs is not None:
            if self.subfield_descs is None and bitfield.subfield_descs is not None:
                self.subfield_descs = [None for i in self.subfield_limits]
                desc_extension = bitfield.subfield_descs
            elif self.subfield_descs is not None and bitfield.subfield_descs is None:
                desc_extension = [None for i in bitfield.subfield_limits]
            if rightside:
                self.subfield_descs += desc_extension
            else:
                self.subfield_descs = desc_extension + self.subfield_descs

        if rightside:
            self.subfield_sizes += bitfield.subfield_sizes
            self.subfield_vals += bitfield.subfield_vals
            self.subfield_extrems += bitfield.subfield_extrems
            self.subfield_defaults += bitfield.subfield_defaults

            for l in bitfield.subfield_limits:
                self.subfield_limits.append(self.size + l)

            self.subfield_fuzzy_vals += bitfield.subfield_fuzzy_vals

        else:
            self.subfield_sizes = bitfield.subfield_sizes + self.subfield_sizes
            self.subfield_vals = bitfield.subfield_vals + self.subfield_vals
            self.subfield_extrems = bitfield.subfield_extrems + self.subfield_extrems
            self.subfield_defaults = bitfield.subfield_defaults + self.subfield_defaults

            supp_limits = []
            for l in self.subfield_limits:
                supp_limits.append(bitfield.size + l)
            self.subfield_limits = bitfield.subfield_limits + supp_limits

            self.subfield_fuzzy_vals = bitfield.subfield_fuzzy_vals + self.subfield_fuzzy_vals

        self.size = self.subfield_limits[-1]
        self.nb_bytes = int(math.ceil(self.size / 8.0))

        if self.size % 8 == 0:
            self.padding_size = 0
        else:
            self.padding_size = 8 - (self.size % 8)

    def extend_right(self, bitfield):
        self.extend(bitfield, rightside=True)

    def extend_left(self, bitfield):
        self.extend(bitfield, rightside=False)

    def set_size_from_constraints(self, size=None, encoded_size=None):
        raise DataModelDefinitionError


    def pretty_print(self, max_size=None):

        current_raw_val = self.get_current_raw_val()

        first_pass = True
        for lim, sz, values, extrems, i in zip(self.subfield_limits[::-1],
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

            if values is None:
                mini, maxi = extrems
                string += bin(mini+self.idx_inuse[i])[2:].zfill(sz)
            else:
                index = 0 if len(values) == 1 else self.idx_inuse[i]
                string += bin(values[index])[2:].zfill(sz)

        if self.padding_size != 0:
            if self.padding == 1:
                # in the case the padding has been modified, following an absorption,
                # to something not standard because of AbsCsts.Contents == False,
                # we use the altered padding which has been stored in self.padding_one
                pad = bin(self.padding_one[self.padding_size])[2:]
            else:
                pad = '0'*self.padding_size
            if self.lsb_padding:
                string += ' |padding: ' + pad + ' |-)'
            else:
                string = '(+|padding: ' + pad + ' ' + string[2:] + ' |-)'

        else:
            string += ' |-)'

        return string + ' ' + str(current_raw_val)


    def is_compatible(self, integer, size):
        return 0 <= integer <= (1 << size) - 1

    def after_enabling_mode(self):
        self.drawn_val = None
        self.__count_of_possible_values = None
        self._reset_idx()

    def _enable_normal_mode(self):
        if self.determinist_save is not None:
            self.determinist = self.determinist_save

        self.subfield_extrems = self.subfield_extrems_save
        self.subfield_extrems_save = None
        self.subfield_vals = self.subfield_vals_save
        self.subfield_vals_save = None
        self.subfield_fuzzy_vals = [None for i in range(len(self.subfield_sizes))]
        self.exhausted = False

    def _enable_fuzz_mode(self, fuzz_magnitude=1.0):

        for idx in range(len(self.subfield_fuzzy_vals)):
            sz = self.subfield_sizes[idx]
            l = []
            self.subfield_fuzzy_vals[idx] = l

            # we substract 1 because after a get_value() call idx is incremented in advance
            # max is needed because self.idx[0] is equal to 0 in this case
            curr_idx = builtins.max(self.idx[idx]-1, 0)

            curr_values = self.subfield_vals[idx]
            if curr_values is not None:
                current = curr_values[curr_idx]
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

            if curr_values is not None:
                orig_set = set(curr_values)
                max_oset = builtins.max(orig_set)
                min_oset = builtins.min(orig_set)
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
        for values, extrems in zip(self.subfield_vals, self.subfield_extrems):
            if values is None:
                mini, maxi = extrems
                s += maxi - mini
            else:
                s += len(values) - 1

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
        """
        Used by .do_absorb().
        side effect: may change self.padding_one dictionary.
        """
        def recompute_padding(masked_val, mask):
            if masked_val != mask and masked_val != 0:
                self.padding = 1
                self.padding_one = copy.copy(self.padding_one)
                self.padding_one[self.padding_size] = masked_val
            elif masked_val == mask and self.padding == 0:
                self.padding = 1
            elif masked_val == 0 and self.padding == 1:
                self.padding = 0

        values = list(struct.unpack('B'*size, blob))

        if endian == VT.BigEndian:
            values = values[::-1]

        # values from LSB to MSB

        if self.padding_size != 0:
            if self.lsb_padding:
                mask = self.padding_one[self.padding_size]
                if constraints[AbsCsts.Contents]:
                    if self.padding == 1 and values[0] & mask != mask:
                        raise ValueError('contents not valid! (padding should be 1s)')
                    elif self.padding == 0 and values[0] & mask != 0:
                        raise ValueError('contents not valid! (padding should be 0s)')
                else:
                    masked_val = values[0] & mask
                    recompute_padding(masked_val, mask)
            else:
                mask = self.padding_one[self.padding_size]<<(8-self.padding_size)
                if constraints[AbsCsts.Contents]:
                    if self.padding == 1 and values[-1] & mask != mask:
                        raise ValueError('contents not valid! (padding should be 1s)')
                    elif self.padding == 0 and values[-1] & mask != 0:
                        raise ValueError('contents not valid! (padding should be 0s)')
                else:
                    masked_val = values[-1] & mask
                    recompute_padding(masked_val, mask)

        values_sz = len(values)
        result = 0
        for v, i in zip(values,range(values_sz)):
            result += v<<(i*8)

        decoded_val = result

        if self.padding_size != 0:
            if self.lsb_padding:
                result >>= self.padding_size
            else:
                shift = (values_sz-1)*8
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
        self.orig_padding = self.padding
        self.padding_one = self.__class__.padding_one

        self.reset_state()

        blob = blob[off:self.nb_bytes]

        self.drawn_val, orig_val = self._read_value_from(blob, self.nb_bytes, self.endian, constraints)

        insert_idx = 0
        first_pass = True
        limits = self.subfield_limits[:-1]
        limits.insert(0, 0)
        for lim, sz, values, extrems, i in zip(limits, self.subfield_sizes, self.subfield_vals,
                                               self.subfield_extrems, range(len(self.subfield_limits))):

            val = (orig_val >> lim) & ((1<<sz)-1)

            if values is None:
                mini, maxi = extrems
                if constraints[AbsCsts.Contents] and (mini > val or maxi < val):
                    raise ValueError("Value for subfield number {:d} does not match the constraints!".format(i+1))
                self.idx[i] = val - mini
                if not constraints[AbsCsts.Contents]: # update extremums if necessary
                    extrems[0] = builtins.min(extrems[0], val)
                    extrems[1] = builtins.max(extrems[1], val)
            else:
                if constraints[AbsCsts.Contents] and val not in values:
                    raise ValueError("Value for subfield number {:d} does not match the constraints!".format(i+1))
                if val in values:
                    values.remove(val)
                values.insert(insert_idx, val)

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
            self.padding = self.orig_padding
            self.padding_one = self.__class__.padding_one

    def do_cleanup_absorb(self):
        '''
        To be called after self.do_absorb() or self.do_revert_absorb()
        '''
        if hasattr(self, 'orig_drawn_val'):
            del self.orig_idx
            del self.orig_subfield_vals
            del self.orig_drawn_val
            del self.orig_padding

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

        for lim, values, extrems, i in zip(self.subfield_limits, self.subfield_vals, self.subfield_extrems,
                                             range(len(self.subfield_limits))):
            if self.determinist:
                if i == self.current_idx:
                    if values is None:
                        mini, maxi = extrems
                        v = mini + self.idx[self.current_idx]
                        if v >= maxi:
                            update_current_idx = True
                        else:
                            self.idx[self.current_idx] += 1
                        val += v << prev_lim
                    else:
                        if len(values) == 1:
                            index = 0
                        else:
                            index = self.idx[self.current_idx]
                        if index >= len(values) - 1:
                            update_current_idx = True
                        else:
                            self.idx[self.current_idx] += 1
                        self.idx_inuse[self.current_idx] = index
                        val += values[index] << prev_lim
                else:
                    if self._fuzzy_mode:
                        cursor = 0
                    else:
                        if values is not None and len(values) == 1:
                            cursor = 0
                        else:
                            if i > self.current_idx and self.subfield_defaults[i] is None:
                                # Note on the use of builtins.max(): in the
                                # case of values, idx is always > 1,
                                # whereas when it is extrems, idx can
                                # be 0.
                                cursor = builtins.max(self.idx[i] - 1, 0)
                            else:
                                cursor = self.idx[i]
                    self.idx_inuse[i] = cursor
                    if values is None:
                        mini, maxi = extrems
                        val += (mini + cursor) << prev_lim
                    else:
                        val += (values[cursor]) << prev_lim
            else:
                if values is None:
                    mini, maxi = extrems
                    drawn_val = random.randint(mini, maxi)
                    self.idx[i] = self.idx_inuse[i] = drawn_val - mini
                else:
                    drawn_val = random.choice(values)
                    self.idx[i] = self.idx_inuse[i] = values.index(drawn_val)

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

        for lim, values, extrems, i in zip(self.subfield_limits, self.subfield_vals, self.subfield_extrems,
                                             range(len(self.subfield_limits))):
            if values is None:
                mini, maxi = extrems
                v = mini + self.idx_inuse[i]
                val += v << prev_lim
            else:
                if len(values) == 1:
                    index = 0
                else:
                    index = self.idx_inuse[i]
                val += values[index] << prev_lim

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



class INT8(INT):
    fuzzy_values = [0xFF, 0, 0x01, 0x80, 0x7F]
    value_space_size = 2**8-1
    size = 8
    usable = False

class SINT8(INT8):
    mini = -2**7
    maxi = 2**7-1
    cformat = 'b'
    alt_cformat = 'B'
    endian = VT.Native
    usable = True

class UINT8(INT8):
    mini = 0
    maxi = 2**8-1
    cformat = 'B'
    alt_cformat = 'b'
    endian = VT.Native
    usable = True

class INT16(INT):
    fuzzy_values = [0xFFFF, 0, 0x8000, 0x7FFF]
    value_space_size = 2**16-1
    size = 16
    usable = False

class SINT16_be(INT16):
    mini = -2**15
    maxi = 2**15-1
    cformat = '>h'
    alt_cformat = '>H'
    endian = VT.BigEndian
    usable = True

class SINT16_le(INT16):
    mini = -2**15
    maxi = 2**15-1
    cformat = '<h'
    alt_cformat = '<H'
    endian = VT.LittleEndian
    usable = True

class UINT16_be(INT16):
    mini = 0
    maxi = 2**16-1
    cformat = '>H'
    alt_cformat = '>h'
    endian = VT.BigEndian
    usable = True

class UINT16_le(INT16):
    mini = 0
    maxi = 2**16-1
    cformat = '<H'
    alt_cformat = '<h'
    endian = VT.LittleEndian
    usable = True

class INT32(INT):
    fuzzy_values = [0xFFFFFFFF, 0, 0x80000000, 0x7FFFFFFF]
    value_space_size = 2**32-1
    size = 32
    usable = False

class SINT32_be(INT32):
    mini = -2**31
    maxi = 2**31-1
    cformat = '>l'
    alt_cformat = '>L'
    endian = VT.BigEndian
    usable = True

class SINT32_le(INT32):
    mini = -2**31
    maxi = 2**31-1
    cformat = '<l'
    alt_cformat = '<L'
    endian = VT.LittleEndian
    usable = True

class UINT32_be(INT32):
    mini = 0
    maxi = 2**32-1
    cformat = '>L'
    alt_cformat = '>l'
    endian = VT.BigEndian
    usable = True

class UINT32_le(INT32):
    mini = 0
    maxi = 2**32-1
    cformat = '<L'
    alt_cformat = '<l'
    endian = VT.LittleEndian
    usable = True

class INT64(INT):
    fuzzy_values = [0xFFFFFFFFFFFFFFFF, 0, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0x1111111111111111]
    value_space_size = 2**64-1
    size = 64
    usable = False

class SINT64_be(INT64):
    mini = -2**63
    maxi = 2**63-1
    cformat = '>q'
    alt_cformat = '>Q'
    endian = VT.BigEndian
    usable = True

class SINT64_le(INT64):
    mini = -2**63
    maxi = 2**63-1
    cformat = '<q'
    alt_cformat = '<Q'
    endian = VT.LittleEndian
    usable = True

class UINT64_be(INT64):
    mini = 0
    maxi = 2**64-1
    cformat = '>Q'
    alt_cformat = '>q'
    endian = VT.BigEndian
    usable = True

class UINT64_le(INT64):
    mini = 0
    maxi = 2**64-1
    cformat = '<Q'
    alt_cformat = '<q'
    endian = VT.LittleEndian
    usable = True