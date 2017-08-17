# -*- coding: utf-8 -*-

##
# framework.knowledge
#
#  Copyright 2017 by Matthieu Daumas <matthieu@daumas.me> and other authors.
#
# This file is a part of fuddly, as part of the knowledge component.
#
#  Licensed under GNU General Public License 3.0 or later.
#  Some rights reserved. See COPYING, AUTHORS.
#
# @license GPL-3.0+ <http://spdx.org/licenses/GPL-3.0+>
##

from __future__ import (absolute_import, division, print_function,
                        unicode_literals, with_statement)

import binascii
import hashlib
import operator
import random
import sys
import time

import framework.knowledge as kn
import framework.knowledge.error
import framework.knowledge.logic
import framework.knowledge.source
import framework.knowledge.tools

assert sys.version_info >= (2, 7)

logic_type = kn.logic.tbsl

_local_occuring_uid = 0

uuid_magic = '49e'
uuid_session = None


def reset_session():
    global uuid_session
    uuid_session = random.uniform(0, 1).hex()[4:10]


reset_session()

# TOFIX: Choose the best suited UUID format (considering python's uuid RFC4122)
#
# We use an universal unique identifier to identify evidences in order to
# enable further collection of serialized evidences in a long-lasting database
# (ideally shared between multiple sessions and multiple instances).
#
# For now, we use a handmade 196b UUID made of these fields.
#  - [12b] (magic)
#  - [16b] API version
#  - [24b] Session token
#  - [32b] Unique identifier (within the session)
#  - [24b] Source (of the information) hash
#  - [32b] Time of creation
#  - [24b+32b] 6 bytes of randomness + CRC32 of the previous 164b
#
# It may be *krm* quite over-engineered and expensive for the use and a regular
# UUID (as provided by python's uuid and RFC4122) may be sufficient.
#
# Thus, it's subject to change when serialization and evidence tracking will be
# added to the framework.knowledge API (be warned).
#
def create_uuid(source):
    global _local_occuring_uid

    src = None
    if sys.version_info < (3, ):
        src = str(source).decode('utf8')
    else:
        src = bytes(str(source), 'utf8')

    s = uuid_magic
    s += '-%x%x%02x' % kn.api_version
    s += '-' + uuid_session
    s += '-%08x' % _local_occuring_uid
    s += '-{}'.format(hashlib.sha224(src).hexdigest()[-6:])
    s += '-%08x' % int(time.time())
    s += '-' + random.uniform(0, 1).hex()[4:10]

    src = None
    if sys.version_info < (3, ):
        src = s.decode('utf8')
    else:
        src = bytes(s, 'utf8')

    s += '%08x' % (binascii.crc32(src) & 0xffffffff)
    _local_occuring_uid += 1
    return s


class evidence:
    def __init__(self,
                 value=None,
                 size=None,
                 source=None,
                 static_source=False,
                 merge_operator=operator.add,
                 **mdata):

        if source is None:
            source = kn.source.default
        assert kn.source.issource(source)

        if value is None:
            assert size is not None  # if value is None then size must be given
            self.size = size
            self.value = logic_type(size=self.size)
        else:
            self.value = logic_type(value)
            if size is not None:
                kn.error.warn('Size given but ignored')
            self.size = len(value)

        global _local_occuring_uid
        self.merge_operator = merge_operator
        self.static_source = static_source
        self.source = source
        self.mdata = dict(**mdata)
        self.uuid = create_uuid(source)
        self.uid = int(_local_occuring_uid)

    def clone(self):
        return evidence(
            value=self.value,
            source=self.source,
            merge_operator=self.merge_operator,
            mdata=self.mdata)

    def __lshift__(self, other):
        assert isinstance(other, evidence)
        assert len(self.value) == len(other.value)

        value = self.merge_operator(self.value, other.value)
        source = None
        if self.static_source or self.source == other.source:
            source = self.source
        else:
            source = kn.source.merge_source(
                op=self.merge_operator, left=self.source, right=other.source)

        return evidence(
            value=value,
            source=source,
            merge_operator=self.merge_operator,
            **self.mdata)


def squash(*evidences):
    _evidences = []
    for e in evidences:
        _evidences += kn.tools.listify(e)
    evidences = _evidences

    base = evidences[0]
    for e in evidences[1:]:
        base <<= e
    return base


def scale(*evidences):
    evidences = kn.tools.listify(evidences)
    for e in evidences:
        v = e.value;

        w = v.inert_weight()
        s = (v.weight > w)
        v[s] = v[s] / 2

        e.value = v
