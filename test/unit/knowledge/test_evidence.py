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
import unittest

import framework.knowledge as kn
import framework.knowledge.evidence
import framework.knowledge.logic
import framework.knowledge.source

assert sys.version_info >= (2, 7)


# TOFIX: restructure tests code in a unittest-friendly fashion
class test_evidence(unittest.TestCase):

    # run tests
    def test_evidence(self):
        # save the « local uid »
        local_uid = int(kn.evidence._local_occuring_uid)

        # check the consistency of each uuid field (see below)
        fake_source = kn.source.named_source(random.uniform(0, 1).hex())
        uuid_tcheck = kn.evidence.create_uuid(fake_source)

        # check if the « local uid » was increased
        self.assertTrue(local_uid + 1 == kn.evidence._local_occuring_uid)

        # check if the uuid's first field is magic
        self.assertTrue(uuid_tcheck.startswith(kn.evidence.uuid_magic))
        uuid_ncheck = uuid_tcheck[len(kn.evidence.uuid_magic) + 1:]

        # check if the uuid's second field is the correct api version
        self.assertTrue(uuid_ncheck.startswith('%x%x%02x' % kn.api_version))
        uuid_ncheck = uuid_ncheck[5:]

        # check if the uuid's third field is equal to the « session » token
        self.assertTrue(uuid_ncheck.startswith(kn.evidence.uuid_session))
        uuid_ncheck = uuid_ncheck[len(kn.evidence.uuid_session) + 1:]

        # check if the uuid's fourth field is equal to current « local uid »
        self.assertTrue(int(uuid_ncheck[:8], 16) == local_uid)
        uuid_ncheck = uuid_ncheck[9:]

        # check if the uuid's fifth field is equal to hashed source
        h = fake_source.name + '()'
        if sys.version_info < (3, ):
            h = hashlib.sha224(h).hexdigest()[-6:]
        else:
            h = hashlib.sha224(bytes(h, 'utf8')).hexdigest()[-6:]

        self.assertTrue(uuid_ncheck.startswith(h))
        uuid_ncheck = uuid_ncheck[len(h) + 1:]

        # check if the uuid's penultimate field is near the current timestamp
        stamp = int(uuid_ncheck[:8], 16)
        self.assertTrue(abs(stamp - time.time()) < 1)
        uuid_ncheck = uuid_ncheck[9:]

        # check if the uuid's ultimate field is finished by a correct crc32
        crc = uuid_tcheck[:-8]
        if sys.version_info < (3, ):
            crc = (binascii.crc32(crc) & 0xffffffff)
        else:
            crc = (binascii.crc32(bytes(crc, 'utf8')) & 0xffffffff)
        self.assertTrue(int(uuid_ncheck[6:], 16) == crc)

        # test by-size evidence constructor & metadata storage
        e = kn.evidence.evidence(size=37, some_meta='data')
        self.assertTrue(isinstance(e.value, kn.logic.tbsl))
        self.assertTrue(kn.logic.obsl(size=37) == e.value)
        self.assertTrue(e.mdata['some_meta'] == 'data')

        # test by-value evidence constructor
        x = kn.evidence.evidence(value=kn.logic.ebsl.uniform(37))
        y = kn.evidence.evidence(value=kn.logic.obsl.uniform(37))
        self.assertTrue(
            x.size == y.size == e.size == len(x.value + y.value + e.value))

        # test value type coherence
        self.assertTrue(
            x.value.__class__ == y.value.__class__ == e.value.__class__)

        # test if the (u)uids are ordered
        self.assertTrue(y.uid == x.uid + 1 == e.uid + 2 == local_uid + 4)
        self.assertTrue(y.uid > x.uid > e.uid > local_uid)
        self.assertTrue(y.uuid > x.uuid > e.uuid)

        # test source conservation while uniform merge
        self.assertTrue((x << y).source == x.source == y.source)

        # test source mixing while merging
        x.source = fake_source
        self.assertTrue(
            str((x << y).source) ==
            'merge<add>(left={}(),right=default())'.format(fake_source.name))

        # test source mixing with another operator
        y.merge_operator = operator.mul
        self.assertTrue(
            str((y << x).source) ==
            'merge<mul>(left=default(),right={}())'.format(fake_source.name))

        # test results obtained while merging
        self.assertTrue((x << y).value == (x.value + y.value))
        self.assertTrue((y << x).value == (y.value * x.value))


if __name__ == '__main__':
    unittest.main()
