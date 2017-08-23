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

import sys
import unittest
import warnings

import numpy as np
import framework.knowledge as kn
import framework.knowledge.error
import framework.knowledge.evidence
import framework.knowledge.logic
import framework.knowledge.refine
import framework.knowledge.table

assert sys.version_info >= (2, 7)


# test near-equality with a relative/absolute tolerance
def _eq(a, b):
    return np.allclose(
        a,
        b,
        rtol=kn.logic.eq_rtol,
        atol=kn.logic.eq_atol,
        equal_nan=kn.logic.eq_nan)


# TOFIX: restructure tests code in a unittest-friendly fashion
class test_table(unittest.TestCase):

    # run tests
    def test_table(self):

        # first, create a label refining backend
        labels = kn.refine.label('main', 5)
        labels.add([
            dict(label='first'),
            dict(label='second'),
            dict(label='third'),
            dict(label='fourth'),
            dict(label='fifth'),
            dict(label='even', where=slice(1, None, 2)),
            dict(label='odd', where=slice(0, None, 2)),
            dict(label='even_only', value=[False, True, False, True, False]),
            dict(label='odd_only', value=[True, False, True, False, True]),
            dict(label='!prime', value=[True, False, False, True, False]),
        ])

        # then, create a translation table using our label refining label
        # backend
        table = kn.table.translation(labels)

        # translate semantic textual labels in abstract representation
        self.assertTrue(
            _eq(table.digest('first')[0].value.trust, [2, 0, 0, 0, 0]))
        self.assertTrue(
            _eq(table.digest('second')[0].value.trust, [0, 2, 0, 0, 0]))
        self.assertTrue(
            _eq(table.digest('third')[0].value.trust, [0, 0, 2, 0, 0]))
        self.assertTrue(
            _eq(table.digest('fourth')[0].value.trust, [0, 0, 0, 2, 0]))
        self.assertTrue(
            _eq(table.digest('fifth')[0].value.trust, [0, 0, 0, 0, 2]))
        self.assertTrue(
            _eq(table.digest('even')[0].value.trust, [0, 2, 0, 2, 0]))
        self.assertTrue(
            _eq(table.digest('odd')[0].value.trust, [2, 0, 2, 0, 2]))
        self.assertTrue(
            _eq(table.digest('even_only')[0].value.trust, [-1, 2, -1, 2, -1]))
        self.assertTrue(
            _eq(table.digest('odd_only')[0].value.trust, [2, -1, 2, -1, 2]))
        self.assertTrue(
            _eq(table.digest('prime')[0].value.trust, [-1, 2, 2, -1, 2]))
        self.assertTrue(
            _eq(table.digest('!prime')[0].value.trust, [2, -1, -1, 2, -1]))
        self.assertTrue(
            _eq(table.digest('!!prime')[0].value.trust, [-1, 2, 2, -1, 2]))

        results = table.digest(['first', 'third', 'fifth'])
        self.assertTrue(_eq(results[2].value.trust, [2, 0, 0, 0, 0]))
        self.assertTrue(_eq(results[1].value.trust, [0, 0, 2, 0, 0]))
        self.assertTrue(_eq(results[0].value.trust, [0, 0, 0, 0, 2]))

        kn.error.state.quiet = True
        v = kn.evidence.squash(results)
        self.assertTrue(_eq(v.value.trust, [2, 0, 2, 0, 2]))

        inversed = table.digest(v, inverse=True)
        self.assertTrue('first' in inversed)
        self.assertTrue('third' in inversed)
        self.assertTrue('fifth' in inversed)
        self.assertTrue('odd' in inversed)
        self.assertTrue(len(inversed) == 4)

        v = kn.evidence.squash(v, table.digest('even_only'))
        inversed = table.digest(v, inverse=True)
        self.assertTrue('second' in inversed)
        self.assertTrue('fourth' in inversed)
        self.assertTrue('even' in inversed)
        self.assertTrue(len(inversed) == 3)


if __name__ == '__main__':
    unittest.main()
