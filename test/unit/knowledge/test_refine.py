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
import framework.knowledge.logic
import framework.knowledge.refine

assert sys.version_info >= (2, 7)


# TOFIX: restructure tests code in a unittest-friendly fashion
class test_refine(unittest.TestCase):

    # run tests
    def test_refine(self):

        # test exception
        try:
            raise kn.refine.NoDataRefinedError
            self.fail('Unable to raise exception ?')
        except kn.refine.NoDataRefinedError:
            pass

        # construct a data refining backend
        class unvalue:
            v = 0

        x = unvalue()

        def xinc(state, parent):
            x.v += state + len(parent.mdata['some']) / 100.

        rd = kn.refine.refine('paul', xinc, xinc, some='thing')
        self.assertTrue(rd.name == 'paul')
        self.assertTrue(rd.mdata['some'] == 'thing')
        self.assertTrue(rd._transform == rd._inverse == xinc)

        # check calls
        self.assertTrue(x.v == 0.)
        rd.transform(1)
        self.assertTrue(x.v == 1.05)

        rd.mdata['some'] = 'not'
        rd.inverse(3)
        self.assertTrue(x.v == 4.08)

        # check warning & repr
        re = kn.refine.refine('more', None, None)
        with warnings.catch_warnings(record=True) as w:
            m = ('No inverse function provided while refining ' +
                 'data with "more" backend ' +
                 '(id: more{}).'.format(object.__repr__(re)))

            try:
                re.inverse(3)
                self.fail('No NoDataRefinedError exception raised ?')
            except kn.refine.NoDataRefinedError:
                pass
            self.assertTrue(m in str(w[0].message).replace('\n', ' '))

        # construct a label collection
        lc = kn.refine.label('again', 21)
        self.assertTrue('again' + object.__repr__(lc) == repr(lc))
        self.assertTrue(repr(lc.source) == 'label<again>()')
        self.assertTrue(lc.size == 21)

        # add various labels to the collection
        lc.add(label='false', value=False)
        lc.add(dict(label='true', value=True))
        lc.add([
            dict(label='always', value=None),
            dict(label='even', value=True),
            dict(label='ever', value=[True, False, False]),
            dict(label='still', value=np.bool_(False)),
            dict(label='there', value=[np.bool_(True),
                                       np.bool_(False)]),
            dict(label='more', value=kn.logic.tbsl.true(4)),
            dict(label='again', value=kn.logic.ebsl.uniform(7)),
            dict(label='exotic', where=slice(3, None, 3)),
        ])


if __name__ == '__main__':
    unittest.main()
