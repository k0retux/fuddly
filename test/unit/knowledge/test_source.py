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

import random
import sys
import unittest

import framework.knowledge as kn
import framework.knowledge.source

assert sys.version_info >= (2, 7)


# TOFIX: restructure tests code in a unittest-friendly fashion
class test_source(unittest.TestCase):

    # run tests
    def test_source(self):

        # check the default source
        self.assertTrue(kn.source.default.name == 'default')
        self.assertTrue(kn.source.issource(kn.source.default))
        self.assertTrue(
            isinstance(kn.source.default, kn.source.default_source))

        # construct named sources
        x = kn.source.named_source(name='what', other_metadata='some')
        y = kn.source.named_source(
            name='whom', other_metadata='some', more='again')
        self.assertTrue(y.more == 'again')
        self.assertTrue(x.name == 'what' and y.name == 'whom')
        self.assertTrue(x.other_metadata == 'some' and y.other_metadata)

        # test issource
        self.assertTrue(kn.source.issource(x) and kn.source.issource(y))
        self.assertTrue(not kn.source.issource(x.name) and
                        not kn.source.issource(y.more))

        # check __str__
        self.assertTrue(str(x) == 'what(other_metadata=some)')
        self.assertTrue(str(y) == 'whom(more=again,other_metadata=some)')

        # check equality
        z = kn.source.named_source(name='what', other_metadata='some')
        self.assertTrue(x == z)
        self.assertTrue(not (x == y or z == y))

        # construct merged sources
        a = kn.source.merge_source(op='concat', left=x, right=y)
        b = kn.source.merge_source(op='concat', right=x, left=x)

        # test property setter
        self.assertTrue(b.right == x)
        b.right = y
        self.assertTrue(b.right == y)

        # (retrieve some identical, but shuffled dicts)
        adict = a.dict()
        bdict = dict(random.sample(b.dict().items(), len(b.dict())))

        # construct pathological merged sources
        c = kn.source.merge_source(op=z, again=(b, a), nope=adict)
        e = kn.source.merge_source(op=x, again=(a, b), nope=bdict)

        # check repr & dict-ordering-sensitive determinism
        strab = ('merge<concat>(left=what(other_metadata=some),' +
                 'right=whom(more=again,other_metadata=some))')
        strec = ('merge<what(other_metadata=some)>(again=(merge' +
                 '<concat>(left=what(other_metadata=some),rig' +
                 'ht=whom(more=again,other_metadata=some)),me' +
                 'rge<concat>(left=what(other_metadata=some),' +
                 'right=whom(more=again,other_metadata=some))' +
                 '),nope={left:what(other_metadata=some),name' +
                 ':merge,op:concat,right:whom(more=again,othe' +
                 'r_metadata=some)})')
        self.assertTrue(str(a) == repr(b) == strab)
        self.assertTrue(repr(e) == str(c) == strec)


if __name__ == '__main__':
    unittest.main()
