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

import unittest
import ddt
from test import mock

from framework.node import *

@ddt.ddt
class TestBitFieldCondition(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        def side_effect(idx):
            return [0, 1, 2][idx]

        cls.node = mock.Mock()
        cls.node.get_subfield = mock.MagicMock(side_effect=side_effect)
        cls.node.is_genfunc = mock.MagicMock(return_value=False)

    @ddt.data((1, 1), (1, [1]), ([1], [1]),
                  (1, (1,)), ((1,), (1,)),
          (2, [2, 6, 7]), (2, (2, 6, 7)),
          ([1, 2], [1, [5, 2, 8]]), ([1, 2], [[1], [5, 6, 2]]),
          ((1, 2), (1, (5, 2, 8))), ((1, 2), ((1,), (5, 6, 2))))
    @ddt.unpack
    def test_with_one_argument(self, sf, val):
        condition = BitFieldCondition(sf=sf, val=val)
        self.assertTrue(condition.check(TestBitFieldCondition.node))

        condition = BitFieldCondition(sf=sf, neg_val=val)
        self.assertFalse(condition.check(TestBitFieldCondition.node))

    @ddt.data(([0, 1, 2], [0, [1, 3], None], [None, None, 5]),
          ([0, 2], [None, 2], [3, None]))
    @ddt.unpack
    def test_true_with_both_arguments(self, sf, val, neg_val):
        condition = BitFieldCondition(sf=sf, val=val, neg_val=neg_val)
        self.assertTrue(condition.check(TestBitFieldCondition.node))

    @ddt.data(([0, 1, 2], [[0, 1], [1, 2], None], [None, None, [1, 2, 3]]),
              ([0, 1, 2], [[1, 2, 3], [1, 2], None], [None, None, [1, 3, 5]]))
    @ddt.unpack
    def test_false_with_both_arguments(self, sf, val, neg_val):
        condition = BitFieldCondition(sf=sf, val=val, neg_val=neg_val)
        self.assertFalse(condition.check(TestBitFieldCondition.node))

    def test_true_val_has_priority(self):
        condition = BitFieldCondition(sf=0, val=[0, 4, 5], neg_val=[0, 4, 5])
        self.assertTrue(condition.check(TestBitFieldCondition.node))

    def test_false_val_has_priority(self):
        condition = BitFieldCondition(sf=0, val=[3, 4, 5], neg_val=[3, 4, 5])
        self.assertFalse(condition.check(TestBitFieldCondition.node))

    @ddt.data((None, [2, 3]), ([1], 1), ((1,), 2),
          ([1], [2, 1, 4]), ((1,), (2, 1, 4)),
          ([1, 2], [1]))
    @ddt.unpack
    def test_invalid_with_one_argument(self, sf, val):
        self.assertRaises(Exception, BitFieldCondition, sf=sf, val=val)
        self.assertRaises(Exception, BitFieldCondition, sf=sf, neg_val=val)

    @ddt.data((1, None, None), (None, 2, 3),
          ([1, 2], [1, None], [2, None]),
          ([1, 2], [1, 2], [[1, 2, 3, 4]]),
          ([1, 2], [1, 2, 3, 4], [[1, 2]]))
    @ddt.unpack
    def test_invalid_with_both_arguments(self, sf, val, neg_val):
        self.assertRaises(Exception, BitFieldCondition, sf=sf, val=val, neg_val=neg_val)
