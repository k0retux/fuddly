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

import framework.knowledge

assert sys.version_info >= (2, 7)

test_list = ['logic', 'source', 'evidence', 'refine', 'table', 'weather']


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for test in test_list:
        test_name = 'test.unit.knowledge.test_{}'.format(test)
        tests = loader.loadTestsFromName(test_name)
        suite.addTests(tests)
    return suite
