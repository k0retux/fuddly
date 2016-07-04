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

import argparse
import sys

mock_module = True
try:
    import unittest.mock as mock_mod
except ImportError:
    try:
        import mock as mock_mod
    except ImportError:
        mock_module = False
        print('ERROR: python-mock module is not installed! '
              'Should be installed to be able to run tests.')


ddt_module = True
try:
    import ddt
except ImportError:
    ddt_module = False
    print('ERROR: python(3)-ddt module is not installed! '
          'Should be installed to be able to run tests.')

if not (mock_module and ddt_module):
    sys.exit("Some dependencies are missing: enable to launch tests.")

mock = mock_mod


parser = argparse.ArgumentParser(description='Process arguments.')
parser.add_argument('-a', '--all', action='store_true',
                    help='Run all test cases. Some can take lot of time. (Disabled by default.)')
parser.add_argument('--ignore-dm-specifics', action='store_true',
                    help='Run Data Models specific test cases. (Enabled by default.)')

test_args = parser.parse_known_args()
run_long_tests = test_args[0].all
ignore_data_model_specifics = test_args[0].ignore_dm_specifics

args = [sys.argv[0]] + test_args[1]
