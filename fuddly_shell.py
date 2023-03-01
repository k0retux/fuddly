#!/usr/bin/env python

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

import sys
from framework.plumbing import *

import argparse

parser = argparse.ArgumentParser(description='Arguments for Fuddly Shell')

group = parser.add_argument_group('Miscellaneous Options')
group.add_argument('-f', '--fmkdb', metavar='PATH', help='Path to an alternative fmkDB.db. Create '
                                                         'it if it does not exist.')
group.add_argument('--external-display', action='store_true', help='Display information on another terminal.')
group.add_argument('--quiet', action='store_true', help='Limit the information displayed at startup.')

args = parser.parse_args()

fmkdb = args.fmkdb
external_display = args.external_display
quiet = args.quiet

fmk = FmkPlumbing(external_term=external_display, fmkdb_path=fmkdb, quiet=quiet)
fmk.start()

shell = FmkShell("Fuddly Shell", fmk)
shell.cmdloop()

sys.exit(0)
