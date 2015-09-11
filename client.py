#!/usr/bin/env python

################################################################################
#
#  Copyright 2014-2015 Eric Lacombe <eric.lacombe@security-labs.org>
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

from fuzzfmk.global_resources import *
from fuzzfmk.plumbing import *

sys.path.insert(0, external_libs_folder)

if __name__ == "__main__":

    fuzzer = Fuzzer()

    shell = FuzzShell("FuzzShell", fuzzer)
    shell.cmdloop()

    sys.exit(0)
