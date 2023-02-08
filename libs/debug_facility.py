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

DEBUG = False
LEVEL = 0

# related to data_model.py
DM_DEBUG = False
ABS_DEBUG = False

# related to value_types.py
VT_DEBUG = False

# related to fuzzing_primitives.py
MW_DEBUG = False

# related to knowledge infrastructure
KNOW_DEBUG = False

try:
    from xtermcolor import colorize
except ImportError:
    print("WARNING [FMK]: python-xtermcolor module is not installed, colors won't be available!")
    def colorize(string, rgb=None, ansi=None, bg=None, ansi_bg=None, fd=1):
        return string

class DebugColor:
    LEVEL = {
        0: 0xFF0000,
        1: 0x66FF00,
        2: 0xB1FF7D
        }
    MISC = 0xFF0000


def DEBUG_PRINT(msg, level=1, rgb=None):
    if DEBUG and level <= LEVEL:
        if rgb is None:
            print(colorize(msg, rgb=DebugColor.LEVEL[level]))
        else:
            print(colorize(msg, rgb=rgb))

def NO_PRINT(msg, level=1, rgb=None):
    return