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

try:
    from xtermcolor import colorize
except ImportError:
    print("WARNING [FMK]: python-xtermcolor module is not installed, colors won't be available!")
    def colorize(string, rgb=None, ansi=None, bg=None, ansi_bg=None, fd=1):
        return string

class Color(object):
    TITLE = 0x1947D1
    PROMPT = 0x6699FF

    SELECTED = 0x0030FF
    FMKINFOGROUP = 0x1947D1
    FMKINFO = 0x66FFFF
    INFO = 0xFF9900
    SUBINFO = 0xE6E68A
    INFO_ALT = 0x0055FF
    INFO_ALT_HLIGHT = 0x00FF00
    SUBINFO_ALT = 0x66FFFF
    SUBINFO_ALT_HLIGHT = 0x800080
    WARNING = 0xFFA500
    ERROR = 0xEF0000

    COMPONENT_INFO = 0x339966
    COMPONENT_START = 0x00FF00
    COMPONENT_STOP = 0x4775A3
    FEEDBACK = 0x800080
    NEWLOGENTRY = 0x1975FF
    FUZZSTEP = 0x009D9D
    LOGSECTION = 0x638C8C
    DISABLED = 0x7D7D7D
    DATAINFO = 0x8CAFCF
    COMMENTS = 0x00FF00

    ND_NONTERM = 0xEF0000
    ND_CONTENTS = 0x00FF00
    ND_RAW = 0x7D7D7D
    ND_RAW_HLIGHT = 0xE5E5E5
    ND_NAME = 0x1975FF
    ND_TYPE = 0x66FFFF
    ND_DUPLICATED = 0x800080

    @staticmethod
    def display():
        for c in dir(Color):
            if not c.startswith('__') and c != 'display':
                print(colorize(c, rgb=object.__getattribute__(Color, c)))

class FontStyle:
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


cups_module = True
try:
    import cups
except ImportError:
    cups_module = False
    print('WARNING [FMK]: python-cups module is not installed, Printer targets will not be available!')
