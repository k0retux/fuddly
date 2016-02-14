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

import os

def ensure_dir(f):
    d = os.path.dirname(f)
    if not os.path.exists(d):
        os.makedirs(d)

def chunk_lines(string, length):
    l = string.split(' ')
    chk_list = []
    full_line = ''
    for wd in l:
        full_line += wd + ' '
        if len(full_line) > (length - 1):
            chk_list.append(full_line)
            full_line = ''
    if full_line:
        chk_list.append(full_line)
    # remove last space char
    if chk_list:
        chk_list[-1] = (chk_list[-1])[:-1]
    return chk_list
