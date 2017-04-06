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

import os
import subprocess
import re

def ensure_dir(f):
    d = os.path.dirname(f)
    if not os.path.exists(d):
        os.makedirs(d)

def ensure_file(f):
    if not os.path.isfile(f):
        open(f, 'a').close()

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

def find_file(filename, root_path):
    for (dirpath, dirnames, filenames) in os.walk(root_path):
        if filename in filenames:
            return dirpath + os.sep + filename
    else:
        return None

def retrieve_app_handler(filename):
    mimetype = subprocess.check_output(['xdg-mime', 'query', 'filetype', filename])[:-1]
    desktop_file = subprocess.check_output(['xdg-mime', 'query', 'default', mimetype])[:-1]

    file_path = find_file(desktop_file.decode(), root_path='~/.local/share/applications/')
    if file_path is None:
        file_path = find_file(desktop_file.decode(), root_path='/usr/share/applications/')

    if file_path is None:
        return None

    with open(file_path, 'r') as f:
        buff = f.read()
        result = re.search("Exec=(.*)", buff)
        app_name = result.group(1).split()[0]
    return app_name
