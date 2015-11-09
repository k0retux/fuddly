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
import fuzzfmk

fuddly_version = '0.20'

fuzzfmk_folder = os.path.dirname(fuzzfmk.__file__)
fuzzfmk_folder  = '.' if fuzzfmk_folder == '' else fuzzfmk_folder

app_folder = os.path.dirname(os.path.dirname(fuzzfmk.__file__))
app_folder = '.' if app_folder == '' else app_folder

workspace_folder = app_folder + os.sep + 'workspace' + os.sep
external_libs_folder = app_folder + os.sep + 'external_libs' + os.sep
external_tools_folder = app_folder + os.sep + 'external_tools' + os.sep
