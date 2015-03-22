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

from fuzzfmk.plumbing import *
from fuzzfmk.target import *
from fuzzfmk.logger import *
from fuzzfmk.tactics_helper import *

tactics = Tactics()

logger = Logger('zip', data_in_seperate_file=True, explicit_export=True, export_orig=False)

local_tg = LocalTarget(tmpfile_ext='.zip')
local_tg.set_target_path('unzip')

targets = [local_tg]
