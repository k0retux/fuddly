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

import random

from framework.target_helpers import Target

class TestTarget(Target):

    _feedback_mode = None
    supported_feedback_mode = []

    def __init__(self, recover_ratio=100):
        Target.__init__(self)
        self._cpt = None
        self._recover_ratio = recover_ratio

    def start(self):
        self._cpt = 0
        return True

    def send_data(self, data, from_fmk=False):
        pass

    def send_multiple_data(self, data_list, from_fmk=False):
        pass

    def is_target_ready_for_new_data(self):
        self._cpt += 1
        if self._cpt > 5 and random.choice([True, False]):
            self._cpt = 0
            return True
        else:
            return False

    def recover_target(self):
        if random.randint(1, 100) > (100 - self._recover_ratio):
            return True
        else:
            return False