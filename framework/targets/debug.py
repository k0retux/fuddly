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
import datetime
import time

from framework.target_helpers import Target
from framework.basic_primitives import rand_string

class TestTarget(Target):

    _feedback_mode = Target.FBK_WAIT_UNTIL_RECV
    supported_feedback_mode = [Target.FBK_WAIT_UNTIL_RECV, Target.FBK_WAIT_FULL_TIME]
    _last_ack_date = None

    def __init__(self, recover_ratio=100, fbk_samples=None):
        Target.__init__(self)
        self._cpt = None
        self._recover_ratio = recover_ratio
        self._fbk_samples = fbk_samples

    def start(self):
        self._cpt = 0
        return True

    def send_data(self, data, from_fmk=False):
        self._last_ack_date = datetime.datetime.now() + datetime.timedelta(microseconds=random.randint(20, 40))
        time.sleep(0.001)
        fbk_content = random.choice(self._fbk_samples) if self._fbk_samples else rand_string(size=10)
        self._logger.collect_feedback(content=fbk_content, status_code=random.randint(-3, 3))

    def send_multiple_data(self, data_list, from_fmk=False):
        self._last_ack_date = datetime.datetime.now() + datetime.timedelta(microseconds=random.randint(20, 40))
        time.sleep(0.001)
        fbk_content = random.choice(self._fbk_samples) if self._fbk_samples else rand_string(size=20)
        self._logger.collect_feedback(content=fbk_content, status_code=random.randint(-3, 3))

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

    def get_last_target_ack_date(self):
        return self._last_ack_date
