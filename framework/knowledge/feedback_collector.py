################################################################################
#
#  Copyright 2018 Eric Lacombe <eric.lacombe@security-labs.org>
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

import copy
import datetime
import threading
import collections

class FeedbackSource(object):

    def __init__(self, src, subref=None, reliability=None):
        self._name = str(src) if subref is None else str(src) + ' - ' + str(subref)
        self._obj = src
        self._reliability = reliability

    def __str__(self):
        return self._name

    def __hash__(self):
        return id(self._obj)

    def __eq__(self, other):
        return id(self._obj) == id(other._obj)

    @property
    def obj(self):
        return self._obj


class FeedbackCollector(object):
    fbk_lock = threading.Lock()

    def __init__(self):
        self.cleanup()
        self._feedback_collector = collections.OrderedDict()
        self._feedback_collector_tstamped = collections.OrderedDict()
        self._tstamped_bstring = None

    def add_fbk_from(self, ref, fbk, status=0):
        now = datetime.datetime.now()
        with self.fbk_lock:
            if ref not in self._feedback_collector:
                self._feedback_collector[ref] = {}
                self._feedback_collector[ref]['data'] = []
                self._feedback_collector[ref]['status'] = 0
                self._feedback_collector_tstamped[ref] = []
            self._feedback_collector[ref]['data'].append(fbk)
            self._feedback_collector[ref]['status'] = status
            self._feedback_collector_tstamped[ref].append(now)

    def has_fbk_collector(self):
        return len(self._feedback_collector) > 0

    def __iter__(self):
        with self.fbk_lock:
            fbk_collector = copy.copy(self._feedback_collector)
            fbk_collector_ts = copy.copy(self._feedback_collector_tstamped)
        for ref, fbk in fbk_collector.items():
            yield ref, fbk['data'], fbk['status'], fbk_collector_ts[ref]

    def iter_and_cleanup_collector(self):
        with self.fbk_lock:
            fbk_collector = self._feedback_collector
            fbk_collector_ts = self._feedback_collector_tstamped
            self._feedback_collector = collections.OrderedDict()
            self._feedback_collector_tstamped = collections.OrderedDict()
        for ref, fbk in fbk_collector.items():
            yield ref, fbk['data'], fbk['status'], fbk_collector_ts[ref]

    def set_error_code(self, err_code):
        self._err_code = err_code

    def get_error_code(self):
        return self._err_code

    def set_bytes(self, bstring):
        now = datetime.datetime.now()
        self._tstamped_bstring = (bstring, now)

    def get_bytes(self):
        return None if self._tstamped_bstring is None else self._tstamped_bstring[0]

    def get_timestamp(self):
        return None if self._tstamped_bstring is None else self._tstamped_bstring[1]

    def cleanup(self):
        # fbk_collector cleanup is done during consumption to avoid loss of feedback in
        # multi-threading context
        self._tstamped_bstring = None
        self.set_error_code(0)