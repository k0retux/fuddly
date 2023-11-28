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

from __future__ import print_function

import functools

from .information import *
from ...libs.utils import Term

from ...libs import debug_facility as dbg

if dbg.KNOW_DEBUG:
    DEBUG_PRINT = dbg.DEBUG_PRINT
else:
    DEBUG_PRINT = dbg.NO_PRINT


@functools.total_ordering
class SimilarityMeasure(object):
    def __init__(self, level=0):
        self._level = level

    @property
    def value(self):
        return self._level

    def __eq__(self, other):
        return self._level == other._level

    def __lt__(self, other):
        return self._level < other._level

    def __add__(self, other):
        new_lvl = (self._level + other._level) // 2
        return SimilarityMeasure(level=new_lvl)


UNIQUE = SimilarityMeasure(level=0)
EQUAL = SimilarityMeasure(level=16)
MID_SIMILAR = SimilarityMeasure(level=8)


class FeedbackHandler(object):
    """
    A feedback handler extract information from binary data.
    """

    def __init__(self, new_window=False, new_window_title=None):
        """
        Args:
            new_window: If `True`, a new terminal emulator is created, enabling the decoder to use
              it for display via the methods `print()` and `print_nl()`

        """
        self._new_window = new_window
        self._new_window_title = new_window_title
        self._s = None
        self.term = None
        self.fmkops = None

    def notify_data_sending(self, current_dm, data_list, timestamp, target):
        """
        *** To be overloaded ***

        This function is called when data have been sent. It enables to process feedback relatively
        to previously sent data.

        Args:
            current_dm (:class:`framework.data_model.DataModel`): current loaded DataModel
            data_list (list): list of :class:`framework.data.Data` that were sent
            timestamp (datetime): date when data was sent
            target (:class:`framework.target_helpers.Target`): target to which data was sent
        """
        pass

    def extract_info_from_feedback(
        self, current_dm, source, timestamp, content, status
    ):
        """
        *** To be overloaded ***

        Args:
            current_dm (:class:`framework.data_model.DataModel`): current loaded DataModel
            source (:class:`framework.knowledge.feedback_collector.FeedbackSource`): source of the feedback
            timestamp (datetime): date of reception of the feedback
            content (bytes): binary data to process
            status (int): negative status signify an error

        Returns:
            Info: a set of :class:`.information.Info` or only one
        """
        return None

    def estimate_last_data_impact_uniqueness(self):
        """
        *** To be overloaded ***

        Estimate the similarity of the consequences triggered by the current data sending
        from previous sending.
        Estimation can be computed with provided feedback.

        Returns:
            SimilarityMeasure: provide an estimation of impact similarity
        """
        return UNIQUE

    def start(self, current_dm):
        pass

    def stop(self):
        pass

    def _start(self, current_dm):
        self._s = ""
        if self._new_window:
            nm = (
                self.__class__.__name__
                if self._new_window_title is None
                else self._new_window_title
            )
            self.term = Term(title=nm, keepterm=True)
            self.term.start()

        self.start(current_dm)

    def _stop(self):
        self._s = None
        if self._new_window and self.term is not None:
            self.term.stop()

        self.stop()

    def print(self, msg):
        if self._new_window:
            self.term.print(msg)
        else:
            print(msg)

    def print_nl(self, msg):
        if self._new_window:
            self.term.print_nl(msg)
        else:
            print(msg)

    def collect_data(self, s):
        self._s += s

    def flush_collector(self):
        self.print(self._s)
        self._s = ""

    def process_feedback(self, current_dm, source, timestamp, content, status):
        info_set = set()
        truncated_content = None if content is None else content[:60]

        DEBUG_PRINT(
            "\n*** Feedback Entry ***\n"
            "    source: {!s}\n"
            " timestamp: {!s}\n"
            "   content: {!r} ...\n"
            "    status: {!s}".format(source, timestamp, truncated_content, status)
        )

        info = self.extract_info_from_feedback(
            current_dm, source, timestamp, content, status
        )
        if info is not None:
            if isinstance(info, list):
                for i in info:
                    info_set.add(i)
            else:
                info_set.add(info)

        return info_set


class TestFbkHandler(FeedbackHandler):
    def extract_info_from_feedback(
        self, current_dm, source, timestamp, content, status
    ):
        if content is None:
            return None
        elif b"Linux" in content:
            # OS.Linux.increase_trust()
            return OS.Linux
        elif b"Windows" in content:
            # OS.Windows.increase_trust()
            return OS.Windows
