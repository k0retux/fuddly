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

import time
import functools
import random

from textual.widgets import RichLog
from xtermcolor import colorize

from fuddly.framework.knowledge.information import Info
from fuddly.info.generic import *
from fuddly.libs import debug_facility as dbg
from fuddly.libs.external_modules import Color
from fuddly.libs.utils import Term, RichTerm

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

    def __init__(self, name=None, new_window=False, new_window_title=None,
                 keep_term=True, markup_mode=False, **kwargs):
        """
        Args:
            new_window: If `True`, a new terminal emulator is created, enabling the decoder to use
              it for display via the methods `print()` and `print_nl()`

        """
        self._new_window = new_window
        self._new_window_title = new_window_title
        self._keep_term = keep_term
        self._name = name
        self._s = None
        self.term = None
        self.fmkops = None
        self._tui_obj = None
        self._markup_mode = markup_mode
        self._fifo = None

        self.specific_init(**kwargs)

    def set_tui_control_interface(self, tui_obj: RichTerm):
        self._tui_obj = tui_obj

    def __str__(self):
        if self._new_window_title is None and self._name is None:
            return f'{self.__class__.__name__}'
        else:
            name = self._new_window_title if self._name is None else self._name
            return f'{self.__class__.__name__}[{name}]'

    def specific_init(self, **kwargs):
        pass

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

        Returns:
            None|str: may return a description that will be added to the contextual information
              stored with the data sent
        """
        return None

    def extract_info_from_feedback(self, current_dm, source, timestamp, content, status):
        """
        *** To be overloaded ***

        Args:
            current_dm (:class:`framework.data_model.DataModel`): current loaded DataModel
            source (:class:`framework.knowledge.feedback_collector.FeedbackSource`): source of the feedback
            timestamp (datetime): date of reception of the feedback
            content (bytes): binary data to process
            status (int): negative status signify an error

        Returns:
            Info: an :class:`.information.Info` that will be stored in the Information Collector
              of the project;
              or a tuple "(timestamp, content, status)" that will be stored as a new feedback
              (processed from the raw feedback) in the fmkDB;
              or a list mixing items of the types described above.
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
        self._s = ''
        if self._tui_obj:
            self._fifo = self._tui_obj.new_log_panel(title=str(self), markup=self._markup_mode)
        else:
            if self._new_window:
                nm = self.__class__.__name__ if self._new_window_title is None else self._new_window_title
                self.term = Term(title=nm, keepterm=self._keep_term)
                self.term.start()

        self.start(current_dm)

    def _stop(self, before_reload=False):
        self._s = None
        if self._tui_obj:
            self._tui_obj.remove_log_panel(self._fifo)
            self._fifo = None
        else:
            if self._new_window and self.term is not None:
                self.term.stop(force_kill=True if before_reload else False)
                self.term = None

        self.stop()

    def print(self, msg):
        if self._tui_obj:
            self._tui_obj.print_on(self._fifo, msg)
        else:
            if self._new_window and self.term is not None:
                self.term.print(msg)
            else:
                print(msg)

    def print_nl(self, msg):
        if self._tui_obj:
            self._tui_obj.print_on(self._fifo, msg, newline=True)
        else:
            if self._new_window and self.term is not None:
                self.term.print_nl(msg)
            else:
                print(msg)

    def collect_data(self, s):
        self._s += s

    def flush_collector(self):
        self.print(self._s)
        self._s = ''

    def process_feedback(self, current_dm, source, timestamp, content, status):
        info_set = set()
        processed_fbk = []
        truncated_content = None if content is None else content[:60]

        DEBUG_PRINT(
            '\n*** Feedback Entry ***\n'
            '    source: {!s}\n'
            ' timestamp: {!s}\n'
            '   content: {!r} ...\n'
            '    status: {!s}'.format(source, timestamp, truncated_content, status))

        info = self.extract_info_from_feedback(current_dm, source, timestamp, content, status)
        if info is not None:
            if isinstance(info, list):
                for i in info:
                    if isinstance(i, Info):
                        info_set.add(i)
                    else:
                        assert isinstance(i, tuple) and len(i) == 3
                        processed_fbk.append(i)
            else:
                if isinstance(info, Info):
                    info_set.add(info)
                else:
                    assert isinstance(info, tuple) and len(info) == 3
                    processed_fbk.append(info)

        return info_set, processed_fbk


class TestFbkHandler(FeedbackHandler):

    def specific_init(self, **kwargs):
        self.idx = 0
        self.color_fmkinfo = Color.to_bbcode(Color.FMKINFO)
        self.color_fbk_hl = Color.to_bbcode(Color.FEEDBACK_HLIGHT)
        self.color_error = Color.to_bbcode(Color.ERROR)
        self.color_warning = Color.to_bbcode(Color.WARNING)

    def notify_data_sending(self, current_dm, data_list, timestamp, target):
        return 'Example of additional contextual information...'

    def extract_info_from_feedback(self, current_dm, source, timestamp, content, status):
        if random.choice([True, False]):
            rd = random.choice(range(4))
            if self._markup_mode:
                self.print_nl({
                    0: f'[{self.color_fmkinfo}]Processing [b]Feedback...[/][/]',
                    1: f'[{self.color_fbk_hl}]Feedback Processed![/]',
                    2: f'[{self.color_error}][ERROR][/] [u]Feedback is erroneous[/]',
                    3: f'[{self.color_warning}][WARNING][/] [blink]Feedback delayed[/]',
                }[rd])
            else:
                self.print_nl({
                    0: colorize('Processing Feedback...', rgb=Color.FMKINFO),
                    1: colorize('Feedback Processed!', rgb=Color.FEEDBACK_HLIGHT),
                    2: colorize('[ERROR] Feedback is erroneous', rgb=Color.ERROR),
                    3: colorize('[WARNING] Feedback delayed', rgb=Color.WARNING),
                }[rd])
        else:
            pass

        if content is None:
            return None
        elif b'Linux' in content:
            # OS.Linux.increase_trust()
            return OS.Linux
        elif b'Windows' in content:
            # OS.Windows.increase_trust()
            return OS.Windows

        self.idx += 1
        # time.sleep(2)
        return (timestamp, f'[{self.idx}] Example of Feedback Processed'.encode(), status)