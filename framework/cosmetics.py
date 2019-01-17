##############################################################################
#
#  Copyright 2017 Matthieu Daumas <matthieu@daumas.me>
#
##############################################################################
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
##############################################################################
"""Handle fuddly shell's cosmetics, like curses-related functionnalities."""

import contextlib
import io
import os
import re
import sys

#: bool: internals, check for an ImportError for curses & termios
import_error = False
try:
    import curses
except ImportError as e:
    sys.stderr.write('WARNING [FMK]: python(3)-curses unavailable, ' +
                     'raw fuddly shell only.')
    sys.stderr.write(str(e))
    import_error = True

try:
    import termios
except ImportError as e:
    sys.stderr.write('WARNING [FMK]: POSIX termios unavailable, ' +
                     'restricted terminal capabilities.')
    sys.stderr.write(str(e))
    import_error = True


def setup_term():
    # type: () -> None
    """Handle curses vs readline issues

    See `issue 2675`__ for further informations, enables resizing
    the terminal.

    __ https://bugs.python.org/issue2675"""

    if import_error:
        return

    # unset env's LINES and COLUMNS to trigger a size update
    os.unsetenv('LINES')
    os.unsetenv('COLUMNS')

    # curses's setupterm with the real output (sys.__stdout__)
    try:
        curses.setupterm(fd=sys.__stdout__.fileno())
    except curses.error as e:
        print('\n*** WARNING: {!s}'.format(e))
        print('    --> set $TERM variable manually to xterm-256color')
        os.environ['TERM'] = 'xterm-256color'
        curses.setupterm(fd=sys.__stdout__.fileno())


#: file: A reference to the "unwrapped" stdout.
stdout_unwrapped = sys.stdout

#: file or io.BytesIO or io.TextIOWrapper: the buffer that will replace stdout
stdout_wrapped = None
if import_error:
    stdout_wrapped = sys.__stdout__


class wrapper:
    """Wrapper class, handle cosmetics internals while wrapping stdout."""

    def __init__(self, parent_wrapper):
        self.countp = 0
        self.initial = True
        self.page_head = re.compile(r'\n')
        self.batch_mode = False
        self.prompt_height = 0

        self.parent_write = parent_wrapper.write

    def write(self, payload, *kargs, **kwargs):
        if self.page_head.match(payload):
            try_flush(batch=self.batch_mode)

        return self.parent_write(self, payload, *kargs, **kwargs)

    def reinit(self):
        """Reset the wrapper to its initial state while keeping configuration.

            (only resets the page counter)"""

        self.countp = 0


if sys.version_info[0] > 2:

    class stdout_wrapper(wrapper, io.TextIOWrapper):
        """Wrap stdout and handle cosmetic issues."""

        def __init__(self):
            io.TextIOWrapper.__init__(self,
                                      io.BytesIO(), sys.__stdout__.encoding)
            wrapper.__init__(self, io.TextIOWrapper)

        def reinit(self):
            wrapper.reinit(self)
            io.TextIOWrapper.__init__(self, io.BytesIO())

    stdout_wrapped = stdout_wrapper()
else:

    class stdout_wrapper(wrapper, io.BytesIO):
        """Wrap stdout and handle cosmetic issues."""

        def __init__(self):
            io.BytesIO.__init__(self)
            wrapper.__init__(self, io.BytesIO)

        def reinit(self):
            wrapper.reinit(self)
            io.BytesIO.__init__(self)

    stdout_wrapped = stdout_wrapper()

if not import_error:

    # (call curses's setupterm at least one time)
    setup_term()

    el = curses.tigetstr("el")
    ed = curses.tigetstr("ed")
    cup = curses.tparm(curses.tigetstr("cup"), 0, 0)
    civis = curses.tigetstr("civis")
    cvvis = curses.tigetstr("cvvis")
else:
    if sys.version_info[0] > 2:
        el, ed, cup, civis, cvvis = ('', ) * 5
    else:
        el, ed, cup, civis, cvvis = (b'', ) * 5


def get_size(
        cutby=(0, 0),  # type: Tuple[int, int]
        refresh=True  # type: bool
):
    # type: (...) -> Tuple[int, int]
    """Returns the terminal size as a (width, height) tuple

    Args:
        refresh (bool): Try to refresh the terminal's size,
            required if you use readline.
        cutby (Tuple[int, int]):
            Cut the terminal size by an offset, the first integer
            of the tuple correspond to the width, the second to the
            height of the terminal.

    Returns:
        The (width, height) tuple corresponding to the terminal's
        size (reduced slightly by the :literal:`cutby` argument).
        The minimal value for the width or the height is 1.
        If curses is not available, returns (79, 63)."""

    if import_error:
        return (79, 63)

    # handle readline/curses interactions
    if refresh:
        setup_term()

    # retrieve the terminal's size:
    #  - if refresh, initiate a curses window for an updated size,
    #  - else, retrieve it via a numeric capability.
    #
    if refresh:
        height, width = curses.initscr().getmaxyx()
        curses.endwin()
    else:
        height = curses.tigetnum("lines")
        width = curses.tigetnum("cols")

    # now *cut* the terminal by the specified offset
    width -= cutby[0]
    height -= cutby[1]

    # handle negative values
    if width < 2:
        width = 1
    if height < 2:
        height = 1

    # return the tuple
    return (width, height)


def buffer_content():
    # type: () -> bytes
    """Returns stdout_wrapped's content

    Returns:
        The whole content of stdout_wrapped."""

    if sys.version_info[0] > 2:
        stdout_wrapped.seek(0)
        payload = stdout_wrapped.buffer.read()
    else:
        payload = stdout_wrapped.getvalue()
    return payload


def estimate_nblines(width  # type: int
                     ):
    # type: (...) -> int
    """Estimate the number of lines in the buffer

    Args:
        width (int): width of the terminal, used to calculate lines
            wrapping in the wrapped stdout.

    Returns:
        The estimated number of lines that the payload will take on
        screen."""

    nblines = 0
    payload = buffer_content()

    lines = payload.splitlines()
    for line in lines:
        length = len(line)
        nblines += length // width + 1
    return nblines + 1


def disp(
        payload,  # type: bytes
):
    # type: (...) -> None
    """Display on stdout the bytes passed.

    Args:
        payload (bytes): the bytes displayed on screen."""

    if sys.version_info[0] > 2:
        stdout_unwrapped.buffer.write(payload)
    else:
        stdout_unwrapped.write(payload)


def tty_noecho():
    # type: () -> None
    """Disable echo mode in the tty."""

    # (we use POSIX tty, as we do not use curses for everything)
    fd = sys.__stdout__.fileno()
    try:
        flags = termios.tcgetattr(fd)
        flags[3] = flags[3] & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, flags)
    except BaseException:
        pass

    # (we hide the cursor for a nicer display)
    disp(civis)


def tty_echo():
    # type: () -> None
    """Re-enable echo mode for the tty."""

    # (we use POSIX tty, as we do not use curses for everything)
    fd = sys.__stdout__.fileno()
    try:
        flags = termios.tcgetattr(fd)
        flags[3] = flags[3] | termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, flags)
    except BaseException:
        pass

    # (we unhide the cursor and clean the line for nicer display)
    disp(cvvis + ed)


def restore_stdout():
    # type: () -> None
    """Restore sys.stdout and the terminal."""

    sys.stdout = stdout_unwrapped
    try_flush(force=True)
    tty_echo()


def try_flush(
        batch=False,  # type: bool
        force=False  # type: bool
):
    # type: (...) -> None
    """Display buffered lines on screen taking into account various factors.

    Args:
        batch (bool): try to put as much as possilbe text on screen.
        force (bool): force the buffer to output its content."""

    # retrieve the terminal size
    width, height = get_size(cutby=(0, stdout_wrapped.prompt_height))

    # flush the buffer, then estimate the number of lines
    stdout_wrapped.flush()
    nblines = estimate_nblines(width)

    # batch mode needs to estimate payloads size (skipped if force)
    if (not force) or batch:
        if stdout_wrapped.countp > 0:
            avg_size_per_payload = nblines // stdout_wrapped.countp
        else:
            avg_size_per_payload = nblines
        stdout_wrapped.countp += 1

    # (if force, or non-batch, or sufficient output, display it)
    if (force or (not batch) or nblines + avg_size_per_payload > height):

        # protect history by padding with line feeds
        if stdout_wrapped.initial:
            stdout_wrapped.initial = False
            disp(b'\n' * (height + nblines + 1))

        # use `el` term capabilitie to wipe endlines as we display
        payload = buffer_content()
        payload = payload.replace(b'\n', el + b'\n')

        # if not force (continuous display), we erase the first
        # payload (to have a log entry without disturbing scrolling
        # nor getting a blinking terminal), then we display the
        # payload a second time (in order to see it on screen), else
        # (force == True), then we have the last payload to display,
        # no need to duplicate it with unnecessary buffering.
        #
        if not force:
            pad = b'\n' * (height - nblines + stdout_wrapped.prompt_height)
            padded_payload = cup + payload * 2 + pad
        else:
            padded_payload = cup + payload

        disp(padded_payload)

        # empty the buffer, reset the payload counter
        stdout_wrapped.reinit()

    # if it is the last payload, reenable echo-ing.
    if force:
        tty_echo()


@contextlib.contextmanager
def aligned_stdout(
        enabled,  # type: bool
        page_head,  # type: str
        batch_mode,  # type: bool
        hide_cursor,  # type: bool
        prompt_height  # type: int
):
    # type: (...) -> None
    """do_send_loop cosmetics, contextualize stdout's wrapper."""

    if enabled:
        if hide_cursor:
            tty_noecho()

        sys.stdout = stdout_wrapped
        stdout_wrapped.prompt_height = prompt_height
        stdout_wrapped.batch_mode = batch_mode
        stdout_wrapped.page_head = re.compile(page_head)
        stdout_wrapped.initial = True

        yield
        restore_stdout()
    else:
        yield
