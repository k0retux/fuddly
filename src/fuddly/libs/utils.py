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
import sys
import subprocess
import re
import inspect
import uuid

from fuddly.framework.global_resources import config_folder
from fuddly.framework.config import config
import shlex

term = config("FmkPlumbing", path=[config_folder]).terminal


class Term(object):
    def __init__(self, title=None, keepterm=False):
        self.title = title
        self.keepterm = keepterm

    def start(self):
        self.main_fifo_ansi = os.sep + os.path.join('tmp', 'fuddly_term_' + str(uuid.uuid4()))
        if not os.path.exists(self.main_fifo_ansi):
            os.mkfifo(self.main_fifo_ansi)

        pipe_cmd = f"tail -f {self.main_fifo_ansi}"
        self.cmd = shlex.split(
                term.cmd.format(
                    title='"'+self.title+'"',
                    hold=term.hold_arg if self.keepterm else "",
                    cmd=pipe_cmd,
                )
            )
        self._p = None

    def _launch_term(self):
        self._p = subprocess.Popen(self.cmd, start_new_session=True)

    def stop(self, force_kill=False):
        if ((force_kill and self._p is not None)
                or (not self.keepterm and self._p is not None and self._p.poll() is None)):
            self._p.kill()
        self._p = None
        try:
            os.remove(self.main_fifo_ansi)
        except FileNotFoundError:
            pass

    def print(self, s, newline=False):
        self._print(s, self.main_fifo_ansi, newline=newline)

    def _print(self, s, fifo: str|None = None, newline=False):
        if not isinstance(s, str):
            s = str(s)
        s += "\n" if newline else ""
        if self._p is None or self._p.poll() is not None:
            self._launch_term()
        try:
            if fifo is None:
                fifo = self.main_fifo_ansi
            with open(fifo, "w") as input_desc:
                input_desc.write(s)
        except BrokenPipeError as err:
            print(f'\n*** [Warning] {err} intercepted, recreate the named pipe '
                  f'and relaunch the reader command ***')
            self.stop(force_kill=True)
            self.start()
            self._print(s, fifo, newline=newline)

    def print_nl(self, s):
        self.print(s, newline=True)

    def print_help(self, s, newline=True):
        self._print(s, self.main_fifo_ansi, newline=newline)

    def print_status(self, s, newline=False):
        pass

    def print_markup(self, s, newline=False):
        pass


class RichTerm(Term):

    CMD_NEW_LOG_PANEL = 1
    CMD_RM_LOG_PANEL = 2

    CMD_HELP_MODE = 5
    CMD_HELP_HIDE = 6

    def __init__(self, title=None, keepterm=False):
        super().__init__(title=title, keepterm=keepterm)
        self.loggers_fifo = []

    def start(self):
        self.cmd_fifo = os.sep + os.path.join('tmp', 'fuddly_term_' + str(uuid.uuid4()))
        if not os.path.exists(self.cmd_fifo):
            os.mkfifo(self.cmd_fifo)

        self.main_fifo_ansi = os.sep + os.path.join('tmp', 'fuddly_term_' + str(uuid.uuid4()))
        if not os.path.exists(self.main_fifo_ansi):
            os.mkfifo(self.main_fifo_ansi)

        self.main_fifo_bbcode = os.sep + os.path.join('tmp', 'fuddly_term_' + str(uuid.uuid4()))
        if not os.path.exists(self.main_fifo_bbcode):
            os.mkfifo(self.main_fifo_bbcode)

        self.status_fifo = os.sep + os.path.join('tmp', 'fuddly_term_' + str(uuid.uuid4()))
        if not os.path.exists(self.status_fifo):
            os.mkfifo(self.status_fifo)

        self.help_fifo = os.sep + os.path.join('tmp', 'fuddly_term_' + str(uuid.uuid4()))
        if not os.path.exists(self.help_fifo):
            os.mkfifo(self.help_fifo)

        pipe_cmd = (f"python -m fuddly.cli tui --cmd-fifo {self.cmd_fifo} "
                    f"--main-fifo-ansi {self.main_fifo_ansi} --main-fifo-bbcode {self.main_fifo_bbcode} "
                    f"--status-fifo {self.status_fifo} "
                    f"--help-fifo {self.help_fifo}")

        self.cmd = shlex.split(
                term.cmd.format(
                    title='"'+self.title+'"',
                    hold=term.hold_arg if self.keepterm else "",
                    cmd=pipe_cmd,
                )
            )
        self._p = None

    def stop(self, force_kill=False):
        if ((force_kill and self._p is not None)
                or (not self.keepterm and self._p is not None and self._p.poll() is None)):
            self._p.kill()
        self._p = None
        try:
            os.remove(self.cmd_fifo)
            os.remove(self.main_fifo_ansi)
            os.remove(self.main_fifo_bbcode)
            os.remove(self.status_fifo)
            os.remove(self.help_fifo)
            for fifo in self.loggers_fifo:
                os.remove(fifo)
        except FileNotFoundError:
            pass

    def print_on(self, fifo, s, newline=False):
        self._print(s, fifo, newline=newline)

    def print_status(self, s, newline=False):
        self._print(s, self.status_fifo, newline=newline)

    def print_markup(self, s, newline=False):
        self._print(s, self.main_fifo_bbcode, newline=newline)

    def print_help(self, s, newline=True):
        self._print(s, self.help_fifo, newline=newline)

    def set_help_mode(self, markup=False):
        mode = 'm' if markup else 'a'
        self._print(f'{self.CMD_HELP_MODE}\x00{mode}\x00\x00\x00', self.cmd_fifo, newline=True)

    def hide_help_panel(self):
        self._print(f'{self.CMD_HELP_HIDE}\x00\x00\x00\x00', self.cmd_fifo, newline=True)

    def new_log_panel(self, title='', markup=False):
        new_fifo = os.sep + os.path.join('tmp', 'fuddly_term_' + str(uuid.uuid4()))
        if not os.path.exists(new_fifo):
            os.mkfifo(new_fifo)
        self.loggers_fifo.append(new_fifo)
        mode = 'm' if markup else 'a'
        self._print(f'{self.CMD_NEW_LOG_PANEL}\x00{new_fifo}\x00{mode}\x00{title}\x00', self.cmd_fifo, newline=True)

        return new_fifo

    def remove_log_panel(self, fifo):
        try:
            os.remove(fifo)
        except FileNotFoundError:
            pass
        if fifo in self.loggers_fifo:
            self.loggers_fifo.remove(fifo)
        self._print(f'{self.CMD_RM_LOG_PANEL}\x00{fifo}\x00\x00\x00', self.cmd_fifo, newline=True)


class ExternalDisplay(object):
    def __init__(self, tui=False):
        self._disp = None
        self._tui = tui

    @property
    def disp(self):
        return self._disp

    @property
    def is_terminal(self):
        return isinstance(self._disp, Term)

    @property
    def is_enabled(self):
        return self.disp is not None

    def stop(self):
        if self._disp:
            self._disp.stop()
            self._disp = None

    def start_term(self, title=None, keepterm=False):
        if self._tui:
            self._disp = RichTerm(title=title, keepterm=keepterm)
        else:
            self._disp = Term(title=title, keepterm=keepterm)
        self._disp.start()
        self._disp.print("")
        # self._disp.print_status('[blue]External display has started[/]')


class Task(object):
    period = None
    fmkops = None
    feedback_gate = None
    targets = None
    dm = None
    prj = None

    def __call__(self, args):
        pass

    def setup(self):
        pass

    def cleanup(self):
        pass

    def __init__(self, period = None, init_delay= 0,
                 new_window= False, new_window_title = None,
                 name: str|None = None,
                 markup_mode= True):
        self._name = name
        self.period = period
        self.init_delay = init_delay
        self.fmkops = None
        self.feedback_gate = None
        self.targets = None
        self.dm = None
        self.prj = None
        # When a task is used in the context of a FmkTask, this attribute is initialized to a
        # threading event by the FmkTask. Then when set, it should be understood by the task that
        # the framework want it to stop.
        self.stop_event = None

        self._markup_mode = markup_mode # only supported with TUI
        self._new_window = new_window
        self._new_window_title = new_window_title

    def __str__(self):
        if self._new_window_title is None and self._name is None:
            pre_desc = f'{self.__class__.__name__}'
        else:
            name = self._new_window_title if self._name is None else self._name
            pre_desc = f'{self.__class__.__name__}[{name}]'

        if self.period is None:
            desc = f'{pre_desc} - Oneshot Task'
        else:
            desc = f'{pre_desc} - Periodic Task (period={self.period}s)'

        return desc


    def _setup(self, tui_obj=None):
        self._tui_obj = tui_obj
        if self._tui_obj:
            self._fifo = self._tui_obj.new_log_panel(title=str(self), markup=self._markup_mode)
        else:
            if self._new_window:
                nm = self.__class__.__name__ if self._new_window_title is None else self._new_window_title
                self.term = Term(title=nm, keepterm=True)
                self.term.start()

        self.setup()

    def _cleanup(self):
        if self._tui_obj:
            self._tui_obj.remove_log_panel(self._fifo)
            self._fifo = None
        else:
            if self._new_window and self.term is not None:
                self.term.stop()

        self.cleanup()

    def print(self, msg):
        if self._tui_obj:
            self._tui_obj.print_on(self._fifo, msg)
        else:
            if self._new_window:
                self.term.print(msg)
            else:
                print(msg)

    def print_nl(self, msg):
        if self._tui_obj:
            self._tui_obj.print_on(self._fifo, msg, newline=True)
        else:
            if self._new_window:
                self.term.print_nl(msg)
            else:
                print(msg)


class Accumulator:
    def __init__(self):
        self.content = ""

    def accumulate(self, msg):
        self.content += msg

    def clear(self):
        self.content = ""


def chunk_lines(string, length, prefix=""):
    l = string.split(" ")
    chk_list = []
    full_line = ""
    for wd in l:
        full_line += wd + " "
        if len(full_line) > (length - 1):
            chk_list.append(prefix + full_line)
            full_line = ""
    if full_line:
        chk_list.append(prefix + full_line)
    # remove last space char
    if chk_list:
        chk_list[-1] = (chk_list[-1])[:-1]
    return chk_list


def find_file(filename, root_path):
    for (dirpath, dirnames, filenames) in os.walk(os.path.expanduser(root_path)):
        if filename in filenames:
            return dirpath + os.sep + filename
    else:
        return None


def retrieve_app_handler(filename):
    mimetype = subprocess.check_output(["xdg-mime", "query", "filetype", filename])[:-1]
    desktop_file = subprocess.check_output(["xdg-mime", "query", "default", mimetype])[:-1]

    file_path = find_file(desktop_file.decode(), root_path="~/.local/share/applications/")
    if file_path is None:
        file_path = find_file(desktop_file.decode(), root_path="/usr/share/applications/")

    if file_path is None:
        return None

    with open(file_path, "r") as f:
        buff = f.read()
        result = re.search("Exec=(.*)", buff)
        app_name = result.group(1).split()[0]
    return app_name


def get_caller_object(stack_frame=2):
    caller_frame_record = inspect.stack()[stack_frame]
    return caller_frame_record.frame.f_locals["self"]
