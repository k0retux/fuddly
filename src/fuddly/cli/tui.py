from argcomplete.scripts import python_argcomplete_check_easy_install_script
from textual import events
from textual.css.query import NoMatches
from typing import Iterable

from xdg.Locale import update

from fuddly.framework.logger import Logger
from fuddly.framework.plumbing import FmkPlumbing
import fuddly.cli.argparse_wrapper as argparse
from fuddly.framework.global_resources import fuddly_version
from fuddly.libs.utils import RichTerm

import time
import asyncio
import select
import os
import re
from pathlib import Path

from rich.console import Console
from rich.traceback import install
install()
from textual.widgets import RichLog, TabbedContent, TabPane, DirectoryTree
from textual.app import App
from textual.containers import Horizontal, Vertical, VerticalScroll, HorizontalGroup
from textual.widgets import Input, Static, Button
from textual.geometry import Size
from rich.text import Text

from fuddly.framework.global_resources import *
from fuddly.framework.data import *

FUDDLY_TUI_FNAME = 'fuddly_tui.tcss'

fuddly_tui_tcss = """
#status {
    height: 3;
    content-align: right middle;
    tint: blue 20%;
}

#global_area {
    box-sizing: border-box;
    height: 1fr;
    width: 100%;
}

#main_area {
    box-sizing: border-box;
    height: 1fr;
    width: 100%;
}

#middle_panel {
    height: auto;
    content-align: left middle;
}

#button_panel {
    content-align: left middle;
}

.small_button {
    min-width: 2;
    background: blue 50%;
    color: azure;
    border-right: solid;
    border-left: solid;
}

#b_enable_autoscroll_rpanel {
    display: none;
}

.as_disabled #b_disable_autoscroll_rpanel {
    display: none;
}

.as_disabled #b_enable_autoscroll_rpanel {
    display: block;
}

#help_zone {
    scrollbar-size: 1 1;
    box-sizing: border-box;
    width: 100%;
    border: solid green;
}

.help_hidden_mode {
    display: none;
}

.help_visible_mode {
    display: block;
}

#main_display {
    scrollbar-size: 1 1;
    box-sizing: border-box;
    text-wrap: wrap;
    text-overflow: fold;
    width: 100%;
    border: solid #008B8B;
}

.main_display_hidden_mode {
    height: 0%;
}

.main_display_visible_mode {
    height: 3fr;
}

#b_enable_autoscroll_main_disp {
    display: none;
}

.as_disabled_main #b_disable_autoscroll_main_disp {
    display: none;
}

.as_disabled_main #b_enable_autoscroll_main_disp {
    display: block;
}


#raw_display {
    scrollbar-size: 1 1;
    box-sizing: border-box;
    text-wrap: wrap;
    text-overflow: fold;
    width: 100%;
    border: solid #88C0D0;
}

.raw_display_hidden_mode {
    height: 0%;
}

.raw_display_visible_mode {
    height: 3fr;
}

.box {
    scrollbar-size: 1 1;
    height: 50%;
    border: solid green;
}

.hl_box {
    scrollbar-size: 1 1;
    height: 50%;
    border: heavy red;
}

#db_status {
    height: 3;
    border: solid blue 70%;
    content-align: right middle;
    tint: blue 20%;
}

#current_fmkdb {
    width: 1fr;
}

#db_dir_tree {
    scrollbar-size: 1 1;
    border: solid blue 70%;
    height: 1fr;
    width: 1fr;
}

#db_display {
    scrollbar-size: 1 1;
    border: solid blue 70%;
    height: 1fr;
    width: 4fr;
}
"""

new_tcss_selectors = [
    '#b_enable_autoscroll_main_disp'
]
tcss_fname = os.path.join(config_folder, FUDDLY_TUI_FNAME)
write_tcss = False
if not os.path.isfile(tcss_fname):
    write_tcss = True
else:
    with open(tcss_fname, 'r') as f:
        read_tcss = f.read()
        for sel in new_tcss_selectors:
            if sel not in read_tcss:
                write_tcss = True
                break
if write_tcss:
    with open(tcss_fname, 'w') as f:
        f.write(fuddly_tui_tcss)

class AltLogger(RichLog):

    def on_focus(self, event: events.Focus) -> None:
        # self.styles.border = ('solid', 'green')
        self.remove_class('hl_box')
        self.add_class('box', update=True)

    def watch_scroll_y(self, old_value, new_value) -> None:
        super().watch_scroll_y(old_value, new_value)

        if self.auto_scroll and new_value > 0 and new_value - old_value < 0:
            self.auto_scroll = False

        elif not self.auto_scroll and self.is_vertical_scroll_end and self.max_scroll_y > 0:
            self.auto_scroll = True


class RawDisplay(RichLog):

    def watch_scroll_y(self, old_value, new_value) -> None:
        super().watch_scroll_y(old_value, new_value)

        if self.auto_scroll and new_value > 0 and new_value - old_value < 0:
            self.auto_scroll = False
            # self.app.notify(f"Auto scroll disabled ({old_value} --> {new_value})")

        elif not self.auto_scroll and self.is_vertical_scroll_end and self.max_scroll_y > 0:
            # Note: self.max_scroll_y == 0 if not enough text to allow scrolling
            self.auto_scroll = True
            # self.app.notify(f"Auto scroll enabled ({old_value} --> {new_value})")


class MainDisplay(RichLog):

    def watch_scroll_y(self, old_value, new_value) -> None:
        super().watch_scroll_y(old_value, new_value)

        # Note: for the main display this scrolling event is generated
        #       not for the reason we want to stop scrolling
        # if (self.app._main_display_auto_scroll
        #         and new_value > 0 and new_value - old_value < 0):
        #     self.app._main_display_auto_scroll = False

        if (not self.app._main_display_auto_scroll
                and self.is_vertical_scroll_end and self.max_scroll_y > 0):
            self.app._main_display_auto_scroll = True


class ButtonPanel(HorizontalGroup):

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'b_enable_autoscroll_raw_disp':
            rlog = self.app.query_one('#raw_display')
            rlog.auto_scroll = True
            self.app.notify(f'auto-scroll [green]enabled[/] on [b]raw display[/]')
        elif event.button.id == 'b_disable_autoscroll_rpanel':
            self.add_class('as_disabled')
            self.app._rpanel_stop_scrolling = True
            self.app.notify(f'auto-scroll [red]disabled[/] on [b]right panel[/]')
        elif event.button.id == 'b_enable_autoscroll_rpanel':
            self.remove_class('as_disabled')
            self.app._rpanel_stop_scrolling = False
            self.app.notify(f'auto-scroll [green]enabled[/] on [b]right panel[/]')
        elif event.button.id == 'b_disable_autoscroll_main_disp':
            self.add_class('as_disabled_main')
            self.app._main_display_auto_scroll = False
            self.app.notify(f'auto-scroll [red]disabled[/] on [b]main display[/]')
        elif event.button.id == 'b_enable_autoscroll_main_disp':
            self.remove_class('as_disabled_main')
            self.app._main_display_auto_scroll = True
            self.app.notify(f'auto-scroll [green]enabled[/] on [b]main display[/]')
        elif event.button.id == 'b_hide_raw_display':
            if not self.app._raw_display_hidden:
                rlog = self.app.query_one('#raw_display')
                rlog.remove_class('raw_display_visible_mode')
                rlog.add_class('raw_display_hidden_mode', update=True)
                self.app._raw_display_hidden = True
        elif event.button.id == 'b_hide_main_display':
            if not self.app._main_display_hidden:
                rlog = self.app.query_one('#main_display')
                rlog.remove_class('main_display_visible_mode')
                rlog.add_class('main_display_hidden_mode', update=True)
                self.app._main_display_hidden = True


    def compose(self):
        yield Button('hide main', id='b_hide_main_display', classes='small_button',
                     compact=True,
                     tooltip=Text('Hide the main display'))
        yield Button('hide raw', id='b_hide_raw_display', classes='small_button',
                     compact=True,
                     tooltip=Text('Hide the raw display'))
        yield Button('!as main', id='b_disable_autoscroll_main_disp', classes='small_button',
                     compact=True,
                     tooltip=Text('Enable auto-scroll of the main display'))
        yield Button('as main', id='b_enable_autoscroll_main_disp', classes='small_button',
                     compact=True,
                     tooltip=Text('Enable auto-scroll of the main display'))
        yield Button('as raw', id='b_enable_autoscroll_raw_disp', classes='small_button',
                     compact=True,
                     tooltip=Text('Enable auto-scroll of the raw display'))
        yield Button('!as rpanel', id='b_disable_autoscroll_rpanel', classes='small_button',
                     compact=True,
                     tooltip=Text('Disable the right panel auto-scroll'))
        yield Button('as rpanel', id='b_enable_autoscroll_rpanel', classes='small_button',
                     compact=True,
                     tooltip=Text('Enable the right panel auto-scroll'))


class FmkDBDirectoryTree(DirectoryTree):

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        l = []
        for p in paths:
            if p.name.startswith('.'):
                continue
            elif p.is_dir():
                l.append(p)
            elif p.is_file() and p.name.endswith('.db'):
                l.append(p)
            else:
                pass

        return l


class FuddlyTUI(App):
    ANSICODE = 1
    BBCODE = 2

    CSS_PATH = os.path.join(config_folder, "fuddly_tui.tcss")
    # DEFAULT_CSS = """
    # """

    BINDINGS = [
        ("a", "enable_autoscroll_rpanel", "auto-scroll [green]enabled[/] on [b]right panel[/]"),
        ("alt+a", "disable_autoscroll_rpanel", "auto-scroll [red]disabled[/] on [b]right panel[/]"),
        ("e", "scroll_end_mpanel", "Scroll to the end (main panel)"),
    ]

    def action_enable_autoscroll_rpanel(self) -> None:
        bt: Button = self.query_one('#b_enable_autoscroll_rpanel')
        bt.action_press()

    def action_disable_autoscroll_rpanel(self) -> None:
        bt: Button = self.query_one('#b_disable_autoscroll_rpanel')
        bt.action_press()

    def action_end_mpanel(self) -> None:
        self._raw_display.scroll_end(animate=False)

    def __init__(self, cmd_fifo, main_fifo_ansi, main_fifo_bbcode, basic_fifo,
                 status_fifo, help_fifo):
        super().__init__()
        self._cmd_fifo = cmd_fifo
        self._main_fifo_ansi = main_fifo_ansi
        self._main_fifo_bbcode = main_fifo_bbcode
        self._basic_fifo = basic_fifo
        self._status_fifo = status_fifo
        self._help_fifo = help_fifo
        self._cmd_re = re.compile(r'(\d)\x00(.*?)\x00(.*?)\x00(.*?)\x00', flags=re.S)
        preamble_pattern = r'(.*' + Logger.PREAMBLE_PREFIX.replace('[', r'\[') + r')(.*)'
        epilogue_pattern = r'(.*' + Logger.EPILOGUE_PREFIX.replace('[', r'\[') + r')(.*)'
        self._sending_preample_re = re.compile(preamble_pattern, flags=re.S)
        self._sending_epilogue_re = re.compile(epilogue_pattern, flags=re.S)
        self._loggers_fd = {}
        self._loggers_fifo = {}
        self._status_msg = Text('')
        self._help_markup_mode = False
        self._main_display_markup_mode = False

        self._global_area = None
        self._raw_display = None
        self._right_panel = None
        self._help_zone = None
        self._help_zone_hidden = True
        # self._help_zone_hidden = True
        self._main_display = None
        self._main_display_auto_scroll = True
        self._raw_display_hidden = True
        self._main_display_hidden = False
        self._previous_text_empty_lines = False
        self._previous_text_nb_added_empty_lines = 0
        self._previous_nb_lines_displayed = 0

        self._wait_for_epilogue = False

        self._rpanel_stop_scrolling = False

        self.fmkdb = None

        self._standalone_app = not self._cmd_fifo

    def on_ready(self) -> None:
        if not self._standalone_app:
            self.run_worker(self.update_text(), thread=False)


    def _launch_fmkdb_analysis(self, fmkdb_path=None):
        db_disp: RichLog = self.query_one("#db_display")
        db_status: Static = self.query_one("#db_status")

        self.fmkdb = Database(fmkdb_path=fmkdb_path)
        ok = self.fmkdb.start()
        if not ok:
            err_msg = f"[red]ERROR: invalid database![/] \\[{fmkdb_path}]"
            text = Text.from_markup(err_msg)

            return

        else:
            if fmkdb_path is None:
                text = Text.from_markup(f"[green]Current FmkDB selected[/]")
            else:
                text = Text.from_markup(f"[green]FmkDB selected[/]: {fmkdb_path}")

        db_status.update(text)

        raw_impact_analysis = False
        fbk_src = None
        fbk_status_formula = '? < 0'
        min_rec_sz = 3
        verbose = True
        prj_name = None

        ret = self.fmkdb.get_db_analysis(
            prj_name=prj_name, fbk_src=fbk_src, fbk_status_formula=fbk_status_formula,
            verbose=verbose,
            op_record_min_size = min_rec_sz,
            raw_analysis=raw_impact_analysis,
            colorized=True)

        self.fmkdb.stop()
        self.fmkdb = None

        if ret is None:
            db_status.update(f"[red]ERROR: incompatible database for analysis![/] \\[{fmkdb_path}]")
        else:
            db_disp.clear()
            _, _, sc_rec_str, op_rec_str = ret
            db_disp.write(Text.from_ansi(sc_rec_str+'\n'))
            db_disp.write(Text.from_ansi(op_rec_str+'\n'))


    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'current_fmkdb':
            self._launch_fmkdb_analysis()

    def on_directory_tree_file_selected(self, event):
        path: Path = event.path
        if not path.is_file():
            return

        self._launch_fmkdb_analysis(path)


    def compose(self):
        with TabbedContent():
            if not self._standalone_app:
                with TabPane('dashboard', id='f_dashboard'):
                    yield Vertical(
                        Static(Text.from_markup(f'[white]Wait for status...[/]'), id="status", classes='box',
                                     expand=True),
                        Horizontal(
                            Vertical(
                                MainDisplay(id='main_display', classes='main_display_visible_mode',
                                        max_lines=20000,
                                        wrap=True, auto_scroll=False),
                                Horizontal(
                                    ButtonPanel(id="button_panel"),
                                    id="middle_panel"
                                ),
                                RawDisplay(id='raw_display', classes='raw_display_hidden_mode',
                                           max_lines=50000,
                                           wrap=True, auto_scroll=True),
                                id="main_area"
                            ),
                            id='global_area'
                        )
                    )
            with TabPane('analyzer', id='f_analyzer'):
                yield Vertical(
                    Static(Text.from_markup(f'FmkDB Analyzer'), id="db_status", classes='box',
                           expand=True),
                    Horizontal(
                        Vertical(
                            Button('Current FmkDB', id='current_fmkdb'),
                            FmkDBDirectoryTree(Path(os.path.expanduser('~')),
                                               id='db_dir_tree'),
                        ),
                        RichLog(id='db_display'),
                    )
                )

    async def _process_command(self, cmd_msg, epobj):
        parsed = self._cmd_re.match(cmd_msg)
        self._status_msg = ''
        if parsed:
            cmd = int(parsed.group(1))
            if cmd == RichTerm.CMD_NEW_LOG_PANEL:
                # add log panel
                fifo = parsed.group(2)
                if not fifo:
                    return
                mode = parsed.group(3)
                title = parsed.group(4)

                markup_mode = True if mode == 'm' else False

                try:
                    new_fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                except FileNotFoundError:
                    self._status_msg = Text.from_markup(
                        f'[b red]New communicated fifo is not found \\[[/][i]{fifo}[/][b red]][/]')
                else:
                    rlog_id = fifo.split('/')[-1]
                    title = title.replace('[', r'\[')
                    self._loggers_fd[new_fd] = ('#' + rlog_id, title, markup_mode)
                    self._loggers_fifo[rlog_id] = new_fd
                    epobj.register(new_fd, select.EPOLLIN | select.EPOLLHUP)

                    self._status_msg = Text.from_ansi(f'New fifo registered: {fifo}')

            elif cmd == RichTerm.CMD_RM_LOG_PANEL:
                # remove log panel
                fifo = parsed.group(2)

                rlog_id = fifo.split('/')[-1]
                fd = self._loggers_fifo.get(rlog_id)
                if fd:
                    epobj.unregister(fd)
                    try:
                        await self.query_one('#' + rlog_id).remove()
                    except NoMatches:
                        pass
                    else:
                        del self._loggers_fifo[rlog_id]
                        del self._loggers_fd[fd]
                        if self._right_panel and not self._loggers_fd:
                            await self._right_panel.remove()
                            self._main_area.styles.width = '100%'
                            self._right_panel = None

            elif cmd == RichTerm.CMD_HELP_MODE:
                mode = parsed.group(2)

                if mode == 'm': # markup mode
                    self._help_markup_mode = True
                else:
                    self._help_markup_mode = False

            elif cmd == RichTerm.CMD_HELP_HIDE:
                if self._help_zone:
                    # self._help_zone.remove()
                    # self._help_zone = None
                    self._help_zone.remove_class('help_visible_mode')
                    self._help_zone.add_class('help_hidden_mode', update=True)
                    self._help_zone_hidden = True

            elif cmd == RichTerm.CMD_MAIN_DISPLAY_MODE:
                mode = parsed.group(2)

                if mode == 'm': # markup mode
                    self._main_display_markup_mode = True
                else:
                    self._main_display_markup_mode = False

            elif cmd == RichTerm.CMD_RAW_DISPLAY_HIDE:
                if self._raw_display:
                    self._raw_display.clear()
                    self._raw_display.remove_class('raw_display_visible_mode')
                    self._raw_display.add_class('raw_display_hidden_mode', update=True)
                    self._raw_display_hidden = True

            else:
                self._status_msg = Text.from_ansi(f'Unknown Command: {cmd}')
        else:
            self._status_msg = Text.from_ansi(f'Command Parsing Error: {cmd_msg}')

    def _remove_empty_lines_from_main_display(self):

        if self._previous_text_empty_lines:
            rlog = self._main_display
            self._previous_text_empty_lines = False
            rlog.lines = rlog.lines[:-self._previous_text_nb_added_empty_lines]
            rlog.virtual_size = Size(rlog.virtual_size.width, len(rlog.lines))
            rlog.clear_cached_dimensions()

            return True

        else:
            return False

    async def update_text(self) -> None:
        self._status_wdg: Static = self.query_one("#status")
        self._status_msg.stylize('bold')
        self._global_area = self.query_one("#global_area")
        self._main_area = self.query_one("#main_area")
        self._main_display: RichLog = self.query_one("#main_display")
        self._raw_display: RichLog = self.query_one("#raw_display")
        self._button_panel = self.query_one("#button_panel")

        epobj = None
        self._button_panel.styles.align = ("right", "middle")
        self._raw_display.border_title = 'raw display'
        self._raw_display_hidden = True

        try:
            epobj = select.epoll()
            if self._cmd_fifo:
                fd_cmd = os.open(self._cmd_fifo, os.O_RDONLY | os.O_NONBLOCK)
                epobj.register(fd_cmd, select.EPOLLIN | select.EPOLLHUP)
            else:
                fd_cmd = None
            if self._main_fifo_ansi:
                fd_ansi = os.open(self._main_fifo_ansi, os.O_RDONLY | os.O_NONBLOCK)
                epobj.register(fd_ansi, select.EPOLLIN | select.EPOLLHUP)
            else:
                fd_ansi = None
            if self._main_fifo_bbcode:
                fd_bbcode = os.open(self._main_fifo_bbcode, os.O_RDONLY | os.O_NONBLOCK)
                epobj.register(fd_bbcode, select.EPOLLIN | select.EPOLLHUP)
            else:
                fd_bbcode = None
            if self._basic_fifo:
                fd_main = os.open(self._basic_fifo, os.O_RDONLY | os.O_NONBLOCK)
                epobj.register(fd_main, select.EPOLLIN | select.EPOLLHUP)
            else:
                fd_main = None
            if self._status_fifo:
                fd_status = os.open(self._status_fifo, os.O_RDONLY | os.O_NONBLOCK)
                epobj.register(fd_status, select.EPOLLIN | select.EPOLLHUP)
            else:
                fd_status = None
            if self._help_fifo:
                fd_help = os.open(self._help_fifo, os.O_RDONLY | os.O_NONBLOCK)
                epobj.register(fd_help, select.EPOLLIN | select.EPOLLHUP)
            else:
                fd_help = None

            if (fd_ansi is None and fd_bbcode is None and fd_main is None and fd_status is None
                    and fd_cmd is None and fd_help is None):
                return

            while True:
                await asyncio.sleep(0)

                evts = epobj.poll(timeout=1)
                for fd, evt in evts:
                    await asyncio.sleep(0)

                    if evt & select.EPOLLIN:
                        if fd == fd_cmd:
                            cmd_msgs = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 128).decode('latin_1')
                                except BlockingIOError:
                                    data = ''
                                else:
                                    cmd_msgs += data
                            cmd_msg_list = cmd_msgs.split('\n')
                            for cmd_msg in cmd_msg_list:
                                if cmd_msg:
                                    await self._process_command(cmd_msg, epobj)
                                    self._status_wdg.update(self._status_msg)

                        elif fd in self._loggers_fd:
                            text = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 512).decode('latin_1')
                                except BlockingIOError:
                                    # await asyncio.sleep(0.05)
                                    data = ''
                                else:
                                    text += data

                            w_id, title, markup_mode = self._loggers_fd[fd]
                            self._status_wdg.update(Text.from_markup(f'[green]Receive data from:[/] [b i]{title}[/]'))
                            if markup_mode:
                                text = Text.from_markup(text)
                            else:
                                text = Text.from_ansi(text)

                            if text:
                                if not self._right_panel:
                                    self._right_panel = VerticalScroll(id="loggers")
                                    await self._global_area.mount(self._right_panel)
                                    self._main_area.styles.width = '60%'

                                try:
                                    rlog = self.query_one(w_id)
                                except NoMatches:
                                    rlog = AltLogger(highlight=True, max_lines=10000,
                                                     id=w_id[1:], classes='box')
                                    rlog.border_title = title
                                    await self._right_panel.mount(rlog)

                                rlog.remove_class('box')
                                rlog.add_class('hl_box', update=True)
                                if not self._rpanel_stop_scrolling:
                                    rlog.scroll_visible()
                                rlog.write(text)

                        elif fd == fd_status:
                            text = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 128).decode()
                                except BlockingIOError:
                                    data = ''
                                else:
                                    text += data
                            text = Text.from_markup(text)
                            if text:
                                text.stylize('bold')
                                self._status_wdg.update(text)
                                # self.app.notify(text)

                        elif fd == fd_help:
                            text = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 256).decode()
                                except BlockingIOError:
                                    data = ''
                                else:
                                    text += data

                            if not self._help_zone:
                                self._help_zone = RichLog(id='help_zone', classes='help_visible_mode',
                                                          auto_scroll=False, max_lines=1000)
                                self._help_zone.border_title = 'help'
                                await self._main_area.mount(self._help_zone, after=self._raw_display)
                                self._help_zone_hidden = False

                            if self._help_markup_mode:
                                text = Text.from_markup(text)
                            else:
                                text = Text.from_ansi(text)

                            if text:
                                if self._help_zone_hidden:
                                    self._help_zone.remove_class('help_hidden_mode')
                                    self._help_zone.add_class('help_visible_mode', update=True)
                                    self._help_zone_hidden = False

                                self._help_zone.clear()
                                self._help_zone.write(text)

                        elif fd == fd_main:
                            rtext = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 512).decode('latin_1')
                                except BlockingIOError:
                                    data = ''
                                else:
                                    rtext += data

                            if self._main_display_hidden:
                                self._main_display.remove_class('main_display_hidden_mode', update=True)
                                self._main_display.add_class('main_display_visible_mode', update=True)
                                self._main_display_hidden = False

                            if not self._help_zone_hidden:
                                self._help_zone.remove_class('help_visible_mode')
                                self._help_zone.add_class('help_hidden_mode', update=True)
                                self._help_zone_hidden = True

                            # lf = rtext.find('\n')
                            # if lf != -1 and lf < 20:
                            #     for c in rtext[:lf]:
                            #         if ord(c) > 0x20:
                            #             break
                            #     else:
                            #         self.app.notify('lf replaced')
                            #         rtext = rtext.replace('\n', '')

                            # self.app.notify(f'text: {repr(text[:10])}')
                            obj = self._sending_epilogue_re.match(rtext)
                            if obj:
                                epilogue_detected = True
                            else:
                                epilogue_detected = False

                            obj = self._sending_preample_re.match(rtext)
                            if obj:
                                nb_lines_till_preamble = obj.group(1).count('\n') # including preamble
                                total_nb_lines = obj.group(0).count('\n')
                                nb_lines_after_preamble = total_nb_lines - nb_lines_till_preamble
                                if nb_lines_till_preamble > 0:
                                    nb_lines_before_preamble = nb_lines_till_preamble - 1
                                else:
                                    # BUG?
                                    raise NotImplementedError
                                if nb_lines_after_preamble == 0:
                                    text_is_only_preamble = True
                                    text_is_preamble_and_more = False
                                else:
                                    text_is_only_preamble = False
                                    text_is_preamble_and_more = True
                            else:
                                nb_lines_before_preamble = 0
                                nb_lines_after_preamble = 0
                                text_is_only_preamble = False
                                text_is_preamble_and_more = False

                            preamble_detected = text_is_preamble_and_more or text_is_only_preamble

                            if self._main_display_markup_mode:
                                text = Text.from_markup(rtext, overflow='fold')
                            else:
                                text = Text.from_ansi(rtext, no_wrap=False, overflow='fold')

                            if text:
                                # self._raw_display.write(Text(repr(rtext[:20])+' ... '+repr(rtext[-20:])))
                                self._main_display.auto_scroll = False
                                available_nb_lines = self._main_display.scrollable_content_region.height
                                virtual_size = self._main_display.virtual_size.height


                                lines_removed = self._remove_empty_lines_from_main_display()
                                self._main_display.refresh(layout=True)
                                await self._main_display.wait_for_refresh()

                                initial_nb_lines = len(self._main_display.lines)
                                self._main_display.write(text)
                                new_nb_lines = len(self._main_display.lines)

                                added_nb_lines = new_nb_lines - initial_nb_lines

                                if preamble_detected:
                                    if not epilogue_detected:
                                        self._wait_for_epilogue = True
                                    nb_lines_to_display = added_nb_lines - nb_lines_before_preamble
                                    # final_nb_lines_to_display = self._previous_nb_lines_displayed + nb_lines_to_display

                                    if available_nb_lines < nb_lines_to_display:
                                        move_up = initial_nb_lines + nb_lines_before_preamble + 1
                                        if self._main_display_auto_scroll:
                                            self._main_display.scroll_to(y=move_up, animate=False)
                                        # self.app.notify(f'1.1 preamble detected - case (1)\n'
                                        #                 f'y:{self._main_display.scroll_y}\n'
                                        #                 f'max_y:{self._main_display.max_scroll_y}\n'
                                        #                 f'init_nb_l:{initial_nb_lines}\n'
                                        #                 f'new_nb_l:{new_nb_lines}\n'
                                        #                 f'avail_nb_l:{available_nb_lines}\n',
                                        #                 timeout=30)

                                    else:
                                        # self.app.notify(f'1.2 preamble detected - case (2)')
                                        nb_empty_lines = available_nb_lines - nb_lines_to_display
                                        empty_lines = '\n' * nb_empty_lines
                                        self._main_display.write(Text(empty_lines))
                                        self._previous_text_empty_lines = True
                                        self._previous_text_nb_added_empty_lines = nb_empty_lines + 1
                                        # TODO: understand why +1 is necessary because of the write?
                                        if self._main_display_auto_scroll:
                                            self._main_display.scroll_end(animate=False)

                                    self._previous_nb_lines_displayed = nb_lines_after_preamble + 1 # +1 to count the preamble line

                                else:
                                    if epilogue_detected:
                                        self._wait_for_epilogue = False
                                        # assumption: preamble is already displayed

                                        nb_lines_to_display = self._previous_nb_lines_displayed + added_nb_lines
                                        if available_nb_lines < nb_lines_to_display:
                                            # self.app.notify(f'2.1 epilogue detected (no preamble) - case (1)\n'
                                            #                 f'y:{self._main_display.scroll_y}, '
                                            #                 f'max_y:{self._main_display.max_scroll_y}, init:{initial_nb_lines},'
                                            #                 f'empty: {self._previous_text_nb_added_empty_lines}',
                                            #                 timeout=10)
                                            if lines_removed:
                                                # move_up = initial_nb_lines - self._previous_text_nb_added_empty_lines - 1
                                                if self._main_display_auto_scroll:
                                                    self._main_display.scroll_relative(
                                                        y=self._previous_text_nb_added_empty_lines, animate=False)
                                                    # self._main_display.scroll_to(y=move_up, animate=False)
                                            else:
                                                pass

                                            self._previous_text_empty_lines = False
                                            self._previous_text_nb_added_empty_lines = 0

                                        else:
                                            # self.app.notify(f'2.2 epilogue detected (no preamble) - case (2)')
                                            nb_empty_lines = available_nb_lines - nb_lines_to_display - 1
                                            # TODO: understand why -1 is necessary because of the write('\n...')
                                            empty_lines = '\n' * nb_empty_lines
                                            self._main_display.write(Text(empty_lines))
                                            self._previous_text_empty_lines = True
                                            self._previous_text_nb_added_empty_lines = nb_empty_lines
                                            if self._main_display_auto_scroll:
                                                self._main_display.scroll_end(animate=False)

                                        self._previous_nb_lines_displayed = 0

                                    else:
                                        if self._wait_for_epilogue:
                                            nb_lines_to_display = self._previous_nb_lines_displayed + added_nb_lines + 1
                                            self._previous_nb_lines_displayed = nb_lines_to_display
                                        else:
                                            nb_lines_to_display = added_nb_lines
                                            self._previous_nb_lines_displayed = 0

                                        if available_nb_lines < nb_lines_to_display:
                                            if self._wait_for_epilogue:
                                                # self.app.notify(f'A. no preamble/epilogue - case (1)')
                                                if lines_removed:
                                                    if self._main_display_auto_scroll:
                                                        self._main_display.scroll_relative(
                                                            y=self._previous_text_nb_added_empty_lines, animate=False)
                                                else:
                                                    pass
                                            else:
                                                move_up = initial_nb_lines + 1
                                                if self._main_display_auto_scroll:
                                                    self._main_display.scroll_to(y=move_up, animate=False)

                                            self._previous_text_empty_lines = False
                                            self._previous_text_nb_added_empty_lines = 0

                                        else:
                                            # if self._wait_for_epilogue:
                                            #     self.app.notify(f'B. no preamble/epilogue - case (2)')
                                            nb_empty_lines = available_nb_lines - nb_lines_to_display
                                            empty_lines = '\n' * nb_empty_lines
                                            self._main_display.write(Text(empty_lines))
                                            self._previous_text_empty_lines = True
                                            self._previous_text_nb_added_empty_lines = nb_empty_lines
                                            if self._main_display_auto_scroll:
                                                self._main_display.scroll_end(animate=False)

                                # self.app.notify(f'y:{self._main_display.scroll_y}\n'
                                #                 f'max_y:{self._main_display.max_scroll_y}\n'
                                #                 f'init_nb_l:{initial_nb_lines}\n'
                                #                 f'new_nb_l:{new_nb_lines}\n'
                                #                 f'avail_nb_l:{available_nb_lines}\n'
                                #                 f'virtual_size:{virtual_size}\n',
                                #                 title='stats',
                                #                 timeout=40)


                        elif fd in (fd_ansi, fd_bbcode):
                            text = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 512).decode('latin_1')
                                except BlockingIOError:
                                    # await asyncio.sleep(0.05)
                                    data = ''
                                else:
                                    text += data

                            if self._raw_display_hidden:
                                self._raw_display.remove_class('raw_display_hidden_mode', update=True)
                                self._raw_display.add_class('raw_display_visible_mode', update=True)
                                self._raw_display_hidden = False

                            if fd == fd_ansi:
                                text = Text.from_ansi(text, no_wrap=False, overflow='fold')
                            else:
                                text = Text.from_markup(text, overflow='fold')

                            if text:
                                self._raw_display.write(text)
                        else:
                            pass

                    elif evt & select.EPOLLHUP:
                        await asyncio.sleep(0.1)

                    else:
                        error_msg = Text.from_markup(f'Unknown epoll() event: {evt}')
                        self._status_wdg.update(error_msg)

                    # hack to force a redraw without playing with the focus
                    # it is necessary to bypass textual redraw optimizations
                    self._main_display.toggle_class("-engine-refresh-trigger")
                    self._main_display.refresh(layout=True)
                    await self._main_display.wait_for_refresh()

        finally:
            if epobj:
                epobj.close()
            error_msg = Text.from_markup(f'Exit from [i]epoll()[/] loop!')
            self._status_wdg.update(error_msg)




def start(args: argparse.Namespace):
    main_fifo_ansi = args.main_fifo_ansi
    main_fifo_bbcode = args.main_fifo_bbcode
    basic_fifo = args.basic_fifo
    status_fifo = args.status_fifo
    cmd_fifo = args.cmd_fifo
    help_fifo = args.help_fifo

    console = Console(record=True, width=200)

    app = FuddlyTUI(cmd_fifo, main_fifo_ansi, main_fifo_bbcode, basic_fifo,
                    status_fifo, help_fifo)
    try:
        app.run()
    except:
        console.print_exception()
    finally:
        if app.fmkdb:
            app.fmkdb.stop()
    # time.sleep(100)
    return
