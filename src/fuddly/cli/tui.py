from argcomplete.scripts import python_argcomplete_check_easy_install_script
from textual import events
from textual.css.query import NoMatches
from typing import Iterable

from xdg.Locale import update

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
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Input, Static, Button
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

#main_panel_area {
    box-sizing: border-box;
    height: 1fr;
    width: 100%;
}

#main_rlog_area {
    box-sizing: border-box;
    height: 1fr;
    width: 100%;
}

#help_zone {
    scrollbar-size: 1 1;
    box-sizing: border-box;
    width: 100%;
    border: solid blue;
}

.help_hidden_mode {
    height: 0%;
}

.help_visible_mode {
    height: 1fr;
}

#main_rlog {
    scrollbar-size: 1 1;
    box-sizing: border-box;
    text-wrap: wrap;
    text-overflow: fold;
    height: 4fr;
    width: 100%;
    border: solid green;
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

tcss_selectors = [
    '#status', '#main_panel_area', '#main_rlog_area', '#help_zone',
    '#main_rlog', '.box', '.hl_box', '.help_visible_mode', '.help_hidden_mode',
    '#db_dir_tree', '#db_display', '#db_status', '#current_fmkdb']
tcss_fname = os.path.join(config_folder, FUDDLY_TUI_FNAME)
write_tcss = False
if not os.path.isfile(tcss_fname):
    write_tcss = True
else:
    with open(tcss_fname, 'r') as f:
        read_tcss = f.read()
        for sel in tcss_selectors:
            if sel not in read_tcss:
                write_tcss = True
                break
if write_tcss:
    with open(tcss_fname, 'w') as f:
        f.write(fuddly_tui_tcss)

class FuddlyLogger(RichLog):

    def on_focus(self, event: events.Focus) -> None:
        # self.styles.border = ('solid', 'green')
        self.remove_class('hl_box')
        self.add_class('box', update=True)

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


    def __init__(self, cmd_fifo, main_fifo_ansi, main_fifo_bbcode, status_fifo, help_fifo):
        super().__init__()
        self._cmd_fifo = cmd_fifo
        self._main_fifo_ansi = main_fifo_ansi
        self._main_fifo_bbcode = main_fifo_bbcode
        self._status_fifo = status_fifo
        self._help_fifo = help_fifo
        self._cmd_re = re.compile(r'(\d)\x00(.*?)\x00(.*?)\x00(.*?)\x00', flags=re.S)
        self._loggers_fd = {}
        self._loggers_fifo = {}
        self._status_msg = Text.from_ansi('')
        self._help_markup_mode = False

        self._main_panel = None
        self._main_rlog = None
        self._right_panel = None
        self._help_zone = None
        # self._help_zone_hidden = True

        self.fmkdb = None

        self._standalone_app = not self._cmd_fifo

    def on_mount(self) -> None:
        if not self._standalone_app:
            self.run_worker(self.update_text())


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
                                RichLog(id='main_rlog', wrap=True),
                                id="main_rlog_area"
                            ),
                            id='main_panel_area'
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

                new_fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
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
                            self._main_rlog_area.styles.width = '100%'
                            self._right_panel = None

            elif cmd == RichTerm.CMD_HELP_MODE:
                mode = parsed.group(2)

                if mode == 'm': # markup mode
                    self._help_markup_mode = True
                else:
                    self._help_markup_mode = False

            elif cmd == RichTerm.CMD_HELP_HIDE:
                if self._help_zone:
                    self._help_zone.remove()
                    self._help_zone = None
                    # self._help_zone.remove_class('help_visible_mode')
                    # self._help_zone.add_class('help_hidden_mode', update=True)
                    # self._help_zone_hidden = True

            else:
                self._status_msg = Text.from_ansi(f'Unknown Command: {cmd}')
        else:
            self._status_msg = Text.from_ansi(f'Command Parsing Error: {cmd_msg}')

    async def update_text(self) -> None:
        self._main_rlog: RichLog = self.query_one("#main_rlog")
        self._status_wdg: Static = self.query_one("#status")
        self._status_msg.stylize('bold')
        self._main_panel = self.query_one("#main_panel_area")
        self._main_panel_area = self.query_one("#main_panel_area")
        self._main_rlog_area = self.query_one("#main_rlog_area")
        epobj = None

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

            if (fd_ansi is None and fd_bbcode is None and fd_status is None
                    and fd_cmd is None and fd_help is None):
                return

            while True:
                evts = epobj.poll(timeout=1)
                for fd, evt in evts:
                    if evt & select.EPOLLIN:
                        if fd == fd_cmd:
                            cmd_msgs = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 64).decode()
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
                                    data = os.read(fd, 256).decode()
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
                                    await self._main_panel.mount(self._right_panel)
                                    self._main_rlog_area.styles.width = '60%'

                                try:
                                    rlog = self.query_one(w_id)
                                except NoMatches:
                                    rlog = FuddlyLogger(highlight=True, id=w_id[1:], classes='box')
                                    rlog.border_title = title
                                    await self._right_panel.mount(rlog)

                                rlog.remove_class('box')
                                rlog.add_class('hl_box', update=True)
                                rlog.scroll_visible()
                                rlog.write(text)

                        elif fd == fd_status:
                            text = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 8).decode()
                                except BlockingIOError:
                                    data = ''
                                else:
                                    text += data
                            text = Text.from_markup(text)
                            if text:
                                text.stylize('bold')
                                self._status_wdg.update(text)

                        elif fd == fd_help:
                            text = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 8).decode()
                                except BlockingIOError:
                                    data = ''
                                else:
                                    text += data

                            if not self._help_zone:
                                self._help_zone = RichLog(id='help_zone', classes='help_visible_mode')
                                self._help_zone.border_title = 'help'
                                await self._main_rlog_area.mount(self._help_zone, before=self._main_rlog)
                            #     self._help_zone_hidden = False
                            #
                            # if self._help_zone_hidden:
                            #     self._help_zone.remove_class('help_hidden_mode', update=True)
                            #     self._help_zone.add_class('help_visible_mode', update=True)
                            #     self._help_zone_hidden = False

                            if self._help_markup_mode:
                                text = Text.from_markup(text)
                            else:
                                text = Text.from_ansi(text)

                            if text:
                                self._help_zone.write(text)

                        elif fd in (fd_ansi, fd_bbcode):
                            text = ''
                            data = 'INIT'
                            while data:
                                try:
                                    data = os.read(fd, 256).decode()
                                except BlockingIOError:
                                    # await asyncio.sleep(0.05)
                                    data = ''
                                else:
                                    text += data

                            if fd == fd_ansi:
                                text = Text.from_ansi(text)
                            else:
                                text = Text.from_markup(text)

                            if text:
                                self._main_rlog.write(text)
                        else:
                            pass

                    elif evt & select.EPOLLHUP:
                        await asyncio.sleep(0.1)

                    else:
                        error_msg = Text.from_markup(f'Unknown epoll() event: {evt}')
                        self._main_rlog.write(error_msg)
        finally:
            if epobj:
                epobj.close()
            error_msg = Text.from_markup(f'Exit from EPOLL loop!')
            self._main_rlog.write(error_msg)




def start(args: argparse.Namespace):
    main_fifo_ansi = args.main_fifo_ansi
    main_fifo_bbcode = args.main_fifo_bbcode
    status_fifo = args.status_fifo
    cmd_fifo = args.cmd_fifo
    help_fifo = args.help_fifo

    console = Console(record=True, width=200)

    app = FuddlyTUI(cmd_fifo, main_fifo_ansi, main_fifo_bbcode,
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
