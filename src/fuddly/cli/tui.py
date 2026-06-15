import fuddly.cli.argparse_wrapper as argparse
from fuddly.framework.plumbing import FmkPlumbing, FmkShell
from fuddly.framework.global_resources import fuddly_version

import time
import asyncio
import select
import os
import re

from rich.console import Console
from rich.traceback import install
install()
from textual.widgets import RichLog
from textual.app import App
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Input, Static
from rich.text import Text

from fuddly.framework.global_resources import *
from fuddly.framework.data import *

FUDDLY_TUI_FNAME = 'fuddly_tui.tcss'

fuddly_tui_tcss = """
#status {
    height: 5%;
    content-align: right middle;
    tint: blue 20%;
}

.main_box {
    box-sizing: border-box;
    height: 100%;
    width: 100%;
    border: solid green;
}

.box {
    height: 50%;
    border: solid green;
}
"""

tcss_fname = os.path.join(config_folder, FUDDLY_TUI_FNAME)
if not os.path.isfile(tcss_fname):
    with open(tcss_fname, 'w') as f:
        f.write(fuddly_tui_tcss)

class FuddlyTUI(App):
    ANSICODE = 1
    BBCODE = 2

    CSS_PATH = os.path.join(config_folder, "fuddly_tui.tcss")
    # DEFAULT_CSS = """
    # """


    def __init__(self, cmd_fifo, main_fifo_ansi, main_fifo_bbcode, status_fifo):
        super().__init__()
        self._cmd_fifo = cmd_fifo
        self._main_fifo_ansi = main_fifo_ansi
        self._main_fifo_bbcode = main_fifo_bbcode
        self._status_fifo = status_fifo
        self._cmd_re = re.compile(r'(\d)\x00(.*?)\x00', flags=re.S)
        self._loggers_fd = {}

    def on_mount(self) -> None:
        self.run_worker(self.update_text())

    def compose(self):
        yield Vertical(
            Static(Text.from_markup(f'[white]Wait for status...[/]'), id="status", classes='box',
                         expand=True),
            Horizontal(
                RichLog(id="left", classes='main_box'),
                id='main'
            )
        )

    async def update_text(self) -> None:
        log: RichLog = self.query_one("#left")
        status: Static = self.query_one("#status")
        main_panel = self.query_one("#main")
        self._right_panel = None
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

            if fd_ansi is None and fd_bbcode is None and fd_status is None and fd_cmd is None:
                return

            while True:
                evts = epobj.poll(timeout=1)
                for fd, evt in evts:
                    if evt & select.EPOLLIN:
                        if fd == fd_cmd:
                            cmd_msgs = ''
                            data = 'INIT'
                            while data:
                                data = os.read(fd, 8).decode()
                                cmd_msgs += data
                            cmd_msg_list = cmd_msgs.split('\n')
                            for cmd_msg in cmd_msg_list:
                                if cmd_msg:
                                    parsed = self._cmd_re.match(cmd_msg)
                                    if parsed:
                                        cmd = int(parsed.group(1))
                                        fifo = parsed.group(2)
                                        if cmd == 1 and fifo:
                                            new_fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                                            rlog_id = f'rlog_{len(self._loggers_fd)}'
                                            self._loggers_fd[new_fd] = '#' + rlog_id
                                            epobj.register(new_fd, select.EPOLLIN | select.EPOLLHUP)
                                            if not self._right_panel:
                                                self._right_panel = VerticalScroll(id="loggers")
                                                await main_panel.mount(self._right_panel)
                                                log.styles.width = '60%'

                                            rlog = RichLog(id=rlog_id, classes='box')
                                            await self._right_panel.mount(rlog)
                                            rlog.scroll_visible()
                                            rlog.write(Text.from_markup('Ceci est un [b]TEST[/] nouveau'))
                                            text = Text.from_ansi(f'New fifo registered: {fifo}')
                                        else:
                                            text = Text.from_ansi(f'Command Error: cmd:{cmd}, fifo:{fifo}')
                                    else:
                                        text = Text.from_ansi('Error with new fifo')
                                    text.stylize('bold')
                                    status.update(text)
                        elif fd in self._loggers_fd:
                            status.update(Text.from_ansi('Receive something in new fifo'))
                            text = ''
                            data = 'INIT'
                            while data:
                                data = os.read(fd, 256).decode()
                                text += data
                            text = Text.from_markup(text)
                            if text:
                                rlog = self.query_one(self._loggers_fd[fd])
                                rlog.scroll_visible()
                                rlog.write(text)

                        elif fd == fd_status:
                            text = ''
                            data = 'INIT'
                            while data:
                                data = os.read(fd, 8).decode()
                                text += data
                            text = Text.from_markup(text)
                            if text:
                                text.stylize('bold')
                                status.update(text)

                        elif fd in (fd_ansi, fd_bbcode):
                            text = ''
                            data = 'INIT'
                            while data:
                                data = os.read(fd, 256).decode()
                                text += data

                            if fd == fd_ansi:
                                text = Text.from_ansi(text)
                            else:
                                text = Text.from_markup(text)

                            if text:
                                log.write(text)
                        else:
                            pass

                    elif evt & select.EPOLLHUP:
                        await asyncio.sleep(0.1)

                    else:
                        error_msg = Text.from_markup(f'Unknown epoll() event: {evt}')
                        log.write(error_msg)
        finally:
            if epobj:
                epobj.close()
            error_msg = Text.from_markup(f'Exit from EPOLL loop!')
            log.write(error_msg)




def start(args: argparse.Namespace):
    main_fifo_ansi = args.main_fifo_ansi
    main_fifo_bbcode = args.main_fifo_bbcode
    status_fifo = args.status_fifo
    cmd_fifo = args.cmd_fifo

    console = Console(record=True, width=200)

    app = FuddlyTUI(cmd_fifo, main_fifo_ansi, main_fifo_bbcode, status_fifo)
    try:
        app.run()
    except:
        console.print_exception()

    # time.sleep(100)
    return
