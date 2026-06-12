import fuddly.cli.argparse_wrapper as argparse
from fuddly.framework.plumbing import FmkPlumbing, FmkShell
from fuddly.framework.global_resources import fuddly_version

import time
import asyncio
import select
import os

from rich.console import Console
from rich.traceback import install
install()
from textual.widgets import RichLog
from textual.app import App
from textual.containers import Horizontal, Vertical
from textual.widgets import Input, Static
from rich.text import Text

from fuddly.framework.global_resources import *
from fuddly.framework.data import *

FUDDLY_TUI_FNAME = 'fuddly_tui.tcss'

fuddly_tui_tcss = """
Screen {
    layout: grid;
    grid-columns: 80% 20%;
    grid-rows: 5% 95%;
    grid-size: 2;
}

#status {
    column-span: 2;
    content-align: right middle;
    tint: blue 20%;
}

.box {
    height: 100%;
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
    # Screen {
    #     layout: grid;
    #     grid-columns: 80% 20%;
    #     grid-rows: 5% 95%;
    #     grid-size: 2;
    # }
    # """


    def __init__(self, main_fifo_ansi, main_fifo_bbcode, status_fifo):
        super().__init__()
        self._main_fifo_ansi = main_fifo_ansi
        self._main_fifo_bbcode = main_fifo_bbcode
        self._status_fifo = status_fifo

    def on_mount(self) -> None:
        self.run_worker(self.update_text())
        # if self._status_fifo:
        #     self.run_worker(self.update_notif(self._status_fifo))
        #
        # msg = Text.from_markup(f'[green]main comm OK[/]')
        # log = self.query_one("#left")
        # log.write(msg)

    def compose(self):
        yield Static(Text.from_markup(f'[white]Wait for status...[/]'), id="status", classes='box',
                     expand=True)
        yield RichLog(id="left", classes='box')
        yield RichLog(id="right", classes='box')

    async def update_text(self) -> None:
        log: RichLog = self.query_one("#left")
        status: Static = self.query_one("#status")
        epobj = None

        try:
            epobj = select.epoll()
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

            if fd_ansi is None and fd_bbcode is None and fd_status is None:
                return

            while True:
                evts = epobj.poll(timeout=1)
                for fd, evt in evts:
                    if evt & select.EPOLLIN:
                        if fd == fd_status:
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

    console = Console(record=True, width=200)

    app = FuddlyTUI(main_fifo_ansi, main_fifo_bbcode, status_fifo)
    try:
        app.run()
    except:
        console.print_exception()

    # time.sleep(100)
    return
