import fuddly.cli.argparse_wrapper as argparse
from fuddly.framework.plumbing import FmkPlumbing, FmkShell
from fuddly.framework.global_resources import fuddly_version

import IPython
from IPython import embed
from fuddly.libs.external_modules import colorize, FontStyle, Color

from fuddly.framework.global_resources import *
from fuddly.framework.node import *
from fuddly.framework.node_builder import *
from fuddly.framework.value_types import *
from fuddly.framework.dmhelpers.generic import *
from fuddly.framework.data import *

def start(args: argparse.Namespace):
    fmkdb = args.fmkdb
    external_display = args.external_display
    quiet = args.quiet
    tui = args.tui

    fmk = FmkPlumbing(external_term=external_display, fmkdb_path=fmkdb, quiet=quiet, tui=tui)
    try:
        fmk.start()
        header = colorize(FontStyle.BOLD + f'\n-=[ IPython ]=- (with Fuddly FmK {fuddly_version})\n',
                          rgb=Color.TITLE)
        embed(header=header, banner1='', colors="linux", display_banner=True)
    finally:
        fmk.stop()
