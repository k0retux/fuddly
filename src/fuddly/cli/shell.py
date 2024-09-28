import fuddly.cli.argparse_wrapper as argparse

def start(args: argparse.Namespace):
    from fuddly.framework.plumbing import FmkPlumbing,FmkShell
    fmkdb = args.fmkdb
    external_display = args.external_display
    quiet = args.quiet

    fmk = FmkPlumbing(external_term=external_display, fmkdb_path=fmkdb, quiet=quiet)
    fmk.start()

    shell = FmkShell("Fuddly Shell", fmk)
    shell.cmdloop()
