import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.error import CliException
import sys

def start(args: argparse.Namespace):
    sys.argv=[]
    sys.argv.append(args.script)
    sys.argv.extend(args.args[0]) # Why is this an array, that weird - someting to do with nargs

    script_dir = "/tmp"
    sys.path.append(script_dir)

    if args.list:
        raise NotImplementedError("Not implemented yet")
        # TODO Find the script dir
        # TODO List the content of the dir
        return 0

    if args.script is None:
        raise CliException("Missing tool name")

    # TODO execute the script from the script directory
    raise NotImplementedError("Not implemented yet")
