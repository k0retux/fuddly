import importlib
import sys
import argcomplete

import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.utils import get_tools
from fuddly.cli.error import CliException


def tool_argument_completer(prefix, parsed_args, **kwargs):
    # Set _ARC_DEBUG in the shell for _DEBUG to be true
    from argcomplete.io import _DEBUG
    if parsed_args.tool is not None:
        if _DEBUG:
            argcomplete.warn(f"Prefix: {prefix}\n"
                             f"parsed_args: {parsed_args}\n"
                             f"kwargs: {kwargs}")
        # TODO For now we always return [], it should eventually be the tool's arguments
        return []
    else:
        return []


def start(args: argparse.Namespace) -> int:
    if args.tool is None:
        raise CliException("Missing tool name")

    if args.tool == "list":
        for i in get_tools():
            print(i)
        return 0

    sys.argv = [args.tool, *args.args]
    pkg = importlib.util.find_spec(f"fuddly.tools.{args.tool}")
    if pkg is None:
        print(f"{args.tool} is not a valid fuddly tool")
        return 1
    mod = pkg.loader.load_module()
    return mod.main()
