import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.error import CliException
import sys
import os
import argcomplete
from pathlib import Path

from fuddly.cli.utils import get_project_scripts
from fuddly.libs.fmk_services import get_project_from_name, get_each_project_module


def script_argument_completer(prefix, parsed_args, **kwargs):
    # Set _ARC_DEBUG in the shell fro _DEBUG to be true
    from argcomplete.io import _DEBUG
    if parsed_args.script is not None:
        if _DEBUG:
            argcomplete.warn(f"Prefix: {prefix}\nparsed_args: {parsed_args}\nkwargs: {kwargs}")
        # TODO For now we always return [], it should eventually be the script's arguments
        return []
    else:
        return []


def start(args: argparse.Namespace):
    if args.project == "list":
        for p in get_each_project_module():
            print(p.name.split(".")[-1])
        return 0

    if args.script == [] or args.script[0] == "list":
        for s in get_project_scripts("", args.project):
            print(s)
        sys.exit(0)

    script = Path(os.path.join(get_project_from_name(args.project).get_fs_path(), "scripts", args.script[0] + ".py"))
    if not script.exists():
        print(f"Script {args.script} not found in project {args.project}")
        sys.exit(1)

    argv = [script, *args.script[1:]]

    if args.ipython:
        executor = "ipython"
    else:
        executor = "python"

    argv.insert(0, executor)
    os.execvp(executor, argv)
