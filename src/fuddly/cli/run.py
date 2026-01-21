import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.error import CliException
from importlib.util import find_spec
from importlib.metadata import entry_points
import sys
import os.path
import os
import argcomplete

import fuddly.framework.global_resources as gr
from fuddly.cli.utils import get_scripts


def script_from_pkg_name(name) -> str:
    # pkg_name.script.name -> ("pkg_name.script", "name.py")
    *pkg, file = name.split('.')
    file += ".py"
    pkg = ".".join(pkg)

    # User scripts
    if pkg.startswith("fuddly.projects_scripts"):
        path = os.path.join(gr.fuddly_data_folder, "projects_scripts", file)
        if os.path.isfile(path):
            return path
        else:
            return None

    # Third party/module scripts
    try:
        path = find_spec(name).origin
    except ModuleNotFoundError:
        return None
    except AttributeError:
        return None
    return path


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
    if args.script is None:
        raise CliException("Missing script name")

    if args.script == "list":
        for i in get_scripts():
            print(i)
        return 0

    script = script_from_pkg_name(args.script)
    if script is None:
        print(f"Script {args.script} not found")
        sys.exit(1)

    argv = [script, *args.args]

    if args.ipython:
        executor = "ipython"
    else:
        executor = "python"

    argv.insert(0, executor)
    os.execvp(executor, argv)
