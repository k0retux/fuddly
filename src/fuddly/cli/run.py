import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.error import CliException
from importlib.util import find_spec
from importlib.metadata import entry_points
import fuddly.framework.global_resources as gr
import sys
import os.path
import os
import argcomplete

from fuddly.libs.fmk_services import get_each_project_module

def get_scripts() -> []:
    # The function is called for when the CLI is called and if we use the list option
    # having paths be an attribute to the functions means we will not run it twice
    if get_scripts.paths is not None:
        return get_scripts.paths
    else:
        get_scripts.paths = []

    project_modules = get_each_project_module()

    for m in project_modules:
        p = m.origin
        if os.path.basename(p) == "__init__.py":
            p = os.path.dirname(p)
        else:
            # Ignoring old single-files projects
            continue
        if os.path.isdir(os.path.join(p, "scripts")):
            for f in next(os.walk(os.path.join(p, "scripts")))[2]:
                if f.endswith(".py") and f != "__init__.py":
                    get_scripts.paths.append(m.name + ".scripts." + f.removesuffix(".py"))

    return get_scripts.paths


get_scripts.paths = None


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
