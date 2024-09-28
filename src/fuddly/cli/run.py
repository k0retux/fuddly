import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.error import CliException
from importlib.util import find_spec
from importlib.metadata import entry_points
import fuddly.framework.global_resources as gr
import sys
import os.path
import os

def get_scripts() -> list():
    paths = []

    # User scripts
    script_dir = os.path.join(gr.fuddly_data_folder, "projects_scripts")
    if os.path.isdir(script_dir):
        path, _, files = next(os.walk(script_dir))
        for f in files:
            paths.append("fuddly.projects_scripts." + f.removesuffix(".py"))

    # Third party/modules
    for ep in entry_points(group=gr.ep_group_names["projects"]):
        p = find_spec(ep.module).origin
        if os.path.basename(p) == "__init__.py":
            p=os.path.dirname(p)
        else:
            # Ignoring old single-files projects
            continue
        if os.path.isdir(os.path.join(p, "scripts")):
            for f in next(os.walk(os.path.join(p, "scripts")))[2]:
                if f.endswith(".py") and f != "__init__.py":
                    paths.append(ep.module + ".scripts." + f.removesuffix(".py"))

    return paths

def script_from_pkg_name(name) -> str:
    # pkg_name.script.name -> ("pkg_name.script", "name.py")
    *pkg, file = name.split('.')
    file+=".py"
    pkg=".".join(pkg)

    # User scripts
    if pkg.startswith("fuddly.projects_scripts"):
        path=os.path.join(gr.fuddly_data_folder, "projects_scripts", file)
        if os.path.isfile(path):
            return path
        else:
            return None

    # Third party/module scripts
    try:
        path=find_spec(name).origin
    except ModuleNotFoundError:
        return None
    return path


# TODO why does this not work 😥
def script_argument_completer(prefix, parsed_args, **kwargs):
    print(parsed_args, file=out)
    return ["HAAAAAA"]


def start(args: argparse.Namespace):
    if args.list:
        for i in get_scripts():
            print(i)
        return 0

    if args.script is None:
        raise CliException("Missing script name")

    script = script_from_pkg_name(args.script)
    if script == None:
        print(f"Script {args.script} not foud")
        sys.exit(1)

    argv = args.args[0] # Why is this an array, that weird - someting to do with nargs
    argv.insert(0, script)


    # TODO Add ipython option
    executor = "python"
    argv.insert(0, executor)

    os.execvp(executor, argv)

