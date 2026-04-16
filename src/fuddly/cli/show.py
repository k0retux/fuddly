import os
import importlib

import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.error import CliException
from fuddly.cli.utils import get_projects


def info_from_project_name(name) -> str | None:
    for prj in get_projects():
        prj_name, path, m = prj
        if prj_name == name:
            info = importlib.import_module(m.name)
            if hasattr(info, "INFO"):
                return info.INFO
            else:
                print(f'[warning] the project "{name}" does not contain a global variable '
                      f'named "INFO" (to be printed by this command)')
                return None
    else:
        return None


def readme_from_project_name(name) -> (str | None, bool):
    for prj in get_projects():
        prj_name, path, m = prj
        if prj_name == name:
            info_path = os.path.join(path, "README")
            if os.path.isfile(info_path):
                return info_path
    else:
        return None


def start(args: argparse.Namespace) -> int:
    if args.project is None:
        raise CliException("Missing project name")

    if args.project == "list":
        for prj in get_projects():
            name, _, _ = prj
            print(name)
        return 0

    readme_path = readme_from_project_name(args.project)
    if readme_path is None:
        print(f"{args.project} does not have a README file")
    else:
        with open(readme_path, 'r') as f:
            buff = f.read()
            print(buff)

    info = info_from_project_name(args.project)
    if info is not None:
        print(info)

    return 0
