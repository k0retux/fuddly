import os
import sys
import importlib
from importlib.util import find_spec
from importlib.metadata import entry_points

import fuddly.framework.global_resources as gr
from fuddly.framework.plumbing import _populate_projects as populate_projects


# Get all modules (from FS and entry_points)
def get_module_of_type(group_name: str, prefix: str):
    path = {
        "targets": gr.user_targets_folder,
        "projects": gr.user_projects_folder,
        "data_models": gr.user_data_models_folder,
    }[group_name]
    modules = []
    # Project from user (FS)
    modules.extend(find_modules_in_dir(path=path, prefix=prefix))
    # Projects from modules
    modules.extend(find_modules_from_ep_group(group_name=gr.ep_group_names[group_name]))
    return modules


def get_each_project_module() -> list():
    return get_module_of_type(
            group_name="projects",
            prefix="fuddly/projects"
        )


def get_each_data_model_module() -> list():
    return get_module_of_type(
            group_name="data_models",
            prefix="fuddly/data_models"
        )


def get_each_target_module() -> list():
    return get_module_of_type(
            group_name="targets",
            prefix="fuddly/targets"
        )


# Find python modules in a specific path, prepend "prefix" to the modules' names
def find_modules_in_dir(path: str, prefix: str) -> list():
    res = []
    fullpath = os.path.join(gr.fuddly_data_folder, path)
    # TODO this is the project specific detector which checks if it's a python
    # module. The data model import should be using the same behavior but has
    # not been converted yet
    modules = populate_projects(fullpath, prefix=prefix)
    for dname, (_, file_list) in modules.items():
        prefix = dname.replace(os.sep, ".") + "."
        for name in file_list:
            m = find_spec(prefix+name)
            # This should never happen
            if m is None or m.origin is None:
                sys.stderr.write(f"{prefix+name} detected as a module in "f"{fullpath},"
                      " but could not be imported\n")
                continue
            res.append(m)
    return res


# Get all the python modules corresponding to a certain entry_point name group
def find_modules_from_ep_group(group_name: str) -> list():
    res = []
    for ep in entry_points(group=group_name):
        if ep.name.endswith("__root__"):
            continue
        m = find_spec(ep.module)
        # If an entry point does not actually point to a module
        # i.e. somebody broke their package
        if m is None or m.origin is None:
            # the entry point is not a module, let's just ignore it
            sys.stderr.write(f"*** {ep.module} is not a python module, check your installed modules ***\n")
            continue
        res.append(m)
    return res


def get_project_from_name(name):
    prj_modules = get_each_project_module()
    for m in prj_modules:
        prj_name = m.name.split(".")[-1]
        if prj_name == name:
            mod = importlib.import_module(m.name)
            try:
                prj_obj = mod.project
            except AttributeError:
                sys.stderr.write(f'[ERROR] the project "{name}" does not contain a global variable '
                      f'named "project"\n')
                return None
            else:
                if os.path.basename(m.origin) == "__init__.py":
                    prj_path = os.path.dirname(m.origin)
                else:
                    prj_path = None
                prj_obj.set_fs_path(prj_path)
                return prj_obj
