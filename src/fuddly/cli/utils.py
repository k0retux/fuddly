import os

from fuddly.libs.fmk_services import (
    get_each_project_module,
    get_each_data_model_module,
    get_each_target_module,
)
import importlib
import types


# Return the type a module is of
def get_module_type(name: str) -> str:
    if name in [x.name for x in get_each_project_module()]:
        return "projects"
    if name in [x.name for x in get_each_data_model_module()]:
        return "data_models"
    if name in [x.name for x in get_each_target_module()]:
        return "targets"
    return None


# Return a list of all projects, dms, and targets fuddly knows about
def get_all_object_names() -> list[str]:
    modules = []

    # Projects
    project_modules = get_each_project_module()
    # Data models
    data_model_modules = get_each_data_model_module()
    # Targets
    target_modules = get_each_target_module()
    # Infos

    for m in project_modules + data_model_modules + target_modules:
        path = m.origin
        if os.path.basename(path) == "__init__.py":
            path = os.path.dirname(path)
        else:
            # Ignoring old single-files projects
            continue
        modules.append(m.name)

    return modules


# Return a list of scripts from all the projects fuddly knows about
def get_project_scripts(prefix: str, parsed_args: (object | str), **kwargs) -> list[str]:
    paths = []
    project_modules = get_each_project_module()
    if type(parsed_args) is str:
        project = parsed_args
    else:
        project = parsed_args.project.split(".")[-1]

    for m in project_modules:
        if project != m.name.split(".")[-1]:
            continue
        p = m.origin
        # origin shoudl point to the __init__.py of the module
        if os.path.basename(p) == "__init__.py":
            p = os.path.dirname(p)
        else:
            # Ignoring old single-files projects
            continue
        if os.path.isdir(os.path.join(p, "scripts")):
            for f in next(os.walk(os.path.join(p, "scripts")))[2]:
                if f.endswith(".py") and f != "__init__.py":
                    paths.append(f.removesuffix(".py"))

    return paths


# Return a list of projects fuddly knows about
def get_projects() -> list[importlib.machinery.ModuleSpec]:
    modules = []

    project_modules = get_each_project_module()

    for m in project_modules:
        path = m.origin
        if os.path.basename(path) == "__init__.py":
            path = os.path.dirname(path)
        else:
            # Ignoring old single-files projects
            continue
        *prefix, prj_name = path.split("/")
        modules.append((prj_name, path, m))

    return modules


# Return a list of all the fuddly tools
def get_tools() -> list[types.ModulesType]:
    import pkgutil
    modules = []
    tools = importlib.import_module("fuddly.tools")
    modules = list(map(lambda x: x.name, pkgutil.walk_packages(tools.__path__)))
    return modules
