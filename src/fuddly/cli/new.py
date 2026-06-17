from pathlib import Path
from importlib import util
from fuddly.framework import global_resources as gr
import string
import os

import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.error import CliException
from fuddly.cli.utils import get_module_type, get_all_object_names

conf = {}

# The conf dict describs the files in the template and what variable to interpolate in them
conf["dm"] = [
    {"name": "__init__.py"},
    {"name": "strategy.py"},
    {
        "name": "dm.py",
        "interpolate": ["name"],
    },
]

conf["project"] = {
    "bare": [
        {"name": "__init__.py"},
        {"name": "prj.py"},
        {"name": "monitoring.py"},
        {"name": "targets.py"},
        {"name": "conf.py", "interpolate": ["name"]},
        {"name": "README"},
        {"name": "README", "path": "samples"},
        {"name": "README", "path": "scripts"},
    ],
    # Not yet created, uncomment once it is created 🙃
    # "example": [
    #     {"name": "__init__.py"},
    #     {"name": "prj.py"},
    #     {"name": "monitoring.py"},
    #     {"name": "targets.py"},
    #     {"name": "README", "path": "scripts"},
    #     {"name": "README", "path": "samples"},
    # ],
}

conf["module"] = [
    {
        "name": "pyproject.toml",
        "interpolate": ["name", "object_name", "module_name"],
    },
    {
        "name": "README.md",
        "interpolate": ["name", "object_name"],
    },
]


class PartialMatchString(str):
    def __eq__(self, str_b):
        return self.__contains__(str_b)


def start(args: argparse.Namespace):

    _conf = dict()
    clone = False
    # TODO should the template dir be in fuddly_folder so users can define their own templates?
    # origin is the __init__.py file of the module so taking "parent" gives us the module folder
    spec = util.find_spec("fuddly.cli")
    if spec is None:
        print("Failed to get the spec of the 'fuddly.cli' module.")
        return 1
    src_dir = Path(spec.origin).parent.joinpath("templates")
    module_name = args.name

    if args.clone is not None and args.pyproject:
        print("--pyproject and --clone cannot be used together")
        return 1

    dest_dir = Path(gr.fuddly_data_folder).absolute()
    if args.dest is not None:
        dest_dir = Path(args.dest).absolute()
    elif args.pyproject:
        dest_dir = Path(".").absolute()
    else:
        if args.clone is not None:
            # This id not ideal, a better solution would be having a list command to show 
            # all the modules (and scripts for that matter)
            if args.clone == "list":
                for m in get_all_object_names():
                    print(m)
                return 0
            dest_dir = dest_dir / get_module_type(args.clone)
        elif args.type.startswith("project"):
            dest_dir = dest_dir/"projects"
        else:
            dest_dir = dest_dir/"data_models"

    if args.pyproject:
        # Overridding the name to reduce the risk of conflicting with an other package
        module_name = f"fuddly_module_{args.name}"
        if dest_dir.joinpath(args.name).exists():
            print(f"A '{args.name}' directory already exists in '{dest_dir}'")
            return 1
        print(f"Initializing a new module '{args.name}' in {dest_dir}")
        dest_dir = dest_dir/args.name
        dest_dir.mkdir(parents=True)

    if args.type is not None:
        match PartialMatchString(args.type):
            case "dm" | "data-model":
                create_msg = f"Creating new data-model \"{module_name}\""
                _src_dir = src_dir/"data_model"
                _conf = conf["dm"]
                object_name = "data_model"
            case "project:":
                args.type, template = args.type.split(':')
                create_msg = f"Creating new project \"{args.name}\" based on the \"{template}\" template"
                _src_dir = src_dir/template
                if not _src_dir.exists():
                    print(f"The '{template}' project template does not exist.")
                    return 1
                _conf = conf["project"][template]
                object_name = args.type
            case _:
                dest_dir.rmdir()
                raise CliException(f"{args.type} is not a valide object name.")
    elif args.clone is not None:
        # Retrieve the files
        # Copy them to the src of the new object
        create_msg = f'Copying "{args.clone}" to "{module_name}"'
        _src_dir = Path(util.find_spec(args.clone).origin).parent
        if not _src_dir.exists():
            print(f"The '{template}' module does not exist. Check your python install")
            return 1
        clone = True
        _conf = []
        for (path, dirs, files) in os.walk(_src_dir):
            # Removing an elem from dirs will not go down the directory
            if "__pycache__" in dirs:
                dirs.remove("__pycache__")
            for f in files:
                p = str(path).removeprefix(str(_src_dir)).removeprefix("/")
                _conf.append({
                    "name": f,
                    "path": p,
                })

        # Find what type the object is off to default to a correct folder
        object_name = ""
        #module_name = args.clone

    if args.pyproject:
        _create_conf(
            dest_dir,
            src_dir/"module",
            conf["module"],
            clone=False,
            name=args.name,
            object_name=object_name,
            module_name=module_name
        )
        # If we are making a module, the sources should go in src/{name}/
        dest_dir = dest_dir/"src"

    dest_dir = dest_dir/module_name
    if dest_dir.exists():
        print(f"A '{args.name}' directory already exists in '{dest_dir}'")
        return 1
    dest_dir.mkdir(parents=True)

    print(f"{create_msg} in {dest_dir}")
    _create_conf(
        dest_dir,
        _src_dir,
        conf=_conf,
        clone=clone,
        # kwargs
        modules_name=module_name,
        name=args.name,
        object_name=object_name,
    )


def _create_conf(dstPath: Path, srcPath: Path, conf: dict, clone: bool, **kwargs):
    for e in conf:
        _srcPath = srcPath
        _dstPath = dstPath
        if e.get("path") is not None and e["path"] != "":
            _dstPath = _dstPath/e["path"]
            _srcPath = _srcPath/e["path"]
            try:
                _dstPath.mkdir(parents=True)
            # If the directory exist, we don't care to much
            except FileExistsError:
                pass
        _srcPath = (_srcPath/e["name"])
        # When cloning a template, the python files are suffixed with _ for VCS
        # reasons, when cloning this is not the case, we copy everything as they are
        if ".py" == _srcPath.suffix and not clone:
            _srcPath = _srcPath.with_suffix(".py_")
        data = _srcPath.read_text()
        f = _dstPath/e["name"]
        f.touch()
        if clone:
            f.write_text(data)
        else:
            f.write_text(string.Template(data).substitute(**kwargs))

