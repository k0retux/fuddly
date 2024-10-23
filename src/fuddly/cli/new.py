import fuddly.cli.argparse_wrapper as argparse
import os
from pathlib import Path
from importlib import util
from fuddly.framework import global_resources as gr
import string

conf = {}


# For DMs
# <args.name>/
# ├── dm.py
# ├── __init__.py
# ├── samples (?)
# │   └── sample_file.txt (?)
# └── strategy.py

conf["dm"] = [
    {"name": "__init__.py"},
    {"name": "strategy.py"},
    {
        "name": "dm.py",
        "interpolate": ["name"],
    },
]

conf["project"] = {
    "skeleton": [
        {"name": "__init__.py"},
        {"name": "prj.py"},
        {"name": "monitoring.py"},
        {"name": "targets.py"},
        {"name": "README", "path": "samples"},
        {"name": "README", "path": "scripts"},
    ],
    "exemple": [
        {"name": "__init__.py"},
        {"name": "prj.py"},
        {"name": "monitoring.py"},
        {"name": "targets.py"},
        {"name": "README", "path": "scripts"},
        {"name": "README", "path": "samples"},
    ],
}

conf["module"] = [
    {
        "name": "pyproject.toml",
        "interpolate": ["name", "target", "module_name"], 
    },
    {
        "name": "README.md",
        "interpolate": ["name", "target"],
    },
]

class PartialMatchString(str):
    def __eq__(self, str_b):
        return self.__contains__(str_b)

def start(args: argparse.Namespace):
    if args.dest is not None:
        target_dir=Path(args.dest).absolute()
    else:
        if args.pyproject:
            target_dir=Path(".").absolute()
        else:
            target_dir=Path(gr.user_data_models_folder).absolute()

    if target_dir.joinpath(args.name).exists():
        print(f"A {args.name} directory already exists in {target_dir}")
        return 1

    # origin is the __init__.py file of the module so taking "parent" gives us the module folder
    src_dir = Path(util.find_spec("fuddly.cli").origin).parent.joinpath("templates")

    module_name=args.name
    if args.pyproject:
        module_name = f"fuddly_module_{args.name}"
        # Overridding the name to reduce the risk of conflicting with an other package
        print(f"Initializing a new module '{args.name}' in {target_dir}")
        target_dir = target_dir/args.name
        target_dir.mkdir(parents=True)
        _create_conf(target_dir, "", conf["module"], )
        # If we are making a module, the sources should go in src/{name}/
        target_dir = target_dir/"src"

    target_dir = target_dir/module_name
    target_dir.mkdir(parents=True)

    match PartialMatchString(args.target):
        case "dm" | "data-model":
            print(f"Creating new data-model \"{module_name}\"")
            _create_conf(
                target_dir, 
                src_dir/"data_model", 
                conf["dm"],
                name=args.name,
                module_name=module_name,
                target="data_model",
            )
        case "project:":
            template=args.target.split(':')[1]
            print(f"Creating new project \"{args.name}\" based on the \"{template}\" template")
            _create_conf(
                 target_dir, 
                 src_dir/template, 
                 conf["project"][template], 
                 name=args.name,
                 module_name=module_name, 
                 target=args.target
            )

def _create_conf(path: Path, srcPath: Path, conf: dict, **kwargs):
    for e in conf:
        print(e)
        _srcPath=srcPath
        _path=path
        if e.get("path") is not None:
            _path = _path/e["path"]
            _srcPath = _srcPath/e["path"]
            _path.mkdir(parents=True)
        data = (_srcPath/e["name"]).read_text()
        f = _path/e["name"]
        f.touch()
        f.write_text(string.Template(data).substitute(**kwargs))
