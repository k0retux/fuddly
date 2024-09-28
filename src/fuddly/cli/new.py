import fuddly.cli.argparse_wrapper as argparse
import os
from pathlib import Path

from fuddly.framework import global_resources as gr

conf = {}


# For DMs
# <args.name>/
# ├── dm.py
# ├── __init__.py
# ├── samples (?)
# │   └── sample_file.txt (?)
# └── strategy.py

conf["dm"] = {
    "dm": {
        "name": "dm.py",
        "content": """from fuddly.framework.data_model import *
from fuddly.framework.global_resources import *
from fuddly.framework.value_types import *

class {name}_DataModel(DataModel):

    name = "{name}"

    def build_data_model(self):
        # Add your model definition here
        # See https://fuddly.readthedocs.io/en/develop/data_model.html
        # and https://fuddly.readthedocs.io/en/develop/tutorial.html#a-first-example
        # For information on how to do that
        raise NotImplementedError()

data_model = {name}_DataModel()""",
    },
    "strategy": {
        "name": "strategy.py",
        "content": """from fuddly.framework.tactics_helpers import *
tactics = Tactics()""",
    },
    "init": {
        "name": "__init__.py",
        "content": "from . import (dm, strategy)"
    },
}


# TODO project strucut will change so I won't bother doing it now
conf["project"] = {}

conf["module"] = {
    "config": {
        "name": "pyproject.toml",
        "content": """# This is a small configuration file for you {target} module.
# you can install it using `pip install .`

[project]
name = "{module_name}"
version = "0.0.1"
authors = [
    {{ name="<YOUR NAME>", email="your@email.here" }},
]
description = "Description of your {target}"
readme = "README.md"
dependencies=["fuddly"] # Add your dependencies here

[project.urls]
"Homepage" = "https://home-page-or-source-repo/url"
"Bug Tracker" = "https://bug-tracker/url"
"Documentation" = "https://documentation/url"

# This is what will link your {target} to fuddly.
# Without this entry, fuddly won't be able to automagically 
# discover your {target}.
[project.entry-points."fuddly.{target}s"]
{name} = "{module_name}"
""",
    },
    "readme": {
        "name": "README.md",
        "content": """# {name}

Here you can add some more info about your {target}""",
    },
}

# TODO the way module name is defined multiple times is redundant, a better way to handle it would
# be nice

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

    # It's nice to use dm on the cmdline, but we want it to be called data-model in the code
    args.target = "data-model" if args.target == "dm" else args.target

    module_name=args.name
    if args.pyproject:
        module_name = f"fuddly_module_{args.name}"
        # Overridding the name to reduce the risk of conflicting with an other package
        print(f"Initializing a new module '{args.name}' in {target_dir}")
        target_dir = target_dir.joinpath(args.name)
        target_dir.mkdir(parents=True)
        _create_conf(args, target_dir, conf["module"])
        # If we are in a module, the sources shoudl go in src/{name}/
        target_dir = target_dir / "src"

    target_dir = target_dir.joinpath(module_name)
    target_dir.mkdir(parents=True)

    match args.target:
        case "data-model":
            args.target="data-model"
            print(f"Creating new data-model {module_name}")
            _create_conf(args, target_dir, conf["dm"])
        case "project":
            print(f"Creating new project {args.name}")
            raise NotImplementedError()
            _create_conf(args, target_dir, conf["project"])

def _create_conf(args: argparse.Namespace, path: Path, conf: dict):
    if args.pyproject:
        module_name = f"fuddly_module_{args.name}"
    else:
        module_name = args.name

    for e in conf.values():
        f = path.joinpath(e["name"])
        f.touch()
        f.write_text(
            e["content"].format(
                name=args.name,
                module_name=module_name,
                target=args.target.replace("-", "_")
            )
        )
