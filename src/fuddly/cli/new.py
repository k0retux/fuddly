import fuddly.cli.argparse_wrapper as argparse
from pathlib import Path
from importlib import util
from fuddly.framework import global_resources as gr
import string
from fuddly.cli.error import CliException

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
    # TODO should the template dir be in fuddly_folder so users can define their own templates?
    # origin is the __init__.py file of the module so taking "parent" gives us the module folder
    src_dir = Path(util.find_spec("fuddly.cli").origin).parent.joinpath("templates")
    module_name = args.name

    dest_dir = Path(gr.fuddly_data_folder).absolute()
    if args.dest is not None:
        dest_dir = Path(args.dest).absolute()
    elif args.pyproject:
        dest_dir = Path(".").absolute()
    else:
        if args.object.startswith("project"):
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

    match PartialMatchString(args.object):
        case "dm" | "data-model":
            create_msg = f"Creating new data-model \"{module_name}\""
            _src_dir = src_dir/"data_model"
            _conf = conf["dm"]
            object_name = "data_model"
        case "project:":
            args.object, template = args.object.split(':')
            create_msg = f"Creating new project \"{args.name}\" based on the \"{template}\" template"
            _src_dir = src_dir/template
            if not _src_dir.exists():
                print(f"The '{template}' project template does not exist.")
                return 1
            _conf = conf["project"][template]
            object_name = args.object
        case _:
            dest_dir.rmdir()
            raise CliException(f"{args.object} is not a valide object name.")

    if args.pyproject:
        _create_conf(
            dest_dir,
            src_dir/"module",
            conf["module"],
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
        # kwargs
        modules_name=module_name,
        name=args.name,
        object_name=object_name,
    )


def _create_conf(dstPath: Path, srcPath: Path, conf: dict, **kwargs):
    for e in conf:
        _srcPath = srcPath
        _dstPath = dstPath
        if e.get("path") is not None:
            _dstPath = _dstPath/e["path"]
            _srcPath = _srcPath/e["path"]
            _dstPath.mkdir(parents=True)
        data = (_srcPath/e["name"]).read_text()
        f = _dstPath/e["name"]
        f.touch()
        f.write_text(string.Template(data).substitute(**kwargs))
