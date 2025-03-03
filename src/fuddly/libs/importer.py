import importlib
from importlib.metadata import entry_points, EntryPoint
from importlib.abc import MetaPathFinder
from importlib.util import spec_from_file_location, module_from_spec
from importlib.machinery import ModuleSpec, PathFinder

import fuddly
from fuddly.framework.global_resources import ep_group_names, fuddly_data_folder
from fuddly.libs.external_modules import colorize, Color

import os.path
import code
import sys


def _entry_point_path_editable(ep: EntryPoint) -> str | None:
    finder_location = ""
    # The RECORD files contains a list of off the files
    record = ep.dist.read_text("RECORD")
    if record is None:
        return None
    for entry in record.split("\n"):
        if "finder.py" in entry:
            finder_location = entry.split(",")[0]
            break
    else:
        return None

    finder_spec = spec_from_file_location(
            f"__{ep.value}_finder",
            ep.dist.locate_file(finder_location)
        )
    m = module_from_spec(finder_spec)
    finder_spec.loader.exec_module(m)

    # This is a bit ugly, but for this find_spec to be able
    # to work, the parent module must have been imported.
    # This would normally had been done by the rest of importlib's
    # machinery, but we are shortcircuiting it a bit here, so we
    # have to redo some of that ourselves.
    mod_name = ".".join(ep.value.split(".")[:-1])
    if mod_name != "":
        importlib.import_module(mod_name)

    for i in range(len(ep.value.split("."))):
        mod_name = ".".join(ep.value.split(".")[:-i])
        modulespec = m._EditableFinder.find_spec(mod_name)
        if modulespec is not None:
            if modulespec.origin is not None:
                return modulespec.origin.removesuffix("__init__.py")
            else:
                # Take the first path in it's submodule search path as an
                # alternative
                return list(modulespec.submodule_search_locations)[0]

    return None


def _entry_point_path(ep: EntryPoint) -> str | None:
    # We use the distribution to find the location of the module's source
    # in the file system
    dist_root = ep.dist.locate_file(".").joinpath(*ep.module.split(".")[:-1])
    if dist_root.exists():
        return str(dist_root)
    else:
        return None


class fuddly_importer_hook(MetaPathFinder):

    path_candidates: dict[str, list[str]] = {}

    # This method configures the paths to search modules in
    # Call it every time you want to take into accound potential
    # changes in this path (On reload for exemple ?)
    @classmethod
    def setup(cls):
        if cls not in sys.meta_path:
            sys.meta_path.insert(0, cls)
            cls.reload()

    @classmethod
    def reload(cls):
        cls.path_candidates = {}
        for obj_type in ep_group_names:
            cls.path_candidates[obj_type] = []

            # Preparing the dict of paths
            candidates = cls.path_candidates[obj_type]

            # Fuddly's user_data_folder
            p = os.path.join(fuddly_data_folder, "user_" + obj_type)
            if os.path.exists(p) and p not in candidates:
                _p, dirs, _ = next(os.walk(p))
                for d in dirs:
                    if d == "__pycache__":
                        continue
                    candidates.append(os.path.join(_p, d))
                candidates.append(p)

            # Fuddly core path
            p = fuddly.__spec__.origin.removesuffix("__init__.py")
            candidates.append(os.path.join(p, obj_type))

            # Entry point paths
            for ep in entry_points(group=ep_group_names[obj_type]):
                p = _entry_point_path(ep)
                if p is not None and p not in candidates:
                    candidates.append(p)
                    continue
                p = _entry_point_path_editable(ep)
                if p is not None and p not in candidates:
                    candidates.append(p)
                    continue

    @classmethod
    def find_spec(cls, fullname: str, path=None, target=None) -> ModuleSpec | None:

        if fullname.startswith("user_"):
            print(colorize(
                "*** Import with the old user_{data_model,projects,target,info} "
                "naming convention detected.",
                rgb=Color.ERROR))
            fullname = fullname.removeprefix("user_")
            print(colorize(
                f"*** Please change the import to fuddly.{fullname}",
                rgb=Color.ERROR))
            return None

        # We do not handle anything that does not start with fuddly.
        if not fullname.startswith("fuddly."):
            return None

        (_, obj_type, *parts) = fullname.split(".")
        # We don't handle imports that are not data_models, projects, targets
        # or info either
        if obj_type not in ep_group_names:
            return None

        path_candidates = cls.path_candidates[obj_type]

        # For the fuddly.{targets,data-models,projects,info} modules, we return
        # a Namespace spec (A ModuleSpec with a submodule_search_location, no
        # loader, and the is_package parameter set to True)
        if len(parts) == 0:
            spec = ModuleSpec(fullname, None, is_package=True)
            spec.submodule_search_locations = path_candidates
            return spec

        # For a first level submodule, we need to handle it before importlib
        # can take over
        elif len(parts) == 1:
            spec = PathFinder.find_spec(
                    fullname,
                    path=path_candidates
                )
            return spec

        elif len(parts) > 1:
            # let importlib handle the rest
            return None

        return None
