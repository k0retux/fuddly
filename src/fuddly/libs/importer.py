import importlib
from importlib.metadata import entry_points, EntryPoint
from importlib.abc import MetaPathFinder
from importlib.util import spec_from_file_location, module_from_spec
from importlib.machinery import ModuleSpec
from importlib.util import find_spec

# This import is important for some of the magic this module does
# At least I think it is
import fuddly
from fuddly.framework.global_resources import (
    ep_group_names,
    fuddly_data_folder,
    app_folder
)
from fuddly.libs.external_modules import colorize, Color

import os.path
import sys


# When a module is installed editable in a venv, it is not present in the venv,
# so you need to some more work to find the real location of the files on disk
# At least in cases where the module was installed with pip, the module's
# dist_info folder will contain a python module which is used to import it
# from it's real location on disk.
# We hijack this module to get the spec of the module so we can return it
# for a name that is not the module's (i.e. we have our fuddly.{obj_type}
# prefix in from of the module name)
def _entry_point_path_editable(ep: EntryPoint, name: str) -> str | None:
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

    modulespec = m._EditableFinder.find_spec(ep.value)
    if modulespec is not None:
        if modulespec.origin is not None:
            return [modulespec.origin.removesuffix("__init__.py")]
        elif modulespec.submodule_search_locations is not None:
            return list(modulespec.submodule_search_locations)

    return None


def _entry_point_path(ep: EntryPoint) -> str | EntryPoint | None:

    # We use the distribution to find the location of the module's source
    # in the file system
    dist_root = ep.dist.locate_file(".").joinpath(*ep.module.split("."))
    if dist_root.exists():
        return str(dist_root)
    else:
        return None


class fuddly_importer_hook(MetaPathFinder):

    # The paths are organised like so:
    # {
    #   <obj_type>: {
    #     <prefix>: [
    #       "path",
    #       "path2",
    #       ...
    #     ]
    #   },
    #   ...
    # }
    entry_point_paths: dict[str, dict[str, list[str]]] = {}

    # This method configures the paths to search modules in
    # Use this at the start of files before any import (preferably)
    @classmethod
    def setup(cls):
        if cls not in sys.meta_path:
            # The hook is installed first in the list so we can
            # intercept everything to do our magic
            sys.meta_path.insert(0, cls)
            cls.reload()

    # This method will reinitialise the search paths
    # Use this during reloads
    @classmethod
    def reload(cls):
        cls.entry_point_paths = {}
        for obj_type in ep_group_names:
            cls.entry_point_paths[obj_type] = {}

            # Preparing the dict of paths
            candidates = cls.entry_point_paths[obj_type]

            # Entry point paths
            for ep in entry_points(group=ep_group_names[obj_type]):
                if not ep.name.endswith("__root__"):
                    continue
                name = ep.name.removesuffix("__root__")
                if candidates.get(name) is None:
                    candidates[name] = []

                # A special cas for modules that are not namespaces,
                # we store store the entry point itself to detect
                # later on that this was a weird case
                if "." not in ep.value:
                    candidates[name] = ep
                    continue

                p = _entry_point_path(ep)
                if p is not None and p not in candidates[name]:
                    candidates[name].append(p)
                    continue

                p = _entry_point_path_editable(ep, name)
                if p is not None and p not in candidates[name]:
                    candidates[name].extend(p)
                    continue

                if len(candidates[name]) == 0:
                    del candidates[name]

    # This method is used by importlib, you probably will never need
    # to call it yourself, but it is where the magic happens
    # When an import is done, this function will be called for every
    # submodule of the imported module e.g.
    # For import top.middle.bottom, this function will be called thrice
    # with fullname being successively "top", "top.middle" and
    # "top.middle.bottom"
    @classmethod
    def find_spec(cls, fullname: str, path=None, target=None) -> (
                ModuleSpec | None
            ):

        if fullname.startswith("user_"):
            print(colorize(
                "*** Import with the old user_{data_model,projects,target,info"
                "} naming convention detected.",
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

        entry_point_paths = cls.entry_point_paths[obj_type]

        # For the fuddly.{targets,data-models,projects,info} modules, we return
        # a Namespace spec (A ModuleSpec with a submodule_search_location, no
        # loader, and the is_package parameter set to True)
        # This namespace lists where submodules can be found, we add:
        #   * fuddly's user_data_folder/{obj_type}
        #   * fuddly's internal {obj_type} folder
        #   * All the paths found from entry_points
        spec = ModuleSpec(fullname, None, is_package=True)
        if len(parts) == 0:
            spec.submodule_search_locations = [
                    os.path.join(fuddly_data_folder, obj_type),
                    os.path.join(app_folder, obj_type)
                ]
            spec.submodule_search_locations.extend(entry_point_paths.values())
            return spec

        # For the first submodule, we want to check if the submodule in
        # question is in the list of prefixes defined by the entry_points.
        # If it is, we should return a namespace that contains
        #   * Fuddly's user_data_folder/{obj_type}/{prefix}
        #   * fuddly's internal {obj_type}/{prefix}
        #   * the entry_point's search paths
        elif len(parts) == 1:
            # if parts[0] is one of our prefixes, that means we need to
            # create a new virtual namespace packages for the entrypoint
            # it maps to
            prefix = parts[0]
            if prefix in entry_point_paths.keys():
                # For modules that only contains and {obj_type}, they are not
                # namespaces, for them we simply return the spec of the module
                # and call it a day...
                if type(entry_point_paths[prefix]) is EntryPoint:
                    return spec_from_file_location(
                            fullname,
                            entry_point_paths[prefix].load().__spec__.origin)

                # We return a namespace for the submodule
                spec.submodule_search_locations = [
                    os.path.join(
                        fuddly_data_folder,
                        obj_type,
                        prefix
                    ),
                    os.path.join(app_folder, obj_type, prefix)
                ]
                spec.submodule_search_locations.extend(
                        entry_point_paths[prefix]
                    )
                return spec

        # For more than one submodule, we should have set everything up so
        # importlib can handle it
        return None
