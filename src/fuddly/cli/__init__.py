#PYTHON_ARGCOMPLETE_OK
################################################################################
#
#  Copyright 2014-2016 Eric Lacombe <eric.lacombe@security-labs.org>
#
################################################################################
#
#  This file is part of fuddly.
#
#  fuddly is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  fuddly is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with fuddly. If not, see <http://www.gnu.org/licenses/>
#
################################################################################

import argcomplete
import fuddly.cli.argparse_wrapper as argparse
import importlib
import sys
from typing import List

# TODO script_argument_completer will be used once a sub-script argument completion logic is developped
from fuddly.cli.run import script_argument_completer
# TODO tool_argument_completer will be used once a sub-script argument completion logic is developped
from fuddly.cli.tool import tool_argument_completer
from fuddly.cli.utils import (
    get_projects,
    get_tools,
    get_all_object_names,
    get_project_scripts, get_data_models,
)
from fuddly.cli.error import CliException

# Import magic
# import fuddly.{obj_type} will find targets, data_models, projects or info
# automagically wethere they are define in an entry point, as part of fuddly's
# core or in the user_data_folder
from fuddly.libs.importer import fuddly_importer_hook
fuddly_importer_hook.setup()


def main(argv: List[str] = None):
    # This is done so you can call it from python shell if you want to
    # and give it parameters like:
    #
    #   main(["run", "some_script", "some", "important args"])
    #    or
    #   main("run some_script some important args")
    #
    #   This second for can not have space in the arguments, but so be it...
    #
    match argv:
        case None:
            argv = sys.argv[1:]
        case str():
            argv = argv.split(" ")

    parsers = {}
    arg_parser = parsers["main"] = argparse.ArgumentParser(
            prog="fuddly",
            description="the fuddly cli interface",
            epilog="use 'fuddly <action>' help more information on their arguments",
            exit_on_error=False
        )
    parsers["main"].add_argument(
        "-v",
        "--version",
        action="store_true",
        help="print the vesion and exit",
    )

    subparsers = arg_parser.add_subparsers(help="", dest="action", metavar="action")

    with subparsers.add_parser("shell", help="launch the fuddly interactive shell") as p:
        parsers["shell"] = p
        group = p.add_argument_group("Miscellaneous Options")
        group.add_argument(
            "-f",
            "--fmkdb",
            metavar="PATH",
            help="path to an alternative fmkDB.db. Create " "it if it does not exist.",
        )
        group.add_argument(
            "--external-display",
            action="store_true",
            help="display information on another terminal.",
        )
        group.add_argument(
            "--quiet",
            action="store_true",
            help="limit the information displayed at startup.",
        )

    with subparsers.add_parser("ishell", help="launch fuddly within IPython") as p:
        parsers["ishell"] = p
        group = p.add_argument_group("Miscellaneous Options")
        group.add_argument(
            "-f",
            "--fmkdb",
            metavar="PATH",
            help="path to an alternative fmkDB.db. Create " "it if it does not exist.",
        )
        group.add_argument(
            "--external-display",
            action="store_true",
            help="display information on another terminal.",
        )
        group.add_argument(
            "--quiet",
            action="store_true",
            help="limit the information displayed at startup.",
        )


    with subparsers.add_parser("run", help="run a fuddly project script") as p:
        # XXX Should you be able to run script from outside the script dirs?
        parsers["run"] = p

        p.add_argument(
            "--ipython",
            action="store_true",
            help="tun the script using ipython",
        )

        p.add_argument(
            "project",
            help="Project who's script to launch",
            choices=["list", *map(lambda x: x[0], get_projects())],
        )

        #p.add_argument(
        #    "script",
        #    metavar="script",
        #    help="name of the script to launch, the special value \"list\" list available scripts",
        #).completer = get_project_scripts

        # TODO add arg completion for scripts
        p.add_argument(
            "script",
            metavar="script",
            nargs=argparse.REMAINDER,
            help="name of the script to launch and it's arguments, the special value \"list\" list available scripts",
            #help="arguments to pass through to the script",
        ).completer = get_project_scripts
        #)  # .completer = script_argument_completer

    with subparsers.add_parser("new", help="create a new project or data model") as p:
        parsers["new"] = p
        p.add_argument(
            "--dest",
            metavar="PATH",
            type=argparse.PathType(
                dash_ok=False,
                type="dir"
            ),
            help="directory to create the object in.",
        )
        p.add_argument(
            "--pyproject",
            action="store_true",
            help="create a python package project structure"
        )
        with p.add_mutually_exclusive_group() as g:
            g.add_argument(
                "--clone",
                metavar="object_name",
                help="name of the object to clone.",
                choices=["list", *get_all_object_names()],
            )
            g.add_argument(
                "--type",
                choices=["dm", "data-model", "project:bare"],
                # This one has not yet been create: "project:example"
                metavar="object",
                help="type of object to create. [dm, data-model, project:bare]",
            )
        p.add_argument(
            "name",
            help="name to give the create object.",
        )

    with subparsers.add_parser("tool", help="execute a fuddly tool") as p:
        parsers["tool"] = p
        p.add_argument(
            "tool",
            metavar="tool",
            help="name of the tool to launch, the special value \"list\" list available tools",
            choices=["list", *get_tools()],
        )
        # TODO add arg completion for tools
        p.add_argument(
            "args",
            nargs=argparse.REMAINDER,
            help="arguments to passthrough to the tool",
            # TODO Add back when something is implemented
        )  # .completer = tool_argument_completer

    with subparsers.add_parser("workspace", help="manage fuddly's workspace") as p:
        parsers["workspace"] = p
        group = p.add_mutually_exclusive_group()
        group.add_argument(
            "--show",
            action="store_true",
            help="print the path to the workspace",
        )
        group.add_argument(
            "--clean",
            action="store_true",
            help="remove everything from the workspace",
        )

    with subparsers.add_parser("show", help="display the README file of a specified Project") as p:
        parsers["show"] = p
        group = p.add_argument_group("Miscellaneous Options")
        group.add_argument(
            "project",
            metavar="project",
            help="name of the project to show, the special value \"list\" list available projects",
            choices=["list", *map(lambda x: x[0], get_projects())],
        )


    with subparsers.add_parser("decode", help="decode the arguments leveraging the provided data model" ) as p:
        parsers["decode"] = p
        p.add_argument(
            "data_model",
            metavar="DATA_MODEL",
            help="name of the data model to use for decoding, the special value \"list\" list available data models",
            choices=["list", *map(lambda x: x[0], get_data_models())],
        )
        group = p.add_argument_group("Miscellaneous Options")
        group.add_argument(
            "-v", "--verbose",
            action='store_true',
            help="verbose mode",
        )
        group = p.add_argument_group("Decoding constraints")
        group = group.add_mutually_exclusive_group()
        group.add_argument(
            "--atom",
            metavar="ATOM_NAME",
            help="optional atom name to support the decoding",
        )
        group.add_argument(
            "--scope",
            metavar="SCOPE",
            type=str,
            help="optional scope to support the decoding",
        )
        group = p.add_mutually_exclusive_group()
        group.add_argument(
            "-d",
            "--data",
            metavar="DATA",
            type=str,
            help="optional data to decode",
        )
        group.add_argument(
            "-f",
            "--from",
            dest='file_path',
            metavar="FILE_PATH",
            type=argparse.PathType(
                dash_ok=False,
                type="file"
            ),
            help="optional file path from which data to decode shall be retrieved",
        )


    # Needed because we set exit_on_error=False in the constructor
    try:
        argcomplete.autocomplete(arg_parser)
        args = arg_parser.parse_args(args=argv)
    except argparse.ArgumentError as e:
        print(e.message)
        print()
        arg_parser.print_help()
        return 0

    if args.version:
        from fuddly.framework.global_resources import fuddly_version
        print(fuddly_version)
        return 0

    if args.action is None:
        arg_parser.print_help()
        return 0

    try:
        m = importlib.import_module(f"fuddly.cli.{args.action}")
        return m.start(args)
    except CliException as e:
        print(e.message)
        print()
        parsers[args.action].print_help()
        return 1
    except NotImplementedError:
        print("This function has not been implemented yet")
        return 1
