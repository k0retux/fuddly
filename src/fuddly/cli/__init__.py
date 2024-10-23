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

import sys
import os
import fuddly.cli.argparse_wrapper as argparse
import importlib

import argcomplete 
from argcomplete.completers import ChoicesCompleter, SuppressCompleter

from typing import List
from fuddly.cli import * 
from fuddly.cli.error import CliException

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
            argv=argv.split(" ")

    parsers = {}
    arg_parser = parsers["main"] = argparse.ArgumentParser(
            prog="fuddly", 
            description="The fuddly cli interface",
            epilog="Use fuddly <action> help more information on their arguments",
            exit_on_error=False
        )
    subparsers = arg_parser.add_subparsers(help="", dest="action", metavar="action")

    with subparsers.add_parser("shell", help="Launch the fuddly interactive shell") as p:
        parsers["shell"] = p
        group = p.add_argument_group("Miscellaneous Options")
        group.add_argument(
            "-f",
            "--fmkdb",
            metavar="PATH",
            help="Path to an alternative fmkDB.db. Create " "it if it does not exist.",
        )
        group.add_argument(
            "--external-display",
            action="store_true",
            help="Display information on another terminal.",
        )
        group.add_argument(
            "--quiet",
            action="store_true",
            help="Limit the information displayed at startup.",
        )

    with subparsers.add_parser("run", help="Run a fuddly project script") as p:
        from .run import get_scripts, script_argument_completer
        # XXX Should you be able to run script from outside the script dir(s?) ?
        parsers["run"] = p
        group = p.add_argument_group()
        group.add_argument(
            "--list",
            action="store_true",
            help="list all available scripts",
        ) 

        group.add_argument(
            "script",
            nargs="?",
            help="Name of the script to launch",
            metavar="script",
        ).completer=ChoicesCompleter(get_scripts())

        # TODO add arg completion for scripts
        p.add_argument(
            "args",
            action="append",
            nargs=argparse.REMAINDER,
            help="Arguments to pass through to the script",
        ).completer = SuppressCompleter() #script_argument_completer



    with subparsers.add_parser("new", help="Create a new project or data model") as p:
        parsers["new"] = p
        p.add_argument(
            "--dest",
            metavar="PATH",
            type=argparse.PathType(
                dash_ok=False,
                type="dir"
            ),
            help="directory to create the target in.",
        )
        p.add_argument(
            "--pyproject",
            action="store_true",
            help="Create a python package project structure"
        )
        p.add_argument(
            "target", 
            choices=["dm", "data-model", "project:skeleton", "project:exemple" ], 
            metavar = "target",
            help="Type of object to create. [dm, data-model, project]",
        )
        p.add_argument(
            "name",
            help="Name to give the create target.",
        )

    with subparsers.add_parser("tool", help="Execute a fuddly tool") as p:
        parsers["tool"] = p
        with p.add_mutually_exclusive_group() as g:
            g.add_argument(
                "--list",
                action="store_true",
                required=False,
                help="List all available tools",
            )
            g.add_argument(
                "tool",
                nargs='?',
                help="Name of the tool to launch",
            )

        # TODO add completion for tools
        p.add_argument(
            "args",
            action="append",
            nargs=argparse.REMAINDER,
            help="Arguments to passthrough to the tool",
        ).completer = SuppressCompleter() 

    with subparsers.add_parser("workspace", help="Manage fuddly's workspace") as p:
        parsers["workspace"] = p
        group = p.add_mutually_exclusive_group()
        group.add_argument(
            "--show",
            action="store_true",
            help="Print the path to the workspace",
        )
        group.add_argument(
            "--clean",
            action="store_true",
            help="Remove everything from the workspace",
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
