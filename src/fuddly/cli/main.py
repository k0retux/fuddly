#!/usr/bin/env python

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

from typing import List
from fuddly.cli import * 
from fuddly.cli.error import CliException

def main(argv: List[str] = None):
    # This is done so you can call it from python shell if you want to
    # and give it parameters like:
    #
    #   main("run some_script some important args".split())
    #
    if argv is not None:
        sys.argv[0] = "fuddly"
        sys.argv.extend(argv)

    # FIXME: The parse still exits on error
    parsers = {}
    arg_parser = parsers["main"] = argparse.ArgumentParser(exit_on_error=False)
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
        # XXX Should you be able to run script from outside the script dir(s?) ?
        parsers["run"] = p
        group = p.add_mutually_exclusive_group()
        group.add_argument(
            "--list",
            action="store_true",
            help="list all available scripts",
        )
        group.add_argument(
            "script",
            nargs="?",
            help="Name of the script to launch",
        )
        p.add_argument(
            "args",
            action="append",
            nargs=argparse.REMAINDER,
            help="Arguments to passthrough to the script",
        )


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
            choices=["dm", "data-model", "project"], 
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
        p.add_argument(
            "args",
            action="append",
            nargs=argparse.REMAINDER,
            help="Arguments to passthrough to the tool",
        )

    with subparsers.add_parser("workspace", help="Manage fuddly's workspace") as p:
        parsers["workspace"] = p
        p.add_argument(
            "clean",
            nargs="?",
            help="Remove everything from the workspace",
        )
        p.add_argument(
            "show",
            nargs="?",
            help="Print the path to the workspace",
        )

    args = arg_parser.parse_args()

    if args.action is None:
        arg_parser.print_help()
        return 0

    # I prefer the seccond method, but both are ugly
    #exec(args.action + "(args)")
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

if __name__ == "__main__":
    sys.exit(main(sys.argv))
