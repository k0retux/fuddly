import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli.error import CliException
from fuddly.framework import global_resources as gr
from pathlib import Path
import subprocess
import sys
import os


def clean_workspace(path):
    for path_, dirs, files in os.walk(path):
        path = Path(path_)
        list(map(lambda f: (path/f).unlink(), files))
        list(map(lambda d: clean_workspace(path/d), dirs))
        dirs.clear()
        path.rmdir()


def start(args: argparse.Namespace) -> int:
    # Lol, the argument is always in clean 🙃
    if args.clean:
        (_, folders, files) = next(Path(gr.workspace_folder).walk())
        if len(files) > 0 or len(folders) > 0:
            print("The workspace contains the folowing files:")
            subprocess.run(["tree", gr.workspace_folder], stdout=sys.stdout)
            match input("Remove? [y/N]"):
                case "y" | "Y":
                    clean_workspace(gr.workspace_folder)
                    # Recreating the folder
                    Path(gr.workspace_folder).mkdir()
                case _:
                    print("Canceled")
        else:
            print("Workspace empty")
    elif args.show:
        # Print the path as an OSC-8 link
        # Copliant terminals, should ignore the escape sequence if they don't understand it.
        print("\033]8;;", end="")
        print(gr.workspace_folder, end="")
        print("\033\\", end="")
        print(gr.workspace_folder, end="")
        print("\033]8;;\033\\")
    else:
        raise CliException("Either --clean or --show is required")
