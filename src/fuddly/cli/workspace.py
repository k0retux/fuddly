import fuddly.cli.argparse_wrapper as argparse
from .error import  CliException
from fuddly.framework import global_resources as gr
from pathlib import Path
import subprocess
import sys
import os

def clean_workspace(path):
    for path, dirs, files in os.walk(path):
        p = Path(path)
        list(map(lambda x: (p/x).unlink(), files))
        list(map(lambda x: clean_workspace(p/x), dirs))
        p.rmdir()

def start(args: argparse.Namespace) -> int:
    # Lol, the argument is always in clean 🙃
    if args.clean:
            (_, folders, files) = next(Path(gr.workspace_folder).walk())
            if len(files) > 0 or len(folders) > 0:
                print("The workspace contains the folowing files:")
                subprocess.run(["tree", gr.workspace_folder], stdout=sys.stdout)
                match input("Remove? [y/N]"):
                    case "y"|"Y":
                        clean_workspace(gr.workspace_folder)
                        # Recreating the folder
                        Path(gr.workspace_folder).mkdir()
                    case _:
                        print("Canceled")
            else:
                print("Workspace empty")
    elif args.show:
        # TODO test for OSC-8 cap before using it?
        print("\033]8;;", end="")
        print(gr.workspace_folder, end="") 
        print("\033\\", end="")
        print(gr.workspace_folder, end="") 
        print("\033]8;;\033\\")
    else:
        raise CliException("One of --clean or --show is required")

