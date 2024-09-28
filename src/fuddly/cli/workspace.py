import fuddly.cli.argparse_wrapper as argparse
from fuddly.framework import global_resources as gr
from pathlib import Path
import subprocess
import sys


def start(args: argparse.Namespace) -> int:
    # Lol, the argument is always in clean 🙃
    match args.clean:
        case "clean":
            (_, folders, files) = next(Path(gr.workspace_folder).walk())
            if len(files) > 0 or len(folders) > 0:
                print("The workspace contains the folowing files:")
                subprocess.run(["tree", gr.workspace_folder], stdout=sys.stdout)
                match input("Remove anyway? [y/N]"):
                    case "y"|"Y":
                        # FIXME, I can't be bothered to do a proper recursive delete of the content
                        subprocess.run(["rm", "-r", gr.workspace_folder])
                        # Recreating the folder
                        Path(gr.workspace_folder).mkdir()
                    case _:
                        print("Canceled")
            else:
                print("Workspace empty")
        case "show":
            print(gr.workspace_folder) 
