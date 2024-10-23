import fuddly.cli.argparse_wrapper as argparse

import importlib
import sys

def start(args: argparse.Namespace) -> int:

    if args.list:
        print("Get the list of tools")
        raise NotImplementedError("Not implemented")
        return 0

    sys.argv=[]
    sys.argv.append(args.tool)
    sys.argv.extend(args.args[0]) # Why is this an array, that's weird - someting to do with nargs?
    
    if args.tool is None:
        print("TODO: Handle missing tool name")
        return 1

    try:
        pkg = importlib.util.find_spec(f"fuddly.tools.{args.tool}")
        if pkg is None:
            print(f"{args.tool} is not a valide fuddly tool")
            return 1
        mod = pkg.loader.load_module()
        return mod.main()
    except Exception as e:
        print(f"Error while starting {args.tool}: {e}")
        return 1
