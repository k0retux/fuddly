import sys

import fuddly.cli.argparse_wrapper as argparse
from fuddly.cli import get_data_models
from fuddly.cli.error import CliException
from fuddly.libs.fmk_services import create_data_model_dict
from fuddly.libs.external_modules import colorize, Color
from fuddly.framework.global_resources import Verbose


def start(args: argparse.Namespace) -> int:
    if args.data_model is None:
        raise CliException("Missing data model name")

    if args.data_model == "list":
        for dm in get_data_models():
            name, _, _ = dm
            print(name)
        return 0

    name2dm = create_data_model_dict()
    dm = name2dm.get(args.data_model)
    if dm is None:
        raise CliException("Incorrect data model name")

    prj_obj = None
    try:
        dm.load_data_model(name2dm, from_prj=prj_obj)
    except:
        msg = (f"Error encountered while loading the data model. "
               f"(checkup the associated '{dm.name}.py' file)")
        sys.stderr(msg)
    else:
        verbose = Verbose.Heavy if args.verbose else Verbose.Normal
        atom_name = args.atom_name
        debug = False

        data_str = input(colorize("*** Data to be decoded:\n", rgb=Color.PROMPT))
        data = eval(data_str)

        if dm.is_existing(atom_name):
            decoded_result = dm.decode(data, atom_name=atom_name,
                                       verbose=verbose, debug=debug)
        else:
            decoded_result = dm.decode(data, verbose=verbose, debug=debug)

        _, decoded_str = decoded_result
        print(decoded_str)

    return 0
