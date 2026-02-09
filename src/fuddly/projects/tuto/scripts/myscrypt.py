from fuddly.framework.plumbing import FmkPlumbing
from fuddly.framework.data import DataProcess
import argparse

parser = argparse.ArgumentParser(description='nFMS script')
group = parser.add_argument_group('Miscellaneous Options')
group.add_argument('-s', '--scenario', metavar='Scenario ID',
                   type=int, default=-1, help='scenario to execute')
group.add_argument("-n", "--scenario-name", dest="name", metavar="Scenario name",
                   help="Textual name of a scenario")
group.add_argument('-v', '--verbose', action='store_true', help='Verbose display')


fmk = FmkPlumbing(quiet=True)
fmk.start()

try:
    args = parser.parse_args()
    verbose = args.verbose

    fmk.run_project(name='tuto')
    fmk.lg.set_log_format(raw=True)

    if args.name is None and args.scenario == -1:

        fmk.process_data_and_send(DataProcess(['SC_FRAG_NOMINAL']), max_loop=1)

    elif args.scenario == 0:

        fmk.process_data_and_send(DataProcess(['SC_FRAG_NOMINAL']), max_loop=-1)

    else:
        raise NotImplementedError

except:
    raise
finally:
    fmk.collect_residual_feedback()
    fmk.stop()