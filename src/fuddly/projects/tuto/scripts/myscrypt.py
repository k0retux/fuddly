from fuddly.framework.plumbing import FmkPlumbing
from fuddly.framework.data import DataProcess
from fuddly.framework.scenario_bricks import FragmentationBrick, FRAG_POL
from fuddly.framework.global_resources import UI
import argparse

parser = argparse.ArgumentParser(description='Tutorial script')
group = parser.add_argument_group('Miscellaneous Options')
group.add_argument("-s", "--scenario-name", dest="name", metavar="SCENARIO_NAME",
                   help="Name of the scenario to execute", type=str, default='valid_ordered')
group.add_argument("-d", "--description", action='store_true',
                   help="Display the scenario description")
group.add_argument('-n', '--nb-steps', type=int, default=-1, metavar='NUMBER_OF_STEPS',
                   help='Do not execute the scenario entirely but only the specified number of steps')
group.add_argument('-v', '--verbose', action='store_true', help='Verbose display')
group.add_argument("--fcount", dest='fragment_count', metavar="FRAGMENT_COUNT",
                   help="Number of fragment to generate [parameter used when relevant]",
                   type=int, default=3)
group.add_argument("--fpolicy", dest='fragment_policy', metavar="FRAGMENT_POLICY",
                   help="Policy for fragment generation (1=equal_sz, 2=increasing_sz, 3=decreasing_sz)",
                   type=int, default=3)
group.add_argument("--add-frag", dest='add_frag_to_send', metavar="ADDITIONAL_FRAGMENT",
                   help='Number of fragment to be sent in addition to the nominal case'
                        ' (by repeating some fragment)',
                   type=int, default=5)
group.add_argument('--update-pld-size', action='store_true',
                   help='Force the size value of the node referenced by @pldsz_ref '
                        'in the fragment wrt. the payload size before sending.')


args = parser.parse_args()
verbose = args.verbose


fmk = FmkPlumbing(quiet=True)
fmk.start()

sc_name = {
    'valid_ordered': 'SC_FRAG_2_VALID_ORDERED',
    'valid_unordered': 'SC_FRAG_2_VALID_UNORDERED',
    'sz01': 'SC_FRAG_2_SZ01',
    'alt01A': 'SC_FRAG_2_ALT01A',
    'alt01B': 'SC_FRAG_2_ALT01B',
    'alt02A': 'SC_FRAG_2_ALT02A',
    'alt02B': 'SC_FRAG_2_ALT02B',
    'alt03': 'SC_FRAG_2_ALT03',
    'alt04': 'SC_FRAG_2_ALT04',
    'alt05A': 'SC_FRAG_2_ALT05A',
    'alt05B': 'SC_FRAG_2_ALT05B',
    'alt06A': 'SC_FRAG_2_ALT06A',
    'alt06B': 'SC_FRAG_2_ALT06B',
    'alt07A': 'SC_FRAG_2_ALT07A',
    'alt07B': 'SC_FRAG_2_ALT07B',
    'alt08': 'SC_FRAG_2_ALT08',
    'alt09': 'SC_FRAG_2_ALT09',
    'alt10': 'SC_FRAG_2_ALT10',
    'alt11': 'SC_FRAG_2_ALT11',
}

frag_pol_from_int = {
    1: FRAG_POL.EQUAL_SZ,
    2: FRAG_POL.INCREASING_SZ,
    3: FRAG_POL.DECREASING_SZ
}

def get_params_from_shape(shape_id, ui: dict):
    ret = FragmentationBrick.scenario_parameters_per_shape_id(shape_id)
    params = {}
    for k, obj in ret.items():
        _, value, _ = obj
        if k in ui:
            value = ui[k]
        params[k] = value

    specific_ui = UI()
    specific_ui.set_user_inputs(params)

    return specific_ui

try:

    user_inputs = {
        'fragment_count': args.fragment_count,
        'fragment_policy': frag_pol_from_int[args.fragment_policy],
        'add_frag_to_send': args.add_frag_to_send,
        'update_pld_size': args.update_pld_size
    }

    ui = get_params_from_shape(args.name, user_inputs)

    fmk.run_project(name='tuto')
    fmk.lg.set_log_format(raw=True)

    if args.description:
        fmk.show_generators(sc_name[args.name])

    else:
        fmk.process_data_and_send(
            DataProcess([(sc_name[args.name], ui)]),
            verbose=args.verbose,
            max_loop=args.nb_steps)


except:
    raise
finally:
    fmk.collect_residual_feedback()
    fmk.stop()