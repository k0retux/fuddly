from tools.plotty.Formula import Formula
from tools.plotty.PlottyDatabase import PlottyDatabase
from tools.plotty.cli.parse.range import parse_int_range_union
from tools.plotty.globals import GridMatch, PlottyOptions
from utils import print_warning, print_error

from framework.database import Database

import os
import sys
import argparse

__parser = argparse.ArgumentParser(description='Arguments for Plotty')


def setup_parser():

    group = __parser.add_argument_group('Main parameters')

    group.add_argument(
        '-ids',
        '--data_ids',
        type=str,
        help='The data ids to take into account should be: '
            'either <id_start>..<id_stop>[|<step>], '
            'or <id_start_1>..<id_stop_1>[|<step_1>], ..., <id_start_n>..<id_stop_n>[|<step_n>]',
        required=True
    )

    group.add_argument(
        '-df',
        '--date-format',
        type=str,
        default='%H:%M:%S.%f',
        help='Wanted date format, in a strftime format (1989 C standard). Default is %%H:%%M:%%S.%%f',
        required=False
    )

    group.add_argument(
        '-db',
        '--fmkdb',
        metavar='PATH',
        default=[],
        action='extend',
        nargs="+",
        help='Path to any fmkDB.db files. There can be many if using the --other_id_range option.'
            ' Default is fuddly/data/directory/fmkDB.db',
        required=False
    )

    group = __parser.add_argument_group('Display Options')

    group.add_argument(
        '-f',
        '--formula',
        default='SENT_DATE~ID',
        type=str,
        help='The formula to plot, in the form "y ~ x"',
        required=False
    )

    group.add_argument(
        '-poi',
        '--points-of-interest',
        type=int,
        default=0,
        help='How many point of interest the plot should show. Default is none',
        required=False
    )

    group.add_argument(
        '-gm',
        '--grid-match',
        type=str,
        default='all',
        help="Should the plot grid specifically match some element. Possible options are 'all', "
            "'poi' and 'auto'. Default is 'all'",
        choices=['all', 'poi', 'auto'],
        required=False
    )

    group.add_argument(
        '-hp',
        '--hide-points',
        action='store_true',
        help='Should the graph display every point above the line, or just the line. Default is to display the points',
        required=False
    )

    group = __parser.add_argument_group('Labels Configuration')

    group.add_argument(
        '-l',
        '--labels',
        dest='annotations',
        action='extend',
        nargs='+',
        help='''
        Display the specified labels for each Data ID represented in the curve.
        ('t' for TYPE, 'g' for TARGET, 's' for SIZE, 'a' for ACK_DATE)
        ''',
        required=False
    )

    group.add_argument(
        '-al',
        '--async-labels',
        dest='async_annotations',
        action='extend',
        nargs='+',
        help='''
        Display the specified labels for each Async Data ID represented in the curve.
        ('i' for 'ID', 't' for TYPE, 'g' for TARGET, 's' for SIZE)
        ''',
        required=False
    )

    group = __parser.add_argument_group('Multiple Curves Options')

    group.add_argument(
        '-o',
        '--other-data_ids',
        type=str,
        default=[],
        action='append',
        help='Other data IDs to plot against the main one. All other options also apply to it',
        required=False
    )

    group.add_argument(
        '-s',
        '--vertical-shift',
        type=float,
        default=1,
        help='When --other-id-range is used, specify the spacing between the curves. The shift is '
            'computed as the multiplication between the original curve height and this value',
        required=False
    )


def parse_arguments():

    args = __parser.parse_args()

    fmkdb = args.fmkdb
    if not fmkdb:
        fmkdb = [Database.get_default_db_path()]
    for db in fmkdb:
        if db is not None and not os.path.isfile(os.path.expanduser(db)):
            print_error(f"'{db}' does not exist")
            sys.exit(ERR_INVALID_FMDBK)

    PlottyOptions.fmkdb = list(map(lambda db: PlottyDatabase(db), fmkdb))

    data_ids = args.data_ids
    if data_ids is None:
        __parser.error('Data ids are mandatory')
    PlottyOptions.data_ids = parse_int_range_union(data_ids)
    if len(data_ids) == 0:
        __parser.error('Given data ids evaluate to an empty range')

    formula_str = args.formula
    if formula_str is None:
        __parser.error('Please provide a valid formula')
    formula = Formula.from_string(formula_str)
    if formula is None:
        __parser.error('Cannot parse the given formula')
    PlottyOptions.formula = formula

    poi = args.points_of_interest
    if poi < 0:
        __parser.error('Please provide a positive or zero number of poi')
    PlottyOptions.poi = poi

    grid_match_str = args.grid_match
    if grid_match_str == 'all':
        PlottyOptions.grid_match = GridMatch.ALL
    elif grid_match_str == 'auto':
        PlottyOptions.grid_match = GridMatch.AUTO
    elif grid_match_str == 'poi':
        PlottyOptions.grid_match = GridMatch.POI
        if poi == 0:
            __parser.error("--points-of-interest must be set to use --grid-match 'poi' option")
    else:
        __parser.error(f"Unknown Grid Match value '{grid_match_str}'")

    PlottyOptions.hide_points = args.hide_points

    if args.annotations is None:
        PlottyOptions.annotations = None
    else:
        labels = []
        known_labels = {
            't': 'TYPE',
            'g': 'TARGET',
            's': 'SIZE',
            'a': 'ACK_DATE'
        }
        for label in args.annotations:
            found_label = known_labels.get(label)
            if found_label is None:
                print_warning(f"Discarded unknown label '{label}'")
            else:
                labels.append(found_label)
        PlottyOptions.annotations = labels

    if args.async_annotations is None:
        PlottyOptions.async_annotations = None
    else:
        async_labels = []
        known_labels = {
            'i': 'CURRENT_DATA_ID',
            't': 'TYPE',
            'g': 'TARGET',
            's': 'SIZE'
        }
        for label in args.async_annotations:
            found_label = known_labels.get(label)
            if found_label is None:
                print_warning(f"Discarded unknown async label '{label}'")
            else:
                async_labels.append(found_label)
        PlottyOptions.async_annotations = async_labels

    PlottyOptions.other_data_ids = args.other_data_ids
    max_fmkdb = len(args.other_data_ids) if args.other_data_ids else 0
    if len(PlottyOptions.fmkdb) not in {1, max_fmkdb + 1}:
        __parser.error('Number of given fmkdbs must be one, or match the total number of given data ranges')
    PlottyOptions.other_data_ids = list(map(parse_int_range_union, PlottyOptions.other_data_ids))

    PlottyOptions.vertical_shift = args.vertical_shift

    PlottyOptions.date_format = args.date_format
