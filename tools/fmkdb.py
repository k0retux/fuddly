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

import os
import sys
import inspect
import datetime

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)

from framework.database import Database
from framework.global_resources import get_user_input
from libs.external_modules import *

import argparse

parser = argparse.ArgumentParser(description='Argument for FmkDB toolkit script')

group = parser.add_argument_group('Miscellaneous Options')
group.add_argument('--fmkdb', metavar='PATH', help='Path to an alternative fmkDB.db')
group.add_argument('--no-color', action='store_true', help='Do not use colors')
group.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
group.add_argument('--page-width', type=int, metavar='WIDTH', default=100,
                    help='Width hint for displaying information')

group = parser.add_argument_group('Configuration Handles')
group.add_argument('--fbk-src', metavar='FEEDBACK_SOURCES',
                   help='Restrict the feedback sources to consider (through a regexp). '
                        'Supported by: --data-with-impact, --data-without-fbk, '
                        '--data-with-specific-fbk')
group.add_argument('--project', metavar='PROJECT_NAME',
                   help='Restrict the data to be displayed to a specific project. '
                        'Supported by: --info-by-date, --info-by-ids, '
                        '--data-with-impact, --data-without-fbk, --data-with-specific-fbk')

group = parser.add_argument_group('Fuddly Database Visualization')
group.add_argument('-s', '--all-stats', action='store_true', help='Show all statistics')

group = parser.add_argument_group('Fuddly Database Information')
group.add_argument('-i', '--data-id', type=int, metavar='DATA_ID',
                   help='Provide the data ID on which actions will be performed. Without '
                        'any other parameters the default action is to display '
                        'information on the specified data ID.')
group.add_argument('--info-by-date', nargs=2, metavar=('START','END'),
                   help='''Display information on data sent between START and END '''
                        '''(date format 'Year/Month/Day' or 'Year/Month/Day-Hour' or
                        'Year/Month/Day-Hour:Minute')''')
group.add_argument('-ids', '--info-by-ids', nargs=2, metavar=('FIRST_DATA_ID','LAST_DATA_ID'), type=int,
                   help='''Display information on all the data included within the specified
                   data ID range''')

group.add_argument('-wf', '--with-fbk', action='store_true', help='Display full feedback (expect --data-id)')
group.add_argument('-wd', '--with-data', action='store_true', help='Display data content (expect --data-id)')
group.add_argument('--without-fmkinfo', action='store_true',
                   help='Do not display fmkinfo (expect --data-id)')
group.add_argument('--without-analysis', action='store_true',
                   help='Do not display user analysis (expect --data-id)')
group.add_argument('--limit', type=int, default=None,
                   help='Limit the size of what is displayed from the sent data and the '
                        'retrieved feedback (expect --with-data or --with-fbk).')
group.add_argument('--raw', action='store_true', help='Display data and feedback in raw format')

group = parser.add_argument_group('Fuddly Decoding')
group.add_argument('-dd', '--decode-data', action='store_true',
                   help='Decode sent data based on the data model used for the selected '
                        'data ID or the atome name provided by --atom')
group.add_argument('-df', '--decode-fbk', action='store_true',
                   help='Decode feedback based on the data model used for the selected '
                        'data ID or the atome name provided by --fbk-atom')
group.add_argument('--data-atom', metavar='ATOM_NAME',
                   help="Atom of the data model to be used for decoding the sent data. "
                        "If not provided, the name of the sent data will be used.")
group.add_argument('--fbk-atom', metavar='ATOM_NAME',
                   help="Atom of the data model to be used for decoding feedback. "
                        "If not provided, the default data model decoder will be used (if one exists), "
                        "or the name of the first registered atom in the data model")
group.add_argument('--force-fbk-decoder', metavar='DATA_MODEL_NAME',
                   help="Decode feedback with the decoder of the data model specified")

group = parser.add_argument_group('Fuddly Database Operations')
group.add_argument('--export-data', nargs=2, metavar=('FIRST_DATA_ID','LAST_DATA_ID'), type=int,
                   help='Extract data from provided data ID range')
group.add_argument('-e', '--export-one-data', type=int, metavar='DATA_ID',
                   help='Extract data from the provided data ID')
group.add_argument('--remove-data', nargs=2, metavar=('FIRST_DATA_ID','LAST_DATA_ID'), type=int,
                   help='Remove data from provided data ID range and all related information from fmkDB')
group.add_argument('-r', '--remove-one-data', type=int, metavar='DATA_ID',
                   help='Remove data ID and all related information from fmkDB')

group = parser.add_argument_group('Fuddly Database Analysis')
group.add_argument('--data-with-impact', action='store_true',
                   help="Retrieve data that negatively impacted a target. Analysis is performed "
                        "based on feedback status and user analysis if present")
group.add_argument('--data-with-impact-raw', action='store_true',
                   help="Retrieve data that negatively impacted a target. Analysis is performed "
                        "based on feedback status")
group.add_argument('--data-without-fbk', action='store_true',
                   help="Retrieve data without feedback")
group.add_argument('--data-with-specific-fbk', metavar='FEEDBACK_REGEXP',
                   help="Retrieve data with specific feedback provided as a regexp")
group.add_argument('-a', '--add-analysis', nargs=2, metavar=('IMPACT', 'COMMENT'),
                   help='''Add an impact analysis to a specific data ID (expect --data-id).
                        IMPACT should be either 0 (no impact) or 1 (impact), and COMMENT 
                        provide information''')
group.add_argument('--disprove-impact', nargs=2, metavar=('FIRST_ID', 'LAST_ID'), type=int,
                   help='''Disprove the impact of a group of data present in the outcomes of 
                   '--data-with-impact-raw'. The group is determined by providing the smaller data ID 
                   (FIRST_ID) and the bigger data ID (LAST_ID).''')

def handle_confirmation():
    try:
        cont = get_user_input(colorize("\n*** Press [ENTER] to continue ('C' to CANCEL) ***\n",
                                       rgb=Color.PROMPT))
    except KeyboardInterrupt:
        cont = 'c'
    except Exception as e:
        print(f'Unexpected exception received: {e}')
        cont = 'c'
    finally:
        if cont.lower() == 'c':
            print(colorize("*** Operation Cancelled ***", rgb=Color.ERROR))
            fmkdb.stop()
            sys.exit(-1)

def handle_date(date_str):
    try:
        date = datetime.datetime.strptime(date_str, "%Y/%m/%d")
    except ValueError:
        try:
            date = datetime.datetime.strptime(date_str, "%Y/%m/%d-%H")
        except ValueError:
            try:
                date = datetime.datetime.strptime(date_str, "%Y/%m/%d-%H:%M")
            except ValueError:
                print(colorize("*** ERROR: Unrecognized Dates ***", rgb=Color.ERROR))
                fmkdb.stop()
                sys.exit(-1)

    return date


if __name__ == "__main__":

    args = parser.parse_args()

    fmkdb = args.fmkdb
    if fmkdb is not None and not os.path.isfile(fmkdb):
        print(colorize("*** ERROR: '{:s}' does not exist ***".format(fmkdb), rgb=Color.ERROR))
        sys.exit(-1)

    verbose = args.verbose
    colorized = not args.no_color
    if not colorized:
        def colorize(string, rgb=None, ansi=None, bg=None, ansi_bg=None, fd=1):
            return string

    page_width = args.page_width

    display_stats = args.all_stats

    data_ID = args.data_id
    data_info_by_date = args.info_by_date
    data_info_by_range = args.info_by_ids
    prj_name = args.project
    with_fbk = args.with_fbk
    with_data = args.with_data
    without_fmkinfo = args.without_fmkinfo
    without_analysis = args.without_analysis
    limit_data_sz = args.limit
    raw_data = args.raw

    export_data = args.export_data
    export_one_data = args.export_one_data
    remove_data = args.remove_data
    remove_one_data = args.remove_one_data

    decode_data = args.decode_data
    decode_fbk = args.decode_fbk
    forced_fbk_decoder = args.force_fbk_decoder
    data_atom_name = args.data_atom
    fbk_atom_name = args.fbk_atom

    impact_analysis = args.data_with_impact
    raw_impact_analysis = args.data_with_impact_raw
    data_without_fbk = args.data_without_fbk
    fbk_src = args.fbk_src
    data_with_specific_fbk = args.data_with_specific_fbk
    add_analysis = args.add_analysis
    disprove_impact = args.disprove_impact

    if decode_data or decode_fbk:
        from framework.plumbing import *
        fmk = FmkPlumbing(quiet=True)
        fmk.get_data_models(fmkDB_update=False)
        dm_list = copy.copy(fmk.dm_list)
        decoding_hints = (fmk._name2dm,
                          decode_data, decode_fbk,
                          data_atom_name, fbk_atom_name, forced_fbk_decoder)
    else:
        dm_list = None
        decoding_hints = None

    fmkdb = Database(fmkdb_path=fmkdb)
    ok = fmkdb.start()
    if not ok:
        print(colorize("*** ERROR: The database {:s} is invalid! ***".format(fmkdb.fmk_db_path),
                       rgb=Color.ERROR))
        sys.exit(-1)

    now = datetime.datetime.now()

    if display_stats:

        fmkdb.display_stats(colorized=colorized)

    elif add_analysis is not None:
        try:
            ia_impact = int(add_analysis[0])
        except ValueError:
            print('*** IMPACT argument is incorrect! ***')
        else:
            ia_comment = add_analysis[1]
            fmkdb.insert_analysis(data_ID, ia_comment, now, impact=bool(ia_impact))


    elif disprove_impact is not None:

        first_data_id = disprove_impact[0]
        last_data_id = disprove_impact[1]

        data_list = fmkdb.get_data_with_impact(prj_name=prj_name, fbk_src=fbk_src, display=False,
                                               raw_analysis=True)
        data_list = sorted(data_list)

        if first_data_id not in data_list or last_data_id not in data_list:
            print('*** Error with provided data IDs! ***')
        else:
            idx_first = data_list.index(first_data_id)
            idx_last = data_list.index(last_data_id)
            data_list_to_disprove = data_list[idx_first:idx_last + 1]

            for data_id in data_list_to_disprove:
                fmkdb.insert_analysis(data_id, "Impact is disproved by user analysis. (False Positive.)",
                                      now, impact=False)

    elif data_ID is not None:

        fmkdb.display_data_info(data_ID, with_data=with_data, with_fbk=with_fbk,
                                with_fmkinfo=not without_fmkinfo,
                                with_analysis=not without_analysis,
                                fbk_src=fbk_src,
                                limit_data_sz=limit_data_sz, raw=raw_data, page_width=page_width,
                                colorized=colorized, decoding_hints=decoding_hints, dm_list=dm_list)

    elif data_info_by_date is not None:

        start = handle_date(data_info_by_date[0])
        end = handle_date(data_info_by_date[1])

        fmkdb.display_data_info_by_date(start, end, with_data=with_data, with_fbk=with_fbk,
                                        with_fmkinfo=not without_fmkinfo, fbk_src=fbk_src,
                                        prj_name=prj_name,
                                        limit_data_sz=limit_data_sz, raw=raw_data, page_width=page_width,
                                        colorized=colorized, decoding_hints=decoding_hints, dm_list=dm_list)

    elif data_info_by_range is not None:

        first_id=data_info_by_range[0]
        last_id=data_info_by_range[1]

        fmkdb.display_data_info_by_range(first_id, last_id, with_data=with_data, with_fbk=with_fbk,
                                         with_fmkinfo=not without_fmkinfo, fbk_src=fbk_src,
                                         prj_name=prj_name,
                                         limit_data_sz=limit_data_sz, raw=raw_data, page_width=page_width,
                                         colorized=colorized, decoding_hints=decoding_hints, dm_list=dm_list)

    elif export_data is not None or export_one_data is not None:

        if export_data is not None:
            fmkdb.export_data(first=export_data[0], last=export_data[1], colorized=colorized)
        else:
            fmkdb.export_data(first=export_one_data, colorized=colorized)

    elif remove_data is not None or remove_one_data is not None:
        handle_confirmation()
        if remove_data is not None:
            for i in range(remove_data[0], remove_data[1]+1):
                fmkdb.remove_data(i, colorized=colorized)
        else:
            fmkdb.remove_data(remove_one_data, colorized=colorized)

    elif impact_analysis or raw_impact_analysis:
        fmkdb.get_data_with_impact(prj_name=prj_name, fbk_src=fbk_src, verbose=verbose,
                                   raw_analysis=raw_impact_analysis,
                                   colorized=colorized)

    elif data_without_fbk:
        fmkdb.get_data_without_fbk(prj_name=prj_name, fbk_src=fbk_src, colorized=colorized)

    elif data_with_specific_fbk:
        fmkdb.get_data_with_specific_fbk(data_with_specific_fbk, prj_name=prj_name, fbk_src=fbk_src,
                                         colorized=colorized)

    fmkdb.stop()
