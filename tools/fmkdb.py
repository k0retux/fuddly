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
from datetime import datetime

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)

from framework.database import Database
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
group.add_argument('-i', '--info', type=int, metavar='DATA_ID',
                   help='Display information on the specified data ID')
group.add_argument('--info-by-date', nargs=2, metavar=('START','END'),
                   help='''Display information on data sent between START and END '''
                        '''(date format 'Year/Month/Day' or 'Year/Month/Day-Hour' or
                        'Year/Month/Day-Hour:Minute')''')
group.add_argument('--info-by-ids', nargs=2, metavar=('FIRST_DATA_ID','LAST_DATA_ID'), type=int,
                   help='''Display information on all the data included within the specified
                   data ID range''')

group.add_argument('--with-fbk', action='store_true', help='Display full feedback (expect --info)')
group.add_argument('--with-data', action='store_true', help='Display data content (expect --info)')
group.add_argument('--without-fmkinfo', action='store_true',
                   help='Do not display fmkinfo (expect --info)')
group.add_argument('--limit', type=int, default=600,
                   help='Limit the size of what is displayed from data (expect --with-data)')

group = parser.add_argument_group('Fuddly Database Operations')
group.add_argument('--export-data', nargs=2, metavar=('FIRST_DATA_ID','LAST_DATA_ID'), type=int,
                   help='Extract data from provided data ID range')
group.add_argument('-e', '--export-one-data', type=int, metavar='DATA_ID',
                   help='Extract data from the provided data ID')
group.add_argument('--remove-data', type=int, metavar='DATA_ID',
                   help='Remove data ID and all related information from fmkDB')

group = parser.add_argument_group('Fuddly Database Analysis')
group.add_argument('--data-with-impact', action='store_true',
                   help="Retrieve data that negatively impacted a target")
group.add_argument('--data-without-fbk', action='store_true',
                   help="Retrieve data without feedback")
group.add_argument('--data-with-specific-fbk', metavar='FEEDBACK_REGEXP',
                   help="Retrieve data with specific feedback provided as a regexp")



def handle_confirmation():
    try:
        if sys.version_info[0] == 2:
            cont = raw_input("\n*** Press [ENTER] to continue ('C' to CANCEL) ***\n")
        else:
            cont = input("\n*** Press [ENTER] to continue ('C' to CANCEL) ***\n")
    except KeyboardInterrupt:
        cont = 'c'
    except:
        cont = 'c'
    finally:
        if cont.lower() == 'c':
            print(colorize("*** Operation Cancelled ***", rgb=Color.ERROR))
            sys.exit(-1)

def handle_date(date_str):
    try:
        date = datetime.strptime(date_str, "%Y/%m/%d")
    except ValueError:
        try:
            date = datetime.strptime(date_str, "%Y/%m/%d-%H")
        except ValueError:
            try:
                date = datetime.strptime(date_str, "%Y/%m/%d-%H:%M")
            except ValueError:
                print(colorize("*** ERROR: Unrecognized Dates ***", rgb=Color.ERROR))
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

    data_info = args.info
    data_info_by_date = args.info_by_date
    data_info_by_range = args.info_by_ids
    prj_name = args.project
    with_fbk = args.with_fbk
    with_data = args.with_data
    without_fmkinfo = args.without_fmkinfo
    limit_data_sz = args.limit

    export_data = args.export_data
    export_one_data = args.export_one_data
    remove_data = args.remove_data

    impact_analysis = args.data_with_impact
    data_without_fbk = args.data_without_fbk
    fbk_src = args.fbk_src
    data_with_specific_fbk = args.data_with_specific_fbk

    fmkdb = Database(fmkdb_path=fmkdb)
    ok = fmkdb.start()
    if not ok:
        print(colorize("*** ERROR: The database {:s} is invalid! ***".format(fmkdb.fmk_db_path),
                       rgb=Color.ERROR))
        sys.exit(-1)

    if display_stats:

        fmkdb.display_stats(colorized=colorized)

    elif data_info is not None:

        fmkdb.display_data_info(data_info, with_data=with_data, with_fbk=with_fbk,
                                with_fmkinfo=not without_fmkinfo, fbk_src=fbk_src,
                                limit_data_sz=limit_data_sz, page_width=page_width,
                                colorized=colorized)

    elif data_info_by_date is not None:

        start = handle_date(data_info_by_date[0])
        end = handle_date(data_info_by_date[1])

        fmkdb.display_data_info_by_date(start, end, with_data=with_data, with_fbk=with_fbk,
                                        with_fmkinfo=not without_fmkinfo, fbk_src=fbk_src,
                                        prj_name=prj_name,
                                        limit_data_sz=limit_data_sz, page_width=page_width,
                                        colorized=colorized)

    elif data_info_by_range is not None:

        first_id=data_info_by_range[0]
        last_id=data_info_by_range[1]

        fmkdb.display_data_info_by_range(first_id, last_id, with_data=with_data, with_fbk=with_fbk,
                                         with_fmkinfo=not without_fmkinfo, fbk_src=fbk_src,
                                         prj_name=prj_name,
                                         limit_data_sz=limit_data_sz, page_width=page_width,
                                         colorized=colorized)

    elif export_data is not None or export_one_data is not None:

        if export_data is not None:
            fmkdb.export_data(first=export_data[0], last=export_data[1], colorized=colorized)
        else:
            fmkdb.export_data(first=export_one_data, colorized=colorized)

    elif remove_data is not None:
        handle_confirmation()
        fmkdb.remove_data(remove_data, colorized=colorized)

    elif impact_analysis:
        fmkdb.get_data_with_impact(prj_name=prj_name, fbk_src=fbk_src, verbose=verbose,
                                   colorized=colorized)

    elif data_without_fbk:
        fmkdb.get_data_without_fbk(prj_name=prj_name, fbk_src=fbk_src, colorized=colorized)

    elif data_with_specific_fbk:
        fmkdb.get_data_with_specific_fbk(data_with_specific_fbk, prj_name=prj_name, fbk_src=fbk_src,
                                         colorized=colorized)

    fmkdb.stop()
