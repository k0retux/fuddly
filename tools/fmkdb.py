#!/usr/bin/env python

################################################################################
#
#  Copyright 2014-2015 Eric Lacombe <eric.lacombe@security-labs.org>
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
import math

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)

from fuzzfmk.database import Database
import fuzzfmk.global_resources as gr
from libs.external_modules import *
from libs.fs_utils import ensure_dir

import argparse

parser = argparse.ArgumentParser(description='Process arguments.')
parser.add_argument('--fmkdb', metavar='fmkdb_path', help='path to an alternative fmkdb.db')
parser.add_argument('--no-color', action='store_true', help='do not use colors')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')

group = parser.add_argument_group('Fuddly Database Statistics')
group.add_argument('-s', '--all-stats', action='store_true', help='show all statistics')

group = parser.add_argument_group('Fuddly Database Export')
group.add_argument('--export-data', nargs=2, metavar=('first_data_ID','last_data_ID'), type=int,
                   help='extract data from provided data IDs')
group.add_argument('-e', '--export-one-data', type=int, metavar='data_id',
                   help='extract data from the provided data ID')

group = parser.add_argument_group('Fuddly Database Analysis')
group.add_argument('--data-with-impact', action='store_true',
                   help="retrieve data that negatively impacted a target")


if __name__ == "__main__":

    args = parser.parse_known_args()

    fmkdb = args[0].fmkdb
    if fmkdb is not None and not os.path.isfile(fmkdb):
        print(colorize("*** ERROR: '{:s}' does not exist ***".format(fmkdb), rgb=Color.ERROR))
        sys.exit(-1)

    verbose = args[0].verbose
    no_color = args[0].no_color
    if no_color:
        def colorize(string, rgb=None, ansi=None, bg=None, ansi_bg=None, fd=1):
            return string

    display_stats = args[0].all_stats

    export_data = args[0].export_data
    export_one_data = args[0].export_one_data

    impact_analysis = args[0].data_with_impact

    fmkdb = Database(fmkdb_path=fmkdb)
    fmkdb.start()

    if display_stats:
        records = fmkdb.execute_sql_statement(
            "SELECT TARGET, TYPE, TOTAL FROM STATS_BY_TARGET;"
        )

        if records:
            current_target = None
            max_len = 0
            for rec in records:
                _, data_type, _ = rec
                data_type_len = len(data_type)
                if max_len < data_type_len:
                    max_len = data_type_len

            data_type_pattern = "{:>"+str(max_len+1)+"s}"

            for rec in records:
                tg, data_type, total = rec

                if tg != current_target:
                    current_target = tg
                    print(colorize("*** {:s} ***".format(tg), rgb=Color.FMKINFOGROUP))

                format_string = data_type_pattern + " : {:d}"
                print(colorize(format_string.format(data_type, total),
                               rgb=Color.FMKSUBINFO))

        else:
            print(colorize("*** ERROR: statistics are unavailable ***", rgb=Color.ERROR))

    elif export_data is not None or export_one_data is not None:

        if export_data is not None:
            records = fmkdb.execute_sql_statement(
                "SELECT ID, TYPE, DM_NAME, SENT_DATE, CONTENT FROM DATA "
                "WHERE {start:d} <= ID and ID <= {end:d};".format(start=export_data[0],
                                                                  end=export_data[1])
            )
        else:
            records = fmkdb.execute_sql_statement(
                "SELECT ID, TYPE, DM_NAME, SENT_DATE, CONTENT FROM DATA "
                "WHERE ID == {data_id:d};".format(data_id=export_one_data)
            )

        if records:
            base_dir = gr.exported_data_folder
            prev_export_date = None
            export_cpt = 0

            for rec in records:
                data_id, data_type, dm_name, sent_date, content = rec
                # print(data_id, data_type, dm_name, sent_date)

                file_extension = dm_name

                current_export_date = sent_date.strftime("%Y-%m-%d-%H%M%S")

                if current_export_date != prev_export_date:
                    prev_export_date = current_export_date
                    export_cpt = 0
                else:
                    export_cpt += 1

                export_fname = '{typ:s}_{date:s}_{cpt:0>2d}.{ext:s}'.format(date=current_export_date,
                                                                            cpt=export_cpt,
                                                                            ext=file_extension,
                                                                            typ=data_type)

                export_full_fn = os.path.join(base_dir, dm_name, export_fname)
                ensure_dir(export_full_fn)

                with open(export_full_fn, 'wb') as fd:
                    fd.write(content)

                print(colorize("Data ID #{:d} --> {:s}".format(data_id, export_full_fn),
                               rgb=Color.FMKINFO))

        else:
            print(colorize("*** ERROR: provided data IDs are incorrect ***", rgb=Color.ERROR))

    elif impact_analysis:
        fbk_records = fmkdb.execute_sql_statement(
            "SELECT DATA_ID, STATUS, SOURCE FROM FEEDBACK "
            "WHERE STATUS < 0;"
        )
        prj_records = fmkdb.execute_sql_statement(
            "SELECT PRJ_NAME, DATA_ID, TARGET FROM PROJECT_RECORDS;"
        )

        if fbk_records and prj_records:
            data_ids = {}
            for rec in fbk_records:
                data_ids[rec[0]] = (rec[1], rec[2])

            data_id_pattern = "{:>"+str(int(math.log10(len(prj_records)))+2)+"s}"

            current_prj = None
            for rec in prj_records:
                prj, data_id, target = rec
                if data_id in data_ids.keys():
                    if prj != current_prj:
                        current_prj = prj
                        print(colorize("*** Project '{:s}' ***".format(prj), rgb=Color.FMKINFOGROUP))
                    format_string = "     [DataID " + data_id_pattern + "] --> {:s}"
                    print(colorize(format_string.format('#'+str(data_id), target),
                                   rgb=Color.DATAINFO))
                    if verbose:
                        print(colorize("       |_ status={:d} from {:s}".format(data_ids[data_id][0], data_ids[data_id][1]),
                                       rgb=Color.FMKSUBINFO))

        else:
            print(colorize("*** No data has negatively impacted a target ***", rgb=Color.FMKINFO))

    fmkdb.stop()
