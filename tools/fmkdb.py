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
import math

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)

from fuzzfmk.database import Database
import fuzzfmk.global_resources as gr
from libs.external_modules import *
from libs.utils import ensure_dir, chunk_lines

import argparse

parser = argparse.ArgumentParser(description='Process arguments.')
parser.add_argument('--fmkdb', metavar='PATH', help='path to an alternative fmkDB.db')
parser.add_argument('--no-color', action='store_true', help='do not use colors')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')
parser.add_argument('--page-width', type=int, metavar='WIDTH', default=100,
                    help='width hint for displaying information')

group = parser.add_argument_group('Fuddly Database Visualization')
group.add_argument('-s', '--all-stats', action='store_true', help='show all statistics')

group = parser.add_argument_group('Fuddly Database Information')
group.add_argument('-i', '--info', type=int, metavar='DATA_ID',
                   help='display information on the specified data ID')
group.add_argument('--info-by-date', nargs=2, metavar=('START','END'),
                   help='''display information on data sent between START and END '''
                        '''(date format 'Year/Month/Day' or 'Year/Month/Day-Hour' or
                        'Year/Month/Day-Hour:Minute')''')
group.add_argument('--info-by-ids', nargs=2, metavar=('FIRST_DATA_ID','LAST_DATA_ID'), type=int,
                   help='''display information on all the data included within the specified
                   data ID range''')

group.add_argument('--project', metavar='PROJECT_NAME',
                   help='restrict the data to be displayed to a specific project (expect --info-by-date)')

group.add_argument('--with-fbk', action='store_true', help='display full feedback (expect --info)')
group.add_argument('--with-data', action='store_true', help='display data content (expect --info)')
group.add_argument('--without-fmkinfo', action='store_true',
                   help='do not display fmkinfo (expect --info)')
group.add_argument('--limit', type=int, default=600,
                   help='limit the size of what is displayed from data (expect --with-data)')

group = parser.add_argument_group('Fuddly Database Operations')
group.add_argument('--export-data', nargs=2, metavar=('FIRST_DATA_ID','LAST_DATA_ID'), type=int,
                   help='extract data from provided data ID range')
group.add_argument('-e', '--export-one-data', type=int, metavar='DATA_ID',
                   help='extract data from the provided data ID')
group.add_argument('--remove-data', type=int, metavar='DATA_ID',
                   help='remove data ID and all related information from fmkDB')

group = parser.add_argument_group('Fuddly Database Analysis')
group.add_argument('--data-with-impact', action='store_true',
                   help="retrieve data that negatively impacted a target")


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

def handle_data_existence(data_id):
    data = fmkdb.execute_sql_statement(
        "SELECT * FROM DATA "
        "WHERE ID == {data_id:d};".format(data_id=data_id)
    )

    if not data:
        print(colorize("*** ERROR: The provided DATA ID does not exist ***", rgb=Color.ERROR))
        sys.exit(-1)

    return data

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



def display_data_info(fmkdb, data_id, with_data, with_fbk, without_fmkinfo, limit_data_sz=600):
    data = handle_data_existence(data_id=data_id)
    prt = sys.stdout.write

    data_id, gr_id, data_type, dm_name, data_content, size, sent_date, ack_date, tg, prj = data[0]

    steps = fmkdb.execute_sql_statement(
        "SELECT * FROM STEPS "
        "WHERE DATA_ID == {data_id:d} "
        "ORDER BY STEP_ID ASC;".format(data_id=data_id)
    )

    if not steps:
        print(colorize("*** BUG with data ID '{:d}' (data should always have at least 1 step) "
                       "***".format(data_id),
                       rgb=Color.ERROR))
        return

    feedback = fmkdb.execute_sql_statement(
        "SELECT SOURCE, DATE, STATUS, CONTENT FROM FEEDBACK "
        "WHERE DATA_ID == {data_id:d} "
        "ORDER BY SOURCE"
        " ASC;".format(data_id=data_id)
    )

    comments = fmkdb.execute_sql_statement(
        "SELECT CONTENT, DATE FROM COMMENTS "
        "WHERE DATA_ID == {data_id:d} "
        "ORDER BY DATE ASC;".format(data_id=data_id)
    )

    fmkinfo = fmkdb.execute_sql_statement(
        "SELECT CONTENT, DATE, ERROR FROM FMKINFO "
        "WHERE DATA_ID == {data_id:d} "
        "ORDER BY ERROR DESC;".format(data_id=data_id)
    )

    line_pattern = '-'*page_width
    data_id_pattern = " Data ID #{:d} ".format(data_id)

    msg = colorize("[".rjust((page_width-20), '='), rgb=Color.NEWLOGENTRY)
    msg += colorize(data_id_pattern, rgb=Color.FMKHLIGHT)
    msg += colorize("]".ljust(page_width-(page_width-20)-len(data_id_pattern),"="),
                    rgb=Color.NEWLOGENTRY)
    msg += colorize("\n   Project: ", rgb=Color.FMKINFO)
    msg += colorize("{:s}".format(prj), rgb=Color.FMKSUBINFO)
    msg += colorize(" | Target: ", rgb=Color.FMKINFO)
    msg += colorize("{:s}".format(tg), rgb=Color.FMKSUBINFO)
    msg += colorize("\n    Status: ", rgb=Color.FMKINFO)
    src_max_sz = 0
    for idx, fbk in enumerate(feedback):
        src, tstamp, status, _ = fbk
        src_sz = len(src)
        src_max_sz = src_sz if src_sz > src_max_sz else src_max_sz
        if status is None:
            continue
        msg += colorize("{!s}".format(status), rgb=Color.FMKSUBINFO) + \
               colorize(" by ", rgb=Color.FMKINFO) + \
               colorize("{!s}".format(src), rgb=Color.FMKSUBINFO)
        if idx < len(feedback)-1:
            msg += colorize(", ".format(src), rgb=Color.FMKINFO)

    msg += '\n'
    sentd = sent_date.strftime("%d/%m/%Y - %H:%M:%S") if sent_date else 'None'
    ackd = ack_date.strftime("%d/%m/%Y - %H:%M:%S") if ack_date else 'None'
    msg += colorize("      Sent: ", rgb=Color.FMKINFO) + colorize(sentd, rgb=Color.DATE)
    msg += colorize("\n  Received: ", rgb=Color.FMKINFO) + colorize(ackd, rgb=Color.DATE)
    msg += colorize("\n      Size: ", rgb=Color.FMKINFO) + colorize(str(size)+' Bytes', rgb=Color.FMKSUBINFO)
    msg += colorize('\n'+line_pattern, rgb=Color.NEWLOGENTRY)

    prt(msg)

    def handle_dmaker(dmk_pattern, info, dmk_type, dmk_name, name_sep_sz, id_src=None):
        msg = ''
        msg += colorize("\n  |_ {:s}: ".format(dmk_pattern), rgb=Color.FMKINFO)
        msg += colorize(str(dmk_type).ljust(name_sep_sz, ' '), rgb=Color.FMKSUBINFO)
        if id_src is None:
            msg += colorize(" | Name: ", rgb=Color.FMKINFO)
            msg += colorize(str(dmk_name), rgb=Color.FMKSUBINFO)
            msg += colorize("  | UI: ", rgb=Color.FMKINFO)
            msg += colorize(str(ui), rgb=Color.FMKSUBINFO)
        else:
            msg += colorize("  | ID source: ", rgb=Color.FMKINFO)
            msg += colorize(str(id_src), rgb=Color.FMKSUBINFO)
        if info is not None:
            if sys.version_info[0] > 2:
                info = info.decode("latin_1")
            else:
                info = str(info)
            info = info.split('\n')
            for i in info:
                chks = chunk_lines(i, page_width-prefix_sz-10)
                for idx, c in enumerate(chks):
                    spc = 1 if idx > 0 else 0
                    msg += '\n' + colorize(' '*prefix_sz+'| ', rgb=Color.FMKINFO) + \
                           colorize(' '*spc+c, rgb=Color.DATAINFO_ALT)
        return msg

    msg = ''
    first_pass = True
    prefix_sz = 7
    name_sep_sz = len(data_type)
    for _, _, dmk_type, _, _, _, _ in steps:
        dmk_type_sz = 0 if dmk_type is None else len(dmk_type)
        name_sep_sz = dmk_type_sz if dmk_type_sz > name_sep_sz else name_sep_sz
    sid = 1
    for _, step_id, dmk_type, dmk_name, id_src, ui, info in steps:
        if first_pass:
            if dmk_type is None:
                assert(id_src is not None)
                continue
            else:
                first_pass = False
            msg += colorize("\n Step #{:d}:".format(sid), rgb=Color.FMKINFOGROUP)
            if dmk_type != data_type:
                msg += colorize("\n  |_ Generator: ", rgb=Color.FMKINFO)
                msg += colorize(str(data_type), rgb=Color.FMKSUBINFO)
                msg += colorize("  | UI: ", rgb=Color.FMKINFO)
                msg += colorize(str(ui), rgb=Color.FMKSUBINFO)
                sid += 1
                msg += colorize("\n Step #{:d}:".format(sid), rgb=Color.FMKINFOGROUP)
                msg += handle_dmaker('Disruptor', info, dmk_type, dmk_name, len(data_type))
            else:
                msg += handle_dmaker('Generator', info, dmk_type, dmk_name, name_sep_sz,
                                     id_src=id_src)
        else:
            msg += colorize("\n Step #{:d}:".format(sid), rgb=Color.FMKINFOGROUP)
            msg += handle_dmaker('Disruptor', info, dmk_type, dmk_name, name_sep_sz)
        sid += 1
    msg += colorize('\n'+line_pattern, rgb=Color.NEWLOGENTRY)
    prt(msg)

    msg = ''
    for idx, com in enumerate(comments, start=1):
        content, date = com
        date_str = sent_date.strftime("%d/%m/%Y - %H:%M:%S") if sent_date else 'None'
        msg += colorize("\n Comment #{:d}: ".format(idx), rgb=Color.FMKINFOGROUP) + \
               colorize(date_str, rgb=Color.DATE)
        chks = chunk_lines(content, page_width-10)
        for c in chks:
            msg += '\n' + colorize(' '*2+'| ', rgb=Color.FMKINFOGROUP) + \
                   colorize(str(c), rgb=Color.DATAINFO_ALT)
    if comments:
        msg += colorize('\n'+line_pattern, rgb=Color.NEWLOGENTRY)
        prt(msg)

    msg = ''
    for idx, info in enumerate(fmkinfo, start=1):
        content, date, error = info
        if without_fmkinfo and not error:
            continue
        date_str = sent_date.strftime("%d/%m/%Y - %H:%M:%S") if sent_date else 'None'
        if error:
            msg += colorize("\n FMK Error: ", rgb=Color.ERROR)
        else:
            msg += colorize("\n FMK Info: ", rgb=Color.FMKINFOGROUP)
        msg += colorize(date_str, rgb=Color.DATE)
        chks = chunk_lines(content, page_width-10)
        for c in chks:
            color = Color.FMKHLIGHT if error else Color.DATAINFO_ALT
            msg += '\n' + colorize(' '*2+'| ', rgb=Color.FMKINFOGROUP) + \
                   colorize(str(c), rgb=color)
    if msg:
        msg += colorize('\n'+line_pattern, rgb=Color.NEWLOGENTRY)
        prt(msg)

    msg = ''
    if with_data:
        msg += colorize("\n Sent Data:\n", rgb=Color.FMKINFOGROUP)
        if sys.version_info[0] > 2:
            data_content = data_content.decode("latin_1")
            data_content = "{!a}".format(data_content)
        else:
            data_content = repr(str(data_content))
        if len(data_content) > limit_data_sz:
            data_content = data_content[:limit_data_sz]
            data_content = data_content
            data_content += colorize(' ...', rgb=Color.FMKHLIGHT)
        else:
            data_content = data_content
        msg += data_content
        msg += colorize('\n'+line_pattern, rgb=Color.NEWLOGENTRY)

    if with_fbk:
        for src, tstamp, status, content in feedback:
            msg += colorize("\n Status(", rgb=Color.FMKINFOGROUP) + \
                   colorize("{:s}".format(src), rgb=Color.FMKSUBINFO) + \
                   colorize(" | ", rgb=Color.FMKINFOGROUP) + \
                   colorize("{:s}".format(tstamp.strftime("%d/%m/%Y - %H:%M:%S")),
                            rgb=Color.FMKSUBINFO) + \
                   colorize(")", rgb=Color.FMKINFOGROUP) + \
                   colorize(" = {!s}".format(status), rgb=Color.FMKSUBINFO)
            if content:
                if sys.version_info[0] > 2:
                    content = content.decode("latin_1")
                else:
                    content = str(content)
                chks = chunk_lines(content, page_width-4)
                for c in chks:
                    c_sz = len(c)
                    for i in range(c_sz):
                        c = c[:-1] if c[-1] == '\n' else c
                        break
                    msg += colorize('\n'+' '*2+'| ', rgb=Color.FMKINFOGROUP) + \
                           colorize(str(c), rgb=Color.DATAINFO_ALT)
        if feedback:
            msg += colorize('\n'+line_pattern, rgb=Color.NEWLOGENTRY)

    prt(msg+'\n')



if __name__ == "__main__":

    args = parser.parse_args()

    fmkdb = args.fmkdb
    if fmkdb is not None and not os.path.isfile(fmkdb):
        print(colorize("*** ERROR: '{:s}' does not exist ***".format(fmkdb), rgb=Color.ERROR))
        sys.exit(-1)

    verbose = args.verbose
    no_color = args.no_color
    if no_color:
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

    fmkdb = Database(fmkdb_path=fmkdb)
    ok = fmkdb.start()
    if not ok:
        print(colorize("*** ERROR: The database {:s} is invalid! ***".format(fmkdb.fmk_db_path),
                       rgb=Color.ERROR))
        sys.exit(-1)

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
            print(colorize("*** ERROR: Statistics are unavailable ***", rgb=Color.ERROR))


    elif data_info is not None:

        display_data_info(fmkdb, data_info, with_data, with_fbk, without_fmkinfo,
                          limit_data_sz=limit_data_sz)

    elif data_info_by_date is not None:

        start = handle_date(data_info_by_date[0])
        end = handle_date(data_info_by_date[1])

        if prj_name:
            records = fmkdb.execute_sql_statement(
                "SELECT ID FROM DATA "
                "WHERE ? <= SENT_DATE and SENT_DATE <= ? and PRJ_NAME == ?;",
                params=(start, end, prj_name)
            )
        else:
            records = fmkdb.execute_sql_statement(
                "SELECT ID FROM DATA "
                "WHERE ? <= SENT_DATE and SENT_DATE <= ?;",
                params=(start, end)
            )

        if records:
            for rec in records:
                data_id = rec[0]
                display_data_info(fmkdb, data_id, with_data, with_fbk, without_fmkinfo,
                                  limit_data_sz=limit_data_sz)
        else:
            print(colorize("*** ERROR: No data found between {!s} and {!s} ***".format(start, end),
                           rgb=Color.ERROR))


    elif data_info_by_range is not None:

        first_id=data_info_by_range[0]
        last_id=data_info_by_range[1]

        records = fmkdb.execute_sql_statement(
            "SELECT ID FROM DATA "
            "WHERE {start:d} <= ID and ID <= {end:d};".format(start=first_id,
                                                              end=last_id)
        )

        if records:
            for rec in records:
                data_id = rec[0]
                display_data_info(fmkdb, data_id, with_data, with_fbk, without_fmkinfo,
                                  limit_data_sz=limit_data_sz)
        else:
            print(colorize("*** ERROR: No data found between {!s} and {!s} ***".format(first_id,
                                                                                       last_id),
                           rgb=Color.ERROR))

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

                if sent_date is None:
                    current_export_date = datetime.now().strftime("%Y-%m-%d-%H%M%S")
                else:
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
            print(colorize("*** ERROR: The provided DATA IDs do not exist ***", rgb=Color.ERROR))


    elif remove_data is not None:
        data_id = remove_data

        data = handle_data_existence(data_id)
        handle_confirmation()

        comments = fmkdb.execute_sql_statement(
            "DELETE FROM COMMENTS "
            "WHERE DATA_ID == {data_id:d};".format(data_id=data_id)
        )

        fmkinfo = fmkdb.execute_sql_statement(
            "DELETE FROM FMKINFO "
            "WHERE DATA_ID == {data_id:d};".format(data_id=data_id)
        )

        fbk = fmkdb.execute_sql_statement(
            "DELETE FROM FEEDBACK "
            "WHERE DATA_ID == {data_id:d};".format(data_id=data_id)
        )

        steps = fmkdb.execute_sql_statement(
            "DELETE FROM STEPS "
            "WHERE DATA_ID == {data_id:d};".format(data_id=data_id)
        )

        data = fmkdb.execute_sql_statement(
            "DELETE FROM DATA "
            "WHERE ID == {data_id:d};".format(data_id=data_id)
        )

        print(colorize("*** Data and all related records have been removed ***", rgb=Color.FMKINFO))


    elif impact_analysis:
        fbk_records = fmkdb.execute_sql_statement(
            "SELECT DATA_ID, STATUS, SOURCE FROM FEEDBACK "
            "WHERE STATUS < 0;"
        )
        prj_records = fmkdb.execute_sql_statement(
            "SELECT ID, TARGET, PRJ_NAME FROM DATA "
            "ORDER BY PRJ_NAME ASC, TARGET ASC;"
        )

        if fbk_records and prj_records:
            data_ids = {}
            for rec in fbk_records:
                data_ids[rec[0]] = (rec[1], rec[2])

            data_id_pattern = "{:>"+str(int(math.log10(len(prj_records)))+2)+"s}"

            current_prj = None
            for rec in prj_records:
                data_id, target, prj = rec
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
