import sys
import os
import re
import math
from datetime import datetime

import fuzzfmk.global_resources as gr
import libs.external_modules as em
from libs.external_modules import *
from libs.utils import ensure_dir, chunk_lines


def regexp(expr, item):
    reg = re.compile(expr)
    if item is None:
        return False
    robj = reg.search(item)
    return robj is not None

def regexp_bin(expr, item):
    expr = bytes(expr)
    reg = re.compile(expr)
    if item is None:
        return False
    robj = reg.search(item)
    return robj is not None


class Database(object):

    DDL_fname = 'fmk_db.sql'

    DEFAULT_DM_NAME = '__DEFAULT_DATAMODEL'
    DEFAULT_GTYPE_NAME = '__DEFAULT_GTYPE'
    DEFAULT_GEN_NAME = '__DEFAULT_GNAME'

    def __init__(self, fmkdb_path=None):
        self.name = 'fmkDB.db'
        if fmkdb_path is None:
            self.fmk_db_path = os.path.join(gr.fuddly_data_folder, self.name)
        else:
            self.fmk_db_path = fmkdb_path
        self._con = None
        self._cur = None
        self.enabled = False

        self.last_feedback = {}
        self.last_data_id = None

    def start(self):
        if not sqlite3_module:
            print("/!\\ WARNING /!\\: Fuddly's FmkDB unavailable because python-sqlite3 is not installed!")
            return False

        if os.path.isfile(self.fmk_db_path):
            self._con = sqlite3.connect(self.fmk_db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            self._cur = self._con.cursor()
            ok = self._is_valid(self._cur)
        else:
            self._con = sqlite3.connect(self.fmk_db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            fmk_db_sql = open(gr.fmk_folder + self.DDL_fname).read()
            ok = False
            with self._con:
                self._cur = self._con.cursor()
                self._cur.executescript(fmk_db_sql)
                ok = True

        if ok:
            self._con.create_function("REGEXP", 2, regexp)
            self._con.create_function("BINREGEXP", 2, regexp_bin)

        self.enabled = ok
        return ok

    def stop(self):
        if self._con:
            self._con.close()

        self._con = None
        self._cur = None
        self.enabled = False

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def _is_valid(self, cursor):
        valid = False
        with self._con:
            tmp_con = sqlite3.connect(':memory:', detect_types=sqlite3.PARSE_DECLTYPES)
            fmk_db_sql = open(gr.fmk_folder + self.DDL_fname).read()
            with tmp_con:
                cur = tmp_con.cursor()
                cur.executescript(fmk_db_sql)
                cur.execute("select name from sqlite_master WHERE type='table'")
                tables = map(lambda x: x[0], cur.fetchall())
                tables = filter(lambda x: not x.startswith('sqlite'), tables)
                for t in tables:
                    cur.execute('select * from {!s}'.format(t))
                    ref_names = list(map(lambda x: x[0], cur.description))
                    cursor.execute('select * from {!s}'.format(t))
                    names = list(map(lambda x: x[0], cursor.description))
                    if ref_names != names:
                        valid = False
                        break
                else:
                    valid = True

        return valid


    def commit(self):
        try:
            self._con.commit()
        except sqlite3.Error as e:
            self._con.rollback()
            return -1
        else:
            return 0

    def rollback(self):
        try:
            self._con.rollback()
        except sqlite3.Error as e:
            return -1
        else:
            return 0

    def execute_sql_statement(self, sql_stmt, params=None):
        with self._con:
            if params:
                self._cur.execute(sql_stmt, params)
                rows = self._cur.fetchall()
            else:
                self._cur.execute(sql_stmt)
                rows = self._cur.fetchall()

            return rows

    def insert_data_model(self, dm_name):
        try:
            self._cur.execute(
                    "INSERT INTO DATAMODEL(NAME) VALUES(?)",
                    (dm_name,))
        except sqlite3.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table DATAMODEL!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_project(self, prj_name):
        try:
            self._cur.execute(
                    "INSERT INTO PROJECT(NAME) VALUES(?)",
                    (prj_name,))
        except sqlite3.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table PROJECT!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid


    def insert_dmaker(self, dm_name, dtype, name, is_gen, stateful, clone_type=None):
        clone_name = None if clone_type is None else name
        try:
            self._cur.execute(
                    "INSERT INTO DMAKERS(DM_NAME,TYPE,NAME,CLONE_TYPE,CLONE_NAME,GENERATOR,STATEFUL)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (dm_name, dtype, name, clone_type, clone_name, is_gen, stateful))
        except sqlite3.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table DMAKERS!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_data(self, dtype, dm_name, raw_data, sz, sent_date, ack_date,
                    target_name, prj_name, group_id=None):
        if not self.enabled:
            return None

        blob = sqlite3.Binary(raw_data)
        try:
            self._cur.execute(
                    "INSERT INTO DATA(GROUP_ID,TYPE,DM_NAME,CONTENT,SIZE,SENT_DATE,ACK_DATE,"
                    "TARGET,PRJ_NAME)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (group_id, dtype, dm_name, blob, sz, sent_date, ack_date, target_name, prj_name))
            self._con.commit()
        except sqlite3.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table DATA!".format(e.args[0]))
            return None
        else:
            return self._cur.lastrowid

    def insert_steps(self, data_id, step_id, dmaker_type, dmaker_name, data_id_src,
                     user_input, info):
        if not self.enabled:
            return None

        if info:
            info = sqlite3.Binary(info)
        try:
            self._cur.execute(
                    "INSERT INTO STEPS(DATA_ID,STEP_ID,DMAKER_TYPE,DMAKER_NAME,DATA_ID_SRC,USER_INPUT,INFO)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (data_id, step_id, dmaker_type, dmaker_name, data_id_src, user_input, info))
        except sqlite3.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table STEPS!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_feedback(self, data_id, source, timestamp, content, status_code=None):

        if data_id != self.last_data_id:
            self.last_data_id = data_id
            self.last_feedback = {}

        if source not in self.last_feedback:
            self.last_feedback[source] = []

        self.last_feedback[source].append(
            {
                'timestamp': timestamp,
                'content': content,
                'status': status_code
            }
        )

        if not self.enabled:
            return None

        if content:
            content = sqlite3.Binary(content)
        try:
            self._cur.execute(
                    "INSERT INTO FEEDBACK(DATA_ID,SOURCE,DATE,CONTENT,STATUS)"
                    " VALUES(?,?,?,?,?)",
                    (data_id, source, timestamp, content, status_code))
            self._con.commit()
        except sqlite3.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table FEEDBACK!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_comment(self, data_id, content, date):
        if not self.enabled:
            return None

        try:
            self._cur.execute(
                    "INSERT INTO COMMENTS(DATA_ID,CONTENT,DATE)"
                    " VALUES(?,?,?)",
                    (data_id, content, date))
            self._con.commit()
        except sqlite3.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table COMMENTS!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_fmk_info(self, data_id, content, date, error=False):
        if not self.enabled:
            return None

        try:
            self._cur.execute(
                    "INSERT INTO FMKINFO(DATA_ID,CONTENT,DATE,ERROR)"
                    " VALUES(?,?,?,?)",
                    (data_id, content, date, error))
            self._con.commit()
        except sqlite3.Error as e:
            try:
                self._con.rollback()
                print("\n*** ERROR[SQL:{:s}] while inserting a value into table FMKINFO!".format(e.args[0]))
                return -1
            except sqlite3.ProgrammingError as e:
                print("\n*** ERROR[sqlite3]: {:s}".format(e.args[0]))
                print("*** Not currently handled by fuddly.")
                return -1
        else:
            return self._cur.lastrowid


    def fetch_data(self, start_id=1, end_id=-1):
        ign_end_id = '--' if end_id < 1 else ''
        try:
            self._cur.execute(
                '''
                SELECT DATA.ID, DATA.CONTENT, DATA.TYPE, DMAKERS.NAME, DATA.DM_NAME
                FROM DATA INNER JOIN DMAKERS
                  ON DATA.TYPE = DMAKERS.TYPE AND DMAKERS.CLONE_TYPE IS NULL
                WHERE DATA.ID >= {sid:d} {ign_eid:s} AND DATA.ID <= {eid:d}
                UNION ALL
                SELECT DATA.ID, DATA.CONTENT, DMAKERS.CLONE_TYPE AS TYPE, DMAKERS.CLONE_NAME AS NAME,
                       DATA.DM_NAME
                FROM DATA INNER JOIN DMAKERS
                  ON DATA.TYPE = DMAKERS.TYPE AND DMAKERS.CLONE_TYPE IS NOT NULL
                WHERE DATA.ID >= {sid:d} {ign_eid:s} AND DATA.ID <= {eid:d}
                '''.format(sid = start_id, eid = end_id, ign_eid = ign_end_id)
            )
        except sqlite3.Error as e:
            print("\n*** ERROR[SQL]: {:s}".format(e.args[0]))
            return
        else:
            return self._cur.fetchall()

    def _get_color_function(self, colorized):
        if not colorized:
            def colorize(string, rgb=None, ansi=None, bg=None, ansi_bg=None, fd=1):
                return string
        else:
            colorize = em.colorize
        return colorize

    def check_data_existence(self, data_id, colorized=True):
        colorize = self._get_color_function(colorized)

        data = self.execute_sql_statement(
            "SELECT * FROM DATA "
            "WHERE ID == {data_id:d};".format(data_id=data_id)
        )

        if not data:
            print(colorize("*** ERROR: The provided DATA ID does not exist ***", rgb=Color.ERROR))

        return data

    def display_data_info(self, data_id, with_data=False, with_fbk=False, with_fmkinfo=True,
                          fbk_src=None, limit_data_sz=600, page_width=100, colorized=True):

        colorize = self._get_color_function(colorized)

        data = self.check_data_existence(data_id=data_id, colorized=colorized)
        if not data:
            return

        prt = sys.stdout.write

        data_id, gr_id, data_type, dm_name, data_content, size, sent_date, ack_date, tg, prj = data[0]

        steps = self.execute_sql_statement(
            "SELECT * FROM STEPS "
            "WHERE DATA_ID == {data_id:d} "
            "ORDER BY STEP_ID ASC;".format(data_id=data_id)
        )

        if not steps:
            print(colorize("*** BUG with data ID '{:d}' (data should always have at least 1 step) "
                           "***".format(data_id),
                           rgb=Color.ERROR))
            return

        if fbk_src:
            feedback = self.execute_sql_statement(
                "SELECT SOURCE, DATE, STATUS, CONTENT FROM FEEDBACK "
                "WHERE DATA_ID == ? AND SOURCE REGEXP ? "
                "ORDER BY SOURCE ASC;",
                params=(data_id, fbk_src)
            )
        else:
            feedback = self.execute_sql_statement(
                "SELECT SOURCE, DATE, STATUS, CONTENT FROM FEEDBACK "
                "WHERE DATA_ID == {data_id:d} "
                "ORDER BY SOURCE"
                " ASC;".format(data_id=data_id)
            )

        comments = self.execute_sql_statement(
            "SELECT CONTENT, DATE FROM COMMENTS "
            "WHERE DATA_ID == {data_id:d} "
            "ORDER BY DATE ASC;".format(data_id=data_id)
        )

        fmkinfo = self.execute_sql_statement(
            "SELECT CONTENT, DATE, ERROR FROM FMKINFO "
            "WHERE DATA_ID == {data_id:d} "
            "ORDER BY ERROR DESC;".format(data_id=data_id)
        )

        line_pattern = '-' * page_width
        data_id_pattern = " Data ID #{:d} ".format(data_id)

        msg = colorize("[".rjust((page_width - 20), '='), rgb=Color.NEWLOGENTRY)
        msg += colorize(data_id_pattern, rgb=Color.FMKHLIGHT)
        msg += colorize("]".ljust(page_width - (page_width - 20) - len(data_id_pattern), "="),
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
            if idx < len(feedback) - 1:
                msg += colorize(", ".format(src), rgb=Color.FMKINFO)

        msg += '\n'
        sentd = sent_date.strftime("%d/%m/%Y - %H:%M:%S") if sent_date else 'None'
        ackd = ack_date.strftime("%d/%m/%Y - %H:%M:%S") if ack_date else 'None'
        msg += colorize("      Sent: ", rgb=Color.FMKINFO) + colorize(sentd, rgb=Color.DATE)
        msg += colorize("\n  Received: ", rgb=Color.FMKINFO) + colorize(ackd, rgb=Color.DATE)
        msg += colorize("\n      Size: ", rgb=Color.FMKINFO) + colorize(str(size) + ' Bytes',
                                                                        rgb=Color.FMKSUBINFO)
        msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)

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
                    chks = chunk_lines(i, page_width - prefix_sz - 10)
                    for idx, c in enumerate(chks):
                        spc = 1 if idx > 0 else 0
                        msg += '\n' + colorize(' ' * prefix_sz + '| ', rgb=Color.FMKINFO) + \
                               colorize(' ' * spc + c, rgb=Color.DATAINFO_ALT)
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
                    assert (id_src is not None)
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
        msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)
        prt(msg)

        msg = ''
        for idx, com in enumerate(comments, start=1):
            content, tstamp = com
            date_str = tstamp.strftime("%d/%m/%Y - %H:%M:%S") if tstamp else 'None'
            msg += colorize("\n Comment #{:d}: ".format(idx), rgb=Color.FMKINFOGROUP) + \
                   colorize(date_str, rgb=Color.DATE)
            chks = chunk_lines(content, page_width - 10)
            for c in chks:
                msg += '\n' + colorize(' ' * 2 + '| ', rgb=Color.FMKINFOGROUP) + \
                       colorize(str(c), rgb=Color.DATAINFO_ALT)
        if comments:
            msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)
            prt(msg)

        msg = ''
        for idx, info in enumerate(fmkinfo, start=1):
            content, tstamp, error = info
            if not with_fmkinfo and not error:
                continue
            date_str = tstamp.strftime("%d/%m/%Y - %H:%M:%S") if tstamp else 'None'
            if error:
                msg += colorize("\n FMK Error: ", rgb=Color.ERROR)
            else:
                msg += colorize("\n FMK Info: ", rgb=Color.FMKINFOGROUP)
            msg += colorize(date_str, rgb=Color.DATE)
            chks = chunk_lines(content, page_width - 10)
            for c in chks:
                color = Color.FMKHLIGHT if error else Color.DATAINFO_ALT
                msg += '\n' + colorize(' ' * 2 + '| ', rgb=Color.FMKINFOGROUP) + \
                       colorize(str(c), rgb=color)
        if msg:
            msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)
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
            msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)

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
                        content = "{!a}".format(content)
                    else:
                        content = repr(str(content))
                    chks = chunk_lines(content, page_width - 4)
                    for c in chks:
                        c_sz = len(c)
                        for i in range(c_sz):
                            c = c[:-1] if c[-1] == '\n' else c
                            break
                        msg += colorize('\n' + ' ' * 2 + '| ', rgb=Color.FMKINFOGROUP) + \
                               colorize(str(c), rgb=Color.DATAINFO_ALT)
            if feedback:
                msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)

        prt(msg + '\n')


    def display_data_info_by_date(self, start, end, with_data=False, with_fbk=False, with_fmkinfo=True,
                                  fbk_src=None, prj_name=None,
                                  limit_data_sz=600, page_width=100, colorized=True):
        colorize = self._get_color_function(colorized)

        if prj_name:
            records = self.execute_sql_statement(
                "SELECT ID FROM DATA "
                "WHERE ? <= SENT_DATE and SENT_DATE <= ? and PRJ_NAME == ?;",
                params=(start, end, prj_name)
            )
        else:
            records = self.execute_sql_statement(
                "SELECT ID FROM DATA "
                "WHERE ? <= SENT_DATE and SENT_DATE <= ?;",
                params=(start, end)
            )

        if records:
            for rec in records:
                data_id = rec[0]
                self.display_data_info(data_id, with_data=with_data, with_fbk=with_fbk,
                                       with_fmkinfo=with_fmkinfo, fbk_src=fbk_src,
                                       limit_data_sz=limit_data_sz, page_width=page_width,
                                       colorized=colorized)
        else:
            print(colorize("*** ERROR: No data found between {!s} and {!s} ***".format(start, end),
                           rgb=Color.ERROR))

    def display_data_info_by_range(self, first_id, last_id, with_data=False, with_fbk=False, with_fmkinfo=True,
                                   fbk_src=None, prj_name=None,
                                   limit_data_sz=600, page_width=100, colorized=True):

        colorize = self._get_color_function(colorized)

        if prj_name:
            records = self.execute_sql_statement(
                "SELECT ID FROM DATA "
                "WHERE ? <= ID and ID <= ? and PRJ_NAME == ?;",
                params=(first_id, last_id, prj_name)
            )
        else:
            records = self.execute_sql_statement(
                "SELECT ID FROM DATA "
                "WHERE ? <= ID and ID <= ?;",
                params=(first_id, last_id)
            )

        if records:
            for rec in records:
                data_id = rec[0]
                self.display_data_info(data_id, with_data=with_data, with_fbk=with_fbk,
                                       with_fmkinfo=with_fmkinfo, fbk_src=fbk_src,
                                       limit_data_sz=limit_data_sz, page_width=page_width,
                                       colorized=colorized)
        else:
            print(colorize("*** ERROR: No data found between {!s} and {!s} ***".format(first_id,
                                                                                       last_id),
                           rgb=Color.ERROR))

    def display_stats(self, colorized=True):
        colorize = self._get_color_function(colorized)

        records = self.execute_sql_statement(
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

            data_type_pattern = "{:>" + str(max_len + 1) + "s}"

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


    def export_data(self, first, last=None, colorized=True):
        colorize = self._get_color_function(colorized)

        if last is not None:
            records = self.execute_sql_statement(
                "SELECT ID, TYPE, DM_NAME, SENT_DATE, CONTENT FROM DATA "
                "WHERE {start:d} <= ID and ID <= {end:d};".format(start=first,
                                                                  end=last)
            )
        else:
            records = self.execute_sql_statement(
                "SELECT ID, TYPE, DM_NAME, SENT_DATE, CONTENT FROM DATA "
                "WHERE ID == {data_id:d};".format(data_id=first)
            )

        if records:
            base_dir = gr.exported_data_folder
            prev_export_date = None
            export_cpt = 0

            for rec in records:
                data_id, data_type, dm_name, sent_date, content = rec

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

                export_fname = '{typ:s}_{date:s}_{cpt:0>2d}.{ext:s}'.format(
                    date=current_export_date,
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

    def remove_data(self, data_id, colorized=True):
        colorize = self._get_color_function(colorized)

        if not self.check_data_existence(data_id, colorized=colorized):
            return

        comments = self.execute_sql_statement(
            "DELETE FROM COMMENTS "
            "WHERE DATA_ID == {data_id:d};".format(data_id=data_id)
        )

        fmkinfo = self.execute_sql_statement(
            "DELETE FROM FMKINFO "
            "WHERE DATA_ID == {data_id:d};".format(data_id=data_id)
        )

        fbk = self.execute_sql_statement(
            "DELETE FROM FEEDBACK "
            "WHERE DATA_ID == {data_id:d};".format(data_id=data_id)
        )

        steps = self.execute_sql_statement(
            "DELETE FROM STEPS "
            "WHERE DATA_ID == {data_id:d};".format(data_id=data_id)
        )

        data = self.execute_sql_statement(
            "DELETE FROM DATA "
            "WHERE ID == {data_id:d};".format(data_id=data_id)
        )

        print(colorize("*** Data and all related records have been removed ***", rgb=Color.FMKINFO))


    def get_project_record(self, prj_name=None):
        if prj_name:
            prj_records = self.execute_sql_statement(
                "SELECT ID, TARGET, PRJ_NAME FROM DATA "
                "WHERE PRJ_NAME == ? "
                "ORDER BY PRJ_NAME ASC, TARGET ASC;",
                params=(prj_name,)
            )
        else:
            prj_records = self.execute_sql_statement(
                "SELECT ID, TARGET, PRJ_NAME FROM DATA "
                "ORDER BY PRJ_NAME ASC, TARGET ASC;",
            )

        return prj_records

    def get_data_with_impact(self, prj_name=None, fbk_src=None, display=True, verbose=False,
                             colorized=True):

        colorize = self._get_color_function(colorized)

        if fbk_src:
            fbk_records = self.execute_sql_statement(
                "SELECT DATA_ID, STATUS, SOURCE FROM FEEDBACK "
                "WHERE STATUS < 0 and SOURCE REGEXP ?;",
                params=(fbk_src,)
            )
        else:
            fbk_records = self.execute_sql_statement(
                "SELECT DATA_ID, STATUS, SOURCE FROM FEEDBACK "
                "WHERE STATUS < 0;"
            )

        prj_records = self.get_project_record(prj_name)
        data_list = []

        if fbk_records and prj_records:
            id2fbk = {}
            for rec in fbk_records:
                data_id, status, src = rec
                if data_id not in id2fbk:
                    id2fbk[data_id] = {}
                if src not in id2fbk[data_id]:
                    id2fbk[data_id][src] = []
                id2fbk[data_id][src].append(status)

            data_id_pattern = "{:>" + str(int(math.log10(len(prj_records))) + 2) + "s}"
            format_string = "     [DataID " + data_id_pattern + "] --> {:s}"

            current_prj = None
            for rec in prj_records:
                data_id, target, prj = rec
                if data_id in id2fbk:
                    data_list.append(data_id)
                    if display:
                        if prj != current_prj:
                            current_prj = prj
                            print(
                                colorize("*** Project '{:s}' ***".format(prj), rgb=Color.FMKINFOGROUP))
                        print(colorize(format_string.format('#' + str(data_id), target),
                                       rgb=Color.DATAINFO))
                        if verbose:
                            for src, status in id2fbk[data_id].items():
                                status_str = ''.join([str(s) + ',' for s in status])[:-1]
                                print(colorize("       |_ status={:s} from {:s}".format(status_str,
                                                                                        src),
                                               rgb=Color.FMKSUBINFO))

        else:
            print(colorize("*** No data has negatively impacted a target ***", rgb=Color.FMKINFO))

        return data_list

    def get_data_without_fbk(self, prj_name=None, fbk_src=None, display=True, colorized=True):
        colorize = self._get_color_function(colorized)

        if fbk_src:
            fbk_records = self.execute_sql_statement(
                "SELECT DATA_ID, STATUS, SOURCE, CONTENT FROM FEEDBACK "
                "WHERE SOURCE REGEXP ?;",
                params=(fbk_src,)
            )
        else:
            fbk_records = self.execute_sql_statement(
                "SELECT DATA_ID, STATUS, SOURCE, CONTENT FROM FEEDBACK;"
            )

        prj_records = self.get_project_record(prj_name)
        data_list = []

        if fbk_records and prj_records:
            id2fbk = {}
            for rec in fbk_records:
                data_id, status, src, content = rec
                if data_id not in id2fbk:
                    id2fbk[data_id] = {}
                if src not in id2fbk[data_id]:
                    id2fbk[data_id][src] = []
                id2fbk[data_id][src].append((status, content))

            data_id_pattern = "{:>" + str(int(math.log10(len(prj_records))) + 2) + "s}"
            format_string = "     [DataID " + data_id_pattern + "] --> {:s}"

            current_prj = None
            for rec in prj_records:
                data_id, target, prj = rec
                to_gather = True
                if data_id in id2fbk:
                    current_fbk = id2fbk[data_id]  # the dictionnay is never empty
                    for src, fbk_list in current_fbk.items():
                        for fbk in fbk_list:
                            if fbk[1] is None or \
                                    (isinstance(fbk[1], bytes) and fbk[1].strip() == b''):
                                continue
                            else:
                                to_gather = False
                                break
                        if not to_gather:
                            break

                if to_gather:
                    data_list.append(data_id)
                    if display:
                        if prj != current_prj:
                            current_prj = prj
                            print(
                                colorize("*** Project '{:s}' ***".format(prj), rgb=Color.FMKINFOGROUP))
                        print(colorize(format_string.format('#' + str(data_id), target),
                                       rgb=Color.DATAINFO))

        else:
            print(colorize("*** No data has been found for analysis ***", rgb=Color.FMKINFO))

        return data_list


    def get_data_with_specific_fbk(self, fbk, prj_name=None, fbk_src=None, display=True,
                                   colorized=True):
        colorize = self._get_color_function(colorized)

        if sys.version_info[0] > 2:
            fbk = bytes(fbk, 'latin_1')

        if fbk_src:
            fbk_records = self.execute_sql_statement(
                "SELECT DATA_ID, CONTENT, SOURCE FROM FEEDBACK "
                "WHERE SOURCE REGEXP ? AND BINREGEXP(?,CONTENT);",
                params=(fbk_src, fbk)
            )
        else:
            fbk_records = self.execute_sql_statement(
                "SELECT DATA_ID, CONTENT, SOURCE FROM FEEDBACK "
                "WHERE BINREGEXP(?,CONTENT);",
                params=(fbk,)
            )

        prj_records = self.get_project_record(prj_name)
        data_list = []

        data_id_pattern = "{:>" + str(int(math.log10(len(prj_records))) + 2) + "s}"
        format_string = "     [DataID " + data_id_pattern + "] --> {:s}"

        if fbk_records and prj_records:

            ids_to_display = {}
            for rec in fbk_records:
                data_id, content, src = rec
                if data_id not in ids_to_display:
                    ids_to_display[data_id] = {}
                if src not in ids_to_display[data_id]:
                    ids_to_display[data_id][src] = []
                ids_to_display[data_id][src].append(content)

            current_prj = None
            for rec in prj_records:
                data_id, target, prj = rec
                if data_id in ids_to_display:
                    data_list.append(data_id)
                    if display:
                        fbk = ids_to_display[data_id]
                        if prj != current_prj:
                            current_prj = prj
                            print(
                                colorize("*** Project '{:s}' ***".format(prj), rgb=Color.FMKINFOGROUP))
                        print(colorize(format_string.format('#' + str(data_id), target),
                                       rgb=Color.DATAINFO))
                        for src, contents in fbk.items():
                            print(colorize("       |_ From [{:s}]:".format(src), rgb=Color.FMKSUBINFO))
                            for ct in contents:
                                print(
                                    colorize("          {:s}".format(str(ct)), rgb=Color.DATAINFO_ALT))

        else:
            print(colorize("*** No data has been found for analysis ***", rgb=Color.FMKINFO))

        return data_list