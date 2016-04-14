import os
import re

from libs.external_modules import *
import fuzzfmk.global_resources as gr


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
