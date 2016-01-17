import os
import sys
import datetime

from libs.external_modules import *
from fuzzfmk.data_model import Data
import fuzzfmk.global_resources as gr

class Database(object):

    DDL_fname = 'fmk_db.sql'

    DEFAULT_DM_NAME = '__DEFAULT_DATAMODEL'
    DEFAULT_GTYPE_NAME = '__DEFAULT_GTYPE'
    DEFAULT_GEN_NAME = '__DEFAULT_GNAME'

    def __init__(self):
        self.name = 'fmkDB.db'
        self.log_db = os.path.join(gr.app_folder, self.name)
        self._con = None
        self._cur = None
        self.enabled = False

    def start(self):
        if not sqlite_module:
            print("/!\\ WARNING /!\\: Fuddly's LogDB unavailable because python-sqlite3 is not installed!")
            return False

        if os.path.isfile(self.log_db):
            self._con = sqlite.connect(self.log_db)
            self._cur = self._con.cursor()

        else:
            self._con = sqlite.connect(self.log_db)
            fmk_db_sql = open(gr.fmk_folder + self.DDL_fname).read()
            with self._con:
                self._cur = self._con.cursor()
                self._cur.executescript(fmk_db_sql)

        self.enabled = True

    def stop(self):
        if self._con:
            self._con.close()

        self._con = None
        self._cur = None
        self.enabled = False

    def commit(self):
        try:
            self._con.commit()
        except sqlite.Error as e:
            self._con.rollback()
            return -1
        else:
            return 0

    def rollback(self):
        try:
            self._con.rollback()
        except sqlite.Error as e:
            return -1
        else:
            return 0


    def insert_data_model(self, dm_name):
        try:
            self._cur.execute(
                    "INSERT INTO DATAMODEL(NAME) VALUES(?)",
                    (dm_name,))
        except sqlite.Error as e:
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
        except sqlite.Error as e:
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
        except sqlite.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table DMAKERS!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_data(self, dtype, dm_name, raw_data, sz, sent_date, ack_date, group_id=None):
        blob = sqlite.Binary(raw_data)
        try:
            self._cur.execute(
                    "INSERT INTO DATA(GROUP_ID,TYPE,DM_NAME,CONTENT,SIZE,SENT_DATE,ACK_DATE)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (group_id, dtype, dm_name, blob, sz, sent_date, ack_date))
            self._con.commit()
        except sqlite.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table DATA!".format(e.args[0]))
            return None
        else:
            return self._cur.lastrowid

    def insert_steps(self, data_id, step_id, dmaker_type, dmaker_name, data_id_src,
                     user_input, info):
        if info:
            info = sqlite.Binary(info)
        try:
            self._cur.execute(
                    "INSERT INTO STEPS(DATA_ID,STEP_ID,DMAKER_TYPE,DMAKER_NAME,DATA_ID_SRC,USER_INPUT,INFO)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (data_id, step_id, dmaker_type, dmaker_name, data_id_src, user_input, info))
        except sqlite.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table STEPS!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_feedback(self, data_id, source, content):
        if content:
            content = sqlite.Binary(content)
        try:
            self._cur.execute(
                    "INSERT INTO FEEDBACK(DATA_ID,SOURCE,CONTENT)"
                    " VALUES(?,?,?)",
                    (data_id, source, content))
            self._con.commit()
        except sqlite.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table FEEDBACK!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_comment(self, data_id, content, date):
        try:
            self._cur.execute(
                    "INSERT INTO COMMENTS(DATA_ID,CONTENT,DATE)"
                    " VALUES(?,?,?)",
                    (data_id, content, date))
            self._con.commit()
        except sqlite.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table COMMENTS!".format(e.args[0]))
            return -1
        else:
            return self._cur.lastrowid

    def insert_fmk_info(self, data_id, content, date, error=False):
        try:
            self._cur.execute(
                    "INSERT INTO FMKINFO(DATA_ID,CONTENT,DATE,ERROR)"
                    " VALUES(?,?,?,?)",
                    (data_id, content, date, error))
            self._con.commit()
        except sqlite.Error as e:
            try:
                self._con.rollback()
                print("\n*** ERROR[SQL:{:s}] while inserting a value into table FMKINFO!".format(e.args[0]))
                return -1
            except sqlite.ProgrammingError as e:
                print("\n*** ERROR[SQLite]: {:s}".format(e.args[0]))
                print("*** Not currently handled by fuddly.")
                return -1
        else:
            return self._cur.lastrowid

    def insert_project_record(self, prj_name, data_id, target):
        try:
            self._cur.execute(
                "INSERT INTO PROJECT_RECORDS(PRJ_NAME,DATA_ID,TARGET)"
                " VALUES(?,?,?)",
                (prj_name, data_id, target))
            self._con.commit()
        except sqlite.Error as e:
            self._con.rollback()
            print("\n*** ERROR[SQL:{:s}] while inserting a value into table PROJECT_RECORDS!".format(e.args[0]))
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
        except sqlite.Error as e:
            print("\n*** ERROR[SQL]: {:s}".format(e.args[0]))
            return
        else:
            return self._cur.fetchall()
