import os
import sys
import datetime

from libs.external_modules import *
from fuzzfmk.data_model import Data
import fuzzfmk.global_resources as gr

class Database(object):

    DDL_fname = 'fmk_db.sql'

    def __init__(self):
        self.name = 'logDB.db'
        self.log_db = os.path.join(gr.trace_folder, self.name)
        self._con = None
        self._cur = None
        self.enabled = False
        # self.populated = None

    def start(self):
        if not sqlite_module:
            print("/!\\ WARNING /!\\: Fuddly's LogDB unavailable because python-sqlite3 is not installed!")
            return False

        if os.path.isfile(self.log_db):
            self._con = sqlite.connect(self.log_db)
            self._cur = self._con.cursor()
            # self._cur.execute("SELECT VALUE FROM CONF WHERE ITEM='populated'")
            # self.populated = self._cur.fetchone()

        else:
            # self.populated = False
            self._con = sqlite.connect(self.log_db)
            log_db_sql = open(gr.fmk_folder + self.DDL_fname).read()
            with self._con:
                self._cur = self._con.cursor()
                self._cur.executescript(log_db_sql)

        self.enabled = True

    def stop(self):
        if self._con:
            self._con.close()

        self._con = None
        self._cur = None
        self.enabled = False

    def insert_data_model(self, dm_name):
        self._cur.execute(
                "INSERT INTO DATAMODEL(DM_NAME) VALUES(?)",
                (dm_name,))
        self._con.commit()
        return self._cur.lastrowid

    def insert_disruptors(self, dm_name, name, disruptor, stateful):
        self._cur.execute(
                "INSERT INTO DMAKERS(DM_NAME,NAME,DISRUPTOR,STATEFUL) VALUES(?,?,?,?)",
                (dm_name, name, disruptor, stateful))
        self._con.commit()
        return self._cur.lastrowid


    def insert_data(self, type, dm_name, raw_data, sz, sent_date, ack_date):
        blob = sqlite.Binary(raw_data)
        self._cur.execute(
                "INSERT INTO DATA(TYPE,DM_NAME,CONTENTS,SIZE,SENT_DATE,ACK_DATE) VALUES(?,?,?,?,?,?)",
                (type, dm_name, blob, sz, sent_date, ack_date))
        self._con.commit()
        return self._cur.lastrowid

    def insert_steps(self):
        pass

    def insert_feedback(self):
        pass

    def insert_steps(self):
        pass


