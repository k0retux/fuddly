import os
import sys
import datetime

from libs.external_modules import *
from fuzzfmk.data_model import Data
import fuzzfmk.global_resources as gr

class Database(object):

    DDL_fname = 'log_db.sql'

    def __init__(self):
        self.name = 'logDB.db'
        self.log_db = os.path.join(gr.trace_folder, self.name)
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
