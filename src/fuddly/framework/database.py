################################################################################
#
#  Copyright 2016 Eric Lacombe <eric.lacombe@security-labs.org>
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

import sys
import os
import re
import math
import threading
import copy
from datetime import datetime, date, timedelta
from typing import Optional

from fuddly.framework import global_resources as gr
from fuddly.framework.config import config
from fuddly.libs import external_modules as em
from fuddly.framework.knowledge.feedback_collector import FeedbackSource
from fuddly.libs.external_modules import *
from fuddly.libs.utils import chunk_lines


def register_adapters_and_converters():
    def adapt_date(val):
        return val.isoformat()

    def adapt_datetime(val):
        return val.isoformat(" ")

    def convert_date(val):
        return datetime.date(*map(int, val.split(b"-")))

    def convert_timestamp(val):
        datepart, timepart = val.split(b" ")
        year, month, day = map(int, datepart.split(b"-"))
        timepart_full = timepart.split(b".")
        hours, minutes, seconds = map(int, timepart_full[0].split(b":"))
        if len(timepart_full) == 2:
            microseconds = int('{:0<6.6}'.format(timepart_full[1].decode()))
        else:
            microseconds = 0

        val = datetime(year, month, day, hours, minutes, seconds, microseconds)
        return val

    sqlite3.register_adapter(date, adapt_date)
    sqlite3.register_adapter(datetime, adapt_datetime)
    sqlite3.register_converter("date", convert_date)
    sqlite3.register_converter("timestamp", convert_timestamp)


register_adapters_and_converters()


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


class FeedbackGate(object):

    def __init__(self, database, only_last_entries=True):
        """
        Args:
            database (Database): database to be associated with
        """
        self.db = database
        self.last_fbk_entries = only_last_entries

    def __iter__(self):
        for item in self.db.iter_feedback_entries(last=self.last_fbk_entries):
            yield item

    def get_feedback_from(self, source):
        if not isinstance(source, FeedbackSource):
            source = FeedbackSource(source)

        try:
            fbk = self.db.last_feedback[source] if self.last_fbk_entries else self.db.feedback_trail[source]
        except KeyError:
            raise
        else:
            return fbk

    def iter_entries(self, source=None):
        """
        Iterate over feedback entries that are related to the last data which has been sent by
        the framework.

        Args:
            source (FeedbackSource): feedback source to consider

        Returns:
            python generator: A generator that iterates over all the requested feedback entries and provides for each:

                - the triplet: (status, timestamp, content) if `source` is associated to a
                  specific feedback source
                - the 4-uplet: (source, status, timestamp, content) if `source` is `None`

        """
        for item in self.db.iter_feedback_entries(last=self.last_fbk_entries, source=source):
            yield item

    def sources_names(self):
        """
        Return a list of the feedback source names related to the last data which has been sent by
        the framework.

        Returns:
            list: names of the feedback sources

        """
        fbk_db = self.db.last_feedback if self.last_fbk_entries else self.db.feedback_trail
        return [str(fs) for fs in fbk_db.keys()]

    @property
    def size(self):
        return len(list(self.db.iter_feedback_entries(last=self.last_fbk_entries)))

    def __bool__(self):
        return bool(self.db.last_feedback if self.last_fbk_entries else self.db.feedback_trail)


class Database(object):

    DDL_fname = 'fmk_db.sql'

    DEFAULT_DB_NAME = 'fmkDB.db'
    DEFAULT_DM_NAME = '__DEFAULT_DATAMODEL'
    DEFAULT_GTYPE_NAME = '__DEFAULT_GTYPE'
    DEFAULT_GEN_NAME = '__DEFAULT_GNAME'

    OUTCOME_ROWID = 1
    OUTCOME_DATA = 2

    FEEDBACK_TRAIL_TIME_WINDOW = 10 # seconds

    def __init__(self, fmkdb_path=None):

        self.name = Database.DEFAULT_DB_NAME
        if fmkdb_path is None:
            self.fmk_db_path = os.path.join(gr.fuddly_data_folder, self.name)
        else:
            self.fmk_db_path = os.path.expanduser(fmkdb_path)

        self._ref_names = {}

        self.config = None
        self.enabled = False

        self.fbk_timeout_re = re.compile('.*feedback timeout = (.*)s$')

        # self.current_project = None
        #
        # self.last_feedback = {}
        # self.feedback_trail = {}  # store feedback entries for self.feedback_trail_time_window
        # self.feedback_trail_init_ts = None
        # self.feedback_trail_time_window = self.FEEDBACK_TRAIL_TIME_WINDOW
        #
        # self._data_id = None
        # self._current_sent_date = None
        #
        # self._sql_handler_thread = None
        # self._sql_handler_stop_event = threading.Event()
        #
        # self._thread_initialized = threading.Event()
        # self._sql_stmt_submitted_cond = threading.Condition()
        # self._sql_stmt_list = []
        # self._sql_stmt_handled = threading.Event()
        #
        # self._sql_stmt_outcome_lock = threading.Lock()
        # self._sql_stmt_outcome = None
        #
        # self._sync_lock = threading.Lock()


    @staticmethod
    def get_default_db_path():
        return os.path.join(gr.fuddly_data_folder, Database.DEFAULT_DB_NAME)

    def _is_valid(self, connection, cursor):
        valid = False
        with connection:
            tmp_con = sqlite3.connect(':memory:', detect_types=sqlite3.PARSE_DECLTYPES)
            with open(gr.fmk_folder + self.DDL_fname) as fd:
                fmk_db_sql = fd.read()
            with tmp_con:
                cur = tmp_con.cursor()
                cur.executescript(fmk_db_sql)
                cur.execute("select name from sqlite_master WHERE type='table'")
                tables = map(lambda x: x[0], cur.fetchall())
                tables = filter(lambda x: not x.startswith('sqlite'), tables)
                for t in tables:
                    cur.execute('select * from {!s}'.format(t))
                    self._ref_names[t] = list(map(lambda x: x[0], cur.description))
                    cursor.execute('select * from {!s}'.format(t))
                    names = list(map(lambda x: x[0], cursor.description))
                    if self._ref_names[t] != names:
                        valid = False
                        break
                else:
                    valid = True

        return valid

    def column_names_from(self, table):
        return self._ref_names[table]

    def _sql_handler(self):
        if os.path.isfile(self.fmk_db_path):
            connection = sqlite3.connect(self.fmk_db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            cursor = connection.cursor()
            self._ok = self._is_valid(connection, cursor)
        else:
            connection = sqlite3.connect(self.fmk_db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            fmk_db_sql = open(gr.fmk_folder + self.DDL_fname).read()
            self._ok = False
            with connection:
                cursor = connection.cursor()
                cursor.executescript(fmk_db_sql)
                self._ok = True

        self._thread_initialized.set()

        if not self._ok:
            return

        connection.create_function("REGEXP", 2, regexp)
        connection.create_function("BINREGEXP", 2, regexp_bin)

        while True:

            with self._sql_stmt_submitted_cond:
                if self._sql_handler_stop_event.is_set() and not self._sql_stmt_list:
                    break
                self._sql_stmt_submitted_cond.wait(0.001)

                if self._sql_stmt_list:
                    sql_stmts = self._sql_stmt_list
                    self._sql_stmt_list = []
                else:
                    continue

            last_stmt_error = True
            for stmt in sql_stmts:
                sql_stmt, sql_params, outcome_type, sql_error = stmt
                try:
                    if sql_params is None:
                        cursor.execute(sql_stmt)
                    else:
                        cursor.execute(sql_stmt, sql_params)
                    connection.commit()
                except sqlite3.Error as e:
                    connection.rollback()
                    print("\n*** ERROR[SQL:{:s}] ".format(e.args[0])+sql_error)
                    last_stmt_error = True
                else:
                    last_stmt_error = False

            if outcome_type is not None:
                with self._sql_stmt_outcome_lock:
                    if self._sql_stmt_outcome is not None:
                        print("\n*** WARNING: SQL statement outcomes have not been consumed."
                              "\n    Will be overwritten!")

                    if last_stmt_error:
                        self._sql_stmt_outcome = None
                    elif outcome_type == Database.OUTCOME_ROWID:
                        self._sql_stmt_outcome = cursor.lastrowid
                    elif outcome_type == Database.OUTCOME_DATA:
                        self._sql_stmt_outcome = cursor.fetchall()
                    else:
                        print("\n*** ERROR: Unrecognized outcome type request")
                        self._sql_stmt_outcome = None

                self._sql_stmt_handled.set()

            self._sql_handler_stop_event.wait(0.001)

        if connection:
            connection.close()

    def _stop_sql_handler(self):
        with self._sync_lock:
            self._sql_handler_stop_event.set()
            self._sql_handler_thread.join()


    def submit_sql_stmt(self, stmt, params=None, outcome_type: Optional[int] = None, error_msg=''):
        """
        This method is the only one that should submit request to the threaded SQL handler.
        It is also synchronized to guarantee request order (especially needed when you wait for
        the outcomes of your submitted SQL statement).

        Args:
            stmt (str): SQL statement
            params (tuple): parameters
            outcome_type (int): type of the expected outcomes. If `None`, no outcomes are expected
            error_msg (str): specific error message to display in case of an error

        Returns:
            `None` or the expected outcomes
        """
        with self._sync_lock:

            with self._sql_stmt_submitted_cond:
                self._sql_stmt_list.append((stmt, params, outcome_type, error_msg))
                self._sql_stmt_submitted_cond.notify()

            if outcome_type is not None:
                # If we care about outcomes, then we are sure to get outcomes from the just
                # submitted SQL statement as this method is 'synchronized'.
                while not self._sql_stmt_handled.is_set():
                    self._sql_stmt_handled.wait(0.001)
                self._sql_stmt_handled.clear()

                with self._sql_stmt_outcome_lock:
                    ret = self._sql_stmt_outcome
                    self._sql_stmt_outcome = None
                    return ret

    def start(self):
        self.current_project = None

        self.last_feedback = {}
        self.feedback_trail = {}  # store feedback entries for self.feedback_trail_time_window
        self.feedback_trail_init_ts = None
        self.feedback_trail_time_window = self.FEEDBACK_TRAIL_TIME_WINDOW

        self._data_id = None
        self._current_sent_date = None

        self._sql_handler_thread = None
        self._sql_handler_stop_event = threading.Event()
        self._thread_initialized = threading.Event()
        self._sql_stmt_submitted_cond = threading.Condition()
        self._sql_stmt_list = []
        self._sql_stmt_handled = threading.Event()
        self._sql_stmt_outcome_lock = threading.Lock()
        self._sql_stmt_outcome = None

        self._sync_lock = threading.Lock()

        self._ok = False
        self.config = config("Database", path=[gr.config_folder])

        if self._sql_handler_thread is not None:
            return

        if not sqlite3_module:
            print("/!\\ WARNING /!\\: Fuddly's FmkDB unavailable because python-sqlite3 is not installed!")
            return False

        self._sql_handler_thread = threading.Thread(None, self._sql_handler, 'db_handler')
        self._sql_handler_thread.start()

        while not self._thread_initialized.is_set():
            self._thread_initialized.wait(0.1)

        self.enabled = self._ok
        return self._ok

    def stop(self):
        self._stop_sql_handler()
        self.enabled = False

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def is_enabled(self):
        return self.enabled

    def flush_feedback(self):
        self.last_feedback = {}
        self.feedback_trail = {}

    def flush_current_feedback(self):
        self.last_feedback = {}

    def execute_sql_statement(self, sql_stmt, params=None):
        return self.submit_sql_stmt(sql_stmt, params=params, outcome_type=Database.OUTCOME_DATA)


    def insert_data_model(self, dm_name):
        stmt = "INSERT INTO DATAMODEL(NAME) VALUES(?)"
        params = (dm_name,)
        err_msg = 'while inserting a value into table DATAMODEL!'
        self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)


    def insert_project(self, prj_name):
        stmt = "INSERT INTO PROJECT(NAME) VALUES(?)"
        params = (prj_name,)
        err_msg = 'while inserting a value into table PROJECT!'
        self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)


    def insert_dmaker(self, dm_name, dtype, name, is_gen, stateful, clone_type=None):
        clone_name = None if clone_type is None else name

        stmt = "INSERT INTO DMAKERS(DM_NAME,TYPE,NAME,CLONE_TYPE,CLONE_NAME,GENERATOR,STATEFUL)"\
               " VALUES(?,?,?,?,?,?,?)"
        params = (dm_name, dtype, name, clone_type, clone_name, is_gen, stateful)
        err_msg = 'while inserting a value into table DATAMODEL!'
        self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)


    def insert_data(self, dtype, dm_name, raw_data, sz, sent_date, ack_date,
                    target_ref, prj_name, group_id=None):

        if not self.enabled:
            return None

        blob = sqlite3.Binary(raw_data)

        stmt = "INSERT INTO DATA(GROUP_ID,TYPE,DM_NAME,CONTENT,SIZE,SENT_DATE,ACK_DATE,"\
               "TARGET,PRJ_NAME)"\
               " VALUES(?,?,?,?,?,?,?,?,?)"
        params = (group_id, dtype, dm_name, blob, sz, sent_date, ack_date, str(target_ref), prj_name)
        err_msg = 'while inserting a value into table DATA!'

        if self._data_id is None:
            d_id = self.submit_sql_stmt(stmt, params=params, outcome_type=Database.OUTCOME_ROWID,
                                        error_msg=err_msg)
            self._data_id = d_id
        else:
            self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)
            self._data_id += 1

        self._current_sent_date = sent_date

        return self._data_id


    def get_next_data_id(self, prev_id=None):
        if prev_id is None and self._data_id is None:
            return None
        elif prev_id is not None:
            return prev_id + 1
        elif self._data_id is not None:
            return self._data_id + 1

    def insert_async_data(self, dtype, dm_name, raw_data, sz, sent_date,
                          target_ref, prj_name, current_data_id=None):

        if not self.enabled:
            return None

        blob = sqlite3.Binary(raw_data)

        stmt = "INSERT INTO ASYNC_DATA(CURRENT_DATA_ID,TYPE,DM_NAME,CONTENT,SIZE,SENT_DATE,"\
               "TARGET,PRJ_NAME)"\
               " VALUES(?,?,?,?,?,?,?,?)"

        if self._current_sent_date is not None:
            # We do not associate an async data to the last data_id if
            # it is sent more than 60 seconds after
            if (sent_date - self._current_sent_date).total_seconds() > self.config.async_data.after_data_id:
                data_id = None
            else:
                data_id = self._data_id if current_data_id is None else current_data_id
        else:
            data_id = self._data_id if current_data_id is None else current_data_id

        params = (data_id, dtype, dm_name, blob, sz, sent_date, str(target_ref), prj_name)
        err_msg = 'while inserting a value into table ASYNC_DATA!'

        self.submit_sql_stmt(stmt, params=params, outcome_type=None, error_msg=err_msg)

        return


    def insert_steps(self, data_id, step_id, dmaker_type, dmaker_name, data_id_src,
                     user_input, info):
        if not self.enabled:
            return None

        if info:
            info = sqlite3.Binary(info)

        stmt = "INSERT INTO STEPS(DATA_ID,STEP_ID,DMAKER_TYPE,DMAKER_NAME,DATA_ID_SRC,USER_INPUT,INFO)"\
               " VALUES(?,?,?,?,?,?,?)"
        params = (data_id, step_id, dmaker_type, dmaker_name, data_id_src, user_input, info)
        err_msg = 'while inserting a value into table STEPS!'
        self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)


    def insert_feedback(self, data_id, source, timestamp, content, status_code=None):

        if self.feedback_trail_init_ts is None:
            self.feedback_trail_init_ts = timestamp

        # timestamp could be None, in this case we ignore the following condition
        if timestamp is not None and \
                timestamp - self.feedback_trail_init_ts > timedelta(seconds=self.feedback_trail_time_window):
            self.feedback_trail = {}
            self.feedback_trail_init_ts = timestamp

        if not isinstance(source, FeedbackSource):
            source = FeedbackSource(source)

        if source not in self.last_feedback:
            self.last_feedback[source] = []

        if source not in self.feedback_trail:
            self.feedback_trail[source] = []

        fbk_entry = {
            'timestamp': timestamp,
            'content': content,
            'status': status_code
        }

        self.last_feedback[source].append(fbk_entry)
        self.feedback_trail[source].append(fbk_entry)

        if self.current_project:
            self.current_project.trigger_feedback_handlers(source, timestamp, content, status_code)

        if not self.enabled:
            return None

        if content:
            content = sqlite3.Binary(content)

        stmt = "INSERT INTO FEEDBACK(DATA_ID,SOURCE,DATE,CONTENT,STATUS)"\
               " VALUES(?,?,?,?,?)"
        params = (data_id, str(source), timestamp, content, status_code)
        err_msg = 'while inserting a value into table FEEDBACK!'
        self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)


    def iter_feedback_entries(self, last=True, source=None):
        feedback = copy.copy(self.last_feedback if last else self.feedback_trail)
        if source is None:
            for src, fbks in feedback.items():
                for item in fbks:
                    status = item['status']
                    ts = item['timestamp']
                    content = item['content']
                    yield src, status, ts, content
        else:
            fbk_from_src = self.last_feedback[source] if last else self.feedback_trail[source]
            for item in fbk_from_src:
                status = item['status']
                ts = item['timestamp']
                content = item['content']
                yield status, ts, content

    def insert_comment(self, data_id, content, date):
        if not self.enabled:
            return None

        stmt = "INSERT INTO COMMENTS(DATA_ID,CONTENT,DATE)" \
               " VALUES(?,?,?)"
        params = (data_id, content, date)
        err_msg = 'while inserting a value into table COMMENTS!'
        self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)


    def insert_fmk_info(self, data_id, content, date, error=False):
        if not self.enabled:
            return None

        stmt = "INSERT INTO FMKINFO(DATA_ID,CONTENT,DATE,ERROR)"\
               " VALUES(?,?,?,?)"
        params = (data_id, content, date, error)
        err_msg = 'while inserting a value into table FMKINFO!'
        self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)

    def insert_analysis(self, data_id, content, date, impact=False):
        if not self.enabled:
            return None

        stmt = "INSERT INTO ANALYSIS(DATA_ID,CONTENT,DATE,IMPACT)"\
               " VALUES(?,?,?,?)"
        params = (data_id, content, date, impact)
        err_msg = 'while inserting a value into table ANALYSIS!'
        self.submit_sql_stmt(stmt, params=params, error_msg=err_msg)

    def fetch_data(self, start_id=1, end_id=-1):
        ign_end_id = '--' if end_id < 1 else ''

        stmt = \
            '''
            SELECT DATA.ID, DATA.CONTENT, DATA.TYPE, DMAKERS.NAME, DATA.DM_NAME
            FROM DATA INNER JOIN DMAKERS
              ON DATA.TYPE = DMAKERS.TYPE AND DATA.DM_NAME = DMAKERS.DM_NAME AND DMAKERS.CLONE_TYPE IS NULL
            WHERE DATA.ID >= {sid:d} {ign_eid:s} AND DATA.ID <= {eid:d}
            UNION ALL
            SELECT DATA.ID, DATA.CONTENT, DMAKERS.CLONE_TYPE AS TYPE, DMAKERS.CLONE_NAME AS NAME,
                   DATA.DM_NAME
            FROM DATA INNER JOIN DMAKERS
              ON DATA.TYPE = DMAKERS.TYPE AND DMAKERS.CLONE_TYPE IS NOT NULL
            WHERE DATA.ID >= {sid:d} {ign_eid:s} AND DATA.ID <= {eid:d}
            '''.format(sid = start_id, eid = end_id, ign_eid = ign_end_id)

        ret = self.submit_sql_stmt(stmt, outcome_type=Database.OUTCOME_DATA)
        return ret


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
                          with_analysis=True, with_async_data=False,
                          fbk_src=None, limit_data_sz=None, page_width=100, colorized=True,
                          raw=False, decoding_hints=None, dm_list=None):

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

        async_data = self.execute_sql_statement(
            f"SELECT ID, CURRENT_DATA_ID, TYPE, DM_NAME, CONTENT, SIZE, SENT_DATE,"
            f"       TARGET, PRJ_NAME FROM ASYNC_DATA "
            f"WHERE PRJ_NAME == ?"
            f"  AND ( CURRENT_DATA_ID == ?"
            # If current_data_id is null, we only keep async data which were
            # sent no more than 5 seconds before the requested data_id.
            # And we ignore the ones (current_data_id is null) that have been sent after
            # (because it means the framework was reset)
            f"        OR ( CURRENT_DATA_ID IS NULL"
            f"             AND CAST((JulianDay(?)-JulianDay(SENT_DATE))*24*60*60 AS INTEGER) "
            f"                    < {self.config.async_data.before_data_id}"
            f"             AND (JulianDay(?)-JulianDay(SENT_DATE)) >= 0 )"
            f"       );",
            params=(prj, data_id, sent_date, sent_date)
        )

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

        fbk_timeout_info = self.execute_sql_statement(
            'SELECT CONTENT, DATE FROM FMKINFO '
            'WHERE CONTENT REGEXP "feedback timeout =" '
            'ORDER BY DATE DESC;'
        )

        analysis_records = self.execute_sql_statement(
            "SELECT CONTENT, DATE, IMPACT FROM ANALYSIS "
            "WHERE DATA_ID == {data_id:d} "
            "ORDER BY DATE ASC;".format(data_id=data_id)
        )

        def search_dm(data_model_name, load_arg):
            for dm in dm_list:
                if dm.name == data_model_name:
                    dm.load_data_model(load_arg)

                    def decode_wrapper(*args, **kwargs):
                        return dm.decode(*args, **kwargs)[1]

                    return decode_wrapper
            else:
                print(colorize("*** ERROR: No available data model matching this database entry "
                               "[requested data model: '{:s}'] ***".format(data_model_name),
                               rgb=Color.ERROR))
                return None

        decode_data = False
        decode_fbk = False
        decoder_func = None
        fbk_decoder_func = None
        if decoding_hints is not None:
            load_arg, decode_data, decode_fbk, user_atom_name, user_fbk_atom_name, forced_fbk_decoder = decoding_hints
            if decode_data or decode_fbk:
                decoder_func = search_dm(dm_name, load_arg)
                if decoder_func is None:
                    decode_data = False
            if decode_fbk:
                if forced_fbk_decoder:
                    fbk_decoder_func = search_dm(forced_fbk_decoder, load_arg)
                else:
                    fbk_decoder_func = decoder_func
                decode_fbk = fbk_decoder_func is not None

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
        status_prefix = "    Status: "
        msg += colorize('\n' + status_prefix, rgb=Color.FMKINFO)
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
                msg += colorize(",\n".format(src) + ' '*len(status_prefix), rgb=Color.FMKINFO)

        msg += '\n'
        sentd = sent_date.strftime("%d/%m/%Y - %H:%M:%S.%f") if sent_date else 'None'
        ackd = ack_date.strftime("%d/%m/%Y - %H:%M:%S.%f") if ack_date else 'None'
        msg += colorize("      Sent: ", rgb=Color.FMKINFO) + colorize(sentd, rgb=Color.DATE)
        msg += colorize("\n  Received: ", rgb=Color.FMKINFO) + colorize(ackd, rgb=Color.DATE)
        msg += colorize("\n      Size: ", rgb=Color.FMKINFO) + colorize(str(size) + ' Bytes',
                                                                        rgb=Color.FMKSUBINFO)
        msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)

        prt(msg)

        msg = ''
        for idx, fbkt in enumerate(fbk_timeout_info, start=1):
            content, tstamp = fbkt
            if sent_date >= tstamp:
                parsed = self.fbk_timeout_re.match(content)
                val = parsed.group(1) + 's' if parsed else 'FmkDB ERROR'
                break
        else:
            val = 'Not found in FmkDB (default value was most likely used)'

        msg += colorize("\n Feedback Timeout: ", rgb=Color.FMKINFO)
        msg += colorize(f"{val}", rgb=Color.FMKSUBINFO)
        msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)
        prt(msg)


        def handle_dmaker(dmk_pattern, info, dmk_type, dmk_name, name_sep_sz, ui, id_src=None):
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
                info = gr.unconvert_from_internal_repr(info)
                info = info.split('\n')
                for i in info:
                    chks = chunk_lines(i, page_width - prefix_sz - 10)
                    for idx, c in enumerate(chks):
                        spc = 1 if idx > 0 else 0
                        msg += '\n' + colorize(' ' * prefix_sz + '| ', rgb=Color.FMKINFO) + \
                               colorize(' ' * spc + c, rgb=Color.DATAINFO_ALT)
            return msg


        if steps:
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
                        sid += 1
                        msg += colorize("\n Step #{:d}:".format(sid), rgb=Color.FMKINFOGROUP)
                        msg += handle_dmaker('Disruptor', info, dmk_type, dmk_name, len(data_type), ui)
                    else:
                        msg += handle_dmaker('Generator', info, dmk_type, dmk_name, name_sep_sz, ui,
                                             id_src=id_src)
                else:
                    msg += colorize("\n Step #{:d}:".format(sid), rgb=Color.FMKINFOGROUP)
                    msg += handle_dmaker('Disruptor', info, dmk_type, dmk_name, name_sep_sz, ui)
                sid += 1
            msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)
            prt(msg)

        msg = ''
        for idx, info in enumerate(analysis_records, start=1):
            content, tstamp, impact = info
            if not with_analysis:
                continue
            date_str = tstamp.strftime("%d/%m/%Y - %H:%M") if tstamp else 'Not Dated'
            msg += colorize("\n User Analysis: ", rgb=Color.FMKINFOGROUP)
            msg += colorize(date_str, rgb=Color.DATE)
            msg += colorize(" | ", rgb=Color.FMKINFOGROUP)
            if impact:
                msg += colorize("Data triggered an unexpected behavior", rgb=Color.ANALYSIS_IMPACT)
            else:
                msg += colorize("Data did not trigger an unexpected behavior", rgb=Color.ANALYSIS_NO_IMPACT)
            if content:
                chks = chunk_lines(content, page_width - 10)
                for c in chks:
                    color = Color.FMKHLIGHT if impact else Color.DATAINFO_ALT
                    msg += '\n' + colorize(' ' * 2 + '| ', rgb=Color.FMKINFOGROUP) + \
                           colorize(str(c), rgb=color)
        if msg:
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
            if decode_data:
                atom_name = data_type.lower() if user_atom_name is None else user_atom_name
                msg += decoder_func(data_content, atom_name=atom_name, colorized=colorized)
            else:
                data_content = gr.unconvert_from_internal_repr(data_content)
                data_content = self._handle_binary_content(data_content, sz_limit=limit_data_sz, raw=raw,
                                                           colorized=colorized)
                msg += data_content
            msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)

        if with_async_data and async_data:
            for async_data_id, curr_data_id, dtype, dm_name, content, size, async_date, target, prj in async_data:
                add_info = f' --> sent before Data ID #{data_id}' if curr_data_id is None else ''
                date_str = async_date.strftime("%d/%m/%Y - %H:%M:%S.%f") if async_date else 'None'
                msg += colorize(f'\n Async Data ID #{async_data_id}', rgb=Color.FMKINFOGROUP)
                msg += colorize(f' (', rgb=Color.FMKINFOGROUP)
                msg += colorize(f'{date_str}', rgb=Color.DATE)
                msg += colorize(f')', rgb=Color.FMKINFOGROUP)
                msg += colorize(add_info, rgb=Color.WARNING)
                msg += colorize(f'\n  | Type:', rgb=Color.FMKINFO)
                msg += colorize(f' {dtype}', rgb=Color.FMKSUBINFO)
                msg += colorize(f' | DM:', rgb=Color.FMKINFO)
                msg += colorize(f' {dm_name}', rgb=Color.FMKSUBINFO)
                msg += colorize(f' | Size:', rgb=Color.FMKINFO)
                msg += colorize(f' {size} Bytes', rgb=Color.FMKSUBINFO)
                msg += colorize(f'\n  | Target:', rgb=Color.FMKINFO)
                msg += colorize(f' {target}\n', rgb=Color.FMKSUBINFO)

                content = gr.unconvert_from_internal_repr(content)
                content = self._handle_binary_content(content, sz_limit=limit_data_sz, raw=raw,
                                                      colorized=colorized)
                msg += content

            if async_data:
                msg += colorize('\n' + line_pattern, rgb=Color.NEWLOGENTRY)

        if with_fbk:
            for src, tstamp, status, content in feedback:
                formatted_ts = None if tstamp is None else tstamp.strftime("%d/%m/%Y - %H:%M:%S.%f")
                msg += colorize("\n Status(", rgb=Color.FMKINFOGROUP)
                msg += colorize("{!s}".format(src), rgb=Color.FMKSUBINFO)
                msg += colorize(" | ", rgb=Color.FMKINFOGROUP)
                msg += colorize("{!s}".format(formatted_ts),
                                rgb=Color.FMKSUBINFO)
                msg += colorize(")", rgb=Color.FMKINFOGROUP)
                msg += colorize(" = {!s}".format(status), rgb=Color.FMKSUBINFO)
                if content:
                    if decode_fbk:
                        msg += fbk_decoder_func(content, atom_name=user_fbk_atom_name, colorized=colorized)
                    else:
                        content = gr.unconvert_from_internal_repr(content)
                        content = self._handle_binary_content(content, sz_limit=limit_data_sz, raw=raw,
                                                              colorized=colorized)
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

    def _handle_binary_content(self, content, sz_limit=None, raw=False, colorized=True):
        colorize = self._get_color_function(colorized)

        content = content if not raw else '{!a}'.format(content)

        if sz_limit is not None and len(content) > sz_limit:
            content = content[:sz_limit]
            content += colorize(' ...', rgb=Color.FMKHLIGHT)

        return content


    def display_data_info_by_date(self, start, end, with_data=False, with_fbk=False, with_fmkinfo=True,
                                  with_analysis=True, with_async_data=False,
                                  fbk_src=None, prj_name=None,
                                  limit_data_sz=None, raw=False, page_width=100, colorized=True,
                                  decoding_hints=None, dm_list=None):
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
                                       with_fmkinfo=with_fmkinfo,
                                       with_analysis=with_analysis,
                                       with_async_data=with_async_data,
                                       fbk_src=fbk_src,
                                       limit_data_sz=limit_data_sz, raw=raw, page_width=page_width,
                                       colorized=colorized,
                                       decoding_hints=decoding_hints, dm_list=dm_list)
        else:
            print(colorize("*** ERROR: No data found between {!s} and {!s} ***".format(start, end),
                           rgb=Color.ERROR))

    def display_data_info_by_range(self, first_id, last_id, with_data=False, with_fbk=False, with_fmkinfo=True,
                                   with_analysis=True, with_async_data=False,
                                   fbk_src=None, prj_name=None,
                                   limit_data_sz=None, raw=False, page_width=100, colorized=True,
                                   decoding_hints=None, dm_list=None):

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
                                       with_fmkinfo=with_fmkinfo, with_analysis=with_analysis,
                                       with_async_data=with_async_data,
                                       fbk_src=fbk_src,
                                       limit_data_sz=limit_data_sz, raw=raw, page_width=page_width,
                                       colorized=colorized,
                                       decoding_hints=decoding_hints, dm_list=dm_list)
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

        data_records = self.execute_sql_statement(
            "SELECT ID FROM DATA;"
        )
        nb_data_records = len(data_records)
        title = colorize("Number of Data IDs: ", rgb=Color.FMKINFOGROUP)
        content = colorize("{:d}".format(nb_data_records), rgb=Color.FMKSUBINFO)
        print(title + content)


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
            data_id = first

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

                export_fname = '{typ:s}_ID{did:d}_{date:s}_{cpt:0>2d}.{ext:s}'.format(
                    date=current_export_date,
                    cpt=export_cpt,
                    ext=file_extension,
                    typ=data_type,
                    did=data_id)

                export_full_fn = os.path.join(base_dir, dm_name, export_fname)
                gr.ensure_dir(export_full_fn)

                with open(export_full_fn, 'wb') as fd:
                    fd.write(content)

                print(colorize("Data ID #{:d} --> {:s}".format(data_id, export_full_fn),
                               rgb=Color.FMKINFO))

                data_id += 1

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

        print(colorize("*** Data {:d} and all related records have been removed ***".format(data_id),
                       rgb=Color.FMKINFO))


    def shrink_db(self):
        self.execute_sql_statement(
            "VACUUM;"
        )

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

    def get_data_with_impact(self, prj_name=None, fbk_src=None, fbk_status_formula='? < 0',
                             display=True, verbose=False,
                             raw_analysis=False,
                             colorized=True):

        fbk_status_formula =  fbk_status_formula.replace('?', 'STATUS')
        colorize = self._get_color_function(colorized)

        if fbk_src:
            fbk_records = self.execute_sql_statement(
                f"SELECT DATA_ID, STATUS, SOURCE FROM FEEDBACK "
                f"WHERE {fbk_status_formula} and SOURCE REGEXP ?;",
                params=(fbk_src,)
            )
        else:
            fbk_records = self.execute_sql_statement(
                f"SELECT DATA_ID, STATUS, SOURCE FROM FEEDBACK "
                f"WHERE {fbk_status_formula};"
            )


        analysis_records = self.execute_sql_statement(
            "SELECT DATA_ID, CONTENT, DATE, IMPACT FROM ANALYSIS "
            "ORDER BY DATE DESC;"
        )
        if analysis_records:
            data_analyzed = set([x[0] for x in analysis_records])
        else:
            data_analyzed = set()

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

            user_src = 'User Analysis'
            for rec in analysis_records:
                data_id, content, tstamp, impact = rec
                if data_id not in id2fbk:
                    id2fbk[data_id] = {}
                if user_src not in id2fbk[data_id]:
                    id2fbk[data_id][user_src] = []
                id2fbk[data_id][user_src].append(impact)

            data_id_pattern = "{:>" + str(int(math.log10(len(prj_records))) + 2) + "s}"
            format_string = "     [DataID " + data_id_pattern + "] --> {:s}"

            current_prj = None
            for rec in prj_records:
                data_id, target, prj = rec
                if data_id in id2fbk:

                    if not raw_analysis and data_id in data_analyzed:
                        records = self.execute_sql_statement(
                            "SELECT IMPACT FROM ANALYSIS "
                            "WHERE DATA_ID == {data_id:d} "
                            "ORDER BY DATE DESC;".format(data_id=data_id)
                        )
                        if records[0][0] == False:
                            continue

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
                                if src == user_src:
                                    if status[0] == 0:
                                        status_str = 'User analysis carried out: False Positive'
                                    else:
                                        status_str = 'User analysis carried out: Impact Confirmed'
                                    color = Color.ANALYSIS_FALSEPOSITIVE if status[0] == 0 else Color.ANALYSIS_CONFIRM
                                    print(colorize("       |_ {:s}".format(status_str),
                                                   rgb=color))
                                else:
                                    status_str = ''.join([str(s) + ',' for s in status])[:-1]
                                    print(colorize("       |_ status={:s} from {:s}"
                                                   .format(status_str, src),
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

        fbk = gr.convert_to_internal_repr(fbk)

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