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
import datetime
import threading
import itertools

from libs.external_modules import *
from fuzzfmk.data_model import Data
from fuzzfmk.global_resources import *
from fuzzfmk.database import Database
from libs.utils import ensure_dir
import fuzzfmk.global_resources as gr

import data_models


class Stats:
    def __init__(self, generic_generators):
        self.reset()
        self.gen = generic_generators

    def reset(self):
        self.__stats = {}
        self.__dt_state = {}

    def inc_stat(self, generator_type, generator_name, user_inputs):

        if generator_type is None:
            return

        dt_full = generator_type

        if dt_full not in self.__stats:
            self.__stats[dt_full] = {}
            self.__stats[dt_full]['total'] = 0
            self.__stats[dt_full]['bygen'] = {}

        self.__stats[dt_full]['total'] += 1

        if generator_name not in self.__stats[dt_full]['bygen']:
            self.__stats[dt_full]['bygen'][generator_name] = 0

        self.__stats[dt_full]['bygen'][generator_name] += 1

    def get_formated_stats(self):
        stats = ""
        for generator_type, val in self.__stats.items():
            stats += "Generator Type '%s'\n" % generator_type
            stats += "  |_ total number of generated data: %d\n" % val['total']
            for gen, nb in val['bygen'].items():
                stats += "  |_ number of generated data by '%s': %d\n" % (gen, nb)
            stats += '\n'

        return stats


class Logger(object):
    '''
    The Logger is used for keeping the history of the communication
    with the Target. The methods are used by the framework, but can
    also be leveraged by an Operator.
    '''

    fmkDB = None

    def __init__(self, name=None, prefix='', export_data=False, explicit_data_recording=False,
                 export_orig=True, export_raw_data=True, console_display_limit=800,
                 enable_file_logging=False):
        '''
        Args:
          name (str): Name to be used in the log filenames. If not specified, the name of the project
            in which the logger is embedded will be used.
          export_data (bool): If True, each emitted data will be stored in a specific
            file within `exported_data/`.
          explicit_data_recording (bool): Used for logging outcomes further to an Operator instruction. If True,
            the operator would have to state explicitly if it wants the just emitted data to be recorded.
            Such notification is possible when the framework call its method
            :meth:`fuzzfmk.operator_helpers.Operator.do_after_all()`, where the Operator can take its decision
            after the observation of the target feedback and/or probes outputs.
          export_orig (bool): If True, will also log the original data on which disruptors have been called.
          export_raw_data (bool): If True, will log the data as it is, without trying to interpret it
            as human readable text.
          console_display_limit (int): maximum amount of characters to display on the console at once.
            If this threshold is overrun, the message to print on the console will be truncated.
          prefix (str): prefix to use for printing on the console.
          enable_file_logging (bool): If True, file logging will be enabled.
        '''
        self.name = name
        self.p = prefix
        self.__export_data = export_data
        self.__explicit_data_recording = explicit_data_recording
        self.__export_orig = export_orig
        self._console_display_limit = console_display_limit

        now = datetime.datetime.now()
        self.__prev_export_date = now.strftime("%Y%m%d_%H%M%S")
        self.__export_cpt = 0
        self.__export_raw_data = export_raw_data

        self._enable_file_logging = enable_file_logging
        self._fd = None

        self._tg_fbk = []
        self._tg_fbk_lck = threading.Lock()

        def init_logfn(x, nl_before=True, nl_after=False, rgb=None, style=None, verbose=False,
                       do_record=True):
            if issubclass(x.__class__, Data):
                if sys.version_info[0] > 2:
                    data = repr(x) if self.__export_raw_data else x.to_bytes().decode('latin-1')
                else:
                    data = repr(x) if self.__export_raw_data else str(x)
                rgb = None
                style = None
            elif issubclass(x.__class__, bytes) and sys.version_info[0] > 2:
                data = repr(x) if self.__export_raw_data else x.decode('latin-1')
            else:
                data = x
            self.print_console(data, nl_before=nl_before, nl_after=nl_after, rgb=rgb, style=style)
            if verbose and issubclass(x.__class__, Data) and x.node is not None:
                x.pretty_print()

            return data

        self.log_fn = init_logfn

    def start(self):

        self.__idx = 0
        self.__tmp = False

        self._reset_current_state()
        self.last_data_id = None
        self.last_data_recordable = None

        with self._tg_fbk_lck:
            self._tg_fbk = []

        if self.name is None:
            self.log_fn = lambda x: x

        elif self._enable_file_logging:
            self.now = datetime.datetime.now()
            self.now = self.now.strftime("%Y_%m_%d_%H%M%S")

            log_file = os.path.join(logs_folder, self.now + '_' + self.name + '_log')
            self._fd = open(log_file, 'w')

            def intern_func(x, nl_before=True, nl_after=False, rgb=None, style=None, verbose=False,
                            do_record=True):
                if issubclass(x.__class__, Data):
                    if sys.version_info[0] > 2:
                        data = repr(x) if self.__export_raw_data else x.to_bytes().decode('latin-1')
                    else:
                        data = repr(x) if self.__export_raw_data else str(x)
                    rgb = None
                    style = None
                elif issubclass(x.__class__, bytes) and sys.version_info[0] > 2:
                    data = repr(x) if self.__export_raw_data else x.decode('latin-1')
                else:
                    data = x
                self.print_console(data, nl_before=nl_before, nl_after=nl_after, rgb=rgb, style=style)
                if not do_record:
                    return data
                try:
                    self._fd.write(data)
                    self._fd.write('\n')
                    if verbose and issubclass(x.__class__, Data) and x.node is not None:
                        x.pretty_print(log_func=self._fd.write)
                    self._fd.flush()
                except ValueError:
                    self.print_console('\n*** ERROR: The log file has been closed.' \
                                       ' (Maybe because the Logger has been stopped and has not been restarted yet.)',
                                       rgb=Color.ERROR)

                return data

            self.log_fn = intern_func

        else:
            # No file logging
            pass

        self.print_console('*** Logger is started ***\n', nl_before=False, rgb=Color.COMPONENT_START)

    def stop(self):

        if self._fd:
            self._fd.close()

        self.log_stats()

        self._reset_current_state()
        self.last_data_id = None
        self.last_data_recordable = None

        self.print_console('*** Logger is stopped ***\n', nl_before=False, rgb=Color.COMPONENT_STOP)


    def _reset_current_state(self):
        self._current_data = None
        self._current_orig_data_id = None
        self._current_size = None
        self._current_sent_date = None
        self._current_ack_date = None
        self._current_dmaker_list= []
        self._current_dmaker_info = {}
        self._current_src_data_id = None

    def commit_log_entry(self, group_id, prj_name, tg_name):
        if self._current_data is not None:  # that means data will be recorded
            init_dmaker = self._current_data.get_initial_dmaker()
            init_dmaker = Database.DEFAULT_GTYPE_NAME if init_dmaker is None else init_dmaker[0]
            dm = self._current_data.get_data_model()
            dm_name = Database.DEFAULT_DM_NAME if dm is None else dm.name

            self.last_data_id = self.fmkDB.insert_data(init_dmaker, dm_name,
                                                       self._current_data.to_bytes(),
                                                       self._current_size,
                                                       self._current_sent_date,
                                                       self._current_ack_date,
                                                       tg_name, prj_name,
                                                       group_id=group_id)

            if self.last_data_id is None:
                print("\n*** ERROR: Cannot insert the data record in FMKDB!")
                self.fmkDB.rollback()
                self.last_data_id = None
                self.last_data_recordable = None
                self._reset_current_state()
                return self.last_data_id

            self._current_data.set_data_id(self.last_data_id)

            if self._current_orig_data_id is not None:
                self.fmkDB.insert_steps(self.last_data_id, 1, None, None,
                                        self._current_orig_data_id,
                                        None, None)
                step_id_start = 2
            else:
                step_id_start = 1

            for step_id, dmaker in enumerate(self._current_dmaker_list, start=step_id_start):
                dmaker_type, dmaker_name, user_input = dmaker
                info = self._current_dmaker_info.get((dmaker_type,dmaker_name), None)
                if info is not None:
                    info = '\n'.join(info)
                    if sys.version_info[0] > 2:
                        info = bytes(info, 'latin_1')
                    else:
                        info = bytes(info)
                self.fmkDB.insert_steps(self.last_data_id, step_id, dmaker_type, dmaker_name,
                                        self._current_src_data_id,
                                        str(user_input), info)

            self.fmkDB.commit()

            self._reset_current_state()

            return self.last_data_id

        else:
            return None


    def log_fmk_info(self, info, nl_before=False, nl_after=False, rgb=Color.FMKINFO,
                     data_id=None, do_record=True):
        now = datetime.datetime.now()
        if nl_before:
            p = '\n'
        else:
            p = ''
        if nl_after:
            s = '\n'
        else:
            s = ''
        msg = p + "*** [ %s ] ***" % info + s
        self.log_fn(msg, rgb=rgb)
        data_id = self.last_data_id if data_id is None else data_id
        if do_record:
            self.fmkDB.insert_fmk_info(data_id, msg, now)

    def collect_target_feedback(self, fbk, status_code=None):
        """
        Used within the scope of the Logger feedback-collector infrastructure.
        If your target implement the interface :meth:`Target.get_feedback`, no need to
        use this infrastructure.

        To be called by the target each time feedback need to be registered.

        Args:
            fbk: feedback record
            status_code (int): should be negative for error
        """
        now = datetime.datetime.now()

        if sys.version_info[0] > 2 and isinstance(fbk, bytes):
            fbk = fbk.decode('latin_1')
        with self._tg_fbk_lck:
            self._tg_fbk.append((now, str(fbk), status_code))

    def log_collected_target_feedback(self, preamble=None, epilogue=None):
        """
        Used within the scope of the Logger feedback-collector feature.
        If your target implement the interface :meth:`Target.get_feedback`, no need to
        use this infrastructure.

        It allows to retrieve the collected feedback, that has been populated
        by the target (through call to :meth:`Logger.collect_target_feedback`).

        Args:
            preamble (str): prefix added to each collected feedback
            epilogue (str): suffix added to each collected feedback

        Returns:
            bool: True if target feedback has been collected through logger infrastructure
              :meth:`Logger.collect_target_feedback`, False otherwise.
        """
        error_detected = False

        with self._tg_fbk_lck:
            fbk_list = self._tg_fbk
            self._tg_fbk = []

        if not fbk_list:
            # self.log_fn("\n::[ NO TARGET FEEDBACK ]::\n") 
            raise NotImplementedError

        if self.last_data_recordable or not self.__explicit_data_recording:
            record = True
        else:
            # feedback will not be recorded because data is not recorded
            record = False

        if preamble is not None:
            self.log_fn(preamble, do_record=record)

        for fbk, idx in zip(fbk_list, range(len(fbk_list))):
            timestamp, m, status = fbk
            fbk_cond = status is not None and status < 0
            hdr_color = Color.FEEDBACK_ERR if fbk_cond else Color.FEEDBACK
            body_color = Color.FEEDBACK_HLIGHT if fbk_cond else None
            self.log_fn("### Collected Target Feedback [{:d}] (status={!s}): ".format(idx, status),
                        rgb=hdr_color, do_record=record)
            self.log_fn(m, rgb=body_color, do_record=record)
            if record:
                self.fmkDB.insert_feedback(self.last_data_id,
                                           "Collector [record #{:d}]".format(idx),
                                           timestamp,
                                           self._encode_target_feedback(m),
                                           status_code=status)
            if status is not None and status < 0:
                error_detected = True

        if epilogue is not None:
            self.log_fn(epilogue, do_record=record)

        return error_detected

    def log_target_feedback_from(self, feedback, timestamp,
                                 preamble=None, epilogue=None,
                                 source=None,
                                 status_code=None):
        decoded_feedback = self._decode_target_feedback(feedback)

        if self.last_data_recordable or not self.__explicit_data_recording:
            record = True
        else:
            # feedback will not be recorded because data is not recorded
            record = False

        if preamble is not None:
            self.log_fn(preamble, do_record=record)

        if not decoded_feedback and (status_code is None or status_code >= 0):
            msg_hdr = "### No Target Feedback!" if source is None else '### No Target Feedback from "{!s}"!'.format(
                source)
            self.log_fn(msg_hdr, rgb=Color.FEEDBACK, do_record=record)
        else:
            fbk_cond = status_code is not None and status_code < 0
            hdr_color = Color.FEEDBACK_ERR if fbk_cond else Color.FEEDBACK
            body_color = Color.FEEDBACK_HLIGHT if fbk_cond else None
            if not decoded_feedback:
                msg_hdr = "### Target Status: {!s}".format(status_code) if source is None \
                    else "### Target Status from '{!s}': {!s}".format(source, status_code)
            else:
                msg_hdr = "### Target Feedback (status={!s}):".format(status_code) if source is None \
                    else "### Target Feedback from '{!s}' (status={!s}):".format(source, status_code)
            self.log_fn(msg_hdr, rgb=hdr_color, do_record=record)
            if decoded_feedback:
                if isinstance(decoded_feedback, list):
                    for dfbk in decoded_feedback:
                        self.log_fn(dfbk, rgb=body_color, do_record=record)
                else:
                    self.log_fn(decoded_feedback, rgb=body_color, do_record=record)

            if record:
                src = 'Default' if source is None else source
                if isinstance(feedback, list):
                    for fbk, ts in zip(feedback, timestamp):
                        self.fmkDB.insert_feedback(self.last_data_id, src, ts,
                                                   self._encode_target_feedback(fbk),
                                                   status_code=status_code)
                else:
                    self.fmkDB.insert_feedback(self.last_data_id, src, timestamp,
                                               self._encode_target_feedback(feedback),
                                               status_code=status_code)

        if epilogue is not None:
            self.log_fn(epilogue, do_record=record)

    def log_operator_feedback(self, feedback, timestamp, op_name, status_code=None):
        if feedback is None:
            decoded_feedback = None
        else:
            decoded_feedback = self._decode_target_feedback(feedback)
            # decoded_feedback can be the empty string

        if self.last_data_recordable or not self.__explicit_data_recording:
            record = True
        else:
            # feedback will not be recorded because data is not recorded
            record = False

        if not decoded_feedback and status_code is None:
            self.log_fn("### No Operator Feedback!", rgb=Color.FEEDBACK,
                        do_record=record)
        else:
            fbk_cond = status_code is not None and status_code < 0
            hdr_color = Color.FEEDBACK_ERR if fbk_cond else Color.FEEDBACK
            body_color = Color.FEEDBACK_HLIGHT if fbk_cond else None
            if decoded_feedback:
                self.log_fn("### Operator Feedback (status={!s}):".format(status_code),
                            rgb=hdr_color, do_record=record)
                self.log_fn(decoded_feedback, rgb=body_color, do_record=record)
            else: # status_code is not None
                self.log_fn("### Operator Status: {:d}".format(status_code),
                            rgb=hdr_color, do_record=record)

            if self.last_data_id is not None and record:
                feedback = None if feedback is None else self._encode_target_feedback(feedback)
                self.fmkDB.insert_feedback(self.last_data_id,
                                           "Operator '{:s}'".format(op_name),
                                           timestamp,
                                           feedback,
                                           status_code=status_code)

    def _decode_target_feedback(self, feedback):
        if feedback is None:
            return feedback

        if isinstance(feedback, list):
            new_fbk = []
            for f in feedback:
                new_f = f.strip()
                if sys.version_info[0] > 2 and new_f and isinstance(new_f, bytes):
                    new_f = new_f.decode('latin_1')
                    new_f = '{!a}'.format(new_f)
                new_fbk.append(new_f)
                if not list(filter(lambda x: x != '', new_fbk)):
                    new_fbk = None
        else:
            new_fbk = feedback.strip()
            if sys.version_info[0] > 2 and new_fbk and isinstance(new_fbk, bytes):
                new_fbk = new_fbk.decode('latin_1')
                new_fbk = '{!a}'.format(new_fbk)

        return new_fbk

    def _encode_target_feedback(self, feedback):
        if sys.version_info[0] > 2 and not isinstance(feedback, bytes):
            feedback = bytes(feedback, 'latin_1')
        return feedback

    def log_probe_feedback(self, source, timestamp, content, status_code, force_record=False):
        if self.last_data_recordable or not self.__explicit_data_recording or force_record:
            record = True
        else:
            # feedback will not be recorded because data is not recorded
            record = False

        fbk_cond = status_code is not None and status_code < 0
        hdr_color = Color.FEEDBACK_ERR if fbk_cond else Color.FEEDBACK
        body_color = Color.FEEDBACK_HLIGHT if fbk_cond else None
        if content is None:
            self.log_fn("### {:s} Status: {:d}".format(source, status_code),
                        rgb=hdr_color, do_record=record)
        else:
            self.log_fn("### {:s} Feedback (status={:d}):".format(source, status_code),
                        rgb=hdr_color, do_record=record)
            self.log_fn(self._decode_target_feedback(content),rgb=body_color,
                        do_record=record)

        if record:
            content = None if content is None else self._encode_target_feedback(content)
            self.fmkDB.insert_feedback(self.last_data_id, source, timestamp, content,
                                       status_code=status_code)

    def start_new_log_entry(self, preamble=''):
        self.__idx += 1
        self._current_sent_date = datetime.datetime.now()
        now = self._current_sent_date.strftime("%d/%m/%Y - %H:%M:%S")
        msg = "====[ {:d} ]==[ {:s} ]====".format(self.__idx, now)
        msg += '='*(max(80-len(msg),0))
        self.log_fn(msg, rgb=Color.NEWLOGENTRY, style=FontStyle.BOLD)

    def log_dmaker_step(self, num):
        msg = "### Step %d:" % num
        self.log_fn(msg, rgb=Color.DMAKERSTEP)

    def log_initial_generator(self, dmaker_type, dmaker_name, dmaker_ui):
        msgs = []
        msgs.append("### Initial Generator (currently disabled):")
        msgs.append(" |- generator type: %s | generator name: %s | User input: %s" % \
                    (dmaker_type, dmaker_name, dmaker_ui))
        msgs.append("  ...")
        for m in msgs:
            self.log_fn(m, rgb=Color.DISABLED)

    def log_generator_info(self, dmaker_type, name, user_input, data_id=None):
        msg = '' if data_id is None else " |- retrieved from data id: {:d}\n".format(data_id)
        if user_input:
            msg += " |- generator type: %s | generator name: %s | User input: %s" % \
                  (dmaker_type, name, user_input)
        else:
            msg += " |- generator type: %s | generator name: %s | No user input" % (dmaker_type, name)
        self._current_dmaker_list.append((dmaker_type, name, user_input))
        self._current_src_data_id = data_id
        self.log_fn(msg, rgb=Color.DATAINFO)

    def log_disruptor_info(self, dmaker_type, name, user_input):
        if user_input:
            msg = " |- disruptor type: %s | disruptor name: %s | User input: %s" % \
                  (dmaker_type, name, user_input)
        else:
            msg = " |- disruptor type: %s | disruptor name: %s | No user input" % (dmaker_type, name)

        self._current_dmaker_list.append((dmaker_type, name, user_input))
        self.log_fn(msg, rgb=Color.DATAINFO)

    def log_data_info(self, data_info, dmaker_type, data_maker_name):
        if not data_info:
            return

        self._current_dmaker_info[(dmaker_type,data_maker_name)] = data_info

        self.log_fn(" |- data info:", rgb=Color.DATAINFO)
        for msg in data_info:
            if len(msg) > 400:
                msg = msg[:400] + ' ...'

            self.log_fn('    |_ ' + msg, rgb=Color.DATAINFO)

    def log_info(self, info):
        msg = "### Info: %s" % info
        self.log_fn(msg, rgb=Color.INFO)

    def log_target_ack_date(self, date):
        self._current_ack_date = date

        msg = "### Target ack received at: "
        self.log_fn(msg, nl_after=False, rgb=Color.LOGSECTION)
        self.log_fn(str(self._current_ack_date), nl_before=False)

    def log_orig_data(self, data):

        if data is None:
            exportable = False
        else:
            exportable = data.is_recordable()

        if self.__explicit_data_recording and not exportable:
            return False

        if data is not None:
            self._current_orig_data_id = data.get_data_id()

        if self.__export_orig and not self.__export_data:
            if data is None:
                msgs = ("### No Original Data",)
            else:
                msgs = ("### Original Data:", data)

            for msg in msgs:
                self.log_fn(msg, rgb=Color.LOGSECTION)

            ret = True

        elif self.__export_orig:

            if data is None:
                ret = False
            else:
                ffn = self._export_data_func(data)
                if ffn:
                    self.log_fn("### Original data is stored in the file:", rgb=Color.DATAINFO)
                    self.log_fn(ffn)
                    ret = True
                else:
                    self.print_console("ERROR: saving data in an extenal file has failed!",
                                       nl_before=True, rgb=Color.ERROR)
                    ret = False

        else:
            ret = False

        return ret

    def log_data(self, data, verbose=False):

        self.log_fn("### Data size: ", rgb=Color.LOGSECTION, nl_after=False)
        self._current_size = data.get_length()
        self.log_fn("%d bytes" % self._current_size, nl_before=False)

        if self.__explicit_data_recording and not data.is_recordable():
            self.last_data_recordable = False
            self.log_fn("### Data emitted but not recorded", rgb=Color.LOGSECTION)
            return False

        self._current_data = data
        self.last_data_recordable = self._current_data.is_recordable()

        if not self.__export_data:
            self.log_fn("### Data emitted:", rgb=Color.LOGSECTION)
            self.log_fn(data, nl_after=True, verbose=verbose)
        else:
            ffn = self._export_data_func(data)
            if ffn:
                self.log_fn("### Emitted data is stored in the file:", rgb=Color.LOGSECTION)
                self.log_fn(ffn)
                ret = True
            else:
                self.print_console("ERROR: saving data in an extenal file has failed!",
                                   nl_before=True, rgb=Color.ERROR)
                ret = False

        return True

    def _export_data_func(self, data, suffix=''):

        base_dir = gr.exported_data_folder

        dm = data.get_data_model()
        if dm:
            file_extension = dm.file_extension
            dm_name = dm.name
        else:
            file_extension = 'bin'
            dm_name = '__unknown_data_model'

        now = datetime.datetime.now()
        current_export_date = now.strftime("%Y_%m_%d_%H%M%S")

        if current_export_date != self.__prev_export_date:
            self.__prev_export_date = current_export_date
            self.__export_cpt = 0
        else:
            self.__export_cpt += 1

        export_fname = '{date:s}_{cpt:0>2d}{suff:s}.{ext:s}'.format(date=current_export_date,
                                                                    cpt=self.__export_cpt,
                                                                    ext=file_extension,
                                                                    suff=suffix)

        export_full_fn = os.path.join(base_dir, dm_name, export_fname)

        ensure_dir(export_full_fn)

        fd = open(export_full_fn, 'wb')
        fd.write(data.to_bytes())
        fd.close()

        return export_full_fn

    def log_comment(self, comment):
        now = datetime.datetime.now()
        current_date = now.strftime("%H:%M:%S")

        self.log_fn("### Comments [{date:s}]:".format(date=current_date), rgb=Color.COMMENTS)
        self.log_fn(comment)
        self.fmkDB.insert_comment(self.last_data_id, comment, now)
        self.print_console('\n')

    def log_error(self, err_msg):
        now = datetime.datetime.now()
        msg = "\n/!\\ ERROR: %s /!\\\n" % err_msg
        self.log_fn(msg, rgb=Color.ERROR)
        self.fmkDB.insert_fmk_info(self.last_data_id, msg, now, error=True)

    def set_stats(self, stats):
        self.stats = stats

    def log_stats(self):
        if self._enable_file_logging:
            fd = open(logs_folder + self.now + '_' + self.name + '_stats', 'w+')
            stats = self.stats.get_formated_stats()
            fd.write(stats + '\n')
            fd.close()

    def print_console(self, msg, nl_before=True, nl_after=False, rgb=None, style=None,
                      raw_limit=None, limit_output=True):

        if raw_limit is None:
            raw_limit = self._console_display_limit

        if nl_before:
            p = '\n'
        else:
            p = ''
        if nl_after:
            s = '\n'
        else:
            s = ''

        prefix = p + self.p

        if sys.version_info[0] > 2:
            if issubclass(msg.__class__, Data) or issubclass(msg.__class__, bytes):
                msg = repr(msg)
        else:
            if issubclass(msg.__class__, Data):
                msg = repr(msg)

        suffix = ''
        if limit_output and len(msg) > raw_limit:
            msg = msg[:raw_limit]
            suffix = ' ...'

        suffix += s

        if rgb is not None:
            msg = colorize(msg, rgb=rgb)

        if style is None:
            style = ''

        sys.stdout.write(style + prefix)
        sys.stdout.write(msg)
        sys.stdout.write(suffix + FontStyle.END)
        sys.stdout.flush()
