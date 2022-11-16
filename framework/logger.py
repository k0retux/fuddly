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
from libs.utils import get_caller_object
from framework.data import Data
from framework.global_resources import *
from framework.database import Database
from framework.knowledge.feedback_collector import FeedbackSource
from libs.utils import ensure_dir
import framework.global_resources as gr

class Logger(object):
    """
    The Logger is used for keeping the history of the communication
    with the Target. The methods are used by the framework, but can
    also be leveraged by an Operator.
    """

    fmkDB = None

    def __init__(self, name=None, prefix='', record_data=False, explicit_data_recording=False,
                 export_raw_data=True, term_display_limit=800, enable_term_display=True,
                 enable_file_logging=False, highlight_marked_nodes=False):
        """
        Args:
          name (str): Name to be used in the log filenames. If not specified, the name of the project
            in which the logger is embedded will be used.
          record_data (bool): If True, each emitted data will be stored in a specific
            file within `exported_data/`.
          explicit_data_recording (bool): Used for logging outcomes further to an Operator instruction. If True,
            the operator would have to state explicitly if it wants the just emitted data to be recorded.
            Such notification is possible when the framework call its method
            :meth:`framework.operator_helpers.Operator.do_after_all()`, where the Operator can take its decision
            after the observation of the target feedback and/or probes outputs.
          export_raw_data (bool): If True, will log the data as it is, without trying to interpret it
            as human readable text.
          term_display_limit (int): maximum amount of characters to display on the terminal at once.
            If this threshold is overrun, the message to print on the console will be truncated.
          enable_term_display (bool): If True, information will be displayed on the terminal
          prefix (str): prefix to use for printing on the console.
          enable_file_logging (bool): If True, file logging will be enabled.
          highlight_marked_nodes (bool): If True, alteration performed by compatible disruptors
            will be highlighted. Only possible if `export_raw_data` is False, as this option forces
            data interpretation.
        """

        self.name = name
        self.p = prefix
        self.__record_data = record_data
        self.__explicit_data_recording = explicit_data_recording
        self._term_display_limit = term_display_limit

        now = datetime.datetime.now()
        self.__prev_export_date = now.strftime("%Y%m%d_%H%M%S")
        self.__export_cpt = 0
        self.export_raw_data = export_raw_data

        self._enable_file_logging = enable_file_logging
        self._fd = None

        if export_raw_data and highlight_marked_nodes:
            raise ValueError('When @highlight_marked_nodes is True, @export_raw_data should be False')
        self._hl_marked_nodes = highlight_marked_nodes

        self._tg_fbk = []
        self._tg_fbk_lck = threading.Lock()

        self.display_on_term = enable_term_display

        def init_logfn(x, nl_before=True, nl_after=False, rgb=None, style=None, verbose=False,
                       do_record=True):
            no_format_mode = False
            if issubclass(x.__class__, Data):
                data = self._handle_binary_content(x.to_bytes(), raw=self.export_raw_data)
                colored_data = x.to_formatted_str() if self._hl_marked_nodes else data
                rgb = None
                style = None
                no_format_mode = self._hl_marked_nodes
            elif isinstance(x, str):
                colored_data = data = x
            else:
                colored_data = data = self._handle_binary_content(x, raw=self.export_raw_data)
            self.print_console(colored_data, nl_before=nl_before, nl_after=nl_after,
                               rgb=rgb, style=style, no_format_mode=no_format_mode)
            if verbose and issubclass(x.__class__, Data):
                x.show()

            return data

        self.log_fn = init_logfn

    def __str__(self):
        return 'Logger'


    def _handle_binary_content(self, content, raw=False):
        content = gr.unconvert_from_internal_repr(content)
        if sys.version_info[0] > 2:
            content = content if not raw else '{!a}'.format(content)
        else:
            content = content if not raw else repr(content)

        return content

    def start(self):

        self.__idx = 0
        self.__tmp = False

        self.reset_current_state()
        self._current_sent_date = None
        self._last_data_IDs = {} # per target_ref
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
                no_format_mode = False
                if issubclass(x.__class__, Data):
                    data = self._handle_binary_content(x.to_bytes(), raw=self.export_raw_data)
                    colored_data = x.to_formatted_str() if self._hl_marked_nodes else data
                    rgb = None
                    style = None
                    no_format_mode = self._hl_marked_nodes
                elif isinstance(x, str):
                    colored_data = data = x
                else:
                    colored_data = data = self._handle_binary_content(x, raw=self.export_raw_data)
                self.print_console(colored_data, nl_before=nl_before, nl_after=nl_after,
                                   rgb=rgb, style=style, no_format_mode=no_format_mode)
                if not do_record:
                    return data
                try:
                    self._fd.write(data)
                    self._fd.write('\n')
                    if verbose and issubclass(x.__class__, Data):
                        x.show(log_func=self._fd.write)
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

        self.reset_current_state()
        self._current_sent_date = None
        self._last_data_IDs = {}
        self.last_data_recordable = None

        self.print_console('*** Logger is stopped ***\n', nl_before=False, rgb=Color.COMPONENT_STOP)


    def reset_current_state(self):
        self._current_data = None
        self._current_group_id = None
        self._current_size = None
        self._current_ack_dates = None
        self._current_dmaker_list= []
        self._current_dmaker_info = {}
        self._current_src_data_id = None
        self._current_fmk_info = []

    def commit_data_table_entry(self, group_id, prj_name):
        if self._current_data is not None:  # that means data will be recorded
            init_dmaker = self._current_data.get_initial_dmaker()
            init_dmaker = Database.DEFAULT_GTYPE_NAME if init_dmaker is None else init_dmaker[0]
            dm = self._current_data.get_data_model()
            dm_name = Database.DEFAULT_DM_NAME if dm is None else dm.name
            self._current_group_id = group_id

            last_data_id = None
            for tg_ref, ack_date in self._current_ack_dates.items():
                last_data_id = self.fmkDB.insert_data(init_dmaker, dm_name,
                                                           self._current_data.to_bytes(),
                                                           self._current_size,
                                                           self._current_sent_date,
                                                           ack_date,
                                                           tg_ref, prj_name,
                                                           group_id=group_id)
                # assert isinstance(tg_ref, FeedbackSource)
                self._last_data_IDs[tg_ref.obj] = last_data_id

                if last_data_id is None:
                    print("\n*** ERROR: Cannot insert the data record in FMKDB!")
                    self.last_data_recordable = None
                    return last_data_id

                self._current_data.set_data_id(last_data_id)

                step_id_start = 1

                for step_id, dmaker in enumerate(self._current_dmaker_list, start=step_id_start):
                    dmaker_type, dmaker_name, user_input = dmaker
                    info = self._current_dmaker_info.get((dmaker_type,dmaker_name), None)
                    if info is not None:
                        info = '\n'.join(info)
                        info = convert_to_internal_repr(info)
                    ui = str(user_input) if bool(user_input) else None
                    self.fmkDB.insert_steps(last_data_id, step_id, dmaker_type, dmaker_name,
                                            self._current_src_data_id,
                                            ui, info)

                for msg, now in self._current_fmk_info:
                    self.fmkDB.insert_fmk_info(last_data_id, msg, now)

            return last_data_id

        else:
            return None


    def log_fmk_info(self, info, nl_before=False, nl_after=False, rgb=Color.FMKINFO,
                     data_id=None, do_show=True, do_record=True, delay_recording=False):
        now = datetime.datetime.now()

        p = '\n' if nl_before else ''
        s = '\n' if nl_after else ''

        msg = "{prefix:s}*** [ {message:s} ] ***{suffix:s}".format(prefix=p, suffix=s, message=info)
        if do_show:
            self.log_fn(msg, rgb=rgb)

        if do_record:
            if not delay_recording:
                if data_id is None:
                    if self._last_data_IDs:
                        for d_id in self._last_data_IDs.values():
                            self.fmkDB.insert_fmk_info(d_id, info, now)
                    else:
                        self.fmkDB.insert_fmk_info(None, info, now)
                else:
                    self.fmkDB.insert_fmk_info(data_id, info, now)
            else:
                self._current_fmk_info.append((info, now))

    def collect_feedback(self, content, status_code=None, subref=None, fbk_src=None):
        """
        Used within the scope of the Logger feedback-collector infrastructure.
        If your target implement the interface :meth:`Target.get_feedback`, no need to
        use this infrastructure.

        To be called by the target each time feedback need to be registered.

        Args:
            content: feedback record
            status_code (int): should be negative for error
            subref (str): specific reference to distinguish internal log sources within the same caller
            fbk_src: [optional] source object of the feedback
        """
        now = datetime.datetime.now()
        fbk_src = get_caller_object() if fbk_src is None else fbk_src

        with self._tg_fbk_lck:
            self._tg_fbk.append((now, FeedbackSource(fbk_src, subref=subref), content, status_code))

    def shall_record(self):
        if self.last_data_recordable or not self.__explicit_data_recording:
            return True
        else:
            # feedback will not be recorded because data is not recorded
            return False

    def _log_feedback(self, source, content, status_code, timestamp, record=True):

        processed_feedback = self._process_target_feedback(content)
        fbk_cond = status_code is not None and status_code < 0
        hdr_color = Color.FEEDBACK_ERR if fbk_cond else Color.FEEDBACK
        body_color = Color.FEEDBACK_HLIGHT if fbk_cond else None
        # now = timestamp.strftime("%d/%m/%Y - %H:%M:%S.%f")
        if isinstance(timestamp, datetime.datetime) or timestamp is None:
            ts_msg = f"received at {timestamp}"
        elif isinstance(timestamp, list):
            if len(timestamp) == 1:
                ts_msg = f"received at {timestamp[0]}"
            else:
                ts_msg = f"received from {timestamp[0]} to {timestamp[-1]}"
        else:
            raise ValueError(f'Wrong format for timestamp [{type(timestamp)}]')

        if not processed_feedback:
            msg_hdr = "### Status from '{!s}': {!s} - {:s}".format(
                source, status_code, ts_msg)
        else:
            msg_hdr = "### Feedback from '{!s}' (status={!s}) - {:s}:".format(
                source, status_code, ts_msg)
        self.log_fn(msg_hdr, rgb=hdr_color, do_record=record)
        if processed_feedback:
            if source.display_feedback:
                if isinstance(processed_feedback, list):
                    for dfbk in processed_feedback:
                        self.log_fn(dfbk, rgb=body_color, do_record=record)
                else:
                    self.log_fn(processed_feedback, rgb=body_color, do_record=record)
            else:
                self.log_fn('Feedback not displayed', rgb=Color.WARNING, do_record=record)

        if record:
            assert isinstance(source, FeedbackSource)
            if source.related_tg is not None:
                try:
                    data_id = self._last_data_IDs[source.related_tg]
                except KeyError:
                    self.print_console(
                        '*** Warning: The feedback source is related to a target to which nothing has been sent.'
                        ' Retrieved feedback will not be attached to any data ID.',
                        nl_before=True, rgb=Color.WARNING)
                    data_id = None
            else:
                ids = self._last_data_IDs.values()
                data_id = max(ids) if ids else None

            if isinstance(content, list):
                for fbk, ts in zip(content, timestamp):
                    self.fmkDB.insert_feedback(data_id, source, ts,
                                               self._encode_target_feedback(fbk),
                                               status_code=status_code)
            else:
                self.fmkDB.insert_feedback(data_id, source, timestamp,
                                           self._encode_target_feedback(content),
                                           status_code=status_code)

    def log_collected_feedback(self, preamble=None, epilogue=None):
        """
        Used within the scope of the Logger feedback-collector feature.
        If your target implement the interface :meth:`Target.get_feedback`, no need to
        use this infrastructure.

        It allows to retrieve the collected feedback, that has been populated
        by the target (through call to :meth:`Logger.collect_feedback`).

        Args:
            preamble (str): prefix added to each collected feedback
            epilogue (str): suffix added to each collected feedback

        Returns:
            bool: True if target feedback has been collected through logger infrastructure
              :meth:`Logger.collect_feedback`, False otherwise.
        """
        collected_status = {}

        with self._tg_fbk_lck:
            fbk_list = self._tg_fbk
            self._tg_fbk = []

        if not fbk_list:
            # self.log_fn("\n::[ NO TARGET FEEDBACK ]::\n") 
            raise NotImplementedError

        record = self.shall_record()

        if preamble is not None:
            self.log_fn(preamble, do_record=record, rgb=Color.FMKINFO)

        for idx, fbk_record in enumerate(fbk_list):
            timestamp, fbk_src, fbk, status = fbk_record
            self._log_feedback(fbk_src, fbk, status, timestamp, record=record)
            collected_status[fbk_src.obj] = status

        if epilogue is not None:
            self.log_fn(epilogue, do_record=record, rgb=Color.FMKINFO)

        return collected_status

    def log_target_feedback_from(self, source, content, status_code, timestamp,
                                 preamble=None, epilogue=None):
        record = self.shall_record()

        if preamble is not None:
            self.log_fn(preamble, do_record=record, rgb=Color.FMKINFO)

        self._log_feedback(source, content, status_code, timestamp, record=record)

        if epilogue is not None:
            self.log_fn(epilogue, do_record=record, rgb=Color.FMKINFO)


    def log_operator_feedback(self, operator, content, status_code, timestamp):
        self._log_feedback(FeedbackSource(operator), content, status_code, timestamp,
                           record=self.shall_record())

    def log_probe_feedback(self, probe, content, status_code, timestamp, related_tg=None):
        self._log_feedback(FeedbackSource(probe, related_tg=related_tg), content, status_code, timestamp,
                           record=self.shall_record())


    def _process_target_feedback(self, feedback):
        if feedback is None:
            return None

        if isinstance(feedback, list):
            new_fbk = []
            for f in feedback:
                if f is None:
                    continue
                new_f = f.strip()
                if isinstance(new_f, bytes):
                    new_f = self._handle_binary_content(new_f, raw=self.export_raw_data)
                new_fbk.append(new_f)

            if not new_fbk:
                new_fbk = None
            elif not list(filter(lambda x: x != b'', new_fbk)):
                new_fbk = None
        else:
            new_fbk = feedback.strip()
            if isinstance(new_fbk, bytes):
                new_fbk = self._handle_binary_content(new_fbk, raw=self.export_raw_data)

        return new_fbk

    def _encode_target_feedback(self, feedback):
        if feedback is None:
            return None
        return convert_to_internal_repr(feedback)


    def start_new_log_entry(self, preamble=''):
        self.__idx += 1
        self._current_sent_date = datetime.datetime.now()
        now = self._current_sent_date.strftime("%d/%m/%Y - %H:%M:%S.%f")
        msg = "====[ {:d} ]==[ {:s} ]====".format(self.__idx, now)
        msg += '='*(max(80-len(msg),0))
        self.log_fn(msg, rgb=Color.NEWLOGENTRY, style=FontStyle.BOLD)

        return self._current_sent_date

    def log_dmaker_step(self, num):
        msg = "### Step %d:" % num
        self.log_fn(msg, rgb=Color.DMAKERSTEP)

    def log_generator_info(self, dmaker_type, name, user_input, data_id=None, disabled=False):
        msg = "### Initial Generator (currently disabled):\n" if disabled else ''
        msg += '' if data_id is None else " |- retrieved from data id: {:d}\n".format(data_id)
        if user_input:
            msg += " |- generator type: %s | generator name: %s | User input: %s" % \
                  (dmaker_type, name, user_input)
        else:
            msg += " |- generator type: %s | generator name: %s | No user input" % (dmaker_type, name)
        msg += '\n  ...' if disabled else ''
        if not disabled:
            self._current_dmaker_list.append((dmaker_type, name, user_input))
            self._current_src_data_id = data_id
        self.log_fn(msg, rgb=Color.DISABLED if disabled else Color.DATAINFO)

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
            if len(msg) > self._term_display_limit:
                msg = msg[:self._term_display_limit] + ' ...'

            self.log_fn('    | ' + msg, rgb=Color.DATAINFO)

    def log_info(self, info):
        msg = "### Info: {:s}".format(info)
        self.log_fn(msg, rgb=Color.INFO)

    def log_target_ack_date(self):
        for tg_ref, ack_date in self._current_ack_dates.items():
            msg = "### Ack from '{!s}' received at: ".format(tg_ref)
            self.log_fn(msg, nl_after=False, rgb=Color.LOGSECTION)
            self.log_fn(str(ack_date), nl_before=False)

    def set_target_ack_date(self, tg_ref, date):
        if self._current_ack_dates is None:
            self._current_ack_dates = {tg_ref: date}
        else:
            self._current_ack_dates[tg_ref] = date

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

        if not self.__record_data:
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
        for data_id in self._last_data_IDs.values():
            self.fmkDB.insert_comment(data_id, comment, now)
        self.print_console('\n')

    def log_error(self, err_msg):
        now = datetime.datetime.now()
        msg = "\n/!\\ ERROR: %s /!\\\n" % err_msg
        self.log_fn(msg, rgb=Color.ERROR)
        for data_id in self._last_data_IDs.values():
            self.fmkDB.insert_fmk_info(data_id, msg, now, error=True)

    def print_console(self, msg, nl_before=True, nl_after=False, rgb=None, style=None,
                      raw_limit=None, limit_output=True, no_format_mode=False):

        if not self.display_on_term:
            return

        if raw_limit is None:
            raw_limit = self._term_display_limit

        p = '\n' if nl_before else ''
        s = '\n' if nl_after else ''

        prefix = p + self.p

        if no_format_mode:
            sys.stdout.write(prefix)
            sys.stdout.write(msg)
            sys.stdout.flush()

            # print(f'{msg}')

        else:
            if isinstance(msg, Data):
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
