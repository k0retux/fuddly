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
import datetime
import threading

from libs.external_modules import *
from fuzzfmk.data_model import Data
from fuzzfmk.global_resources import *

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
    All log_* function is to be used internally by the framework
    '''
    def __init__(self, name, prefix='', data_in_seperate_file=False, explicit_export=False, export_orig=True,
                 export_raw_data=True):

        self.name = name
        self.p = prefix
        self.__seperate_file = data_in_seperate_file
        self.__explicit_export = explicit_export
        self.__export_orig = export_orig

        now = datetime.datetime.now()
        self.__prev_export_date = now.strftime("%Y%m%d_%H%M%S")
        self.__export_cpt = 0
        self.__export_raw_data = export_raw_data

        self._tg_fbk = []
        self._tg_fbk_lck = threading.Lock()

        def init_logfn(x, nl_before=True, nl_after=False, rgb=None, style=None, verbose=False):
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

        self.log_fn = init_logfn


    def start(self):

        self.__idx = 0
        self.__tmp = False

        with self._tg_fbk_lck:
            self._tg_fbk = []

        if self.name is None:
            self.log_fn = lambda x:x
        else:
            self.now = datetime.datetime.now()
            self.now = self.now.strftime("%Y_%m_%d_%H%M%S")

            trace_folder = os.path.join(app_folder, 'trace')
            log_file = os.path.join(trace_folder, self.now + '_' + self.name + '_log')
            self._fd = open(log_file, 'w')

            def intern_func(x, nl_before=True, nl_after=False, rgb=None, style=None, verbose=False):
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

            self.log_fn = intern_func

        self.print_console('*** Logger is started ***\n', nl_before=False, rgb=Color.COMPONENT_START)


    def stop(self):

        if self._fd:
            self._fd.close()

        self.log_stats()

        self.print_console('*** Logger is stopped ***\n', nl_before=False, rgb=Color.COMPONENT_STOP)


    def log_fmk_info(self, info, nl_before=False, nl_after=False, rgb=Color.FMKINFO):
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

    def collect_target_feedback(self, fbk):
        if sys.version_info[0] > 2 and isinstance(fbk, bytes):
            fbk = fbk.decode('latin_1')
        with self._tg_fbk_lck:
            self._tg_fbk.append(str(fbk))

    def log_current_target_feedback(self, preamble=None, epilogue=None):
        with self._tg_fbk_lck:
            fbk_list = self._tg_fbk
            self._tg_fbk = []

        if not fbk_list:
            # self.log_fn("\n::[ NO TARGET FEEDBACK ]::\n") 
            return False

        if preamble is not None:
            self.log_fn(preamble)

        for m, idx in zip(fbk_list, range(len(fbk_list))):
            self.log_fn("### Target feedback [%d]: " % idx, rgb=Color.FEEDBACK)
            self.log_fn(m)

        if epilogue is not None:
            self.log_fn(epilogue)

        self.print_console('\n')

        return True
        
    def log_target_feedback_from(self, feedback, preamble=None, epilogue=None, source=None):
        feedback = self._decode_target_feedback(feedback)

        if preamble is not None:
            self.log_fn(preamble)

        if not feedback:
            msg_hdr = "### Target Feedback!" if source is None else '### Target Feedback from "{!s}"!'.format(source)
            self.log_fn(msg_hdr, rgb=Color.FEEDBACK)
        else:
            msg_hdr = "### Target Feedback:" if source is None else "### Target Feedback ({!s}):".format(source)
            self.log_fn(msg_hdr, rgb=Color.FEEDBACK)
            self.log_fn(feedback)

        if epilogue is not None:
            self.log_fn(epilogue)

    def log_target_feedback_from_operator(self, feedback):
        feedback = self._decode_target_feedback(feedback)
        if not feedback:
            self.log_fn("### No Target Feedback!", rgb=Color.FEEDBACK)
        else:
            self.log_fn("### Target Feedback (collected from the Operator):", rgb=Color.FEEDBACK)
            self.log_fn(feedback)

    def _decode_target_feedback(self, feedback):
        if sys.version_info[0] > 2 and isinstance(feedback, bytes):
            feedback = feedback.decode('latin_1')
            feedback = '{!a}'.format(feedback)
        return feedback.strip()

    def start_new_log_entry(self, preamble=''):
        self.__idx += 1
        now = datetime.datetime.now()
        now = now.strftime("%d/%m/%Y - %H:%M:%S")
        msg = preamble + "========[ %d ]==[ %s ]=======================" % \
              (self.__idx, now)

        self.log_fn(msg, rgb=Color.NEWLOGENTRY, style=FontStyle.BOLD)

    def log_fuzzing_step(self, num):
        msg = "### Fuzzing (step %d):" % num
        self.log_fn(msg, rgb=Color.FUZZSTEP)

    def log_fuzzing_initial_generator(self, dmaker_type, dmaker_name, dmaker_ui):
        msgs = []
        msgs.append("### Initial Generator (currently disabled):")
        msgs.append(" |- generator type: %s | generator name: %s | User input: %s" % \
                    (dmaker_type, dmaker_name, dmaker_ui))
        msgs.append("  ...")
        for m in msgs:
            self.log_fn(m, rgb=Color.DISABLED)

    def log_generator_info(self, dmaker_type, name, user_input):
        if user_input:
            msg = " |- generator type: %s | generator name: %s | User input: %s" % \
                (dmaker_type, name, user_input)
        else:
            msg = " |- generator type: %s | generator name: %s | No user input" % (dmaker_type, name)

        self.log_fn(msg, rgb=Color.DATAINFO)

    def log_disruptor_info(self, dmaker_type, name, user_input):
        if user_input:
            msg = " |- disruptor type: %s | disruptor name: %s | User input: %s" % \
                (dmaker_type, name, user_input)
        else:
            msg = " |- disruptor type: %s | disruptor name: %s | No user input" % (dmaker_type, name)

        self.log_fn(msg, rgb=Color.DATAINFO)

    def log_data_info(self, data_info):
        if not data_info:
            return

        self.log_fn(" |- data info:", rgb=Color.DATAINFO)
        for msg in data_info:
            if len(msg) > 400:
                msg = msg[:400] + ' ...'

            self.log_fn('    |_ ' + msg, rgb=Color.DATAINFO)


    def log_info(self, info):
        msg = "### Info: %s" % info

        self.log_fn(msg, rgb=Color.INFO)

    def log_target_ack_date(self, date):
        if date is None:
            ack_date = 'None'
        else:
            ack_date = str(date)
        msg = "### Target ack received at: "

        self.log_fn(msg, nl_after=False, rgb=Color.LOGSECTION)
        self.log_fn(ack_date, nl_before=False)


    def log_orig_data(self, data):

        if data is None:
            exportable = False
        else:
            exportable = data.is_exportable()

        if self.__explicit_export and not exportable:
            return False

        if self.__export_orig and not self.__seperate_file:
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
                ffn = self.__export_data(data)
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
        self.log_fn("%d bytes" % data.get_length(), nl_before=False)

        if self.__explicit_export and not data.is_exportable():
            self.log_fn("### Data emitted but not exported", rgb=Color.LOGSECTION)
            return False

        if not self.__seperate_file:
            self.log_fn("### Data emitted:", rgb=Color.LOGSECTION)
            self.log_fn(data, nl_after=True, verbose=verbose)
        else:
            ffn = self.__export_data(data)
            if ffn:
                self.log_fn("### Emitted data is stored in the file:", rgb=Color.LOGSECTION)
                self.log_fn(ffn)
                ret = True
            else:
                self.print_console("ERROR: saving data in an extenal file has failed!",
                                   nl_before=True, rgb=Color.ERROR)
                ret = False

        return True


    def __export_data(self, data, suffix=''):

        def ensure_dir(f):
            d = os.path.dirname(f)
            if not os.path.exists(d):
                os.makedirs(d)

        base_dir = os.path.join(app_folder, 'exported_data')

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

        export_fname = '{date:s}_{cpt:0>2d}{suff:s}.{ext:s}'.format(date=self.__prev_export_date,
                                                                    cpt=self.__export_cpt,
                                                                    ext=file_extension,
                                                                    suff=suffix)

        export_full_fn = os.path.join(base_dir, dm_name, export_fname)

        ensure_dir(export_full_fn)

        fd = open(export_full_fn, 'wb')
        fd.write(data.to_bytes())
        # self._fd.flush()
        fd.close()

        return export_full_fn


    def log_comment(self, comment):
        now = datetime.datetime.now()
        current_date = now.strftime("%H:%M:%S")

        self.log_fn("### Comments [{date:s}]:".format(date=current_date), rgb=Color.COMMENTS)
        self.log_fn(comment)
        self.print_console('\n')


    def log_error(self, err_msg):
        msg = "\n/!\\ ERROR: %s /!\\\n" % err_msg
        self.log_fn(msg, rgb=Color.ERROR)


    def set_stats(self, stats):
        self.stats = stats

    def log_stats(self):
        fd = open(app_folder + '/trace/' + self.now + '_' + self.name + '_stats', 'w+')

        stats = self.stats.get_formated_stats()

        fd.write(stats + '\n')
        fd.close()


    def print_console(self, msg, nl_before=True, nl_after=False, rgb=None, style=None,
                      raw_limit=800, limit_output=True):

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
