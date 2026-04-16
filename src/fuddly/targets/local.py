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

import fcntl
import os
import random
import select
import signal
import subprocess

from fuddly.framework.global_resources import workspace_folder
from fuddly.framework.target_helpers import Target
from fuddly.framework.knowledge.feedback_collector import FeedbackCollector


class LocalTarget(Target):

    _feedback_mode = Target.FBK_WAIT_UNTIL_RECV
    supported_feedback_mode = [Target.FBK_WAIT_UNTIL_RECV]

    def __init__(self, target_path=None, pre_args=None, post_args=None,
                 tmpfile_ext='.bin', send_via_stdin=False, send_via_cmdline=False,
                 error_samples=None, error_parsing_func=lambda x: (False, '')):
        Target.__init__(self)
        self._suffix = '{:0>12d}'.format(random.randint(2 ** 16, 2 ** 32))
        self._app = None
        self._pre_args = pre_args
        self._post_args = post_args
        self._send_via_stdin = send_via_stdin
        self._send_via_cmdline = send_via_cmdline
        self._error_samples = [b'error', b'invalid'] if error_samples is None else error_samples
        self._error_parsing_func = error_parsing_func
        self._data_sent = None
        self._feedback_computed = None
        self._feedback = FeedbackCollector()
        self.set_target_path(target_path)
        self.set_tmp_file_extension(tmpfile_ext)

    def get_description(self):
        pre_args = self._pre_args
        post_args = self._post_args
        if pre_args or post_args:
            args = ', Args: ' + ('' if pre_args is None else pre_args) + ('' if post_args is None else post_args)
        else:
            args = ''
        return 'Program: ' + self._target_path + args

    def set_tmp_file_extension(self, tmpfile_ext):
        self._tmpfile_ext = tmpfile_ext

    def set_target_path(self, target_path):
        self._target_path = target_path

    def get_target_path(self):
        return self._target_path

    def set_pre_args(self, pre_args):
        self._pre_args = pre_args

    def get_pre_args(self):
        return self._pre_args

    def set_post_args(self, post_args):
        self._post_args = post_args

    def get_post_args(self):
        return self._post_args

    def initialize(self):
        '''
        To be overloaded if some intial setup for the target is necessary.
        '''
        return True

    def terminate(self):
        '''
        To be overloaded if some cleanup is necessary for stopping the target.
        '''
        return True

    def start(self):
        if not self._target_path:
            print('/!\\ ERROR /!\\: the LocalTarget path has not been set')
            return False

        self._data_sent = False

        return self.initialize()

    def stop(self):
        return self.terminate()

    def _before_sending_data(self):
        self._feedback_computed = False

    def send_data(self, data, from_fmk=False):
        self._before_sending_data()
        data = data.to_bytes()

        if self._send_via_stdin:
            name = ''
        elif self._send_via_cmdline:
            name = data
        else:
            name = os.path.join(workspace_folder, 'fuzz_test_' + self._suffix + self._tmpfile_ext)
            with open(name, 'wb') as f:
                 f.write(data)

        if self._pre_args is not None and self._post_args is not None:
            if self._send_via_stdin:
                cmd = [self._target_path] + self._pre_args.split() + self._post_args.split()
            else:
                cmd = [self._target_path] + self._pre_args.split() + [name] + self._post_args.split()
        elif self._pre_args is not None:
            cmd = [self._target_path] + self._pre_args.split()
            if not self._send_via_stdin:
                cmd += [name]
        elif self._post_args is not None:
            cmd = [self._target_path] if self._send_via_stdin else [self._target_path, name]
            cmd += self._post_args.split()
        else:
            cmd = [self._target_path] if self._send_via_stdin else [self._target_path, name]

        stdin_arg = subprocess.PIPE if self._send_via_stdin else None
        self._app = subprocess.Popen(args=cmd, stdin=stdin_arg, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)

        if self._send_via_stdin:
            with self._app.stdin as f:
                f.write(data)

        if not self._send_via_stdin and not self._send_via_cmdline:
            fl = fcntl.fcntl(self._app.stderr, fcntl.F_GETFL)
            fcntl.fcntl(self._app.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)

            fl = fcntl.fcntl(self._app.stdout, fcntl.F_GETFL)
            fcntl.fcntl(self._app.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        self._data_sent = True

    def cleanup(self):
        if self._app is None:
            return

        try:
            os.kill(self._app.pid, signal.SIGTERM)
        except:
            print("\n*** WARNING: cannot kill application with PID {:d}".format(self._app.pid))
        finally:
            self._data_sent = False

    def get_feedback(self, timeout=0.2):
        timeout = self.feedback_timeout if timeout is None else timeout
        if self._feedback_computed:
            return self._feedback
        else:
            self._feedback_computed = True

        if self._app is None:
            # application not yet started
            return self._feedback

        exit_error = False
        proc_killed = False
        return_code = self._app.poll()
        if return_code is not None: # process has terminate
            if return_code < 0:
                # process terminated by a signal (python behavior for POSIX system)
                proc_killed = True
                self._feedback.add_fbk_from(f"Application[{self._app.pid}]",
                                            f"Application terminated by a signal (ID: {-return_code})",
                                            status=-3)

            else:
                if self.is_processed_data_altered() and return_code == 0:
                    exit_error = True
                    msg = f"Wrong exit status ({return_code}) - expecting != 0 (as altered data was provided)"
                elif not self.is_processed_data_altered() and return_code != 0:
                    exit_error = True
                    msg = f"Wrong exit status ({return_code}) - expecting 0 (as valid data was provided)"
                else:
                    msg = f'Expected exit status ({return_code})'

                self._feedback.add_fbk_from(f"Application[{self._app.pid}]", msg, status=-1 if exit_error else 0)

        console_error = False
        ret = select.select([self._app.stdout, self._app.stderr], [], [], timeout)
        if ret[0]:
            byte_string = b''
            for fd in ret[0][:-1]:
                byte_string += fd.read() + b'\n\n'

            console_error, msg = self._error_parsing_func(byte_string)
            if console_error:
                self._feedback.add_fbk_from("LocalTarget[stdout]",
                                            f"Error detected on stdout (by provided parsing function)\n --> {msg}",
                                            status=-1)

            for err_msg in self._error_samples:
                if err_msg in byte_string:
                    console_error = True
                    self._feedback.add_fbk_from("LocalTarget[stdout]",
                                                f"Error detected on stdout (from provided samples): '{err_msg.decode()}'",
                                                status=-1)

            stderr_msg = ret[0][-1].read()
            if stderr_msg:
                console_error = True
                self._feedback.add_fbk_from("LocalTarget[stderr]",
                                            "Application outputs on stderr",
                                            status=-2)
                byte_string += stderr_msg
            else:
                byte_string = byte_string[:-2]  # remove '\n\n'

        else:
            byte_string = b''

        if proc_killed or exit_error or console_error:
            self._feedback.set_error_code(-1)
        self._feedback.set_bytes(byte_string)

        return self._feedback
