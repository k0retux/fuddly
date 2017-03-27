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

from framework.global_resources import workspace_folder
from framework.target_helpers import Target, TargetFeedback

class LocalTarget(Target):

    _feedback_mode = Target.FBK_WAIT_UNTIL_RECV
    supported_feedback_mode = [Target.FBK_WAIT_UNTIL_RECV]

    def __init__(self, tmpfile_ext, target_path=None):
        Target.__init__(self)
        self.__suffix = '{:0>12d}'.format(random.randint(2**16, 2**32))
        self.__app = None
        self.__pre_args = None
        self.__post_args = None
        self._data_sent = None
        self._feedback_computed = None
        self.__feedback = TargetFeedback()
        self.set_target_path(target_path)
        self.set_tmp_file_extension(tmpfile_ext)

    def set_tmp_file_extension(self, tmpfile_ext):
        self._tmpfile_ext = tmpfile_ext

    def set_target_path(self, target_path):
        self.__target_path = target_path

    def get_target_path(self):
        return self.__target_path

    def set_pre_args(self, pre_args):
        self.__pre_args = pre_args

    def get_pre_args(self):
        return self.__pre_args

    def set_post_args(self, post_args):
        self.__post_args = post_args

    def get_post_args(self):
        return self.__post_args

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
        if not self.__target_path:
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
        wkspace = workspace_folder

        name = os.path.join(wkspace, 'fuzz_test_' + self.__suffix + self._tmpfile_ext)
        with open(name, 'wb') as f:
             f.write(data)

        if self.__pre_args is not None and self.__post_args is not None:
            cmd = [self.__target_path] + self.__pre_args.split() + [name] + self.__post_args.split()
        elif self.__pre_args is not None:
            cmd = [self.__target_path] + self.__pre_args.split() + [name]
        elif self.__post_args is not None:
            cmd = [self.__target_path, name] + self.__post_args.split()
        else:
            cmd = [self.__target_path, name]

        self.__app = subprocess.Popen(args=cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        fl = fcntl.fcntl(self.__app.stderr, fcntl.F_GETFL)
        fcntl.fcntl(self.__app.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        fl = fcntl.fcntl(self.__app.stdout, fcntl.F_GETFL)
        fcntl.fcntl(self.__app.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        self._data_sent = True

    def cleanup(self):
        if self.__app is None:
            return

        try:
            os.kill(self.__app.pid, signal.SIGTERM)
        except:
            print("\n*** WARNING: cannot kill application with PID {:d}".format(self.__app.pid))
        finally:
            self._data_sent = False

    def get_feedback(self, timeout=0.2):
        timeout = self.feedback_timeout if timeout is None else timeout
        if self._feedback_computed:
            return self.__feedback
        else:
            self._feedback_computed = True

        err_detected = False

        if self.__app is None and self._data_sent:
            err_detected = True
            self.__feedback.add_fbk_from("LocalTarget", "Application has terminated (crash?)",
                                         status=-3)
            return self.__feedback
        elif self.__app is None:
            return self.__feedback

        exit_status = self.__app.poll()
        if exit_status is not None and exit_status < 0:
            err_detected = True
            self.__feedback.add_fbk_from("Application[{:d}]".format(self.__app.pid),
                                         "Negative return status ({:d})".format(exit_status),
                                         status=exit_status)

        ret = select.select([self.__app.stdout, self.__app.stderr], [], [], timeout)
        if ret[0]:
            byte_string = b''
            for fd in ret[0][:-1]:
                byte_string += fd.read() + b'\n\n'

            if b'error' in byte_string or b'invalid' in byte_string:
                err_detected = True
                self.__feedback.add_fbk_from("LocalTarget[stdout]",
                                             "Application outputs errors on stdout",
                                             status=-1)

            stderr_msg = ret[0][-1].read()
            if stderr_msg:
                err_detected = True
                self.__feedback.add_fbk_from("LocalTarget[stderr]",
                                             "Application outputs on stderr",
                                             status=-2)
                byte_string += stderr_msg
            else:
                byte_string = byte_string[:-2]  # remove '\n\n'

        else:
            byte_string = b''

        if err_detected:
            self.__feedback.set_error_code(-1)
        self.__feedback.set_bytes(byte_string)

        return self.__feedback