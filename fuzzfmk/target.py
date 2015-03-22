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
import random
import subprocess
import fcntl
import select
import signal

from libs.external_modules import *

import data_models
import fuzzfmk
fuzzfmk_folder = os.path.dirname(fuzzfmk.__file__)
app_folder = os.path.dirname(os.path.dirname(fuzzfmk.__file__))


class Target(object):
    
    def __init__(self, args=None):
        self._logger=None
        self.args = args
        self.init_specific(args)

    def init_specific(self, args):
        '''
        To be overloaded if needed
        '''
        pass

    def set_logger(self, logger):
        self._logger = logger

    def _start(self):
        self._logger.print_console('*** Target initialization\n', nl_before=False, rgb=Color.COMPONENT_START)
        return self.start()

    def _stop(self):
        self._logger.print_console('*** Target cleanup procedure\n', nl_before=False, rgb=Color.COMPONENT_STOP)
        return self.stop()

    def start(self):
        '''
        To be overloaded if needed
        '''
        return True

    def stop(self):
        '''
        To be overloaded if needed
        '''
        return True

    def send_data(self, data):
        '''
        To be overloaded.
        Note: Use data.to_bytes() to get binary data
        '''
        raise NotImplementedError

    def send_multiple_data(self, data_list):
        '''
        Used to send multiple data to the target, or to stimulate several
        target's inputs in one shot.

        @data_list: list of data to be sent

        Note: Use data.to_bytes() to get binary data
        '''
        raise NotImplementedError

    def do_before_sending_data(self):
        '''
        Called by the framework before sending data
        '''
        pass

    def is_target_ready_for_new_data(self):
        '''
        The FMK busy wait on this method() before sending a new data
        '''
        return True

    def get_last_target_ack_date(self):
        '''
        If different from None the return value is used by the FMK to log the
        date of the target acknowledgment after a message has been sent to it.

        [Note: If this method is overloaded, is_target_ready_for_new_data() should also be]
        '''
        return None

    def stop_target(self):
        raise NotImplementedError

    def get_target_feedback(self):
        raise NotImplementedError

    def is_alive(self):
        raise NotImplementedError

    def get_description(self):
        return None


class TargetFeedback(object):

    def __init__(self, bstring=b''):
        self.set_bytes(bstring)

    def set_bytes(self, bstring):
        self.__bstring = bstring

    def get_bytes(self):
        return self.__bstring

    def set_error_code(self, err_code):
        self.__err_code = err_code

    def get_error_code(self):
        return self.__err_code


class EmptyTarget(Target):

    def send_data(self, data):
        pass

    def send_multiple_data(self, data_list):
        pass


class PrinterTarget(Target):

    def __init__(self, tmpfile_ext):
        self.__suffix = '{:0>12d}'.format(random.randint(2**16, 2**32))
        self.__feedback = TargetFeedback()
        self.__tmpfile_ext = tmpfile_ext
        self.__target_ip = None
        self.__printer_name = None
        self.__cpt = None

    def set_target_ip(self, target_ip):
        self.__target_ip = target_ip

    def get_target_ip(self):
        return self.__target_ip

    def set_printer_name(self, printer_name):
        self.__printer_name = printer_name

    def get_printer_name(self):
        return self.__printer_name

    def start(self):
        self.__cpt = 0

        if not cups_module:
            print('/!\\ ERROR /!\\: the PrinterTarget has been disabled because python-cups module is not installed')
            return False

        if not self.__target_ip:
            print('/!\\ ERROR /!\\: the PrinterTarget IP has not been set')
            return False

        cups.setServer(self.__target_ip)
        self.__connection = cups.Connection()

        try:
            printers = self.__connection.getPrinters()
        except cups.IPPError as err:
            print('CUPS Server Errror: ', err)
            return False
        
        if self.__printer_name is not None:
            try:
                params = printers[self.__printer_name]
            except:
                print("Printer '%s' is not connected to CUPS server!" % self.__printer_name)
                return False
        else:
            self.__printer_name, params = printers.popitem()

        print("\nDevice-URI: %s\nPrinter Name: %s" % (params["device-uri"], self.__printer_name))

        return True

    def send_data(self, data):

        data = data.to_bytes()
        wkspace = os.path.join(app_folder, 'workspace')
        file_name = os.path.join(wkspace, 'fuzz_test_' + self.__suffix + self.__tmpfile_ext)

        with open(file_name, 'wb') as f:
             f.write(data)

        inc = '_{:0>5d}'.format(self.__cpt)
        self.__cpt += 1

        try:
            self.__connection.printFile(self.__printer_name, file_name, 'job_'+ self.__suffix + inc, {})
        except cups.IPPError as err:
            print('CUPS Server Errror: ', err)

    def stop_target(self):
        raise NotImplementedError

    def get_target_feedback(self):
        raise NotImplementedError

    def is_alive(self):
        raise NotImplementedError



class LocalTarget(Target):

    def __init__(self, tmpfile_ext):
        self.__suffix = '{:0>12d}'.format(random.randint(2**16, 2**32))
        self.__app = None
        self.__target_path = None
        self.__feedback = TargetFeedback()
        self.__tmpfile_ext = tmpfile_ext

    def set_target_path(self, target_path):
        self.__target_path = target_path

    def get_target_path(self):
        return self.__target_path

    def start(self):
        if not self.__target_path:
            print('/!\\ ERROR /!\\: the LocalTarget path has not been set')
            return False

        return True

    def send_data(self, data):

        data = data.to_bytes()
        wkspace = os.path.join(app_folder, 'workspace')

        name = os.path.join(wkspace, 'fuzz_test_' + self.__suffix + self.__tmpfile_ext)
        with open(name, 'wb') as f:
             f.write(data)

        cmd = [self.__target_path, name]
        self.__app = subprocess.Popen(args=cmd, stderr=subprocess.PIPE)

        fl = fcntl.fcntl(self.__app.stderr, fcntl.F_GETFL)
        fcntl.fcntl(self.__app.stderr, fcntl.F_SETFL, fl | os.O_NONBLOCK)


    def stop_target(self):
        os.kill(self.__app.pid, signal.SIGTERM)


    def get_target_feedback(self, delay=0.2):
        ret = select.select([self.__app.stderr], [], [], delay)
        if ret[0]:
            err_fd = ret[0][0]
            byte_string = err_fd.read()
        else:
            byte_string = b''

        self.__feedback.set_bytes(byte_string)

        return self.__feedback


    def is_alive(self):
        target_exit_status = self.__app.poll()

        self.__feedback.set_error_code(target_exit_status)

        if target_exit_status == None:
            ret = True
        else:
            ret = False

        return ret

    def is_damaged(self):
        bstring = self.__feedback.get_bytes().lower()

        if b'error' in bstring or b'invalid' in bstring:
            return True
        else:
            return False
