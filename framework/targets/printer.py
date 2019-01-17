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
import random

from framework.global_resources import workspace_folder
from framework.target_helpers import Target
from framework.knowledge.feedback_collector import FeedbackCollector
from libs.external_modules import cups_module

if cups_module:
   import cups

class PrinterTarget(Target):

    # No target feedback implemented
    _feedback_mode = None
    supported_feedback_mode = []

    def __init__(self, tmpfile_ext):
        Target.__init__(self)
        self._suffix = '{:0>12d}'.format(random.randint(2 ** 16, 2 ** 32))
        self._feedback = FeedbackCollector()
        self._target_ip = None
        self._target_port = None
        self._printer_name = None
        self._cpt = None
        self.set_tmp_file_extension(tmpfile_ext)

    def get_description(self):
        printer_name = ', Name: ' + self._printer_name if self._printer_name is not None else ''
        return 'IP: ' + self._target_ip + printer_name

    def set_tmp_file_extension(self, tmpfile_ext):
        self._tmpfile_ext = tmpfile_ext

    def set_target_ip(self, target_ip):
        self._target_ip = target_ip

    def get_target_ip(self):
        return self._target_ip

    def set_target_port(self, target_port):
        self._target_port = target_port

    def get_target_port(self):
        return self._target_port

    def set_printer_name(self, printer_name):
        self._printer_name = printer_name

    def get_printer_name(self):
        return self._printer_name

    def start(self):
        self._cpt = 0

        if not cups_module:
            print('/!\\ ERROR /!\\: the PrinterTarget has been disabled because python-cups module is not installed')
            return False

        if not self._target_ip:
            print('/!\\ ERROR /!\\: the PrinterTarget IP has not been set')
            return False

        if self._target_port is None:
            self._target_port = 631

        cups.setServer(self._target_ip)
        cups.setPort(self._target_port)

        self.__connection = cups.Connection()

        try:
            printers = self.__connection.getPrinters()
        except cups.IPPError as err:
            print('CUPS Server Errror: ', err)
            return False

        if self._printer_name is not None:
            try:
                params = printers[self._printer_name]
            except:
                print("Printer '%s' is not connected to CUPS server!" % self._printer_name)
                return False
        else:
            self._printer_name, params = printers.popitem()

        print("\nDevice-URI: %s\nPrinter Name: %s" % (params["device-uri"], self._printer_name))

        return True

    def send_data(self, data, from_fmk=False):

        data = data.to_bytes()
        wkspace = workspace_folder
        file_name = os.path.join(wkspace, 'fuzz_test_' + self._suffix + self._tmpfile_ext)

        with open(file_name, 'wb') as f:
             f.write(data)

        inc = '_{:0>5d}'.format(self._cpt)
        self._cpt += 1

        try:
            self.__connection.printFile(self._printer_name, file_name, 'job_' + self._suffix + inc, {})
        except cups.IPPError as err:
            print('CUPS Server Errror: ', err)