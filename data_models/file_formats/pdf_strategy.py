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

import subprocess
import signal
import select
import fcntl
import os
import random

from fuzzfmk.plumbing import *
from fuzzfmk.target import *
from fuzzfmk.logger import *

from fuzzfmk.data_model import *
from fuzzfmk.tactics_helper import *
from fuzzfmk.fuzzing_primitives import *

tactics = Tactics()

logger = Logger('pdf', data_in_seperate_file=True, explicit_export=False, export_orig=False)

printer_tg = PrinterTarget(tmpfile_ext='.pdf')
printer_tg.set_target_ip('172.20.130.1')
printer_tg.set_printer_name('OSFCprinter')

printer2_tg = PrinterTarget(tmpfile_ext='.pdf')
printer2_tg.set_target_ip('127.0.0.1')
printer2_tg.set_printer_name('PDF')

local_tg = LocalTarget(tmpfile_ext='.pdf')
local_tg.set_target_path('okular')

targets = [local_tg, printer_tg, printer2_tg]

@generator(tactics, gtype="PDF_loop", weight=2)
class g_pdf_loop01(Generator):
    def generate_data(self, dm, monitor, target):
        return Data(dm.get_data('PDF_pagetree_loop'))

@generator(tactics, gtype="PDF_loop", weight=2)
class g_pdf_loop02(Generator):
    def generate_data(self, dm, monitor, target):
        return Data(dm.get_data('PDF_page_loop'))

@generator(tactics, gtype="PDF_loop", weight=2)
class g_pdf_loop03(Generator):
    def generate_data(self, dm, monitor, target):
        return Data(dm.get_data('PDF_xref_loop'))

@generator(tactics, gtype="PDF_bigpage", weight=2)
class g_pdf_bomb02(Generator):

    def setup(self, dm, user_input):
        self.pdf = dm.get_data('PDF_basic')
        self.pdf.get_flatten_value()

        return True

    def generate_data(self, dm, monitor, target):
        self.pdf.set_current_conf('ALT', root_regexp='PDF.*leaf_0-0$')
        self.pdf.unfreeze

        return Data(self.pdf)

