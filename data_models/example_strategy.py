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

import sys
import random
import array
from copy import *

from framework.plumbing import *

from framework.data_model import *
from framework.tactics_helpers import *
from framework.fuzzing_primitives import *
from framework.basic_primitives import *

tactics = Tactics()

@generator(tactics, gtype="EX1", weight=2)
class example_02(Generator):

    def setup(self, dm, user_input):
        self.tux = dm.get_data('TUX')
        self.tux_h = self.tux.get_node_by_path('TUX/h$')
        self.tx = self.tux.get_node_by_path('TUX/TX$')
        self.tc = self.tux.get_node_by_path('TUX/TC$')

        self.delim = Node('DELIM', values=[' [@] '])

        self.tux.set_subnodes_with_csts([
                1, ['u>', [self.delim, 1],
                    'u=+', [self.tux_h, 1, 3], [self.tc, 1],
                    'u>', [self.delim, 1], [self.tx, 1], [self.delim, 1],
                    'u=.', [self.tx, 1], [self.tc, 1]]
                ])
    
        return True

    def generate_data(self, dm, monitor, target):
        exported_node = Node(self.tux.name, base_node=self.tux)
        dm.set_new_env(exported_node)
        return Data(exported_node)



@generator(tactics, gtype="TVE_w", weight=2)
class g_typed_value_example_01(Generator):

    def generate_data(self, dm, monitor, target):
        return Data(dm.get_data('TVE'))


@generator(tactics, gtype="TVE_w", weight=10)
class g_typed_value_example_02(Generator):

    def generate_data(self, dm, monitor, target):
        return Data(dm.get_data('TVE'))


@disruptor(tactics, dtype="TVE/basic", weight=4)
class t_fuzz_tve_01(Disruptor):

    def disrupt_data(self, dm, target, prev_data):

        val = b"NEW_" + rand_string(mini=5, maxi=10, str_set='XYZRVW')

        if prev_data.node:
            prev_data.node.get_node_by_path('TVE.*EVT1$').set_frozen_value(val)

        else:
            print('DONT_PROCESS_THIS_KIND_OF_DATA')

        return prev_data
