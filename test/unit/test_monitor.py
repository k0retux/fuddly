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

import unittest
from test import mock
from framework.monitor import *

class ProbeUserTest(unittest.TestCase):
    """Test case used to test the 'ProbeUser' class."""

    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        """Initialisation des tests."""

        self.timeout = 5

        self.probe = Probe()
        self.probe.main = mock.Mock()

        self.probe.start = mock.Mock()
        self.probe.stop = mock.Mock()

        self.dm = mock.Mock()
        self.target = mock.Mock()
        self.logger = mock.Mock()

        self._set_up_specific()

    def _set_up_specific(self):
        self.probe_user = ProbeUser(self.probe)

    def tearDown(self):
        pass

    def test_not_started_is_alive(self):
        self.assertFalse(self.probe_user.is_alive())

    def test_started_is_alive(self):
        self.probe_user.start(self.dm, self.target, self.logger)
        self.assertTrue(self.probe_user.is_alive())
        self.probe_user.stop()
        self.probe_user.join(self.timeout)

    def test_stopped_is_alive(self):
        self.probe_user.start(self.dm, self.target, self.logger)
        self.probe_user.stop()
        self.probe_user.join(self.timeout)
        self.assertFalse(self.probe_user.is_alive())

    def test_multiple_starts(self):
        self.probe_user.start(self.dm, self.target, self.logger)
        self.assertRaises(RuntimeError, self.probe_user.start, self.dm, self.target, self.logger)
        self.probe_user.stop()
        self.probe_user.join(self.timeout)

    def test_start_and_stop(self):
        self.probe_user.start(self.dm, self.target, self.logger)
        self.probe_user.stop()
        self.probe_user.join(self.timeout)
        self.probe.start.assert_called_once_with(self.dm, self.target, self.logger)
        self.probe.stop.assert_called_once_with(self.dm, self.target, self.logger)

    def test_main(self):
        test_period = 0.5
        delta = 0.01
        self.probe_user.set_probe_delay(0.05)

        print("***** test period:                       " + str(test_period))
        print("***** tolerate delta between executions: " + str(delta))
        print("***** probe delay:                       " + str(self.probe_user.get_probe_delay()))

        execution_times = []

        def side_effect(*args, **kwargs):
            execution_times.append(datetime.datetime.now())
            return mock.Mock()

        self.probe.main.side_effect = side_effect

        self.probe_user.start(self.dm, self.target, self.logger)
        time.sleep(test_period)
        self.probe_user.stop()
        self.probe_user.join(self.timeout)
        self.probe.main.assert_called_with(self.dm, self.target, self.logger)

        print("***** probe's main method execution times:             ")
        for execution in execution_times:
            print("      " + str(execution))

        self.assertTrue(self.probe.main.call_count >= test_period/self.probe_user.get_probe_delay() - 1)

        for i in range(len(execution_times)):
            if i+1 < len(execution_times):
                self.assertTrue(0 <= (execution_times[i+1] - execution_times[i]).total_seconds()
                                - self.probe_user.get_probe_delay() <= delta)
