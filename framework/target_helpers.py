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

import datetime
import threading

from framework.data import Data
from libs.external_modules import *

class TargetStuck(Exception): pass

class Target(object):
    '''
    Class abstracting the target we interact with.
    '''
    feedback_timeout = None
    sending_delay = 0

    # tg_id = None  # this is set by FmkPlumbing

    FBK_WAIT_FULL_TIME = 1
    fbk_wait_full_time_slot_msg = 'Wait for the full time slot allocated for feedback retrieval'
    FBK_WAIT_UNTIL_RECV = 2
    fbk_wait_until_recv_msg = 'Wait until the target has sent something back to us'

    _feedback_mode = None
    supported_feedback_mode = []

    _logger = None
    _probes = None
    _send_data_lock = threading.Lock()

    _altered_data_queued = None

    _pending_data = None

    def set_logger(self, logger):
        self._logger = logger

    def set_data_model(self, dm):
        self.current_dm = dm

    def _start(self, target_desc, tg_id):
        self._logger.print_console('*** Target initialization: ({:d}) {!s} ***\n'.format(tg_id, target_desc),
                                   nl_before=False, rgb=Color.COMPONENT_START)
        self._pending_data = []
        return self.start()

    def _stop(self, target_desc, tg_id):
        self._logger.print_console('*** Target cleanup procedure for ({:d}) {!s} ***\n'.format(tg_id, target_desc),
                                   nl_before=False, rgb=Color.COMPONENT_STOP)
        self._pending_data = None
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

    def record_info(self, info):
        """
        Can be used by the target to record some information during initialization or anytime
        it make sense for your purpose.

        Args:
            info (str): info to be recorded

        Returns:
            None
        """
        self._logger.log_comment(info)

    def send_data(self, data, from_fmk=False):
        '''
        To be overloaded.

        Note: use data.to_bytes() to get binary data.

        Args:
          from_fmk (bool): set to True if the call was performed by the framework itself,
            otherwise the call comes from user-code (e.g., from a `probe` or an `operator`)
          data (Data): data container that embeds generally a
            modeled data accessible through `data.content`. However if the
            latter is None, it only embeds the raw data.
        '''
        raise NotImplementedError

    def send_multiple_data(self, data_list, from_fmk=False):
        '''
        Used to send multiple data to the target, or to stimulate several
        target's inputs in one shot.

        Note: Use data.to_bytes() to get binary data

        Args:
            from_fmk (bool): set to True if the call was performed by the framework itself,
              otherwise the call comes from user-code (e.g., from a `Probe` or an `Operator`)
            data_list (list): list of data to be sent

        '''
        raise NotImplementedError


    def is_target_ready_for_new_data(self):
        '''
        The FMK busy wait on this method() before sending a new data.
        This method should take into account feedback timeout (that is the maximum
        time duration for gathering feedback from the target)
        '''
        return True

    def get_last_target_ack_date(self):
        '''
        If different from None the return value is used by the FMK to log the
        date of the target acknowledgment after a message has been sent to it.

        [Note: If this method is overloaded, is_target_ready_for_new_data() should also be]
        '''
        return None

    def cleanup(self):
        '''
        To be overloaded if something needs to be performed after each data emission.
        It is called after any feedback has been retrieved.
        '''
        pass

    def recover_target(self):
        '''
        Implementation of target recovering operations, when a target problem has been detected
        (i.e. a negative feedback from a probe, an operator or the Target() itself)

        Returns:
            bool: True if the target has been recovered. False otherwise.
        '''
        raise NotImplementedError

    def get_feedback(self):
        '''
        If overloaded, should return a FeedbackCollector object.
        '''
        return None

    def collect_feedback_without_sending(self):
        """
        If overloaded, it can be used by the framework to retrieve additional feedback from the
        target without sending any new data.

        Returns:
            bool: False if it is not possible, otherwise it should be True
        """
        return True

    def set_feedback_timeout(self, fbk_timeout):
        '''
        To set dynamically the feedback timeout.

        Args:
            fbk_timeout: maximum time duration for collecting the feedback

        '''
        assert fbk_timeout >= 0
        self.feedback_timeout = fbk_timeout
        self._set_feedback_timeout_specific(fbk_timeout)

    def _set_feedback_timeout_specific(self, fbk_timeout):
        '''
        Overload this function to handle feedback specifics

        Args:
            fbk_timeout: time duration for collecting the feedback

        '''
        pass

    def set_feedback_mode(self, mode):
        if mode in self.supported_feedback_mode:
            self._feedback_mode = mode
            return True
        else:
            return False

    @property
    def fbk_wait_full_time_slot_mode(self):
        return self._feedback_mode == Target.FBK_WAIT_FULL_TIME

    def set_sending_delay(self, sending_delay):
        '''
        Set the sending delay.

        Args:
            sending_delay (int): maximum time (in seconds) taken to send data
              once the method ``send_(multiple_)data()`` has been called.
        '''
        assert sending_delay >= 0
        self.sending_delay = sending_delay

    def __str__(self):
        return self.__class__.__name__ + ' [' + self.get_description() + ']'

    def get_description(self):
        return 'ID: ' + str(id(self))[-6:]

    def add_pending_data(self, data):
        with self._send_data_lock:
            if isinstance(data, list):
                self._pending_data += data
            else:
                self._pending_data.append(data)

    def send_pending_data(self, from_fmk=False):
        with self._send_data_lock:
            data_list = self._pending_data
            self._pending_data = []

        if len(data_list) == 1:
            self.send_data_sync(data_list[0], from_fmk=from_fmk)
        elif len(data_list) > 1:
            self.send_multiple_data_sync(data_list, from_fmk=from_fmk)
        else:
            raise ValueError('No pending data')

    def send_data_sync(self, data, from_fmk=False):
        '''
        Can be used in user-code to send data to the target without interfering
        with the framework.

        Use case example: The user needs to send some message to the target on a regular basis
        in background. For that purpose, it can quickly define a :class:`framework.monitor.Probe` that just
        emits the message by itself.
        '''
        with self._send_data_lock:
            self._altered_data_queued = data.altered
            self.send_data(data, from_fmk=from_fmk)

    def send_multiple_data_sync(self, data_list, from_fmk=False):
        '''
        Can be used in user-code to send data to the target without interfering
        with the framework.
        '''
        with self._send_data_lock:
            self._altered_data_queued = data_list[0].altered
            self.send_multiple_data(data_list, from_fmk=from_fmk)

    def add_probe(self, probe):
        if self._probes is None:
            self._probes = []
        self._probes.append(probe)

    def remove_probes(self):
        self._probes = None

    def is_processed_data_altered(self):
        return self._altered_data_queued

    @property
    def probes(self):
        return self._probes if self._probes is not None else []


class EmptyTarget(Target):

    _feedback_mode = Target.FBK_WAIT_FULL_TIME
    supported_feedback_mode = [Target.FBK_WAIT_FULL_TIME, Target.FBK_WAIT_UNTIL_RECV]

    def __init__(self, enable_feedback=True):
        Target.__init__(self)
        self._feedback_enabled = enable_feedback
        self._sending_time = None

    def send_data(self, data, from_fmk=False):
        if self._feedback_enabled:
            self._sending_time = datetime.datetime.now()

    def send_multiple_data(self, data_list, from_fmk=False):
        if self._feedback_enabled:
            self._sending_time = datetime.datetime.now()

    def is_target_ready_for_new_data(self):
        if self._feedback_enabled and self.feedback_timeout is not None and \
                self._sending_time is not None:
            return (datetime.datetime.now() - self._sending_time).total_seconds() > self.feedback_timeout
        else:
            return True


