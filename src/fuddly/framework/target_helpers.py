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
import copy
import logging
import os

from fuddly.framework.data import Data
from fuddly.framework.knowledge.feedback_collector import FeedbackSource
from fuddly.libs.external_modules import *
import fuddly.framework.global_resources as gr

class TargetStuck(Exception): pass
class TargetError(Exception): pass
class TargetNotReady(Exception): pass

class Target(object):
    """
    Class abstracting the real target we interact with.

    About feedback:
    Feedback retrieved from a real target has to be provided to the user (i.e., the framework) through
    either after Target.send_data() is called or when Target.collect_unsolicited_feedback() is called.

    """

    _cls_user_count = None

    name = None
    feedback_timeout = None
    sending_delay = 0
    store_fbk_in_db = True

    # tg_id = None  # this is set by FmkPlumbing

    FBK_WAIT_FULL_TIME = 1
    fbk_wait_full_time_slot_msg = 'Wait for the full time slot allocated for feedback retrieval'
    FBK_WAIT_UNTIL_RECV = 2
    fbk_wait_until_recv_msg = 'Wait until the target has sent something back to us'

    _feedback_mode = None
    supported_feedback_mode = [FBK_WAIT_FULL_TIME, FBK_WAIT_UNTIL_RECV]

    STATUS_THRESHOLD_FOR_RECOVERY = 0  # When a feedback status gathered by FmkPlumbing is
                                       # strictly lesser than this value, .recover_target() will be called
    _started = None

    _logger = None
    _extensions = None
    _send_data_lock = threading.Lock()

    _altered_data_queued = None

    _pending_data = None
    _pending_data_id = None

    _last_sending_date = None

    display_feedback = False

    # This list can be updated by any subclasses in order to declare
    # the attributes that shall be configurable by the config_attribute interface.
    _configurable_attributes = None

    def __init__(self, name=None, display_feedback=True, enable_specific_logger=False, log_level=logging.INFO,
                 config_attributes: list | None = None):
        """
        Attributes:
            config_attributes (list): This list can be updated by any subclasses in order to declare
               the attributes that shall be configurable by the config_attribute interface.
        """

        self.name = name
        self.display_feedback = display_feedback
        self._started = False
        self._cls_user_count = 0
        self.log_level = log_level
        self.enable_specific_logger = enable_specific_logger
        self._configurable_attributes = ['custo'] if config_attributes is None else ['custo'] + config_attributes
        self._custo = None

    def setup_child_logger(self, filename=None, level=logging.INFO):

        def get_obj():
            f = sys._getframe(1)
            try:
                obj = f.f_locals['self']
            except KeyError:
                obj = None
            return obj

        now = datetime.datetime.now().strftime("%Y_%m_%d_%H%M%S")

        obj = get_obj()
        cls_name = 'Unknown' if obj is None else obj.__class__.__name__
        user_count = f'_{obj._cls_user_count}' if hasattr(obj, '_cls_user_count') else ''
        # caller_name = inspect.currentframe().f_back.f_code.co_name
        name = f'{cls_name}{user_count}'

        if filename is None:
            filename = os.path.join(gr.logs_folder, f'{cls_name}_trace_{now}{user_count}.log')

        handler = logging.FileHandler(filename)
        formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        logger = logging.getLogger(name)
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False

        return logger

    @staticmethod
    def get_fbk_mode_desc(fbk_mode, short=False):
        if fbk_mode == Target.FBK_WAIT_FULL_TIME:
            return 'wait full time' if short else Target.fbk_wait_full_time_slot_msg
        elif fbk_mode == Target.FBK_WAIT_UNTIL_RECV:
            return 'wait until reception' if short else Target.fbk_wait_until_recv_msg

    def set_logger(self, logger):
        self._logger = logger

    def set_data_model(self, dm):
        self.current_dm = dm

    def set_project(self, prj):
        self._project = prj

    def _start(self, target_desc, tg_id):
        self._logger.print_console('*** Target initialization: ({:d}) {!s} ***\n'.format(tg_id, target_desc),
                                   nl_before=False, rgb=Color.COMPONENT_START)
        self._pending_data = []
        self._pending_data_id = None
        self._cls_user_count += 1
        if self.enable_specific_logger:
            self.logger = self.setup_child_logger(level=self.log_level)
        else:
            self.logger = None
        self._started = self.start()
        return self._started

    def _stop(self, target_desc, tg_id):
        self._logger.print_console('*** Target cleanup procedure for ({:d}) {!s} ***\n'.format(tg_id, target_desc),
                                   nl_before=False, rgb=Color.COMPONENT_STOP)
        self._pending_data = None
        self._pending_data_id = None
        ret = self.stop()
        self._started = not ret
        return ret

    def start(self):
        """
        To be overloaded if needed
        """
        return True

    def stop(self):
        """
        To be overloaded if needed
        """
        return True

    def is_started(self):
        return self._started

    @property
    def custo(self):
        """
        To be overloaded if needed.

        Can be used by any subclasses as a customization property that may
        serve any purposes. This variable is exported to the framework so that it can be
        changed easily.
        """
        return self._custo

    @custo.setter
    def custo(self, value):
        """
        To be overloaded if needed.

        Allows to trigger some needed code execution further to the modification of the
        custo property.
        """
        self._custo = value

    def get_config_attribute_list(self):
        return copy.copy(self._configurable_attributes)

    def set_config_attribute(self, attribute, value):
        """
        Allow the user to change attributes of the target
        """
        if attribute not in self._configurable_attributes:
            return False

        try:
            object.__setattr__(self, attribute, value)
        except AttributeError:
            return False
        else:
            return True

    def get_config_attribute(self, attribute):
        if attribute not in self._configurable_attributes:
            raise AttributeError

        try:
            attr_val = getattr(self, attribute)
        except AttributeError:
            raise
        else:
            return attr_val


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
        """
        To be overloaded.

        Note: use data.to_bytes() to get binary data.

        Args:
          from_fmk (bool): set to True if the call was performed by the framework itself,
            otherwise the call comes from user-code (e.g., from a `probe` or a `director`)
          data (Data): data container that embeds generally a
            modeled data accessible through `data.content`. However if the
            latter is None, it only embeds the raw data.
        """
        raise NotImplementedError

    def send_multiple_data(self, data_list, from_fmk=False):
        """
        Used to send multiple data to the target, or to stimulate several
        target's inputs in one shot.

        Note: Use data.to_bytes() to get binary data

        Args:
            from_fmk (bool): set to True if the call was performed by the framework itself,
              otherwise the call comes from user-code (e.g., from a `Probe` or a `Director`)
            data_list (list): list of data to be sent

        """
        raise NotImplementedError

    def is_target_ready_for_new_data(self):
        """
        To be overloaded if the target needs some time (for conditions to occur) before data can be sent.
        Note: The FMK busy wait on this method() before sending a new data.
        """
        return True

    def is_feedback_received(self):
        """
        To be overloaded if the target implements FBK_WAIT_UNTIL_RECV mode, so that
        it can inform the framework about feedback reception.
        """
        return True

    def get_last_target_ack_date(self):
        """
        If different from None the return value is used by the FMK to log the
        date of the target acknowledgment after a message has been sent to it.

        [Note: If this method is overloaded, is_feedback_received() should also be]
        """
        return None

    def cleanup(self):
        """
        To be overloaded if something needs to be performed after each data emission.
        It is called after any feedback has been retrieved.
        """
        pass

    def recover_target(self):
        """
        Implementation of target recovering operations, when a target problem has been detected
        (i.e. a negative feedback from a probe, a director or the Target() itself)

        Returns:
            bool: True if the target has been recovered. False otherwise.
        """
        raise NotImplementedError

    def get_feedback(self):
        """
        If overloaded, should return a FeedbackCollector object.
        """
        return None

    def collect_unsolicited_feedback(self, timeout=0):
        """
        If overloaded, it should collect any data from the associated real target that may be sent
        without solicitation (i.e. without any data sent through it) and make it available through
        the method .get_feedback()

        Args:
            timeout: Maximum delay before returning from feedback collecting

        Returns:
            bool: False if it is not possible, otherwise it should be True
        """
        return True

    def set_feedback_timeout(self, fbk_timeout):
        """
        To set dynamically the feedback timeout.

        Args:
            fbk_timeout (float): maximum time duration for collecting the feedback

        """
        assert fbk_timeout is None or fbk_timeout >= 0
        if fbk_timeout == self.feedback_timeout:
            return False
        else:
            self.feedback_timeout = fbk_timeout
            self._set_feedback_timeout_specific(fbk_timeout)
            return True

    def _set_feedback_timeout_specific(self, fbk_timeout):
        """
        Overload this function to handle feedback specifics

        Args:
            fbk_timeout (float): time duration for collecting the feedback

        """
        pass

    def set_feedback_mode(self, mode):
        if mode in self.supported_feedback_mode:
            self._feedback_mode = mode
            return True
        else:
            return False

    @property
    def feedback_mode(self):
        return self._feedback_mode

    @property
    def fbk_wait_full_time_slot_mode(self):
        return self._feedback_mode == Target.FBK_WAIT_FULL_TIME

    @property
    def fbk_wait_until_recv_mode(self):
        return self._feedback_mode == Target.FBK_WAIT_UNTIL_RECV

    def set_sending_delay(self, sending_delay):
        """
        Set the sending delay.

        Args:
            sending_delay (float): maximum time (in seconds) taken to send data
              once the method ``send_(multiple_)data()`` has been called.
        """
        assert sending_delay >= 0
        self.sending_delay = sending_delay

    def __str__(self):
        return self.__class__.__name__ + ' [' + self.get_description() + ']'

    def get_description(self):
        prefix = '{:s} | '.format(self.name) if self.name is not None else ''
        return '{:s}ID: {:s}'.format(prefix, str(id(self))[-6:])

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

    def send_data_sync(self, data: Data, from_fmk=False):
        """
        Can be used in user-code to send data to the target without interfering
        with the framework.

        Use case example: The user needs to send some message to the target on a regular basis
        in background. For that purpose, it can quickly define a :class:`framework.monitor.Probe` that just
        emits the message by itself.
        """
        with self._send_data_lock:
            if data is not None:
                self._altered_data_queued = data.altered
            if self.is_target_ready_for_new_data():
                self._last_sending_date = datetime.datetime.now()
                self.send_data(data, from_fmk=from_fmk)
                meta_info = self._project.notify_data_sending([data], self._last_sending_date, self)

                if from_fmk:
                    self._pending_data_id = data.estimated_data_id
                if not from_fmk:
                    self._logger.log_async_data(data, sent_date=self._last_sending_date,
                                                target_ref=FeedbackSource(self),
                                                prj_name=self._project.name,
                                                current_data_id=self._pending_data_id)
                if meta_info:
                    for fh, mi in meta_info.items():
                        self._logger.register_post_processed_info(f'from {fh!s}: {mi}')
            else:
                self._logger.print_console( f"*** Target {self!s} Not ready ***\n",
                                           nl_before=False, rgb=Color.WARNING)
                # raise TargetNotReady

    def send_multiple_data_sync(self, data_list, from_fmk=False):
        """
        Can be used in user-code to send data to the target without interfering
        with the framework.
        """
        with self._send_data_lock:
            if data_list is not None:
                self._altered_data_queued = data_list[0].altered
            if self.is_target_ready_for_new_data():
                self._last_sending_date = datetime.datetime.now()
                self.send_multiple_data(data_list, from_fmk=from_fmk)
                meta_info = self._project.notify_data_sending(data_list, self._last_sending_date, self)
                if from_fmk and data_list is not None:
                    self._pending_data_id = data_list[-1].estimated_data_id
                if not from_fmk and data_list is not None:
                    self._logger.log_async_data(data_list, sent_date=self._last_sending_date,
                                                target_ref=FeedbackSource(self),
                                                prj_name=self._project.name,
                                                current_data_id=self._pending_data_id)
                if meta_info:
                    for fh, mi in meta_info.items():
                        self._logger.register_post_processed_info(f'from {fh!s}: {mi}')
            else:
                self._logger.print_console(f'*** Target {self!s} Not ready ***\n',
                                           nl_before=False, rgb=Color.WARNING)
                # raise TargetNotReady

    def add_extensions(self, probe):
        if self._extensions is None:
            self._extensions = []
        self._extensions.append(probe)

    def del_extensions(self):
        self._extensions = None

    def is_processed_data_altered(self):
        return self._altered_data_queued

    @property
    def extensions(self):
        return self._extensions if self._extensions is not None else []


class EmptyTarget(Target):

    _feedback_mode = Target.FBK_WAIT_FULL_TIME
    supported_feedback_mode = [Target.FBK_WAIT_FULL_TIME, Target.FBK_WAIT_UNTIL_RECV]

    def __init__(self, verbose=False):
        Target.__init__(self)
        self.verbose = verbose

    def send_data(self, data, from_fmk=False):
        if self.verbose:
            print(f'\n*** data sent: {data.to_bytes()}')

    def send_multiple_data(self, data_list, from_fmk=False):
        pass
