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

import random
import datetime
import time
import queue
import threading

import struct
from multiprocessing import shared_memory

from ..target_helpers import Target
from ..basic_primitives import rand_string
from ..knowledge.feedback_collector import FeedbackCollector
from ..data import Data
from ...libs.external_modules import Color

class IncorrectTargetError(Exception): pass
class ShmemMappingError(Exception): pass

class TestTarget(Target):

    _feedback_mode = Target.FBK_WAIT_FULL_TIME
    supported_feedback_mode = [Target.FBK_WAIT_UNTIL_RECV, Target.FBK_WAIT_FULL_TIME]
    _last_ack_date = None

    # shared memory constants
    dlen_start = 0
    dlen_stop = 4
    dlen_format = '>L'
    producer_status_idx = 5
    consumer_start = 6
    consumer_stop = 15
    max_consumer = consumer_stop - consumer_start + 1
    data_start = meta_data_size = 16
    shmem_size = 4096


    def __init__(self, name=None, recover_ratio=100, fbk_samples=None, repeat_input=False,
                 fbk_timeout=0.05, shmem_mode=False, shmem_timeout=10):
        Target.__init__(self, name)
        self._cpt = None
        self._recover_ratio = recover_ratio
        self._fbk_samples = fbk_samples
        self._repeat_input = repeat_input
        self._bound_targets = []
        if shmem_mode and not name:
            raise ValueError('name parameter should be specified in shmem_mode')
        self._shmem_mode= shmem_mode
        self.output_shmem = None
        self.input_shmem_list = None
        self.fbk_sources = None

        self.controled_targets = None
        self.control_delay = 0
        self.forward_queue = queue.Queue()

        self._current_consumer_idx = -1
        self._stop_event = None
        self._fbk_collector_exit_event = None
        self._fbk_collector_thread = None
        self._map_timeout = shmem_timeout
        self._target_ready = None
        self._send_data_finished_event = None

        self._shared_queue = queue.Queue()
        self._fbk_collector = FeedbackCollector()
        self.set_feedback_timeout(fbk_timeout)

    def start(self):
        self._cpt = 0
        if self._shmem_mode:
            self._target_ready = False
            if self.fbk_sources is not None:
                self.input_shmem_list = []
            self.output_shmem = shared_memory.SharedMemory(name=self.name,
                                                           create=True,
                                                           size=self.shmem_size)
            buf = self.output_shmem.buf
            for i in range(self._current_consumer_idx+1):
                # every consumers are ready at start
                buf[self.consumer_start+i] = 1
            # nothing has been produced
            buf[self.producer_status_idx] = 0

            self._stop_event = threading.Event()
            self._stop_event.clear()
            self._fbk_collector_exit_event = threading.Event()
            self._fbk_collector_exit_event.set()
            self._send_data_finished_event = threading.Event()
            self._send_data_finished_event.set()

            if self.controled_targets is not None:
                self.forward_queue = queue.Queue()
                self._forward_data_thread = threading.Thread(None, self._forward_data)
                self._forward_data_thread.start()

            self._fbk_collector_thread = threading.Thread(None, self._collect_fbk_loop)
            self._fbk_collector_thread.start()

        return True

    def stop(self):
        if self._shmem_mode:
            self._stop_event.set()
            self._target_ready = False
            while not self._fbk_collector_exit_event.is_set():
                time.sleep(0.05)
            while not self._send_data_finished_event.is_set():
                time.sleep(0.001)
            if self.output_shmem:
                self.output_shmem.close()
                try:
                    self.output_shmem.unlink()
                except FileNotFoundError:
                    pass
            if self.input_shmem_list:
                for shm, _ in self.input_shmem_list:
                    shm.close()

    def _map_input_shmem(self):
        if self.fbk_sources is None:
            return False

        else:
            for tg, c_idx in self.fbk_sources:
                if tg._shmem_mode:
                    try:
                        shm = shared_memory.SharedMemory(name=tg.name, create=False)
                    except FileNotFoundError:
                        return False
                    else:
                        self.input_shmem_list.append((shm, c_idx))
                else:
                    raise IncorrectTargetError()

        return True

    def _collect_fbk_loop(self):
        self._fbk_collector_exit_event.clear()
        shmem_ok = False
        t0 = datetime.datetime.now()
        while (datetime.datetime.now() - t0).total_seconds() < self._map_timeout:
            if self._map_input_shmem():
                shmem_ok = True
                break
            else:
                # print('\n*** DBG wait for fbk sources')
                time.sleep(0.2)

        if shmem_ok:
            self._target_ready = True
            self._logger.print_console("*** Shared memory from feedback sources have been mapped ***",
                                     rgb=Color.COMMENTS,
                                     nl_before=True, nl_after=True)
        else:
            self._logger.print_console("*** ERROR: cannot map shared memory from feedback sources ***",
                                     rgb=Color.ERROR,
                                     nl_before=True, nl_after=True)
            self._fbk_collector_exit_event.set()
            return

        while not self._stop_event.is_set():
            feedback_items = []
            for shm, _ in self.input_shmem_list:
                if shm.buf[self.producer_status_idx] == 1:
                    break
            else:
                time.sleep(0.01)
                continue

            for tg_idx, obj in enumerate(self.input_shmem_list):
                shm, c_idx = obj
                if shm.buf[self.producer_status_idx] == 0 \
                        or shm.buf[self.consumer_start+c_idx] == 1:
                    continue

                dlen = struct.unpack(self.dlen_format,
                                     bytes(shm.buf[self.dlen_start:self.dlen_stop]))[0]
                fbk_item = bytes(shm.buf[self.data_start:self.data_start+dlen])
                self._logger.collect_feedback(fbk_item, status_code=0,
                                              fbk_src=self.fbk_sources[tg_idx][0])
                shm.buf[self.consumer_start+c_idx] = 1
                feedback_items.append(fbk_item)

            if self.controled_targets:
                for fi in feedback_items:
                    # print(f'\n***DBG put {fi}')
                    self.forward_queue.put(fi)

            time.sleep(0.01)

        # print('\n*** DBG fbk collector exits')
        self._fbk_collector_exit_event.set()

    def _forward_data(self):
        while not self._stop_event.is_set():
            data_to_send = []
            while not self.forward_queue.empty():
                data_to_send.append(self.forward_queue.get_nowait())

            # print(f'\n***DBG get {data_to_send}')

            if data_to_send:
                time.sleep(self.control_delay)
                for tg, fbk_filter in self.controled_targets:
                    for data in data_to_send:
                        d = fbk_filter(data, self.current_dm)
                        if d is not None:
                            tg.send_data_sync(Data(d))
            else:
                time.sleep(0.1)

        # print('\n***DBG leave forward')

    def _handle_fbk(self, data):
        if self._repeat_input:
            fbk_content = data.to_bytes()
        elif self._fbk_samples:
            fbk_content = random.choice(self._fbk_samples)
        else:
            fbk_content = rand_string(size=10)
        return fbk_content

    def get_consumer_idx(self):
        # This function is OK even when linked TestTargets are run in different fuddly instance
        if self._current_consumer_idx + 1 > self.max_consumer:
            raise IndexError
        self._current_consumer_idx += 1
        return self._current_consumer_idx

    def add_feedback_sources(self, *targets):
        if self.fbk_sources is None:
            self.fbk_sources = []
        for tg in targets:
            self.fbk_sources.append((tg, tg.get_consumer_idx()))

    def set_control_over(self, *test_targets, feedback_filter=lambda x, y: x):
        if self.controled_targets is None:
            self.controled_targets = []
        for tg in test_targets:
            self.controled_targets.append((tg, feedback_filter))

    def set_control_delay(self, delay):
        self.control_delay = delay

    # obsolete API
    def add_binding(self, target):
        if self.output_shmem:
            raise ValueError('In shmem mode, binding are not possible')
        self._bound_targets.append(target)

    def send_data(self, data, from_fmk=False):
        if self.output_shmem:
            self._send_data_finished_event.clear()
            if self._stop_event.is_set():
                self._send_data_finished_event.set()
                time.sleep(0.01)
                return

            d = data.to_bytes()
            dlen = len(d)
            if dlen > self.shmem_size - self.meta_data_size:
                raise ValueError('data too long, exceeds shared memory size')

            data_consumed = False
            buf = self.output_shmem.buf
            t0 = datetime.datetime.now()
            self._last_ack_date = None
            while (datetime.datetime.now() - t0).total_seconds() < 2:
                time.sleep(0.001)
                for i in range(self._current_consumer_idx+1):
                    if buf[self.consumer_start+i] == 0:
                        # one consumer is not ready thus we busy wait
                        break
                else:
                    # All the consumers are ready (0 everywhere)
                    # print('\n*** consumer are ready')
                    self._last_ack_date = datetime.datetime.now()
                    data_consumed = True
                    # print('\n*** DBG: data consumed on time!')
                    break
                # print('\n*** DBG: data not consumed yet')


            if data_consumed:
                buf[self.producer_status_idx] = 0

                for i in range(self._current_consumer_idx+1):
                    buf[self.consumer_start+i] = 0
                buf[self.dlen_start:self.dlen_stop] = struct.pack(self.dlen_format, dlen)
                buf[self.data_start:self.data_start+dlen] = d
                buf[self.producer_status_idx] = 1
            else:
                print(f'\n*** Warning: previous data not consumed on time, thus ignore new sending of "{d[:10]}..." ***')

            self._send_data_finished_event.set()
        else:
            time.sleep(0.001)
            if self._bound_targets:
                for tg in self._bound_targets:
                    tg._shared_queue.put((data.to_bytes(), str(self)))
            else:
                self._logger.collect_feedback(content=self._handle_fbk(data),
                                              status_code=random.randint(-3, 3))

            self._last_ack_date = datetime.datetime.now() + datetime.timedelta(microseconds=random.randint(20, 40))

    def send_multiple_data(self, data_list, from_fmk=False):
        for data in data_list:
            self.send_data(data, from_fmk=from_fmk)


    def is_target_ready_for_new_data(self):
        if self._shmem_mode:
            return self._target_ready
        else:
            return True

    def is_feedback_received(self):
        if self._shmem_mode:
            for shm, c_idx in self.input_shmem_list:
                if shm.buf[self.producer_status_idx] == 1 and \
                        shm.buf[self.consumer_start+c_idx] == 0:
                    return True
            else:
                return False

        elif self._bound_targets:
            return not self._shared_queue.empty()

        else:
            self._cpt += 1
            if self._cpt > 5 and random.choice([True, False]):
                self._cpt = 0
                return True
            else:
                return False

    def get_feedback(self):
        fbk = None
        if self._bound_targets:
            t0 = datetime.datetime.now()
            timeout = 0.01 if self.feedback_timeout is None else self.feedback_timeout
            while (datetime.datetime.now() - t0).total_seconds() < timeout:
                try:
                    item = self._shared_queue.get(block=True, timeout=0.01)
                except queue.Empty:
                    pass
                else:
                    self._fbk_collector.add_fbk_from(f'sent by {item[1]}', item[0])
                    self._shared_queue.task_done()

            fbk = self._fbk_collector

        else:
            pass

        return fbk

    def recover_target(self):
        if self._shmem_mode or self._bound_targets:
            return False
        else:
            if random.randint(1, 100) > (100 - self._recover_ratio):
                return True
            else:
                return False

    def get_last_target_ack_date(self):
        return self._last_ack_date
