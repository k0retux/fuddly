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
import datetime
import socket
import threading
import copy

import errno
from socket import error as socket_error

from libs.external_modules import *
import data_models
from fuzzfmk.global_resources import *

class TargetStuck(Exception): pass

class Target(object):
    '''
    Class abstracting the target we interact with.
    '''
    
    _logger=None
    _time_beetwen_data_emission = None

    def __init__(self):
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

    def is_alive(self):
        raise NotImplementedError

    def get_feedback(self):
        '''
        If overloaded, should return a TargetFeedback object.
        '''
        return None

    def get_description(self):
        return None


class TargetFeedback(object):

    def __init__(self, bstring=b''):
        self.cleanup()
        self.set_bytes(bstring)

    def add_fbk_from(self, ref, fbk):
        self._feedback_collector[ref] = fbk

    def has_fbk_collector(self):
        return len(self._feedback_collector) > 0

    def cleanup(self):
        self._feedback_collector = {}
        self.set_bytes(b'')
        self.set_error_code(0)

    def __iter__(self):
        for ref, fbk in self._feedback_collector.items():
            yield ref, fbk

    def set_bytes(self, bstring):
        self._bstring = bstring

    def get_bytes(self):
        return self._bstring

    def set_error_code(self, err_code):
        self._err_code = err_code

    def get_error_code(self):
        return self._err_code


class EmptyTarget(Target):

    def send_data(self, data):
        print(self._logger)
        pass

    def send_multiple_data(self, data_list):
        pass


class NetworkTarget(Target):
    '''Generic target class for interacting with a network resource. Can
    be used directly, but some methods may require to be overloaded to
    fit your needs.
    '''

    UNKNOWN_SEMANTIC = 42
    CHUNK_SZ = 2048

    def __init__(self, host='localhost', port=12345, socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                 data_semantics=UNKNOWN_SEMANTIC):
        self.host = {}
        self.port = {}
        self.socket_type = {}
        self.host[self.UNKNOWN_SEMANTIC] = self.host[data_semantics] = host
        self.port[self.UNKNOWN_SEMANTIC] = self.port[data_semantics] = port
        self.socket_type[self.UNKNOWN_SEMANTIC] = self.socket_type[data_semantics] = socket_type
        self.known_semantics = []
        self.sending_sockets = []
        self.multiple_destination = False

        self._feedback = TargetFeedback()

        self._fbk_handling_lock = threading.Lock()
        self.set_feedback_timeout(10)

        self.feedback_length = None  # if specified, timeout will be ignored
        self.sending_delay = 10

        self._default_fbk_socket_id = 'Default Feedback Socket'
        self._default_fbk_id = {}
        self._additional_fbk_desc = {}
        self._default_additional_fbk_id = 1

        self._default_fbk_id[(host, port)] = self._default_fbk_socket_id + ' - {:s}:{:d}'.format(host, port)


    def register_new_interface(self, host, port, socket_type, data_semantic):
        self.multiple_destination = True
        self.host[data_semantic] = host
        self.port[data_semantic] = port
        self.socket_type[data_semantic] = socket_type
        self.known_semantics.append(data_semantic)
        self._default_fbk_id[(host, port)] = self._default_fbk_socket_id + ' - {:s}:{:d}'.format(host, port)

    def set_feedback_timeout(self, timeout):
        self._feedback_timeout = timeout
        self._time_beetwen_data_emission = self._feedback_timeout

    def feedback_handling(self, fbk, ref):
        '''To be overloaded if feedback from the target need to be filtered
        before being logged and/or collected in some way and/or for
        any other reasons.

        Args:
          fbk (bytes): feedback received by the target through a socket referenced by `ref`.
          ref (string): user-defined reference of the socket used to retreive the feedback
        '''
        return fbk, ref

    def add_additional_feedback_interface(self, host, port,
                                          socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                                          fbk_id=None, fbk_length=None):
        '''Allows to register additional socket to get feedback
        from. Connection is attempted be when target starts, that is
        when :meth:`NetworkTarget.start()` is called.
        '''
        self._default_additional_fbk_id += 1
        if fbk_id is None:
            fbk_id = 'Default Additional Feedback ID %d' % self._default_additional_fbk_id
        else:
            assert(not str(fbk_id).startswith('Default Additional Feedback ID'))
        self._additional_fbk_desc[fbk_id] = (host, port, socket_type, fbk_id, fbk_length)

    def connect_to_additional_feedback_sockets(self):
        '''
        Connection to additional feedback sockets, if any.
        '''
        if self._additional_fbk_desc:
            for host, port, socket_type, fbk_id, fbk_length in self._additional_fbk_desc.values():
                s = self._connect_to_target(host, port, socket_type)
                if s is None:
                    self._logger.log_comment('WARNING: Feedback not available from {:s}:{:d}'.format(host, port))
                else:
                    self._additional_fbk_sockets.append(s)
                    self._additional_fbk_ids[s] = fbk_id
                    self._additional_fbk_lengths[s] = fbk_length


    def get_additional_feedback_sockets(self):
        '''Used if any additional socket to get feedback from has been added
        by :meth:`NetworkTarget.add_additional_feedback_interface()`,
        related to the data emitted if needed.

        Args:
          data (Data): the data that will be sent.

        Returns:
          tuple: list of sockets, dict of associated ids/names,
            dict of associated length (a length can be None)
        '''
        fbk_sockets = copy.copy(self._additional_fbk_sockets) if self._additional_fbk_sockets else None
        fbk_ids = copy.copy(self._additional_fbk_ids) if self._additional_fbk_sockets else None
        fbk_lengths = copy.copy(self._additional_fbk_lengths) if self._additional_fbk_sockets else None

        return fbk_sockets, fbk_ids, fbk_lengths


    def start(self):
        self._additional_fbk_sockets = []
        self._additional_fbk_ids = {}
        self._additional_fbk_lengths = {}
        self._feedback_handled = None
        self.feedback_thread_qty = 0
        self.feedback_complete_cpt = 0
        self._sending_id = 0
        self._last_ack_date = None  # Note that `self._last_ack_date`
                                    # could be updated many times if
                                    # self.send_multiple_data() is
                                    # used.
        self.connect_to_additional_feedback_sockets()
        return True

    def stop(self):
        for s in self._additional_fbk_sockets:
            s.close()
        return True

    def send_data(self, data):
        self._feedback.cleanup()
        host, port, socket_type = self._get_net_info_from(data)
        s = self._connect_to_target(host, port, socket_type)
        if s is None:
            self._feedback.set_error_code(-1)
            err_msg = '>>> WARNING: unable to send data to {:s}:{:d} <<<'.format(host, port)
            self._feedback.add_fbk_from(self._default_fbk_id[(host, port)], err_msg)
        else:
            self._send_data([s], {s:(data, host, port)})

    def send_multiple_data(self, data_list):
        self._feedback.cleanup()
        sockets = []
        data_refs = {}
        for data in data_list:
            host, port, socket_type = self._get_net_info_from(data)
            s = self._connect_to_target(host, port, socket_type)
            if s is None:
                self._feedback.set_error_code(-1)
                err_msg = '>>> WARNING: unable to send data to {:s}:{:d} <<<'.format(host, port)
                self._feedback.add_fbk_from(self._default_fbk_id[(host, port)], err_msg)
            else:
                sockets.append(s)
                data_refs[s] = (data, host, port)
                self._send_data(sockets, data_refs)

    def _get_data_semantic_key(self, data):
        semantics = data.node.get_semantics()
        if semantics is not None:
            matching_crit = semantics.what_match_from(self.known_semantics)
        else:
            matching_crit = None

        if matching_crit:
            key = matching_crit[0]
        else:
            key = self.UNKNOWN_SEMANTIC

        return key

    def _get_net_info_from(self, data):
        key = self._get_data_semantic_key(data)
        return self.host[key], self.port[key], self.socket_type[key]

    def _connect_to_target(self, host, port, socket_type):
        s = socket.socket(*socket_type)
        try:
            s.connect((host, port))
        except socket_error as serr:
            # if serr.errno != errno.ECONNREFUSED:
            print('\n*** ERROR: ' + str(serr))
            return None

        s.setblocking(0)
        return s

    @staticmethod
    def _collect_feedback_from(fbk_sockets, fbk_ids, fbk_lengths, fbk_lock, fbk_handling, fbk_collect, fbk_complete,
                               send_id, fbk_timeout, register_ack):
        chunks = {}
        bytes_recd = {}
        t0 = datetime.datetime.now()
        duration = 0
        first_pass = True
        ack_date = None
        dont_stop = True
        
        for s in fbk_sockets:
            bytes_recd[s] = 0

        while dont_stop:
            ready_to_read, ready_to_write, in_error = select.select(fbk_sockets, [], [], 1)
            now = datetime.datetime.now()
            duration = (now - t0).total_seconds()
            if ready_to_read:
                if first_pass:
                    first_pass = False
                    register_ack(now)
                for s in ready_to_read:
                    if fbk_lengths[s] is None:
                        sz = NetworkTarget.CHUNK_SZ
                    else:
                        sz = min(fbk_lengths[s] - bytes_recd[s], NetworkTarget.CHUNK_SZ)
                    try:
                        chunk = s.recv(sz)
                    except Exception as e:
                        print('\n*** WARNING: ' + str(e))
                        continue
                    if chunk == b'':
                        # Ok nothing more to receive
                        break
                    bytes_recd[s] = bytes_recd[s] + len(chunk)
                    if s not in chunks:
                        chunks[s] = []
                    chunks[s].append(chunk)

            for s in fbk_sockets:
                if s in ready_to_read:
                    s_fbk_len = fbk_lengths[s]
                    if (s_fbk_len is None and duration > fbk_timeout) or (s_fbk_len is not None and bytes_recd[s] >= s_fbk_len):
                        dont_stop = False
                        break
                elif duration > fbk_timeout:
                    dont_stop = False

        for s, chks in chunks.items():
            fbk = b''.join(chks)
            with fbk_lock:
                fbk, fbkid = fbk_handling(fbk, fbk_ids[s])
                fbk_collect(fbk, fbkid)
                s.close()

        with fbk_lock:
            fbk_complete(send_id)

        return


    def _send_data(self, sockets, data_refs):
        ready_to_read, ready_to_write, in_error = select.select([], sockets, [], self.sending_delay)
        if ready_to_write:
            for s in ready_to_write:
                data, host, port = data_refs[s]
                fbk_sockets, fbk_ids, fbk_lengths = self.get_additional_feedback_sockets()
                raw_data = data.to_bytes()
                totalsent = 0
                while totalsent < len(raw_data):
                    sent = s.send(raw_data[totalsent:])
                    if sent == 0:
                        s.close()
                        raise TargetStuck("socket connection broken")
                    totalsent = totalsent + sent

                if fbk_sockets is None:
                    assert(fbk_ids is None)
                    assert(fbk_lengths is None)
                    fbk_sockets = []
                    fbk_ids = {}
                    fbk_lengths = {}
                else:
                    assert(self._default_fbk_id[(host, port)] not in fbk_ids.values())
                fbk_sockets.append(s)
                fbk_ids[s] = self._default_fbk_id[(host, port)]
                fbk_lengths[s] = self.feedback_length

            first_pass = False
            self.feedback_thread_qty += 1
            feedback_thread = threading.Thread(None, self._collect_feedback_from, name='FBK-' + repr(self._sending_id),
                                               args=(fbk_sockets, fbk_ids, fbk_lengths, self._fbk_handling_lock,
                                                     self.feedback_handling, self._feedback_collect,
                                                     self._feedback_complete, self._sending_id,
                                                     self._feedback_timeout, self._register_last_ack_date))
            feedback_thread.start()

        else:
            raise TargetStuck("system not ready for sending data!")


    def _feedback_collect(self, fbk, ref):
        self._feedback.add_fbk_from(ref, fbk)
        # self._logger.collect_target_feedback(fbk)

    def _feedback_complete(self, sid):
        if sid == self._sending_id:
            self.feedback_complete_cpt += 1
        if self.feedback_complete_cpt == self.feedback_thread_qty:
            self._feedback_handled = True

    def get_feedback(self):
        return self._feedback

    def do_before_sending_data(self):
        self._feedback_handled = False
        self._sending_id += 1

    def is_target_ready_for_new_data(self):
        # We answer we are ready if at least one receiver has
        # terminated its job, either because the target answered to
        # it, or because of the current specified timeout.
        if self._feedback_handled:
            return True
        else:
            return False

    def _register_last_ack_date(self, ack_date):
        self._last_ack_date = ack_date

    def get_last_target_ack_date(self):
        return self._last_ack_date

    def get_description(self):
        desc = ''
        for key, host in self.host.items():
            port = self.port[key]
            desc += '{:s}:{:d}, '.format(host, port)

        return desc[:-2]

    def stop_target(self): # cleanup_target()
        raise NotImplementedError

    def is_alive(self):
        raise NotImplementedError




class PrinterTarget(Target):

    def __init__(self, tmpfile_ext):
        self.__suffix = '{:0>12d}'.format(random.randint(2**16, 2**32))
        self.__feedback = TargetFeedback()
        self.__tmpfile_ext = tmpfile_ext
        self.__target_ip = None
        self.__target_port = None
        self.__printer_name = None
        self.__cpt = None

    def set_target_ip(self, target_ip):
        self.__target_ip = target_ip

    def get_target_ip(self):
        return self.__target_ip

    def set_target_port(self, target_port):
        self.__target_port = target_port

    def get_target_port(self):
        return self.__target_port

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

        if self.__target_port is None:
            self.__target_port = 631

        cups.setServer(self.__target_ip)
        cups.setPort(self.__target_port)

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


class LocalTarget(Target):

    def __init__(self, tmpfile_ext):
        self.__suffix = '{:0>12d}'.format(random.randint(2**16, 2**32))
        self.__app = None
        self.__target_path = None
        self.__pre_args = None
        self.__post_args = None
        self.__feedback = TargetFeedback()
        self.__tmpfile_ext = tmpfile_ext

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
        
    def stop_target(self):
        os.kill(self.__app.pid, signal.SIGTERM)


    def get_feedback(self, delay=0.2):
        if self.__app is None:
            return

        ret = select.select([self.__app.stdout, self.__app.stderr], [], [], delay)
        if ret[0]:
            byte_string = b''
            for fd in ret[0][:-1]:
                byte_string += fd.read() + '\n\n'
            byte_string += ret[0][-1].read()
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
