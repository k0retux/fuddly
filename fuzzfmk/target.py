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

from __future__ import print_function

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
import struct
import time
import collections

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
    _probes = None

    def __init__(self):
        '''
        To be overloaded if needed
        '''
        pass

    def set_logger(self, logger):
        self._logger = logger

    def _start(self):
        self._logger.print_console('*** Target initialization ***\n', nl_before=False, rgb=Color.COMPONENT_START)
        return self.start()

    def _stop(self):
        self._logger.print_console('*** Target cleanup procedure ***\n', nl_before=False, rgb=Color.COMPONENT_STOP)
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

        Note: use data.to_bytes() to get binary data.

        Args:
          data (Data): data container that embeds generally a
            modeled data accessible through `data.node`. However if the
            latter is None, it only embeds the raw data.
        '''
        raise NotImplementedError

    def send_multiple_data(self, data_list):
        '''
        Used to send multiple data to the target, or to stimulate several
        target's inputs in one shot.

        Args:
            data_list (list): list of data to be sent

        Note: Use data.to_bytes() to get binary data
        '''
        raise NotImplementedError

    def do_before_sending_data(self, data_list):
        '''
        Called by the framework before sending data

        Args:
          data_list (list): list of Data objects that will be sent to the target.
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

    def cleanup(self):
        '''
        To be overloaded if something needs to be performed after each data emission.
        It is called after any feedback has been retrieved.
        '''
        pass

    def recover_target(self):
        '''
        Implementation of target recovering operations, when a target problem has been detected
        (i.e. a negative feedback from a probe or an operator)

        Returns:
            bool: True if the target has been recovered. False otherwise.
        '''
        raise NotImplementedError

    def get_feedback(self):
        '''
        If overloaded, should return a TargetFeedback object.
        '''
        return None

    def get_description(self):
        return None


    def add_probe(self, probe):
        if self._probes is None:
            self._probes = []
        self._probes.append(probe)

    def remove_probes(self):
        self._probes = None

    @property
    def probes(self):
        return self._probes if self._probes is not None else []


class TargetFeedback(object):

    def __init__(self, bstring=b''):
        self.cleanup()
        self.set_bytes(bstring)

    def add_fbk_from(self, ref, fbk):
        self._feedback_collector[ref] = fbk

    def has_fbk_collector(self):
        return len(self._feedback_collector) > 0

    def cleanup(self):
        self._feedback_collector = collections.OrderedDict()
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
                 data_semantics=UNKNOWN_SEMANTIC, server_mode=False, hold_connection=False):
        '''
        Args:
          host (str): the IP address of the target to connect to, or
            the IP address on which we will wait for target connecting
            to us (if `server_mode` is True).
          port (int): the port for communicating with the target, or
            the port to listen to.
          socket_type (tuple): tuple composed of the socket address family
            and socket type
          data_semantics (str): string of characters that will be used for
            data routing decision. Useful only when more than one interface
            are defined. In such case, the data semantics will be checked in
            order to find a matching interface to which data will be sent. If
            the data have no semantic, it will be routed to the default first
            declared interface.
          server_mode (bool): If `True`, the interface will be set in server mode,
            which means we will wait for the real target to connect to us for sending
            it data.
          hold_connection (bool): If `True`, we will maintain the connection while
            sending data to the real target. Otherwise, after each data emission,
            we close the related socket.
        '''

        self._host = {}
        self._port = {}
        self._socket_type = {}
        self.host = self._host[self.UNKNOWN_SEMANTIC] = self._host[data_semantics] = host
        self.port = self._port[self.UNKNOWN_SEMANTIC] = self._port[data_semantics] = port
        self._socket_type[self.UNKNOWN_SEMANTIC] = self._socket_type[data_semantics] = socket_type

        self.known_semantics = []
        self.sending_sockets = []
        self.multiple_destination = False

        self._feedback = TargetFeedback()

        self._fbk_handling_lock = threading.Lock()
        self.socket_desc_lock = threading.Lock()

        self.set_timeout(fbk_timeout=6, sending_delay=4)

        self.feedback_length = None  # if specified, timeout will be ignored

        self._default_fbk_socket_id = 'Default Feedback Socket'
        self._default_fbk_id = {}
        self._additional_fbk_desc = {}
        self._default_additional_fbk_id = 1

        self._default_fbk_id[(host, port)] = self._default_fbk_socket_id + ' - {:s}:{:d}'.format(host, port)

        self.server_mode = {}
        self.server_mode[(host,port)] = server_mode
        self.hold_connection = {}
        self.hold_connection[(host, port)] = hold_connection

        self.stop_event = threading.Event()
        self._server_thread_lock = threading.Lock()


    def register_new_interface(self, host, port, socket_type, data_semantics, server_mode=False,
                               hold_connection=False):
        self.multiple_destination = True
        self._host[data_semantics] = host
        self._port[data_semantics] = port
        self._socket_type[data_semantics] = socket_type
        self.known_semantics.append(data_semantics)
        self.server_mode[(host,port)] = server_mode
        self._default_fbk_id[(host, port)] = self._default_fbk_socket_id + ' - {:s}:{:d}'.format(host, port)
        self.hold_connection[(host, port)] = hold_connection

    def set_timeout(self, fbk_timeout, sending_delay):
        self._feedback_timeout = max(fbk_timeout, 0.2)
        self._sending_delay = min(sending_delay, max(self._feedback_timeout-0.2, 0))
        self._time_beetwen_data_emission = self._feedback_timeout + 2

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

    def add_additional_feedback_interface(self, host, port,
                                          socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                                          fbk_id=None, fbk_length=None, server_mode=False):
        '''Allows to register additional socket to get feedback
        from. Connection is attempted be when target starts, that is
        when :meth:`NetworkTarget.start()` is called.
        '''
        self._default_additional_fbk_id += 1
        if fbk_id is None:
            fbk_id = 'Default Additional Feedback ID %d' % self._default_additional_fbk_id
        else:
            assert(not str(fbk_id).startswith('Default Additional Feedback ID'))
        self._additional_fbk_desc[fbk_id] = (host, port, socket_type, fbk_id, fbk_length, server_mode)
        self.hold_connection[(host, port)] = True

    def _custom_data_handling_before_emission(self, data_list):
        '''To be overloaded if you want to perform some operation before
        sending `data_list` to the target.

        Args:
          data_list (list): list of Data objects that will be sent to the target.
        '''
        pass

    def _feedback_handling(self, fbk, ref):
        '''To be overloaded if feedback from the target need to be filtered
        before being logged and/or collected in some way and/or for
        any other reasons.

        Args:
          fbk (bytes): feedback received by the target through a socket referenced by `ref`.
          ref (string): user-defined reference of the socket used to retreive the feedback
        '''
        return fbk, ref


    def listen_to(self, host, port, ref_id,
                  socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                  chk_size=CHUNK_SZ, wait_time=None, hold_connection=True):
        '''
        Used for collecting feedback from the target while it is already started.
        '''
        self.hold_connection[(host, port)] = hold_connection
        self._raw_listen_to(host, port, ref_id, socket_type, chk_size, wait_time=wait_time)
        self._dynamic_interfaces[(host, port)] = (-1, ref_id)

    def _raw_listen_to(self, host, port, ref_id,
                       socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                       chk_size=CHUNK_SZ, wait_time=None):

        if wait_time is None:
            wait_time = self._feedback_timeout

        initial_call = False
        if (host, port) not in self._server_sock2hp.values():
            initial_call = True

        connected_client_event = threading.Event()
        self._listen_to_target(host, port, socket_type,
                               self._handle_connection_to_fbk_server, args=(ref_id, chk_size, connected_client_event))

        if initial_call or not self.hold_connection[(host, port)]:
            connected_client_event.wait(wait_time)
            if not connected_client_event.is_set():
                self._logger.log_comment('WARNING: Feedback from ({:s}:{:d}) is not available as no client connects to us'.format(host, port))


    def connect_to(self, host, port, ref_id,
                   socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                   chk_size=CHUNK_SZ, hold_connection=True):
        '''
        Used for collecting feedback from the target while it is already started.
        '''
        self.hold_connection[(host, port)] = hold_connection
        s = self._raw_connect_to(host, port, ref_id, socket_type, chk_size, hold_connection=hold_connection)
        self._dynamic_interfaces[(host, port)] = (s, ref_id)

        return s

    def _raw_connect_to(self, host, port, ref_id,
                        socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                        chk_size=CHUNK_SZ, hold_connection=True):
        s = self._connect_to_target(host, port, socket_type)
        if s is None:
            self._logger.log_comment('WARNING: Unable to connect to {:s}:{:d}'.format(host, port))
            return None
        else:
            with self.socket_desc_lock:
                if s not in self._additional_fbk_sockets:
                    self._additional_fbk_sockets.append(s)
                    self._additional_fbk_ids[s] = ref_id
                    self._additional_fbk_lengths[s] = chk_size

        return s


    def remove_dynamic_interface(self, host, port):
        if (host, port) in self._dynamic_interfaces.keys():
            if (host, port) in self.hold_connection:
                del self.hold_connection[(host, port)]
                if (host, port) in self._hclient_hp2sock:
                    s = self._hclient_hp2sock[(host, port)]
                    del self._hclient_hp2sock[(host, port)]
                    del self._hclient_sock2hp[s]

            req_sock, ref_id = self._dynamic_interfaces[(host, port)]
            del self._dynamic_interfaces[(host, port)]
            with self.socket_desc_lock:
                if req_sock == -1:
                    for s, rid in copy.copy(self._additional_fbk_ids).items():
                        if ref_id == rid:
                            self._additional_fbk_sockets.remove(s)
                            del self._additional_fbk_ids[s]
                            del self._additional_fbk_lengths[s]

                elif req_sock in self._additional_fbk_sockets:
                    self._additional_fbk_sockets.remove(req_sock)
                    del self._additional_fbk_ids[req_sock]
                    del self._additional_fbk_lengths[req_sock]
            if req_sock != -1 and req_sock is not None:
                req_sock.close()
        else:
            print('\n*** WARNING: Unable to remove inexistent interface ({:s}:{:d})'.format(host,port))


    def remove_all_dynamic_interfaces(self):
        dyn_interface = copy.copy(self._dynamic_interfaces)
        for hp, req_sock in dyn_interface.items():
            self.remove_dynamic_interface(*hp)


    def _connect_to_additional_feedback_sockets(self):
        '''
        Connection to additional feedback sockets, if any.
        '''
        if self._additional_fbk_desc:
            for host, port, socket_type, fbk_id, fbk_length, server_mode in self._additional_fbk_desc.values():
                if server_mode:
                    self._raw_listen_to(host, port, fbk_id, socket_type, chk_size=fbk_length)
                else:
                    self._raw_connect_to(host, port, fbk_id, socket_type, chk_size=fbk_length)


    def _get_additional_feedback_sockets(self):
        '''Used if any additional socket to get feedback from has been added
        by :meth:`NetworkTarget.add_additional_feedback_interface()`,
        related to the data emitted if needed.

        Args:
          data (Data): the data that will be sent.

        Returns:
          tuple: list of sockets, dict of associated ids/names,
            dict of associated length (a length can be None)
        '''
        with self.socket_desc_lock:
            fbk_sockets = copy.copy(self._additional_fbk_sockets) if self._additional_fbk_sockets else None
            fbk_ids = copy.copy(self._additional_fbk_ids) if self._additional_fbk_sockets else None
            fbk_lengths = copy.copy(self._additional_fbk_lengths) if self._additional_fbk_sockets else None

        return fbk_sockets, fbk_ids, fbk_lengths


    def start(self):
        # Used by _raw_listen_to()
        self._server_sock2hp = {}
        self._server_thread_share = {}
        self._last_client_sock2hp = {}  # only for hold_connection
        self._last_client_hp2sock = {}  # only for hold_connection

        # Used by _raw_connect_to()
        self._hclient_sock2hp = {}  # only for hold_connection
        self._hclient_hp2sock = {}  # only for hold_connection

        self._additional_fbk_sockets = []
        self._additional_fbk_ids = {}
        self._additional_fbk_lengths = {}
        self._dynamic_interfaces = {}
        self._feedback_handled = None
        self.feedback_thread_qty = 0
        self.feedback_complete_cpt = 0
        self._sending_id = 0
        self._initial_sending_id = -1
        self._first_send_data_call = True
        self._thread_cpt = 0
        self._last_ack_date = None  # Note that `self._last_ack_date`
                                    # could be updated many times if
                                    # self.send_multiple_data() is
                                    # used.
        self._connect_to_additional_feedback_sockets()
        return self.initialize()

    def stop(self):
        self.stop_event.set()
        for s in self._server_sock2hp.keys():
            s.close()
        for s in self._last_client_sock2hp.keys():
            s.close()
        for s in self._hclient_sock2hp.keys():
            s.close()
        for s in self._additional_fbk_sockets:
            s.close()

        self._server_sock2hp = None
        self._server_thread_share = None
        self._last_client_sock2hp = None
        self._last_client_hp2sock = None
        self._hclient_sock2hp = None
        self._hclient_hp2sock = None
        self._additional_fbk_sockets = None
        self._additional_fbk_ids = None
        self._additional_fbk_lengths = None
        self._dynamic_interfaces = None

        return self.terminate()

    def send_data(self, data):
        connected_client_event = None
        host, port, socket_type, server_mode = self._get_net_info_from(data)
        if server_mode:
            connected_client_event = threading.Event()
            self._listen_to_target(host, port, socket_type,
                                   self._handle_target_connection, args=(data, host, port, connected_client_event))
            connected_client_event.wait(self._sending_delay)
            if not connected_client_event.is_set():
                self._feedback.set_error_code(-2)
                err_msg = ">>> WARNING: unable to send data because the target did not connect to us <<<".format(host, port)
                self._feedback.add_fbk_from(self._default_fbk_id[(host, port)], err_msg)
        else:
            s = self._connect_to_target(host, port, socket_type)
            if s is None:
                self._feedback.set_error_code(-1)
                err_msg = '>>> WARNING: unable to send data to {:s}:{:d} <<<'.format(host, port)
                self._feedback.add_fbk_from(self._default_fbk_id[(host, port)], err_msg)
            else:
                self._send_data([s], {s:(data, host, port)}, self._sending_id)


    def send_multiple_data(self, data_list):
        sockets = []
        data_refs = {}
        connected_client_event = {}
        client_event = None
        for data in data_list:
            host, port, socket_type, server_mode = self._get_net_info_from(data)
            if server_mode:
                connected_client_event[(host, port)] = threading.Event()
                self._listen_to_target(host, port, socket_type,
                                       self._handle_target_connection, args=(data, host, port,
                                                                             connected_client_event[(host, port)]))
            else:
                s = self._connect_to_target(host, port, socket_type)
                if s is None:
                    self._feedback.set_error_code(-2)
                    err_msg = '>>> WARNING: unable to send data to {:s}:{:d} <<<'.format(host, port)
                    self._feedback.add_fbk_from(self._default_fbk_id[(host, port)], err_msg)
                else:
                    sockets.append(s)
                    data_refs[s] = (data, host, port)

        self._send_data(sockets, data_refs, self._sending_id)
        t0 = datetime.datetime.now()

        if connected_client_event:
            duration = 0
            client_event = connected_client_event
            client_event_copy = copy.copy(connected_client_event)
            while duration < self._sending_delay:
                if len(client_event) != len(client_event_copy):
                    client_event = copy.copy(client_event_copy)
                for ref, event in client_event.items():
                    event.wait(0.2)
                    if event.is_set():
                        del client_event_copy[ref]
                now = datetime.datetime.now()
                duration = (now - t0).total_seconds()

            for ref, event in connected_client_event.items():
                host, port = ref
                if not event.is_set():
                    self._feedback.set_error_code(-1)
                    err_msg = ">>> WARNING: unable to send data because the target did not connect to us <<<"
                    self._feedback.add_fbk_from(self._default_fbk_id[(host, port)], err_msg)


    def _get_data_semantic_key(self, data):
        if data.node is None:
            print('\n*** ERROR: None data has been received!')
            return self.UNKNOWN_SEMANTIC

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
        host = self._host[key]
        port = self._port[key]
        return host, port, self._socket_type[key], self.server_mode[(host, port)]

    def _connect_to_target(self, host, port, socket_type):
        if self.hold_connection[(host, port)] and (host, port) in self._hclient_hp2sock.keys():
            return self._hclient_hp2sock[(host, port)]

        family, sock_type = socket_type
        s = socket.socket(family, sock_type)

        try:
            s.connect((host, port))
        except socket_error as serr:
            # if serr.errno != errno.ECONNREFUSED:
            print('\n*** ERROR: ' + str(serr))
            return None

        s.setblocking(0)

        if self.hold_connection[(host, port)]:
            self._hclient_sock2hp[s] = (host, port)
            self._hclient_hp2sock[(host, port)] = s

        return s


    def _listen_to_target(self, host, port, socket_type, func, args=None):
        if (host, port) in self._server_sock2hp.values():
            # After data has been sent to the target that first
            # connect to us, new data is sent through the same socket
            # if hold_connection is set for this interface. And new
            # connection will always receive the most recent data to
            # send.
            with self._server_thread_lock:
                self._server_thread_share[(host, port)] = args
                if self.hold_connection[(host, port)] and (host, port) in self._last_client_hp2sock:
                    csocket, addr = self._last_client_hp2sock[(host, port)]
                else:
                    csocket = None
            if csocket:
                func(csocket, addr, args)
            return True

        family, sock_type = socket_type

        serversocket = socket.socket(family, sock_type)
        serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serversocket.settimeout(0.2)
        try:
            serversocket.bind((host, port))
        except socket.error as serr:
            print('\n*** ERROR: ' + str(serr))
            return False

        self._server_sock2hp[serversocket] = (host, port)
        with self._server_thread_lock:
            self._server_thread_share[(host, port)] = args

        if sock_type == socket.SOCK_STREAM:
            serversocket.listen(5)
            server_thread = threading.Thread(None, self._server_main, name='SRV-' + '',
                                             args=(serversocket, host, port, func))
            server_thread.start()

        elif sock_type == socket.SOCK_DGRAM:
            self._handle_connection_to_fbk_server(serversocket, None, args)

        else:
            raise ValueError("Unrecognized socket type")

    def _server_main(self, serversocket, host, port, func):
        while not self.stop_event.is_set():
            try:
                # accept connections from outside
                (clientsocket, address) = serversocket.accept()
            except socket.timeout:
                pass
            except OSError as e:
                if e.errno == 9: # [Errno 9] Bad file descriptor
                    # TOFIX: It may occur with python3.
                    # In this case the resource seem to have been released by
                    # the OS whereas there is still a reference on it.
                    pass
                else:
                    raise
            else:
                with self._server_thread_lock:
                    args = self._server_thread_share[(host, port)]
                func(clientsocket, address, args)


    def _handle_connection_to_fbk_server(self, clientsocket, address, args):
        fbk_id, fbk_length, connected_client_event = args
        connected_client_event.set()
        with self.socket_desc_lock:
            self._additional_fbk_sockets.append(clientsocket)
            self._additional_fbk_ids[clientsocket] = fbk_id
            self._additional_fbk_lengths[clientsocket] = fbk_length

    def _handle_target_connection(self, clientsocket, address, args):
        data, host, port, connected_client_event = args
        if self.hold_connection[(host, port)]:
            with self._server_thread_lock:
                self._last_client_hp2sock[(host, port)] = (clientsocket, address)
                self._last_client_sock2hp[clientsocket] = (host, port)
        connected_client_event.set()
        self._send_data([clientsocket], {clientsocket:(data, host, port)}, self._sending_id)


    def _collect_feedback_from(self, fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                               send_id, fbk_timeout):

        def _check_and_handle_obsolete_socket(socket, error=None, error_list=None):
            # print('\n*** NOTE: Remove obsolete socket {!r}'.format(socket))
            epobj.unregister(socket)
            self._server_thread_lock.acquire()
            if socket in self._last_client_sock2hp.keys():
                if error is not None:
                    error_list.append((fbk_ids[socket], error))
                host, port = self._last_client_sock2hp[socket]
                del self._last_client_sock2hp[socket]
                del self._last_client_hp2sock[(host, port)]
                self._server_thread_lock.release()
            else:
                self._server_thread_lock.release()
                with self.socket_desc_lock:
                    if socket in self._hclient_sock2hp.keys():
                        if error is not None:
                            error_list.append((fbk_ids[socket], error))
                        host, port = self._hclient_sock2hp[socket]
                        del self._hclient_sock2hp[socket]
                        del self._hclient_hp2sock[(host, port)]
                    if socket in self._additional_fbk_sockets:
                        if error is not None:
                            error_list.append((self._additional_fbk_ids[socket], error))
                        self._additional_fbk_sockets.remove(socket)
                        del self._additional_fbk_ids[socket]
                        del self._additional_fbk_lengths[socket]


        chunks = collections.OrderedDict()
        t0 = datetime.datetime.now()
        duration = 0
        first_pass = True
        ack_date = None
        dont_stop = True

        bytes_recd = {}
        for fd in fbk_sockets:
            bytes_recd[fd] = 0
            chunks[fd] = []

        socket_errors = []

        while dont_stop:
            ready_to_read = []
            for fd, ev in epobj.poll(timeout=0.2):
                socket = fileno2fd[fd]
                if ev != select.EPOLLIN:
                    _check_and_handle_obsolete_socket(socket, error=ev, error_list=socket_errors)
                    if socket in fbk_sockets:
                        fbk_sockets.remove(socket)
                    continue
                ready_to_read.append(socket)

            now = datetime.datetime.now()
            duration = (now - t0).total_seconds()
            if ready_to_read:
                if first_pass:
                    first_pass = False
                    self._register_last_ack_date(now)
                for s in ready_to_read:
                    if fbk_lengths[s] is None:
                        sz = NetworkTarget.CHUNK_SZ
                    else:
                        sz = min(fbk_lengths[s] - bytes_recd[s], NetworkTarget.CHUNK_SZ)
                    chunk = s.recv(sz)
                    if chunk == b'':
                        # print('\n*** NOTE: Nothing more to receive from : {!r}'.format(fbk_ids[s]))
                        fbk_sockets.remove(s)
                        _check_and_handle_obsolete_socket(s)
                        s.close()
                        continue
                    else:
                        bytes_recd[s] = bytes_recd[s] + len(chunk)
                        chunks[s].append(chunk)

            if fbk_sockets:
                for s in fbk_sockets:
                    if s in ready_to_read:
                        s_fbk_len = fbk_lengths[s]
                        if s_fbk_len is None or bytes_recd[s] < s_fbk_len:
                            dont_stop = True
                            break
                    else:
                        dont_stop = True
                        break
                else:
                    dont_stop = False

                if duration > fbk_timeout:
                    dont_stop = False

            else:
                dont_stop = False

        for s, chks in chunks.items():
            fbk = b'\n'.join(chks)
            with self._fbk_handling_lock:
                fbk, fbkid = self._feedback_handling(fbk, fbk_ids[s])
                self._feedback_collect(fbk, fbkid)
                if s not in self._additional_fbk_sockets and \
                   s not in self._hclient_sock2hp.keys() and \
                   s not in self._last_client_sock2hp.keys():
                    s.close()

        with self._fbk_handling_lock:
            for fbkid, ev in socket_errors:
                self._feedback_collect(">>> ERROR[{:d}]: unable to interact with '{:s}' "
                                       "<<<".format(ev,fbkid), fbkid, error=-ev)
            self._feedback_complete(send_id)

        return


    def _send_data(self, sockets, data_refs, sid):
        if sid != self._initial_sending_id:
            self._initial_sending_id = sid
            # self._first_send_data_call = True

        ready_to_read, ready_to_write, in_error = select.select([], sockets, [], self._sending_delay)
        if ready_to_write:

            epobj = select.epoll()
            fileno2fd = {}

            if self._first_send_data_call:
                self._first_send_data_call = False

                fbk_sockets, fbk_ids, fbk_lengths = self._get_additional_feedback_sockets()
                if fbk_sockets:
                    for fd in fbk_sockets:
                        epobj.register(fd, select.EPOLLIN)
                        fileno2fd[fd.fileno()] = fd
            else:
                fbk_sockets, fbk_ids, fbk_lengths = None, None, None

            for s in ready_to_write:
                add_main_socket = True
                data, host, port = data_refs[s]

                epobj.register(s, select.EPOLLIN)
                fileno2fd[s.fileno()] = s

                raw_data = data.to_bytes()
                totalsent = 0
                send_retry = 0
                while totalsent < len(raw_data) and send_retry < 10:
                    try:
                        sent = s.send(raw_data[totalsent:])
                    except socket.error as serr:
                        send_retry += 1
                        print('\n*** ERROR: ' + str(serr))
                        if serr.errno == socket.errno.EWOULDBLOCK:
                            time.sleep(0.2)
                            continue
                        else:
                            add_main_socket = False
                            raise TargetStuck("system not ready for sending data!")
                            # break
                    else:
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

                if add_main_socket:
                    fbk_sockets.append(s)
                    fbk_ids[s] = self._default_fbk_id[(host, port)]
                    fbk_lengths[s] = self.feedback_length

            self._start_fbk_collector(fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd)

        else:
            raise TargetStuck("system not ready for sending data!")


    def _start_fbk_collector(self, fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd):
        self._thread_cpt += 1
        self.feedback_thread_qty += 1
        feedback_thread = threading.Thread(None, self._collect_feedback_from,
                                           name='FBK-' + repr(self._sending_id) + '#' + repr(self._thread_cpt),
                                           args=(fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                                                 self._sending_id, self._feedback_timeout))
        feedback_thread.start()



    def _feedback_collect(self, fbk, ref, error=0):
        if error < 0:
            self._feedback.set_error_code(error)
        self._feedback.add_fbk_from(ref, fbk)

    def _feedback_complete(self, sid):
        if sid == self._sending_id:
            self.feedback_complete_cpt += 1
        if self.feedback_complete_cpt == self.feedback_thread_qty:
            self._feedback_handled = True

    def get_feedback(self):
        return self._feedback

    def do_before_sending_data(self, data_list):
        self._feedback_handled = False
        self._first_send_data_call = True
        self._sending_id += 1
        self._thread_cpt = 0
        self._custom_data_handling_before_emission(data_list)

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
        desc_added = []
        desc = ''
        for key, host in self._host.items():
            port = self._port[key]
            if (host, port) in desc_added:
                continue
            desc_added.append((host, port))
            server_mode = self.server_mode[(host, port)]
            hold_connection = self.hold_connection[(host, port)]
            desc += '{:s}:{:d} (serv:{!r},hold:{!r}), '.format(host, port, server_mode, hold_connection)

        return desc[:-2]



class PrinterTarget(Target):

    def __init__(self, tmpfile_ext):
        self.__suffix = '{:0>12d}'.format(random.randint(2**16, 2**32))
        self.__feedback = TargetFeedback()
        self.__target_ip = None
        self.__target_port = None
        self.__printer_name = None
        self.__cpt = None
        self.set_tmp_file_extension(tmpfile_ext)

    def set_tmp_file_extension(self, tmpfile_ext):
        self._tmpfile_ext = tmpfile_ext

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
        file_name = os.path.join(wkspace, 'fuzz_test_' + self.__suffix + self._tmpfile_ext)

        with open(file_name, 'wb') as f:
             f.write(data)

        inc = '_{:0>5d}'.format(self.__cpt)
        self.__cpt += 1

        try:
            self.__connection.printFile(self.__printer_name, file_name, 'job_'+ self.__suffix + inc, {})
        except cups.IPPError as err:
            print('CUPS Server Errror: ', err)


class LocalTarget(Target):

    def __init__(self, tmpfile_ext, target_path=None):
        self.__suffix = '{:0>12d}'.format(random.randint(2**16, 2**32))
        self.__app = None
        self.__pre_args = None
        self.__post_args = None
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
        return self.initialize()

    def stop(self):
        return self.terminate()

    def send_data(self, data):

        data = data.to_bytes()
        wkspace = os.path.join(app_folder, 'workspace')

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
        
    def cleanup(self):
        try:
            os.kill(self.__app.pid, signal.SIGTERM)
        except:
            print("\n*** WARNING: cannot kill application with PID {:d}".format(self.__app.pid))

    def get_feedback(self, delay=0.2):
        if self.__app is None:
            return

        ret = select.select([self.__app.stdout, self.__app.stderr], [], [], delay)
        if ret[0]:
            byte_string = b''
            for fd in ret[0][:-1]:
                byte_string += fd.read() + b'\n\n'
            byte_string += ret[0][-1].read()
        else:
            byte_string = b''

        self.__feedback.set_bytes(byte_string)

        return self.__feedback

    def is_alive(self):
        if self.__app is None:
            return True

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
