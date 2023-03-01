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

import collections
import copy
import datetime
import fcntl
import select
import socket
import struct
import sys
import threading
import time
import uuid
from _socket import error as socket_error

from framework.data import Data
from framework.node import Node, NodeSemanticsCriteria
from framework.target_helpers import Target, TargetStuck
from framework.knowledge.feedback_collector import FeedbackCollector

from framework.value_types import *
from framework.node_builder import NodeBuilder

eth_hdr_desc = \
    {'name': 'eth_hdr',
     'contents': [
         {'name': 'mac_dst',
          'semantics': 'mac_dst',
          'contents': String(size=6)},
         {'name': 'mac_src',
          'semantics': 'mac_src',
          'contents': String(size=6)},
         {'name': 'proto',
          'contents': UINT16_be(values=[0x0800])},
     ]}

eth_hdr_node = NodeBuilder(add_env=True).create_graph_from_desc(eth_hdr_desc)


class NetworkTarget(Target):
    """
    Generic target class for interacting with a network resource. Can
    be used directly, but some methods may require to be overloaded to
    fit your needs.
    """

    General_Info_ID = 'General Information'

    UNKNOWN_SEMANTIC = "Unknown Semantic"
    CHUNK_SZ = 2048
    _INTERNALS_ID = 'NetworkTarget()'

    _feedback_mode = Target.FBK_WAIT_FULL_TIME
    supported_feedback_mode = [Target.FBK_WAIT_FULL_TIME, Target.FBK_WAIT_UNTIL_RECV]

    def __init__(self, host='localhost', port=12345, socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                 data_semantics=UNKNOWN_SEMANTIC,
                 server_mode=False, listen_on_start=True, target_address=None, wait_for_client=True,
                 hold_connection=False, keep_first_client=True,
                 mac_src=None, mac_dst=None, add_eth_header=False,
                 fbk_timeout=2, fbk_mode=Target.FBK_WAIT_FULL_TIME, sending_delay=1, recover_timeout=0.5):
        """
        Args:
          host (str): IP address of the target to connect to, or
            the IP address on which we will wait for target connecting
            to us (if `server_mode` is True). For raw socket type, it should contain the name of
            the interface.
          port (int): Port for communicating with the target, or
            the port to listen to. For raw socket type, it should contain the protocol ID.
          socket_type (tuple): Tuple composed of the socket address family
            and socket type
          data_semantics (str): String of characters that will be used for
            data routing decision. Useful only when more than one interface
            are defined. In such case, the data semantics will be checked in
            order to find a matching interface to which data will be sent. If
            the data have no semantic, it will be routed to the default first
            declared interface.
          server_mode (bool): If `True`, the interface will be set in server mode,
            which means we will wait for the real target to connect to us for sending
            it data.
          listen_on_start (bool): If `True`, servers will be launched right after the `NetworkTarget`
            starts. Otherwise, they will be launched in a lazy mode, meaning just when something is
            about to be sent through the server mode interface.
          target_address (tuple): Used only if `server_mode` is `True` and socket type
            is `SOCK_DGRAM`. To be used if data has to be sent to a specific address
            (which is not necessarily the client). It is especially
            useful if you need to send data before receiving anything. What should be provided is
            a tuple `(host(str), port(int))` associated to the target.
          wait_for_client (bool): Used only in server mode (`server_mode` is `True`) when the
            `socket type` is `SOCK_DGRAM` and a `target_address` is provided, or when the `socket_type`
            is `SOCK_RAW`. If set to `True`, before sending any data, the `NetworkTarget` will
            wait for the reception of data (from any client); otherwise it will send data as soon
            as provided.
          hold_connection (bool): If `True`, we will maintain the connection while
            sending data to the real target. Otherwise, after each data emission,
            we close the related socket.
          keep_first_client (bool): Used only in server mode (`server_mode` is `True`) with `SOCK_STREAM`
            socket type. If set to `True`, the first client that connects to the server will remain
            the one used for data sending until the target is reloaded. Otherwise, last client
            information are used. This is not supported for `SOCK_DGRAM` where the first client will
            always be the one used for data sending.
          mac_src (bytes): Only in conjunction with raw socket. For each data sent through
            this interface, and if this data contain nodes with the semantic ``'mac_src'``,
            these nodes will be overwritten (through absorption) with this parameter. If nothing
            is provided, the MAC address will be retrieved from the interface specified in 'host'.
            (works accurately for Linux system).
          mac_dst (bytes): Only in conjunction with raw socket. For each data sent through
            this interface, and if this data contain nodes with the semantic ``'mac_dst'``,
            these nodes will be overwritten (through absorption) with this parameter.
          add_eth_header (bool): Add an ethernet header to the data to send. Only possible in
            combination with a SOCK_RAW socket type.
          fbk_timeout (float): maximum time duration for collecting the feedback
          sending_delay (float): maximum time (in seconds) taken to send data
            once the method ``send_(multiple_)data()`` has been called.
          recover_timeout (int): Allowed delay for recovering the target. (the recovering can be triggered
            by the framework if the feedback threads did not terminate before the target health check)
            Impact the behavior of self.recover_target().
        """

        Target.__init__(self)

        if not self._is_valid_socket_type(socket_type):
            raise ValueError("Unrecognized socket type")

        if sys.platform in ['linux']:
            def get_mac_addr(ifname):
                ifname = bytes(ifname, 'latin_1')
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
                except (OSError, IOError):
                    ret = b''
                else:
                    info = bytearray(info)
                    ret = bytes(info[18:24])
                s.close()
                return ret
        else:
            def get_mac_addr(ifname):
                return struct.pack('>Q', uuid.getnode())[2:]

        self.get_mac_addr = get_mac_addr

        self._mac_src_semantic = NodeSemanticsCriteria(mandatory_criteria=['mac_src'])
        self._mac_dst_semantic = NodeSemanticsCriteria(mandatory_criteria=['mac_dst'])
        self._mac_src = {}
        self._mac_dst = {}
        self._add_eth_header = {}

        self._host = {}
        self._port = {}
        self._socket_type = {}
        self.host = host  # main interface host
        self.port = port  # main interface port

        self.server_mode = {}
        self._server_mode_additional_info = {}

        # interfaces semantics
        self.known_semantics = set()
        self._semantics_to_intf = {}

        self._default_fbk_socket_id = 'Default Feedback Socket'
        self._default_fbk_id = {}

        self.hold_connection = {}

        self.register_new_interface(host=host, port=port, socket_type=socket_type, data_semantics=data_semantics,
                                    server_mode=server_mode, target_address=target_address,
                                    wait_for_client=wait_for_client, hold_connection=hold_connection,
                                    keep_first_client=keep_first_client, mac_src=mac_src,
                                    mac_dst=mac_dst, add_eth_header=add_eth_header)
        self.multiple_destination = False

        self._additional_fbk_desc = {}
        self._default_additional_fbk_id = 1

        self._feedback = FeedbackCollector()
        self.feedback_length = None  # if specified, timeout will be ignored
        self._fbk_handling_lock = threading.Lock()
        self.socket_desc_lock = threading.Lock()
        self.sending_sockets = []
        self.stop_event = threading.Event()
        self._server_thread_lock = threading.Lock()
        self._network_send_lock = threading.Lock()
        self._raw_server_private = None
        self._recover_timeout = recover_timeout

        self._listen_on_start = listen_on_start

        self.set_timeout(fbk_timeout=fbk_timeout, sending_delay=sending_delay)
        self.set_feedback_mode(fbk_mode)

    def _is_valid_socket_type(self, socket_type):
        skt_sz = len(socket_type)
        if skt_sz == 3:
            family, sock_type, proto = socket_type
            if sock_type != socket.SOCK_RAW:
                return False
        elif skt_sz == 2:
            family, sock_type = socket_type
            if sock_type not in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
                return False
        return True

    def register_new_interface(self, host, port, socket_type, data_semantics, server_mode=False,
                               target_address = None, wait_for_client=True,
                               hold_connection=False, keep_first_client=True,
                               mac_src=None, mac_dst=None, add_eth_header=False):

        if not self._is_valid_socket_type(socket_type):
            raise ValueError("Unrecognized socket type")

        self.multiple_destination = True
        self._host[data_semantics] = host
        self._port[data_semantics] = port
        self._socket_type[data_semantics] = socket_type
        assert data_semantics not in self.known_semantics
        self.known_semantics.add(data_semantics)
        self._semantics_to_intf[data_semantics] = (host, port, socket_type, server_mode)
        self.server_mode[(host,port)] = server_mode
        self._server_mode_additional_info[(host, port)] = (target_address, wait_for_client, keep_first_client)
        self._default_fbk_id[(host, port)] = self._default_fbk_socket_id + ' - {:s}:{:d}'.format(host, port)
        self.hold_connection[(host, port)] = hold_connection
        if socket_type[1] == socket.SOCK_RAW:
            self._mac_src[(host, port)] = self.get_mac_addr(host) if mac_src is None else mac_src
            self._mac_dst[(host, port)] = b'\xff\xff\xff\xff\xff\xff' if mac_dst is None else mac_dst
        else:
            self._mac_src[(host, port)] = None
            self._mac_dst[(host, port)] = None

        if add_eth_header:
            assert self._mac_src[(host, port)] is not None and self._mac_dst[(host, port)] is not None
        self._add_eth_header[(host, port)] = add_eth_header

    def set_timeout(self, fbk_timeout, sending_delay):
        '''
        Set the time duration for feedback gathering and the sending delay above which
        we give up:
        - sending data to the target (client mode)
        - waiting for client connections before sending data to them (server mode)

        Args:
            fbk_timeout: time duration for feedback gathering (in seconds)
            sending_delay: sending delay (in seconds)
        '''
        self.set_sending_delay(sending_delay)
        self.set_feedback_timeout(fbk_timeout)

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
                                          fbk_id=None, fbk_length=None, server_mode=False,
                                          wait_time=None):
        '''Allows to register additional socket to get feedback
        from. Connection is attempted be when target starts, that is
        when :meth:`NetworkTarget.start()` is called.
        '''
        self._default_additional_fbk_id += 1
        if fbk_id is None:
            fbk_id = 'Default Additional Feedback ID %d' % self._default_additional_fbk_id
        else:
            assert(not str(fbk_id).startswith('Default Additional Feedback ID'))
        self._additional_fbk_desc[fbk_id] = (host, port, socket_type, fbk_id, fbk_length,
                                             server_mode, wait_time)
        self.hold_connection[(host, port)] = True
        self._server_mode_additional_info[(host, port)] = (None, None, None)

    def _custom_data_handling_before_emission(self, data_list):
        '''To be overloaded if you want to perform some operation before
        sending `data_list` to the target.

        Args:
          data_list (list): list of Data objects that will be sent to the target.

        Returns:
          list: the data list to send
        '''
        return data_list

    def _feedback_handling(self, fbk, ref):
        '''To be overloaded if feedback from the target need to be filtered
        before being logged and/or collected in some way and/or for
        any other reasons.

        Args:
          fbk (bytes): feedback received by the target through a socket referenced by `ref`.
          ref (string): user-defined reference of the socket used to retrieve the feedback.

        Returns:
          tuple: a tuple `(new_fbk, status)` where `new_fbk` is the feedback
            you want to log and `status` is a status that enables you to notify a problem to the
            framework (should be positive if everything is fine, otherwise should be negative).
        '''
        return fbk, 0

    def cleanup(self):
        return True

    def listen_to(self, host, port, ref_id,
                  socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                  chk_size=CHUNK_SZ, wait_time=None, hold_connection=True):
        '''
        Used for collecting feedback from the target while it is already started.
        '''
        self.hold_connection[(host, port)] = hold_connection
        self._server_mode_additional_info[(host, port)] = (None, False, False)
        self._raw_listen_to(host, port, ref_id, socket_type, chk_size, wait_time=wait_time)
        self._dynamic_interfaces[(host, port)] = (-1, ref_id)

    def _raw_listen_to(self, host, port, ref_id,
                       socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                       chk_size=CHUNK_SZ, wait_time=None):

        if wait_time is None:
            wait_time = self.feedback_timeout

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
            for host, port, socket_type, fbk_id, fbk_length, server_mode, wait_time in self._additional_fbk_desc.values():
                if server_mode:
                    self._raw_listen_to(host, port, fbk_id, socket_type, chk_size=fbk_length,
                                        wait_time=wait_time)
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
        self.stop_event.clear()

        # Used by _raw_listen_to()
        self._server_sock2hp = {}
        self._server_thread_share = {}
        self._last_client_sock2hp = {}  # only for hold_connection
        self._last_client_hp2sock = {}  # only for hold_connection
        self._raw_server_private = {}  # useful only for hold_connection

        # Used by _raw_connect_to()
        self._hclient_sock2hp = {}  # only for hold_connection
        self._hclient_hp2sock = {}  # only for hold_connection

        self._additional_fbk_sockets = []
        self._additional_fbk_ids = {}
        self._additional_fbk_lengths = {}
        self._dynamic_interfaces = {}
        self._feedback_thread_qty = 0
        self._fbk_collector_finished_cpt = 0
        self._fbk_collector_to_launch_cpt = 0
        self._first_send_data_call = True
        self._last_ack_date = None  # Note that `self._last_ack_date`
                                    # could be updated many times if
                                    # self.send_multiple_data() is
                                    # used.
        self._flush_feedback_delay = None

        self._connect_to_additional_feedback_sockets()

        if self._listen_on_start:
            # In the case there are server mode interfaces,
            # we initiate the server threads by the following method and could thus catch
            # information from any connected clients trying to reach us. This could then
            # be leveraged when we sent data.
            self.collect_unsolicited_feedback()

        for k, mac_src in self._mac_src.items():
            if mac_src is not None:
                if mac_src:
                    mac_src = mac_src.hex()
                    self.record_info('*** Detected HW address for {!s}: {!s} ***'
                                     .format(k[0], mac_src))
                else:
                    self.record_info('*** WARNING: HW Address not detected for {!s}! ***'
                                     .format(k[0]))

        return self.initialize()

    def stop(self):
        self.stop_event.set()
        for ev, _ in self._raw_server_private.values():
            ev.set()
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

    def recover_target(self):
        t0 = datetime.datetime.now()
        while not self.is_feedback_received():
            time.sleep(0.0001)
            now = datetime.datetime.now()
            if (now - t0).total_seconds() > self._recover_timeout:
                return False
        return True

    def send_data(self, data, from_fmk=False):
        self.send_multiple_data(data_list=[data], from_fmk=from_fmk)

    def send_multiple_data(self, data_list, from_fmk=False):
        data_list = self._before_sending_data(data_list, from_fmk)
        sockets = []
        data_refs = {}
        connected_client_event = {}
        client_event = None

        sending_list = []
        if data_list is None:
            fbk_timeout = self.feedback_timeout if self._flush_feedback_delay is None else self._flush_feedback_delay
            # If data_list is None, it means that we want to collect feedback from every interface
            # without sending data.
            for key in self.known_semantics:
                sending_list.append((None,) + self._semantics_to_intf[key])
        else:
            fbk_timeout = self.feedback_timeout
            data_to_send = {intf: None for intf in self._semantics_to_intf.values()}
            for data in data_list:
                intf = self._get_net_info_from(data)
                data_to_send[intf] = data.to_bytes()
            for intf, data in data_to_send.items():
                sending_list.append((data,)+intf)

        for data, host, port, socket_type, server_mode in sending_list:
            if server_mode:
                # if from_fmk:
                #     self._fbk_collector_to_launch_cpt += 1
                connected_client_event[(host, port)] = threading.Event()
                self._listen_to_target(host, port, socket_type,
                                       self._handle_target_connection,
                                       args=(data, host, port,
                                             connected_client_event[(host, port)], from_fmk))
            else:
                s = self._connect_to_target(host, port, socket_type)
                if s is None:
                    err_msg = '>>> WARNING: unable to send data to {:s}:{:d} <<<'.format(host, port)
                    self._feedback.add_fbk_from(self._INTERNALS_ID, err_msg, status=-2)
                else:
                    if s not in sockets:
                        sockets.append(s)
                        data_refs[s] = (data, host, port, None)

        if data_refs:
            if from_fmk:
                self._fbk_collector_to_launch_cpt += 1
            with self._network_send_lock:
                self._send_data(sockets, data_refs, fbk_timeout, from_fmk)
        else:
            # this case exist when data are only sent through 'server_mode'-configured interfaces
            # (because self._send_data() is called through self._handle_target_connection())
            # or a connection error has occurred.
            if from_fmk:
                self._fbk_collector_to_launch_cpt += 1

        if data_list is None:
            return

        if connected_client_event:
            t0 = datetime.datetime.now()
            duration = 0
            client_event = connected_client_event
            client_event_copy = copy.copy(connected_client_event)
            while duration < self.sending_delay:
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
                    err_msg = ">>> WARNING: unable to send data because the target did not connect" \
                              " to us [{:s}:{:d}] <<<".format(host, port)
                    self._feedback.add_fbk_from(self._INTERNALS_ID, err_msg, status=-1)
                # self._fbk_collector_to_launch_cpt -= 1

        # else:
        #     self._fbk_collector_to_launch_cpt -= 1

    def _get_data_semantic_key(self, data):
        if not isinstance(data.content, Node):
            if data.is_empty():
                print('\n*** ERROR: Empty data has been received!')
            return self.UNKNOWN_SEMANTIC

        semantics = data.content.get_semantics()
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
            try:
                fd = self._hclient_hp2sock[(host, port)].fileno()
                if fd == -1:
                    # if the socket has been closed, -1 is received by python3
                    raise OSError
            except Exception:
                print('\n*** WARNING: Current socket was closed unexpectedly! --> create new one.')
                # we remove the bad references then go on with the rest of the function
                with self.socket_desc_lock:
                    del self._hclient_sock2hp[self._hclient_hp2sock[(host, port)]]
                    del self._hclient_hp2sock[(host, port)]
            else:
                return self._hclient_hp2sock[(host, port)]

        skt_sz = len(socket_type)
        if skt_sz == 2:
            family, sock_type = socket_type
            proto = 0
        else:
            family, sock_type, proto = socket_type

        s = socket.socket(*socket_type)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        s.settimeout(self.sending_delay)

        if sock_type == socket.SOCK_RAW:
            assert port == socket.ntohs(proto)
            try:
                s.bind((host, port))
            except socket.error as serr:
                print('\n*** ERROR(while binding socket -- host={!s} port={:d}): {:s}'.format(host, port, str(serr)))
                return False
        else:
            try:
                s.connect((host, port))
            except socket_error as serr:
                # if serr.errno != errno.ECONNREFUSED:
                print('\n*** ERROR(while connecting): ' + str(serr))
                return None

            s.setblocking(0)

        if self.hold_connection[(host, port)]:
            self._hclient_sock2hp[s] = (host, port)
            self._hclient_hp2sock[(host, port)] = s

        return s


    def _listen_to_target(self, host, port, socket_type, func, args=None):

        def start_raw_server(serversocket, sending_event, notif_host_event):
            server_thread = threading.Thread(None, self._raw_server_main, name='SRV-' + '',
                                             args=(serversocket, host, port, sock_type, func,
                                                   sending_event, notif_host_event))
            server_thread.start()

        skt_sz = len(socket_type)
        if skt_sz == 2:
            family, sock_type = socket_type
            proto = 0
        else:
            family, sock_type, proto = socket_type

        if (host, port) in self._server_sock2hp.values():
            # After data has been sent to the target that first
            # connect to us, new data is sent through the same socket
            # if hold_connection is set for this interface. And new
            # connection will always receive the most recent data to
            # send.
            if sock_type == socket.SOCK_DGRAM or sock_type == socket.SOCK_RAW:
                with self._server_thread_lock:
                    self._server_thread_share[(host, port)] = args
                if self.hold_connection[(host, port)] and (host, port) in self._last_client_hp2sock:
                    sending_event, notif_host_event = self._raw_server_private[(host, port)]
                    sending_event.set()
                    # serversocket, _ = self._last_client_hp2sock[(host, port)]
                    # start_raw_server(serversocket)
                    notif_host_event.wait(5)
                    notif_host_event.clear()
            else:
                with self._server_thread_lock:
                    self._server_thread_share[(host, port)] = args
                    if self.hold_connection[(host, port)] and (host, port) in self._last_client_hp2sock:
                        csocket, addr = self._last_client_hp2sock[(host, port)]
                    else:
                        csocket = None
                if csocket:
                    func(csocket, addr, args)
            return True

        serversocket = socket.socket(*socket_type)
        if sock_type != socket.SOCK_RAW:
            serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:
            assert port == socket.ntohs(proto)

        try:
            serversocket.bind((host, port))
        except socket.error as serr:
            print('\n*** ERROR(while binding socket -- host={!s} port={:d}): {:s}'.format(host, port, str(serr)))
            return False

        serversocket.settimeout(self.sending_delay)

        self._server_sock2hp[serversocket] = (host, port)
        with self._server_thread_lock:
            self._server_thread_share[(host, port)] = args

        if sock_type == socket.SOCK_STREAM:
            serversocket.listen(5)
            server_thread = threading.Thread(None, self._server_main, name='SRV-' + '',
                                             args=(serversocket, host, port, func))
            server_thread.start()

        elif sock_type == socket.SOCK_DGRAM or sock_type == socket.SOCK_RAW:
            sending_event = threading.Event()
            notif_host_event = threading.Event()
            self._raw_server_private[(host, port)] = (sending_event, notif_host_event)
            self._last_client_hp2sock[(host, port)] = (serversocket, None)
            self._last_client_sock2hp[serversocket] = (host, port)
            start_raw_server(serversocket, sending_event, notif_host_event)
            sending_event.set()
        else:
            raise ValueError("Unrecognized socket type")

    def _cleanup_state(self):
        self._fbk_collector_to_launch_cpt -= 1

    # For SOCK_STREAM
    def _server_main(self, serversocket, host, port, func):
        _first_client = {}
        while not self.stop_event.is_set():
            _, _, keep_first_client = self._server_mode_additional_info[(host, port)]
            try:
                fc_addr = _first_client.get((host,port), None)
                clientsocket, address = serversocket.accept()
                if keep_first_client and fc_addr is not None:
                    continue
                elif keep_first_client:
                    _first_client[(host, port)] = (clientsocket, address)
                else:
                    pass
                msg = "Connection from {!s}({!s}). Use this information to send data to " \
                      "the interface '{!s}:{:d}'.".format(address, clientsocket, host, port)
                self._feedback_collect(msg, self.General_Info_ID, error=0)

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

    # For SOCK_RAW and SOCK_DGRAM
    def _raw_server_main(self, serversocket, host, port, sock_type, func,
                         sending_event, notif_host_event):

        _first_client = {}
        while True:
            sending_event.wait()
            sending_event.clear()
            if self.stop_event.is_set():
                notif_host_event.set()
                break

            with self._server_thread_lock:
                args = self._server_thread_share[(host, port)]

            notif_host_event.set()

            target_address, wait_for_client, _ = self._server_mode_additional_info[(host, port)]
            if func == self._handle_connection_to_fbk_server:
                # args = fbk_id, fbk_length, connected_client_event
                assert args[0] in self._additional_fbk_desc
                wait_before_first_sending = False
            elif func == self._handle_target_connection:
                # args = data, host, port, connected_client_event, from_fmk
                if args[0] is None:
                    # In the case 'data' is None there is no data to send,
                    # thus we are requested to only collect feedback
                    wait_before_first_sending = False
                elif target_address is not None:
                    wait_before_first_sending = wait_for_client
                elif sock_type == socket.SOCK_RAW:
                    # in this case target_address is not provided, but it is OK if it is a SOCK_RAW
                    wait_before_first_sending = wait_for_client
                else:
                    wait_before_first_sending = True
            else:
                raise ValueError

            retry = 0
            while retry < 10:
                saved_addr = _first_client.get((host, port), None)
                try:
                    if saved_addr is not None:
                        data, address = None, saved_addr
                    elif wait_before_first_sending:
                        data, address = serversocket.recvfrom(self.CHUNK_SZ)
                        _first_client[(host, port)] = address
                        msg = "Received data from {!s}. Use this information to send data to " \
                              "the interface '{!s}:{:d}'.".format(address, host, port)
                        self._feedback_collect(msg, self.General_Info_ID, error=0)
                    else:
                        data, address = None, None
                except socket.timeout:
                    break
                except OSError as e:
                    if e.errno == 9: # [Errno 9] Bad file descriptor
                        break
                    elif e.errno == 11: # [Errno 11] Resource temporarily unavailable
                        retry += 1
                        time.sleep(0.5)
                        continue
                    else:
                        raise
                else:
                    address = address if target_address is None else target_address
                    serversocket.settimeout(self.feedback_timeout)
                    func(serversocket, address, args, pre_fbk=data)
                    break

    def _handle_connection_to_fbk_server(self, clientsocket, address, args, pre_fbk=None):
        fbk_id, fbk_length, connected_client_event = args
        connected_client_event.set()
        with self.socket_desc_lock:
            self._additional_fbk_sockets.append(clientsocket)
            self._additional_fbk_ids[clientsocket] = fbk_id
            self._additional_fbk_lengths[clientsocket] = fbk_length

    def _handle_target_connection(self, clientsocket, address, args, pre_fbk=None):
        # can be called  simultaneously by two different threads _raw_server_main() and _server_main()
        # in the context of .send_multiple_data() with various interfaces.
        with self._network_send_lock:
            data, host, port, connected_client_event, from_fmk = args
            if self.hold_connection[(host, port)]:
                with self._server_thread_lock:
                    self._last_client_hp2sock[(host, port)] = (clientsocket, address)
                    self._last_client_sock2hp[clientsocket] = (host, port)
            # if from_fmk:
            #     self._fbk_collector_to_launch_cpt += 1
            connected_client_event.set()
            self._send_data([clientsocket], {clientsocket:(data, host, port, address)},
                            fbk_timeout=self.feedback_timeout, from_fmk=from_fmk,
                            pre_fbk={clientsocket: pre_fbk})


    def _collect_feedback_from(self, thread_id, fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                               fbk_timeout, flush_received_fbk, pre_fbk):

        def _check_and_handle_obsolete_socket(skt, error=None, error_list=None):
            # print('\n*** NOTE: Remove obsolete socket {!r}'.format(socket))
            try:
                epobj.unregister(skt)
            except ValueError as e:
                # in python3, file descriptor == -1 witnessed (!?)
                print('\n*** ERROR(check obsolete socket): ' + str(e))
            except socket.error as serr:
                # in python2, bad file descriptor (errno 9) witnessed
                print('\n*** ERROR(check obsolete socket): ' + str(serr))

            self._server_thread_lock.acquire()
            if skt in self._last_client_sock2hp.keys():
                if error is not None:
                    error_list.append((fbk_ids[skt], error))
                host, port = self._last_client_sock2hp[skt]
                del self._last_client_sock2hp[skt]
                del self._last_client_hp2sock[(host, port)]
                self._server_thread_lock.release()
            else:
                self._server_thread_lock.release()
                with self.socket_desc_lock:
                    if skt in self._hclient_sock2hp.keys():
                        if error is not None:
                            error_list.append((fbk_ids[skt], error))
                        host, port = self._hclient_sock2hp[skt]
                        del self._hclient_sock2hp[skt]
                        del self._hclient_hp2sock[(host, port)]
                    if skt in self._additional_fbk_sockets:
                        if error is not None:
                            error_list.append((self._additional_fbk_ids[skt], error))
                        self._additional_fbk_sockets.remove(skt)
                        del self._additional_fbk_ids[skt]
                        del self._additional_fbk_lengths[skt]

        # print('\n*** DBG: start - collect_thread {:d}'.format(thread_id))

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
            if pre_fbk is not None and fd in pre_fbk and pre_fbk[fd] is not None:
                chunks[fd].append(pre_fbk[fd])

        socket_errors = []
        has_read = False

        while dont_stop:
            ready_to_read = []
            for fd, ev in epobj.poll(timeout=0.001):
                skt = fileno2fd[fd]
                if ev != select.EPOLLIN:
                    _check_and_handle_obsolete_socket(skt, error=ev, error_list=socket_errors)
                    if skt in fbk_sockets:
                        fbk_sockets.remove(skt)
                    continue
                ready_to_read.append(skt)

            now = datetime.datetime.now()
            duration = (now - t0).total_seconds()

            if flush_received_fbk:
                if not ready_to_read or duration > fbk_timeout:
                    break

            if ready_to_read:
                if first_pass:
                    first_pass = False
                    self._register_last_ack_date(now)
                for s in ready_to_read:
                    if fbk_lengths[s] is None:
                        sz = NetworkTarget.CHUNK_SZ
                    else:
                        sz = min(fbk_lengths[s] - bytes_recd[s], NetworkTarget.CHUNK_SZ)

                    retry = 0
                    socket_timed_out = False
                    while retry < 10:
                        try:
                            chunk = s.recv(sz)
                        except socket.timeout:
                            chunk = b''
                            print('\n*** Socket timeout')
                            socket_timed_out = True  # for UDP we keep the socket
                            break
                        except socket.error as serr:
                            chunk = b''
                            print('\n*** ERROR[{!s}] (while receiving): {:s}'.format(
                                serr.errno, str(serr)))
                            if serr.errno == socket.errno.EAGAIN:
                                retry += 1
                                time.sleep(2)
                                continue
                            else:
                                break
                        else:
                            break

                    if chunk == b'':
                        print('\n*** NOTE: Nothing more to receive from: {!r}'.format(fbk_ids[s]))
                        fbk_sockets.remove(s)
                        _check_and_handle_obsolete_socket(s)
                        if not socket_timed_out:
                            s.close()
                        continue
                    else:
                        bytes_recd[s] = bytes_recd[s] + len(chunk)
                        chunks[s].append(chunk)

                has_read = True

            if flush_received_fbk:
                dont_stop = True

            elif fbk_sockets:
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

                if duration > fbk_timeout or \
                        (has_read and not self.fbk_wait_full_time_slot_mode):
                    dont_stop = False

            else:
                dont_stop = False

        for s, chks in chunks.items():
            fbk = b'\n'.join(chks)
            with self._fbk_handling_lock:
                if fbk != b'':
                    fbkid = fbk_ids[s]
                    fbk, err = self._feedback_handling(fbk, fbkid)
                    self._feedback_collect(fbk, fbkid, error=err)
                if (self._additional_fbk_sockets is None or s not in self._additional_fbk_sockets) and \
                        (self._hclient_sock2hp is None or s not in self._hclient_sock2hp.keys()) and \
                        (self._last_client_sock2hp is None or s not in self._last_client_sock2hp.keys()):
                    s.close()

        with self._fbk_handling_lock:
            for fbkid, ev in socket_errors:
                self._feedback_collect(">>> ERROR[{:d}]: unable to interact with '{:s}' "
                                       "<<<".format(ev,fbkid), fbkid, error=-ev)
            self._feedback_complete()

        # print('\n*** DBG: stop - collect_thread {:d}'.format(thread_id))

        return

    def _send_data(self, sockets, data_refs, fbk_timeout, from_fmk, pre_fbk=None):
        # Should be called with the lock self_network_send_lock.
        # Especially needed in the context of self.send_multiple_data() as different threads can reach
        # this code simultaneously (_raw_server_main, _server_main and the main framework thread).

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

        if data_refs[sockets[0]][0] is None:
            # We check the data to send. If it is None, we only collect feedback from the sockets.
            # This is used by self.collect_unsolicited_feedback()
            if fbk_sockets is None:
                assert fbk_ids is None
                assert fbk_lengths is None
                fbk_sockets = []
                fbk_ids = {}
                fbk_lengths = {}

            for s in sockets:
                data, host, port, address = data_refs[s]
                epobj.register(s, select.EPOLLIN)
                fileno2fd[s.fileno()] = s
                fbk_sockets.append(s)
                fbk_ids[s] = self._default_fbk_id[(host, port)]
                fbk_lengths[s] = self.feedback_length

            assert from_fmk
            self._start_fbk_collector(fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                                      pre_fbk=pre_fbk, timeout=fbk_timeout, flush_received_fbk=True)

            return

        ready_to_read, ready_to_write, in_error = select.select([], sockets, [], self.sending_delay)
        if ready_to_write:

            for s in ready_to_write:
                data, host, port, address = data_refs[s]
                epobj.register(s, select.EPOLLIN)
                fileno2fd[s.fileno()] = s

                raw_data = data.to_bytes() if isinstance(data, Data) else data
                totalsent = 0
                send_retry = 0
                while totalsent < len(raw_data) and send_retry < 10:
                    try:
                        if address is None:
                            sent = s.send(raw_data[totalsent:])
                        else:
                            # with SOCK_RAW, address is ignored
                            sent = s.sendto(raw_data[totalsent:], address)
                    except socket.error as serr:
                        send_retry += 1
                        print('\n*** ERROR(while sending): ' + str(serr))
                        if serr.errno == socket.errno.EWOULDBLOCK:
                            time.sleep(0.2)
                            continue
                        elif serr.errno == socket.errno.EMSGSIZE:  # for SOCK_RAW
                            self._feedback.add_fbk_from(self._INTERNALS_ID,
                                                        'Message was not sent because it was too long!',
                                                        status=-1)
                            break
                        else:
                            if from_fmk:
                                self._fbk_collector_to_launch_cpt -= 1
                            raise TargetStuck("system not ready for sending data! {!r}".format(serr))
                    else:
                        if sent == 0:
                            s.close()
                            if from_fmk:
                                self._fbk_collector_to_launch_cpt -= 1
                            raise TargetStuck("socket connection broken")
                        totalsent = totalsent + sent

                if fbk_sockets is None:
                    assert fbk_ids is None
                    assert fbk_lengths is None
                    fbk_sockets = []
                    fbk_ids = {}
                    fbk_lengths = {}
                # else:
                #     assert(self._default_fbk_id[(host, port)] not in fbk_ids.values())

                fbk_sockets.append(s)
                fbk_ids[s] = self._default_fbk_id[(host, port)]
                fbk_lengths[s] = self.feedback_length

            if from_fmk:
                self._start_fbk_collector(fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                                          pre_fbk=pre_fbk, timeout=fbk_timeout)

        else:
            raise TargetStuck("system not ready for sending data!")


    def _start_fbk_collector(self, fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                             pre_fbk=None, timeout=None, flush_received_fbk=False):

        self._feedback_thread_qty += 1
        feedback_thread = threading.Thread(None, self._collect_feedback_from,
                                           name='FBK-#' + repr(self._feedback_thread_qty),
                                           args=(self._feedback_thread_qty,
                                                 fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                                                 timeout, flush_received_fbk,
                                                 pre_fbk))
        feedback_thread.start()

    def _feedback_collect(self, fbk, ref, error=0):
        if error < 0:
            self._feedback.set_error_code(error)
        self._feedback.add_fbk_from(ref, fbk, status=error)

    def _feedback_complete(self):
        self._fbk_collector_finished_cpt += 1
        # print('\n***DBG _fc: {} {}'.format(self._fbk_collector_to_launch_cpt, self._fbk_collector_finished_cpt))

    def _before_sending_data(self, data_list, from_fmk):
        if from_fmk:
            self._last_ack_date = None
            self._first_send_data_call = True  # related to additional feedback
            with self._fbk_handling_lock:
                # print('\n***DBG _bsd: {} {}'.format(self._fbk_collector_to_launch_cpt, self._fbk_collector_finished_cpt))
                assert self._fbk_collector_to_launch_cpt == self._fbk_collector_finished_cpt
                self._fbk_collector_finished_cpt = 0
                self._fbk_collector_to_launch_cpt = 0
        else:
            self._first_send_data_call = False  # we ignore all additional feedback

        if data_list is None:
            return

        if isinstance(data_list, Data):
            data_list = [data_list]

        new_data_list = []
        for data in data_list:
            if isinstance(data.content, Node):
                data.content.freeze()
            host, port, socket_type, _ = self._get_net_info_from(data)
            if socket_type[1] == socket.SOCK_RAW:
                mac_src = self._mac_src[(host,port)]
                mac_dst = self._mac_dst[(host,port)]

                if self._add_eth_header[(host,port)]:
                    eth_hdr = eth_hdr_node.get_clone()
                    eth_hdr[self._mac_src_semantic] = mac_src
                    eth_hdr[self._mac_dst_semantic] = mac_dst

                    if isinstance(data.content, Node):
                        payload = data.content
                    else:
                        payload = Node('payload', values=[data.to_bytes()])

                    n = Node(name='eth_packet', subnodes=[eth_hdr, payload])
                    data = Data(n)

                elif isinstance(data.content, Node):
                    if mac_src is not None:
                        try:
                            data.content[self._mac_src_semantic] = mac_src
                        except ValueError:
                            self._logger.log_comment('WARNING: Unable to set the MAC SOURCE on the packet')
                    if mac_dst is not None:
                        try:
                            data.content[self._mac_dst_semantic] = mac_dst
                        except ValueError:
                            self._logger.log_comment('WARNING: Unable to set the MAC DESTINATION on the packet')
                else:
                    pass

            new_data_list.append(data)

        return self._custom_data_handling_before_emission(new_data_list)

    def collect_unsolicited_feedback(self, timeout=0):
        self._flush_feedback_delay = timeout
        self.send_multiple_data_sync(None, from_fmk=True)
        return True

    def get_feedback(self):
        return self._feedback

    def is_feedback_received(self):
        # print('\n*** DBG network is fbk received: {} {}'.format(self._fbk_collector_to_launch_cpt, self._fbk_collector_finished_cpt))
        return self._fbk_collector_to_launch_cpt == self._fbk_collector_finished_cpt

    def is_target_ready_for_new_data(self):
        return self.is_feedback_received()

    def _register_last_ack_date(self, ack_date):
        self._last_ack_date = ack_date

    def get_last_target_ack_date(self):
        return self._last_ack_date

    def _get_socket_type(self, host, port):
        for key, h in self._host.items():
            if h == host and self._port[key] == port:
                st = self._socket_type[key]
                if st[:2] == (socket.AF_INET, socket.SOCK_STREAM):
                    return 'STREAM'
                elif st[:2] == (socket.AF_INET, socket.SOCK_DGRAM):
                    return 'DGRAM'
                elif st[:2] == (socket.AF_PACKET, socket.SOCK_RAW):
                    return 'RAW'
                else:
                    return repr(st)
        else:
            return None

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
            socket_type = self._get_socket_type(host, port)
            desc += '{:s}:{:d}#{!s} (serv:{!r},hold:{!r}), '.format(
                host, port, socket_type, server_mode, hold_connection)

        return desc[:-2]