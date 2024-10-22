import socket

from fuddly.framework.targets.debug import TestTarget
from fuddly.framework.target_helpers import EmptyTarget
from fuddly.framework.targets.network import NetworkTarget
from fuddly.libs.external_modules import serial_module

from .monitoring import (P1, P2, health_check, probe_pid, probe_mem)

### TARGETS DEFINITION ###

class TutoNetTarget(NetworkTarget):

    def _custom_data_handling_before_emission(self, data_list):
        self.listen_to('localhost', 64001, 'Dynamic server interface')
        # self.connect_to('localhost', 64002, 'Dynamic client interface')
        # self._logger.collect_feedback('TEST', status_code=random.randint(-2,2))
        return data_list

    def _feedback_handling(self, fbk, ref):
        # self.remove_all_dynamic_interfaces()
        ok_status = 0
        return fbk, ok_status

tuto_tg = TutoNetTarget(host='localhost', port=12345, data_semantics='TG1', hold_connection=True)
tuto_tg.register_new_interface('localhost', 54321, (socket.AF_INET, socket.SOCK_STREAM), 'TG2',
                               server_mode=True, hold_connection=True)
tuto_tg.add_additional_feedback_interface('localhost', 7777, (socket.AF_INET, socket.SOCK_STREAM),
                                          fbk_id='My Feedback Source', server_mode=True)
tuto_tg.set_timeout(fbk_timeout=5, sending_delay=2)

net_tg = NetworkTarget(host='localhost', port=12345,
                       socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                       hold_connection=True, server_mode=False, keep_first_client=False)

udpnet_tg = NetworkTarget(host='localhost', port=12345,
                          socket_type=(socket.AF_INET, socket.SOCK_DGRAM),
                          hold_connection=True, server_mode=False)

udpnetsrv_tg = NetworkTarget(host='localhost', port=12345,
                          socket_type=(socket.AF_INET, socket.SOCK_DGRAM),
                          hold_connection=True, server_mode=True)

ETH_P_ALL = 3
rawnetsrv_tg = NetworkTarget(host='eth0', port=ETH_P_ALL,
                             socket_type=(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)),
                             hold_connection=True, server_mode=False)
rawnetsrv_tg.register_new_interface(host='eth2', port=ETH_P_ALL,
                                    socket_type=(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)),
                                    data_semantics='TG2')


### TARGETS ALLOCATION ###

targets = [(EmptyTarget(), (P1, 2), (P2, 1.4), health_check),
           tuto_tg, net_tg, udpnet_tg, udpnetsrv_tg, rawnetsrv_tg,
           TestTarget(fbk_samples=['CRC error', 'OK']),
           TestTarget()]

if serial_module:
    targets.append((TestTarget(), probe_pid, (probe_mem, 0.2)))

