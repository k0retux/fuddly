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

from framework.tactics_helpers import *
from framework.scenario import *
from framework.data_model import AbsorbStatus, AbsNoCsts

tactics = Tactics()

def retrieve_X_from_feedback(env, current_step, next_step, feedback, x='padi'):
    if not feedback:
        print('\n\n*** No Feedback!')
        return False
    else:
        print('\n\n*** Feedback retrieved')

        for source, fbks in feedback.items():
            for item in fbks:
                msg_x = env.dm.get_data(x)
                msg_x.set_current_conf('ABS', recursive=True)
                data = item['content']
                if x == 'padi':
                    mac_dst = b'\xff\xff\xff\xff\xff\xff'
                elif x == 'padr':
                    if current_step.node is not None:
                        mac_src = current_step.node['.*/mac_src']
                        env.mac_src = mac_src
                    else:
                        mac_src = env.mac_src
                    if mac_src is not None:
                        mac_dst = mac_src.to_bytes()
                        print('\n*** Destination MAC will be set to: {!r}'.format(mac_dst))
                    else:
                        raise ValueError
                else:
                    raise ValueError
                off = data.find(mac_dst)
                data = data[off:]
                result = msg_x.absorb(data, constraints=AbsNoCsts(size=True, struct=True))
                if result[0] == AbsorbStatus.FullyAbsorbed:
                    try:
                        service_name = msg_x['.*/value/v101'].to_bytes()
                        mac_src = msg_x['.*/mac_src'].to_bytes()
                    except:
                        continue
                    print(' [ {:s} received! ]'.format(x.upper()))
                    next_step.node.freeze()

                    error_msg = '\n*** The node has no path to: {:s}. Thus, ignore it.\n'\
                                '    (probable reason: the node has been fuzzed in a way that makes the' \
                                'path unavailable)'
                    try:
                        next_step.node['.*/mac_dst'] = mac_src
                    except:
                        print(error_msg.format('mac_dst'))
                    try:
                        next_step.node['.*/tag_sn/value/v101'] = service_name
                    except:
                        print(error_msg.format('service_name'))
                    host_uniq = msg_x['.*/value/v103']
                    if host_uniq is not None:
                        host_uniq = host_uniq.to_bytes()
                        env.host_uniq = host_uniq
                    elif hasattr(env, 'host_uniq'):
                        host_uniq = env.host_uniq
                    else:
                        pass

                    if host_uniq is not None:
                        new_tag = env.dm.get_data('tag_host_uniq')
                        new_tag['.*/v103'] = host_uniq
                        try:
                            next_step.node['.*/host_uniq_stub'].set_contents(new_tag)
                        except:
                            print(error_msg.format('host_uniq_stub'))
                    else:
                        print('\n***WARNING: Host-Uniq not provided')
                    next_step.node.unfreeze(recursive=True, reevaluate_constraints=True)
                    return True

        print(' [ {:s} not found! ]'.format(x.upper()))

        return False


def retrieve_padr_from_feedback(env, current_step, next_step, feedback):
    return retrieve_X_from_feedback(env, current_step, next_step, feedback, x='padr')

def retrieve_padi_from_feedback(env, current_step, next_step, feedback):
    return retrieve_X_from_feedback(env, current_step, next_step, feedback, x='padi')


### PADI fuzz scenario ###
step_wait_padi = NoDataStep(fbk_timeout=1)

dp_pado = DataProcess(process=[('tTYPE', UI(init=1), UI(order=True))], seed='pado')
dp_pado.append_new_process([('tSTRUCT', UI(init=1), UI(deep=True))])
step_send_pado = Step(dp_pado)
# step_send_pado = Step('pado')
step_end = Step('padt')

step_wait_padi.connect_to(step_send_pado, cbk_after_fbk=retrieve_padi_from_feedback)
step_send_pado.connect_to(step_end)
step_end.connect_to(step_wait_padi)

sc1 = Scenario('PADO')
sc1.set_anchor(step_wait_padi)

### PADS fuzz scenario ###
step_wait_padi = NoDataStep(fbk_timeout=1)
step_send_valid_pado = Step('pado')

dp_pads = DataProcess(process=[('tTYPE#2', UI(init=1), UI(order=True))], seed='pads')
dp_pads.append_new_process([('tSTRUCT#2', UI(init=1), UI(deep=True))])
step_send_fuzzed_pads = Step(dp_pads)
step_wait_padr = NoDataStep(fbk_timeout=1)

step_wait_padi.connect_to(step_send_valid_pado, cbk_after_fbk=retrieve_padi_from_feedback)
step_send_valid_pado.connect_to(step_send_fuzzed_pads, cbk_after_fbk=retrieve_padr_from_feedback)

step_send_fuzzed_pads.connect_to(step_wait_padr)

step_wait_padr.connect_to(step_send_fuzzed_pads, cbk_after_fbk=retrieve_padr_from_feedback)
step_wait_padr.connect_to(step_send_valid_pado, cbk_after_fbk=retrieve_padi_from_feedback)

sc2 = Scenario('PADS')
sc2.set_anchor(step_wait_padi)

tactics.register_scenarios(sc1, sc2)
