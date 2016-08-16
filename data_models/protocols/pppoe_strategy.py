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
from framework.global_resources import *

tactics = Tactics()

def retrieve_X_from_feedback(env, current_step, next_step, feedback, x='padi', update=False):
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

                if data is None:
                    return False
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

                    t_fix_pppoe_msg_fields.mac_src = mac_src
                    t_fix_pppoe_msg_fields.service_name = service_name

                    host_uniq = msg_x['.*/value/v103']
                    if host_uniq is not None:
                        host_uniq = host_uniq.to_bytes()
                        env.host_uniq = host_uniq
                        t_fix_pppoe_msg_fields.host_uniq = host_uniq

                    if update:  # we update the seed of the data process
                        next_step.node.freeze()
                        try:
                            next_step.node['.*/tag_sn/value/v101'] = service_name
                            next_step.node['.*/tag_sn$'].unfreeze(recursive=True, reevaluate_constraints=True)
                            next_step.node.freeze()
                        except:
                            pass

                    return True

        print(' [ {:s} not found! ]'.format(x.upper()))

        return False


def retrieve_padr_from_feedback(env, current_step, next_step, feedback):
    return retrieve_X_from_feedback(env, current_step, next_step, feedback, x='padr')

def retrieve_padi_from_feedback(env, current_step, next_step, feedback):
    return retrieve_X_from_feedback(env, current_step, next_step, feedback, x='padi')

def retrieve_padr_from_feedback_and_update(env, current_step, next_step, feedback):
    return retrieve_X_from_feedback(env, current_step, next_step, feedback, x='padr', update=True)

def retrieve_padi_from_feedback_and_update(env, current_step, next_step, feedback):
    return retrieve_X_from_feedback(env, current_step, next_step, feedback, x='padi', update=True)


@disruptor(tactics, dtype="FIX_FIELDS", weight=1,
           args={'reevaluate_csts': ('reevaluate constraints on the whole message to preserve consistency',
                                     False, bool)})
class t_fix_pppoe_msg_fields(Disruptor):
    mac_src = None
    service_name = None
    host_uniq = None

    def disrupt_data(self, dm, target, prev_data):
        n = prev_data.node
        error_msg = '\n*** The node has no path to: {:s}. Thus, ignore it.\n'\
                    '    (probable reason: the node has been fuzzed in a way that makes the' \
                    'path unavailable)'
        if self.mac_src:
            try:
                n['.*/mac_dst'] = self.mac_src
                prev_data.add_info("update 'mac_src'")
                if not self.reevaluate_csts:
                    n['.*/mac_dst'].unfreeze(dont_change_state=True)
            except:
                print(error_msg.format('mac_dst'))
        else:
            print("\n*** 'mac_src' not found in the environment! ***")

        if self.reevaluate_csts:
            if self.service_name:
                try:
                    n['.*/tag_sn/value/v101'] = self.service_name
                    prev_data.add_info("update 'service_name'")
                except:
                    print(error_msg.format('service_name'))
            else:
                print("\n*** 'service_name' not found in the environment! ***")

        if self.host_uniq:
            new_tag = dm.get_data('tag_host_uniq')
            new_tag['.*/v103'] = self.host_uniq
            new_tag.unfreeze(recursive=True, reevaluate_constraints=True)
            new_tag.freeze()
            try:
                n['.*/host_uniq_stub'].set_contents(new_tag)
                prev_data.add_info("update 'host_uniq'")
            except:
                print(error_msg.format('host_uniq_stub'))
        else:
            print("\n*** 'host_uniq_stub' not found in the environment! ***")

        if self.reevaluate_csts:
            n.unfreeze(recursive=True, reevaluate_constraints=True)

        n.freeze()
        # n.show()

        return prev_data

### PADI fuzz scenario ###
step_wait_padi = NoDataStep(fbk_timeout=1)

dp_pado = DataProcess(process=[('tTYPE', UI(init=1), UI(order=True, fuzz_mag=0.7)), 'FIX_FIELDS'], seed='pado')
dp_pado.append_new_process([('tSTRUCT', UI(init=1), UI(deep=True)), 'FIX_FIELDS'])
step_send_pado = Step(dp_pado)
# step_send_pado = Step('pado')
step_end = Step('padt')

step_wait_padi.connect_to(step_send_pado, cbk_after_fbk=retrieve_padi_from_feedback_and_update)
step_send_pado.connect_to(step_end)
step_end.connect_to(step_wait_padi)

sc1 = Scenario('PADO')
sc1.set_anchor(step_wait_padi)

### PADS fuzz scenario ###
step_wait_padi = NoDataStep(fbk_timeout=1)
step_send_valid_pado = Step(DataProcess(process=[('FIX_FIELDS#2', None, UI(reevaluate_csts=True))],
                                        seed='pado'))
step_send_padt = Step(DataProcess(process=[('FIX_FIELDS#3', None, UI(reevaluate_csts=True))],
                                  seed='padt'), fbk_timeout=0.1)

dp_pads = DataProcess(process=[('tTYPE#2', UI(init=1), UI(order=True, fuzz_mag=0.7)), 'FIX_FIELDS'], seed='pads')
dp_pads.append_new_process([('tSTRUCT#2', UI(init=1), UI(deep=True)), 'FIX_FIELDS'])
step_send_fuzzed_pads = Step(dp_pads)
step_wait_padr = NoDataStep(fbk_timeout=1)

step_wait_padi.connect_to(step_send_valid_pado, cbk_after_fbk=retrieve_padi_from_feedback)
step_send_valid_pado.connect_to(step_send_fuzzed_pads, cbk_after_fbk=retrieve_padr_from_feedback_and_update)
step_send_valid_pado.connect_to(step_wait_padr)

# step_send_fuzzed_pads.connect_to(step_wait_padr)
step_send_fuzzed_pads.connect_to(step_send_padt)
step_send_padt.connect_to(step_wait_padr)

step_wait_padr.connect_to(step_send_fuzzed_pads, cbk_after_fbk=retrieve_padr_from_feedback_and_update)
step_wait_padr.connect_to(step_send_valid_pado, cbk_after_fbk=retrieve_padi_from_feedback)

sc2 = Scenario('PADS')
sc2.set_anchor(step_wait_padi)

tactics.register_scenarios(sc1, sc2)
