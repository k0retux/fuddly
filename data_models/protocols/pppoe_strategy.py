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


def wait_for_padi(env, current_step, next_step, feedback):
    if not feedback:
        print('\n\n*** No Feedback!')
        return False
    else:
        print('\n\n*** Feedback retrieved')

        for source, fbks in feedback.items():
            for item in fbks:
                padi = env.dm.get_data('padi')
                padi.set_current_conf('ABS', recursive=True)
                data = item['content']
                off = data.find(b'\xff\xff\xff\xff\xff\xff')
                data = data[off:]
                result = padi.absorb(data, constraints=AbsNoCsts(size=True, struct=True))
                if result[0] == AbsorbStatus.FullyAbsorbed:
                    try:
                        service_name = padi['.*/value/v101'].to_bytes()
                        mac_src = padi['.*/mac_src'].to_bytes()
                    except:
                        continue
                    print(' [ PADI received! ]')
                    next_step.node.freeze()
                    next_step.node['.*/mac_dst'] = mac_src
                    next_step.node['.*/tag_sn/value/v101'] = service_name
                    next_step.node.unfreeze(recursive=True, reevaluate_constraints=True)
                    return True

        print(' [ PADI not found ]')

        return False

step_wait_padi = NoDataStep(fbk_timeout=2)
step_send_pado = Step(DataProcess(process=['tTYPE'], seed='pado'))
step_end = Step('padt')

step_wait_padi.connect_to(step_send_pado, cbk_after_fbk=wait_for_padi)
step_send_pado.connect_to(step_end)
step_end.connect_to(step_wait_padi)

sc1 = Scenario('PADO')
sc1.set_anchor(step_wait_padi)

tactics.register_scenarios(sc1)
