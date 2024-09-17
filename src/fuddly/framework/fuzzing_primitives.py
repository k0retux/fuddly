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

import sys
import random
import string
import copy
import re

from fuddly.framework import value_types as vtype
from fuddly.framework import node as dm

from fuddly.framework.basic_primitives import *
from fuddly.libs.external_modules import *

from fuddly.libs import debug_facility as dbg

DEBUG = dbg.MW_DEBUG
DEBUG_PRINT = dbg.DEBUG_PRINT

class ModelWalker(object):
    '''
    We walk through all states of the model and give opportunity to
    the Consumer to act on each node, and to be involved in the
    walking process in some extents.

    The first rule of the walking process is to step up to a node
    exhaustion (which means that the consume_node() method of the Consumer won't be
    called in-between)

    Note: the change of a non-terminal node does not reset the
    indirect parents (just the direct parent), otherwise it could lead
    to a combinatorial explosion, with limited interest...
    '''

    def __init__(self, root_node, node_consumer, make_determinist=False, make_random=False,
                 max_steps=-1, initial_step=1):
        self._root_node = root_node
        self._root_node.make_finite(all_conf=True, recursive=True)

        if make_determinist:
            assert not make_random
            self._root_node.make_determinist(all_conf=True, recursive=True)
        elif make_random:
            assert not make_determinist
            self._root_node.make_random(all_conf=True, recursive=True)

        self._root_node.freeze()

        self._max_steps = int(max_steps)
        self._initial_step = int(initial_step)

        assert(self._max_steps > 0 or self._max_steps == -1)

        if node_consumer.ignore_mutable_attr:
            mattr = [dm.NodeInternals.Finite]
        else:
            mattr = [dm.NodeInternals.Mutable, dm.NodeInternals.Finite]

        self.ic = dm.NodeInternalsCriteria(mandatory_attrs=mattr)
        self.triglast_ic = dm.NodeInternalsCriteria(mandatory_custo=[dm.GenFuncCusto.TriggerLast])

        self.consumed_node_path = None

        self.set_consumer(node_consumer)

    def set_consumer(self, node_consumer):
        self._consumer = node_consumer
        self._consumer._root_node = self._root_node
        self._consumer.preload(self._root_node)


    def __iter__(self):

        self._cpt = 1
        gen = self.walk_graph_rec([self._root_node], structure_has_changed=False,
                                  consumed_nodes=set(), parent_node=self._root_node,
                                  consumer=self._consumer)
        for consumed_node, orig_node_val in gen:
            self._root_node.freeze(resolve_csp=True)

            if consumed_node is None:
                # this case happen only when the generated data does not comply with a CSP defined
                # in the model and that the consumers wants compliance with it.
                print("\n[Warning] While walking the node graph, data has been skipped"
                      "\n   as a CSP violation has been detected and the current consumer"
                      "\n   has its attribute 'csp_compliance_matters' set.")
                continue

            self.consumed_node_path = consumed_node.get_path_from(self._root_node)
            if self.consumed_node_path == None:
                # 'consumed_node_path' can be None if
                # consumed_node is not part of the frozen rnode
                # (it may however exist when rnode is not
                # frozen). This situation can trigger in some
                # specific situations related to the use of
                # existence conditions within a data model. Thus,
                # in this case we skip the just generated case as
                # nothing is visible.
                continue

            if self._cpt >= self._initial_step:
                yield self._root_node, consumed_node, orig_node_val, self._cpt
            else:
                pass

            if self._max_steps != -1 and self._cpt >= (self._max_steps+self._initial_step-1):
                self._cpt += 1
                break
            else:
                self._cpt += 1

        if self._cpt <= self._initial_step and self._cpt > 1:
            print("\n*** DEBUG: initial_step idx ({:d}) is after" \
                      " the last idx ({:d})!\n".format(self._initial_step, self._cpt-1))
            self._initial_step = 1
            self.consumed_node_path = consumed_node.get_path_from(self._root_node)
            if self.consumed_node_path == None:
                return
            else:
                yield self._root_node, consumed_node, orig_node_val, self._cpt-1

        return


    def _do_reset(self, node, consumer):
        last_gen = self._root_node.get_reachable_nodes(internals_criteria=self.triglast_ic,
                                                       resolve_generator=True)
        for n in last_gen:
            n.unfreeze(ignore_entanglement=True)
        node.unfreeze(recursive=False)
        # self._root_node.unfreeze(recursive=True, dont_change_state=True)
        node.unfreeze(recursive=True, dont_change_state=True, ignore_entanglement=True)
        consumer.do_after_reset(node)

    def walk_graph_rec(self, node_list, structure_has_changed, consumed_nodes, parent_node, consumer):

        reset = False
        guilty = None

        # We iterate over the children nodes of a parent node which is
        # in a frozen state (which means that it may have some
        # children in other states that are not dealt with in this current call)
        for node in node_list:
            perform_second_step = True
            again = True

            DEBUG_PRINT('--(1)-> Node:' + node.name + ', exhausted:' + repr(node.is_exhausted()), level=2)

            # We enter here at least once, and if a reset on the same
            # node has been triggered (typically for a non-terminal
            # node)

            while again:
                again = False

                ### STEP 1 ###

                # We freeze the node before making a research on it,
                # otherwise we could catch some nodes that won't exist
                # in the node we will finally output.
                node.freeze()

                # For each node we look for direct subnodes
                fnodes = node.get_reachable_nodes(internals_criteria=self.ic, exclude_self=True,
                                                  respect_order=consumer.respect_order,
                                                  resolve_generator=True, relative_depth=1)
                if DEBUG:
                    DEBUG_PRINT('--(2)-> Node:' + node.name + ', exhausted:' + repr(node.is_exhausted()), level=2)
                    for e in fnodes:
                        DEBUG_PRINT('   |> ' + e.name, level=2)

                # If we don't find direct subnodes, it means that the
                # node is terminal, and we go to Step 2. Otherwise, we
                # call ourselves recursively with the list of subnodes
                if fnodes:
                    generator = self.walk_graph_rec(fnodes, structure_has_changed, consumed_nodes,
                                                    parent_node=node, consumer=consumer)
                    for consumed_node, orig_node_val in generator:
                        yield consumed_node, orig_node_val # YIELD

                ### STEP 2 ###

                # In this step, we provide the node to the Consumer,
                # for possible uses/modifications. This is performed within our
                # method node_consumer_helper().
                if perform_second_step:

                    if consumer.consider_side_effects_on_sibbling:
                        original_parent_node_list = None
                        if parent_node.is_nonterm():
                            original_parent_node_list = set(parent_node.subnodes_set).intersection(set(parent_node.frozen_node_list))

                    consumer_gen = self.node_consumer_helper(node, structure_has_changed, consumed_nodes,
                                                             parent_node=parent_node, consumer=consumer)
                    for consumed_node, orig_node_val, reset, ignore_node in consumer_gen:

                        DEBUG_PRINT("   [ reset: {!r:s} | ignore_node: {!r:s} | " \
                                               "name: {!r:s} ]".format(reset, ignore_node, node.name))

                        # Depending on the choice of the consumer, we
                        # can go to Step 1 again with the same node
                        # (if the consumer triggers a reset), or
                        # continue with the next node after exhaustion
                        # of the current one. The consumer can also
                        # decide to ignore the node, if it triggers a
                        # reset, in order that we avoid bothering him
                        # again with it (that means that Step 2 will
                        # be directly skipped after Step 1 completes)

                        if ignore_node and reset:
                            perform_second_step = False
                            again = True
                            self._do_reset(node, consumer)
                            break
                        elif ignore_node and not reset:
                            perform_second_step = False
                            again = False
                            break
                        elif reset:
                            perform_second_step = True
                            again = True
                            self._do_reset(node, consumer)
                            break
                        else:
                            perform_second_step = True
                            again = False

                        yield consumed_node, orig_node_val # YIELD

                        if consumer.consider_side_effects_on_sibbling:
                            if parent_node.is_nonterm():
                                parent_node.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
                                parent_node.freeze()
                                new_parent_node_list = set(parent_node.subnodes_set).intersection(set(parent_node.frozen_node_list))

                                if original_parent_node_list != new_parent_node_list:
                                    fnodes = parent_node.get_reachable_nodes(internals_criteria=self.ic, exclude_self=True,
                                                                             respect_order=consumer.respect_order,
                                                                             resolve_generator=True, relative_depth=1)
                                    if fnodes:
                                        fnodes.remove(node)
                                        # TODO: check if there is a need to instantiate a copy of the
                                        #  current consumer with a specific state.
                                        #  For BasicVisitor, there is no need, as the only state is
                                        #  the .firstcall value. And we don't need to reset it, because
                                        #  when we reach this code we already yield once the node value that
                                        #  we will walk through. Thus, firstcall need to stay to False,
                                        #  otherwise we will yield the same value twice.
                                        #
                                        #  Needed for tTYPE:
                                        #  - new_consumer = copy.copy(consumer) with a special reset (TBC)
                                        #  - tTYPE or the walker need to be changed somehow so that it could discover
                                        #    other NT shapes linked to node existence.
                                        generator = self.walk_graph_rec(fnodes, structure_has_changed, consumed_nodes,
                                                                        parent_node=parent_node, consumer=consumer)
                                        for consumed_node, orig_node_val in generator:
                                            yield consumed_node, orig_node_val # YIELD


                # We reach this case if the consumer is not interested
                # with 'node'.  Then if the node is not exhausted we
                # may have new cases where the consumer will find
                # something (assuming the consumer accepts to reset).
                elif consumer.need_reset(node) and node.is_attr_set(dm.NodeInternals.Mutable):
                    again = False if node.is_exhausted() else True
                    # Not consumed so we don't unfreeze() with recursive=True
                    self._do_reset(node, consumer)
                else:
                    again = False

                if consumer.consider_side_effects_on_sibbling:
                    parent_node.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
                    parent_node.freeze()

                if node.is_nonterm():
                    structure_has_changed = node.cc.structure_will_change()

                if structure_has_changed and consumer.need_reset_when_structure_change:
                    structure_has_changed = False

                    idx = node_list.index(node)

                    gen = self.walk_graph_rec(node_list[:idx], False, set(), parent_node=parent_node, consumer=consumer)
                    for consumed_node, orig_node_val in gen:
                        yield consumed_node, orig_node_val # YIELD

                    # we need to reassess all the subnodes of the
                    # guilty node that has produced the
                    # structure_change (as it is not dealt with the
                    # previous recursive call). To simplify the process
                    consumed_nodes = set()

                    # This solution does not work as expected especially for USB data model
                    # nodes_to_remove = node.get_reachable_nodes(internals_criteria=self.ic, exclude_self=False)
                    # for n in nodes_to_remove:
                    #     if n in consumed_nodes:
                    #         consumed_nodes.remove(n)

                elif structure_has_changed and not consumer.need_reset_when_structure_change:
                    structure_has_changed = False
                    # print('--> ', node.name, node, node.is_attr_set(dm.NodeInternals.Mutable), 'exhausted: ', node.is_exhausted())
                    consumed_nodes = set()

        return


    def node_consumer_helper(self, node, structure_has_changed, consumed_nodes, parent_node,
                             consumer):

        def _do_if_not_interested(nd, orig_val):
            reset = consumer.need_reset(nd)
            if reset and not nd.is_exhausted():
                return nd, orig_val, True, True # --> x, x, reset, ignore_node
            elif reset and nd.is_exhausted():
                return None, None, False, True # --> x, x, dont_reset, ignore_node
            elif nd.is_exhausted():
                return nd, orig_val, False, True
            else:
                return nd, orig_val, False, True

        def is_csp_compliant(nd):
            if (consumer.csp_compliance_matters and
                    nd.env.csp and nd.env.csp.no_solution_exists):
                return False
            else:
                return True

        orig_node_val = node.to_bytes()

        not_recovered = False
        consume_called_again = False

        if consumer.interested_by(node):
            if node in consumed_nodes:
                go_on = False
            else:
                consumer.save_node(node)
                go_on = consumer.consume_node(node)
        else:
            go_on = False

        if not go_on:
            yield _do_if_not_interested(node, orig_node_val)
            raise ValueError  # We should never return here, otherwise it's a bug we want to alert on

        consumed_nodes.add(node)
        node.freeze(restrict_csp=True, resolve_csp=True)
        not_recovered = True

        max_steps = consumer.wait_for_exhaustion(node)
        again = True

        # We enter this loop only if the consumer is interested in the node
        while again:
            consume_called_again = False
            reset = consumer.need_reset(node)

            if not is_csp_compliant(node):
                if node.is_exhausted():
                    yield None, None, False, True  # --> x, x, dont_reset, ignore_node
                else:
                    yield None, None, False, False  # --> x, x, dont_reset, dont_ignore_node

            elif reset and not node.is_exhausted():

                yield node, orig_node_val, True, False # --> x, x, reset, dont_ignore_node

            elif reset and node.is_exhausted():

                yield None, None, False, True # --> x, x, dont_reset, ignore_node
                raise ValueError  # We should never return here, otherwise its a bug we want to alert on

            elif node.is_exhausted(): # --> (reset and node.is_exhausted()) or (not reset and node.is_exhausted())

                # DEBUG_PRINT('*** node_consumer_helper(): exhausted')
                yield node, orig_node_val, False, False

                if consumer.interested_by(node):
                    if consumer.still_interested_by(node):
                        consumer.consume_node(node)
                    else:
                        consumer.recover_node(node)
                        if consumer.fix_constraints:
                            node.fix_synchronized_nodes()
                        yield _do_if_not_interested(node, orig_node_val)
                        raise ValueError  # We should never return here, otherwise it's a bug we want to alert on

                    consume_called_again = True

                    not_recovered = True
                else:
                    if node in consumed_nodes:
                        consumer.recover_node(node)
                        if consumer.fix_constraints:
                            node.fix_synchronized_nodes()
                        not_recovered = False
                    return

            else:
                yield node, orig_node_val, False, False


            if max_steps != 0:
                max_steps -= 1
                if consume_called_again:
                    node.freeze(restrict_csp=True, resolve_csp=True)
                    # consume_called_again = False
                else:
                    # In this case we iterate only on the current node
                    node.unfreeze(recursive=False, ignore_entanglement=True)
                    node.freeze(restrict_csp=True, resolve_csp=True)
                    if consumer.fix_constraints:
                        node.fix_synchronized_nodes()
            else:
                if not_recovered and (consumer.interested_by(node) or node in consumed_nodes):
                    consumer.recover_node(node)
                    if consumer.fix_constraints:
                        node.fix_synchronized_nodes()
                    if not node.is_exhausted() and consumer.need_reset(node):
                        yield None, None, True, True
                again = False


        return



class NodeConsumerStub(object):

    def __init__(self, max_runs_per_node=-1, min_runs_per_node=-1, respect_order=True,
                 fuzz_magnitude=1.0, fix_constraints=False, ignore_mutable_attr=False,
                 consider_side_effects_on_sibbling=False,
                 **kwargs):
        self.need_reset_when_structure_change = False
        self.consider_side_effects_on_sibbling = consider_side_effects_on_sibbling
        self.fuzz_magnitude = fuzz_magnitude
        self.fix_constraints = fix_constraints
        self.ignore_mutable_attr = ignore_mutable_attr

        self._internals_criteria = None
        self._semantics_criteria = None
        self._owned_confs = None
        self._path_regexp = None
        self._conf = None

        assert(max_runs_per_node > 0 or max_runs_per_node==-1)
        assert(min_runs_per_node > 0 or min_runs_per_node==-1)

        self.max_runs_per_node = int(max_runs_per_node)
        self.min_runs_per_node = int(min_runs_per_node)

        self.respect_order = respect_order

        self.__node_backup = None

        self._csp_compliance_matters = True
        self._only_corner_cases = False
        self._only_invalid_cases = False

        self.init_specific(**kwargs)

    def reset_state(self):
        """
        Called by the ModelWalker to reinitialize the disruptor.
        """

    def init_specific(self, **kwargs):
        self._internals_criteria = dm.NodeInternalsCriteria(negative_node_kinds=[dm.NodeInternals_NonTerm])
        self._semantics_criteria = dm.NodeSemanticsCriteria()

    def preload(self, root_node):
        """
        Called by the ModelWalker when it initializes

        Args:
            root_node: Root node of the modeled data

        Returns: None

        """
        pass

    def consume_node(self, node):
        '''
        Use this method to modify/alter or just read information on
        @node. This function will be called for each node that satisfy
        the criteria. (to be implemented according to the
        implementation of need_reset())

        Return True to say that you have correctly consumed the node.
        Return False, if despite your current criteria for node interest,
        you are in fact not interested
        '''
        DEBUG_PRINT('*** consume_node() called on: {:s}, (depth: {:d})'.format(node.name, node.depth))
        if node.is_exhausted():
            return False
        else:
            return True

    # The methods save_node() & recover_node() does not work for all situations
    def save_node(self, node):
        '''
        Generic way to save a node (can impact performance)
        '''
        self.__node_backup = node.get_internals_backup()

    def recover_node(self, node):
        '''
        Generic way to recover a node
        '''
        node.set_internals(self.__node_backup)

    def still_interested_by(self, node):
        return False

    def need_reset(self, node):
        if node.is_nonterm():
            return True
        else:
            return False

    def do_after_reset(self, node):
        pass

    def wait_for_exhaustion(self, node):
        '''
        * return -1 to wait until exhaustion
        * return 0 to stop node iteration after consumption (and yielding a value once)
        * return N-1 to stop iteration after at most N step (or before if exhaustion triggers)
        '''
        return max(self.max_nb_runs_for(node)-1, -1)

    def max_nb_runs_for(self, node):
        if node.get_fuzz_weight() > 1:
            return self.max_runs_per_node
        else:
            return self.min_runs_per_node


    def set_node_interest(self, internals_criteria=None, semantics_criteria=None,
                          owned_confs=None, path_regexp=None, conf=None):
        '''
        @conf: criteria are applied for the provided conf if not None, otherwise current_conf is used
        Note: when all is None, NodeConsumer is interested by every node (that is interested_by() return always True)
        '''
        if internals_criteria:
            self._internals_criteria.extend(internals_criteria)
        if semantics_criteria:
            self._semantics_criteria.extend(semantics_criteria)
        if owned_confs:
            self._owned_confs=owned_confs
        if path_regexp:
            self._path_regexp=path_regexp
        if conf:
            self._conf=conf


    def interested_by(self, node):
        if self._conf is None:
            config = node.current_conf
        elif node.is_conf_existing(self._conf):
            config = self._conf
        else:
            return False

        if self._owned_confs is not None:
            for oc in self._owned_confs:
                if node.is_conf_existing(oc):
                    break
            else:
                return False

        if self._internals_criteria is not None:
            cond1 = node.internals[config].match(self._internals_criteria)
        else:
            cond1 = True

        if self._semantics_criteria is not None and self._semantics_criteria:
            if node.semantics is None:
                cond2 = False
            else:
                cond2 = node.semantics.match(self._semantics_criteria)
        else:
            cond2 = True

        if self._path_regexp is not None:
            paths = node.get_all_paths_from(self._root_node)
            for p in paths:
                if re.search(self._path_regexp, p):
                    cond3 = True
                    break
            else:
                cond3 = False
        else:
            cond3 = True

        return cond1 and cond2 and cond3

    @property
    def csp_compliance_matters(self):
        return self._csp_compliance_matters


class BasicVisitor(NodeConsumerStub):

    def init_specific(self, reset_when_change=True):
        self._reset_when_change = reset_when_change
        self.reset_state()

    def reset_state(self):
        self._internals_criteria = dm.NodeInternalsCriteria(negative_node_kinds=[dm.NodeInternals_NonTerm])
        self._semantics_criteria = dm.NodeSemanticsCriteria()
        self.need_reset_when_structure_change = self._reset_when_change
        self.firstcall = True

    def consume_node(self, node):
        if node.is_exhausted() and not self.firstcall:
            # in this case we ignore the node
            return False
        else:
            if self.firstcall:
                self.firstcall = False
                return True
            if not node.is_exhausted():
                node.freeze(restrict_csp=True, resolve_csp=True)
                node.unfreeze(recursive=False, ignore_entanglement=True)
                node.freeze(restrict_csp=True, resolve_csp=True)
            return True

    def save_node(self, node):
        pass

    def recover_node(self, node):
        node.reset_state(recursive=False)
        node.freeze(restrict_csp=True, resolve_csp=True)

    def need_reset(self, node):
        if node.is_nonterm():
            if not node.is_exhausted():
                self.firstcall = True
            return True
        else:
            return False

    # def wait_for_exhaustion(self, node):
    #     return -1


class NonTermVisitor(BasicVisitor):

    def init_specific(self, reset_when_change=True):
        self._internals_criteria = dm.NodeInternalsCriteria(node_kinds=[dm.NodeInternals_NonTerm],
                                                            mandatory_attrs=[dm.NodeInternals.Mutable])
        self._semantics_criteria = dm.NodeSemanticsCriteria()
        self.need_reset_when_structure_change = reset_when_change
        self.last_node = None
        self.current_node = None

    def need_reset(self, node):
        # DEBUG_PRINT('--(RESET)-> Node:' + node.name + ', exhausted:' + repr(node.is_exhausted()), level=0)
        if node.is_nonterm() and self.last_node is not None and \
                        node is not self.last_node and not node.is_exhausted():
            self.last_node = None
            self.current_node = None
            return True
        else:
            return False

    def consume_node(self, node):
        self.last_node = self.current_node
        self.current_node = node

        if node.is_exhausted() and self.last_node is not None:
            return False
        else:
            # last_name = self.last_node.name if self.last_node else 'None'
            # DEBUG_PRINT('--(1)-> Node:' + node.name + ', exhausted:' + repr(node.is_exhausted()) + \
            #             ', curr: ' + self.current_node.name + ', last: ' + last_name, level=0)
            return True

    def still_interested_by(self, node):
        return False

    def wait_for_exhaustion(self, node):
        return -1 # wait until exhaustion



class AltConfConsumer(NodeConsumerStub):
    '''
    Note: save_node()/restore_node() are not overloaded although
    default implementation can triggers overhead, because for some
    cases copying the Elt is the better (e.g., for alternate conf on nonterm
    nodes, that reuse same subnodes over the various confs).
    '''

    def init_specific(self, **kwargs):
        self.__node_backup = None

        self.need_reset_when_structure_change = True

        self._internals_criteria = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable])
        self._semantics_criteria = dm.NodeSemanticsCriteria()
        self._owned_confs = ['MAIN']
        self.current_consumed_node = None
        self.orig_conf = None
        self.confs_list = None
        self.recover = False

    def need_reset(self, node):
        if node.is_nonterm() and node is not self.current_consumed_node:
            return True
        else:
            return False

    def consume_node(self, node):
        if node is self.current_consumed_node and not self.confs_list:
            return False

        if not self.confs_list:
            self.confs_list = copy.copy(self._owned_confs)
            for c in self.confs_list:
                if node.is_conf_existing(c):
                    ok = True
                    break
            else:
                ok = False

            if ok:
                self.confs_list = list(filter(lambda c: node.is_conf_existing(c), self.confs_list))
            else:
                return False

        new_conf = self.confs_list.pop(0)

        # case 1
        if node.is_conf_existing(new_conf):
            DEBUG_PRINT(' *** CONSUME: ' + node.name + ', ' + repr(node.c.keys()), level=0)
            self.orig_conf = node.get_current_conf()
            self.current_consumed_node = node
            node.set_current_conf(conf=new_conf, recursive=False)
            # node.get_value()

            self.recover = True
            return True

        # case 2
        else:
            self.recover = False
            return True

    def still_interested_by(self, node):
        if self.confs_list:
            return True
        else:
            return False

    def save_node(self, node):
        pass

    def recover_node(self, node):
        if node is self.current_consumed_node and self.recover:
            DEBUG_PRINT(' *** RECOVER: ' + node.name + ', ' + node.get_current_conf())

            node.reset_state(recursive=True)
            node.get_value()

            node.set_current_conf(conf=self.orig_conf, reverse=True, recursive=False)
            node.get_value()
            self.orig_conf = None
            self.current_consumed_node = None
        else:
            # correspond to consume_node() case 2
            pass

    def wait_for_exhaustion(self, node):
        if self.current_consumed_node is None:
            return 0

        if node is self.current_consumed_node:
            if node.get_fuzz_weight() > 1:
                return max(self.max_runs_per_node-1, -1)
            else:
                return max(self.min_runs_per_node-1, -1)
        else:
            return 0


class TypedNodeDisruption(NodeConsumerStub):

    def init_specific(self, ignore_separator=False, determinist=True, csp_compliance_matters=False,
                      only_corner_cases=False, only_invalid_cases=False):
        mattr = None if self.ignore_mutable_attr else [dm.NodeInternals.Mutable]
        if ignore_separator:
            self._internals_criteria = dm.NodeInternalsCriteria(mandatory_attrs=mattr,
                                                                negative_attrs=[dm.NodeInternals.Separator],
                                                                node_kinds=[dm.NodeInternals_TypedValue,
                                                                            dm.NodeInternals_GenFunc])
        else:
            self._internals_criteria = dm.NodeInternalsCriteria(mandatory_attrs=mattr,
                                                                node_kinds=[dm.NodeInternals_TypedValue,
                                                                            dm.NodeInternals_GenFunc])

        self._semantics_criteria = dm.NodeSemanticsCriteria()

        # self.orig_value = None
        self.current_fuzz_vt_list = None
        self.current_node = None
        self.orig_internal = None
        self.determinist = determinist
        self._ignore_separator  = ignore_separator
        self.sep_list = None

        self.need_reset_when_structure_change = True

        self._csp_compliance_matters = csp_compliance_matters
        self._only_corner_cases = only_corner_cases
        self._only_invalid_cases = only_invalid_cases

    def preload(self, root_node):
        if not self._ignore_separator:
            ic = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Separator])
            self.sep_list = set(map(lambda x: x.to_bytes(),
                                    root_node.get_reachable_nodes(internals_criteria=ic, resolve_generator=True)))
            self.sep_list = list(self.sep_list)

    def consume_node(self, node):
        if node.is_genfunc() and (node.is_attr_set(dm.NodeInternals.Freezable) or
                not node.generated_node.is_typed_value()):
            return False

        if node is not self.current_node:
            self.current_node = node
            self.current_fuzz_vt_list = None

        if not self.current_fuzz_vt_list:
            self.orig_internal = node.cc
            self.orig_all_attrs = node.cc.get_attrs_copy()
            # self.orig_value = node.to_bytes()

            vt_node = node.generated_node if node.is_genfunc() else node
            self._populate_fuzzy_vt_list(vt_node, self.fuzz_magnitude)

        DEBUG_PRINT(' *** CONSUME: ' + node.name + ', ' + repr(self.current_fuzz_vt_list), level=0)

        if self.current_fuzz_vt_list:
            vt_obj = self.current_fuzz_vt_list.pop(0)

            DEBUG_PRINT(f' *** Test cases for node "{node.name}": {vt_obj.values}\n', level=0)

            node.set_values(value_type=vt_obj, ignore_entanglement=True, preserve_node=True)
            node.make_finite()
            if self.determinist is None:
                pass
            elif self.determinist:
                node.make_determinist()
            else:
                node.make_random()
            node.unfreeze(ignore_entanglement=True)
            # we need to be sure that the current node is freezable
            node.set_attr(dm.NodeInternals.Freezable)
            node.set_attr(dm.NodeInternals.LOCKED)

            node.cc.highlight = True

            return True
        else:
            return False
            # raise ValueError

    def _populate_fuzzy_vt_list(self, vt_node, fuzz_magnitude):

        vt = vt_node.get_value_type()

        if issubclass(vt.__class__, vtype.VT_Alt):
            new_vt = copy.copy(vt)
            new_vt.make_private(forget_current_state=False)
            ok = new_vt.enable_fuzz_mode(fuzz_magnitude=fuzz_magnitude,
                                         only_corner_cases=self._only_corner_cases,
                                         only_invalid_cases=self._only_invalid_cases)

            self.current_fuzz_vt_list = [new_vt] if ok else []
        else:
            self.current_fuzz_vt_list = []

        fuzzed_vt = vt.get_fuzzed_vt_list(only_corner_cases=self._only_corner_cases,
                                          only_invalid_cases=self._only_invalid_cases)
        if fuzzed_vt:
            self.current_fuzz_vt_list += fuzzed_vt

        if self.sep_list:
            self._add_separator_cases(vt_node)

    def _add_separator_cases(self, vt_node):
        current_val = vt_node.get_current_value()
        if vt_node.is_attr_set(dm.NodeInternals.Separator):
            sep_l = copy.copy(self.sep_list)
            try:
                sep_l.remove(current_val)
            except ValueError:
                print("\n*** WARNING: separator not part of the initial set. (Could happen if "
                      "separators are generated dynamically)")
            if sep_l:
                self.current_fuzz_vt_list.insert(0, vtype.String(values=sep_l))
        else:
            sz = len(current_val)
            if sz > 1:
                fuzzy_sep_val_list = []
                for sep in self.sep_list:
                    new_val = current_val[:-1] + sep + current_val[-1:]
                    fuzzy_sep_val_list.append(new_val)
                self.current_fuzz_vt_list.insert(0, vtype.String(values=fuzzy_sep_val_list))

    def save_node(self, node):
        pass

    def recover_node(self, node):
        node.cc = self.orig_internal
        node.cc.set_attrs_from(self.orig_all_attrs)

    def need_reset(self, node):
        if node.is_nonterm():
            return True
        else:
            return False

    def still_interested_by(self, node):
        if self.current_fuzz_vt_list:
            return True
        else:
            return False


class SeparatorDisruption(NodeConsumerStub):

    def init_specific(self, separators=None):
        self._internals_criteria = \
            dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable, dm.NodeInternals.Separator],
                                     node_kinds=[dm.NodeInternals_Term])

        self._semantics_criteria = dm.NodeSemanticsCriteria()

        self.values = [b'']
        if separators is not None:
            self.values += list(separators)

        # self.need_reset_when_structure_change = True

    def consume_node(self, node):
        orig_val = node.to_bytes()
        new_values = copy.copy(self.values)

        if orig_val in new_values:
            new_values.remove(orig_val)

        node.cc.import_value_type(value_type=vtype.String(values=new_values))
        # Note, that node attributes are not altered by this
        # operation, especially usefull in our case, because we have
        # to preserve dm.NodeInternals.Separator

        node.unfreeze() # ignore previous state

        node.make_finite()
        node.make_determinist()

        return True


def fuzz_data_tree(top_node, paths_regexp=None):

    c = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable],
                             node_kinds=[dm.NodeInternals_NonTerm])

    if paths_regexp:
        node_list = top_node.get_reachable_nodes(path_regexp=paths_regexp, resolve_generator=True)
    else:
        node_list = [top_node]

    for node in node_list:
        l = node.get_reachable_nodes(internals_criteria=c, resolve_generator=True)
        for e in l:
            e.cc.change_subnodes_csts([('*', 'u=.')])

