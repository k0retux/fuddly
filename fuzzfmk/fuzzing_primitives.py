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

sys.path.append('.')

import fuzzfmk.value_types as vtype
import fuzzfmk.data_model as dm

from fuzzfmk.basic_primitives import *

from libs.external_modules import *
from libs.debug_facility import *


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
            assert(not make_random)
            self._root_node.make_determinist(all_conf=True, recursive=True)
        elif make_random:
            assert(not make_determinist)
            self._root_node.make_random(all_conf=True, recursive=True)

        self._root_node.freeze()

        self._max_steps = int(max_steps)
        self._initial_step = int(initial_step)
        
        assert(self._max_steps > 0 or self._max_steps == -1)

        self.ic = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable, dm.NodeInternals.Finite])
        self.triglast_ic = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.TriggerLast])

        self.consumed_node_path = None

        self.set_consumer(node_consumer)

    def set_consumer(self, node_consumer):
        self._consumer = node_consumer
        self._consumer._root_node = self._root_node


    def __iter__(self):

        self._cpt = 1

        gen = self.walk_graph_rec([self._root_node], self._consumer.yield_original_val,
                                  structure_has_changed=False, consumed_nodes=set())
        for consumed_node, orig_node_val in gen:
            self._root_node.get_value()

            if self._cpt >= self._initial_step:
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

                yield self._root_node, consumed_node, orig_node_val, self._cpt

            if self._max_steps != -1 and self._cpt >= (self._max_steps+self._initial_step-1):
                self._cpt += 1
                break
            else:
                self._cpt += 1

        if self._cpt <= self._initial_step and self._cpt > 1:
            self._initial_step = 1
            print("\n*** DEBUG: initial_step idx ({:d}) is after" \
                      " the last idx ({:d})!\n".format(self._initial_step, self._cpt-1))
            self.consumed_node_path = consumed_node.get_path_from(self._root_node)
            if self.consumed_node_path == None:
                return
            else:
                yield self._root_node, consumed_node, orig_node_val, self._cpt-1

        return


    def _do_reset(self, node):
        last_gen = self._root_node.get_reachable_nodes(internals_criteria=self.triglast_ic)
        for n in last_gen:
            n.unfreeze()
        node.unfreeze(recursive=False)
        # self._root_node.unfreeze(recursive=True, dont_change_state=True)
        node.unfreeze(recursive=True, dont_change_state=True)
        self._consumer.do_after_reset(node)

    def walk_graph_rec(self, node_list, value_not_yielded_yet, structure_has_changed, consumed_nodes):

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

                if reset or value_not_yielded_yet:
                    value_not_yielded_yet = self._consumer.yield_original_val

                ### STEP 1 ###

                # We freeze the node before making a research on it,
                # otherwise we could catch some nodes that won't exist
                # in the node we will finally output.
                node.freeze()

                # For each node we look for direct subnodes
                fnodes = node.get_reachable_nodes(internals_criteria=self.ic, exclude_self=True,
                                                  respect_order=self._consumer.respect_order, relative_depth=1)

                if DEBUG:
                    DEBUG_PRINT('--(2)-> Node:' + node.name + ', exhausted:' + repr(node.is_exhausted()), level=2)
                    for e in fnodes:
                        DEBUG_PRINT('   |> ' + e.name, level=2)

                # If we don't find direct subnodes, it means that the
                # node is terminal, and we go to Step 2. Otherwise, we
                # call ourselves recursively with the list of subnodes
                if fnodes:
                    generator = self.walk_graph_rec(fnodes, value_not_yielded_yet,
                                                    structure_has_changed, consumed_nodes)
                    for consumed_node, orig_node_val in generator:
                        yield consumed_node, orig_node_val # YIELD

                ### STEP 2 ###

                # In this step, we provide the node to the Consumer,
                # for possible uses/modifications. This is performed within our
                # method node_consumer_helper().
                if perform_second_step:
                    
                    consumer_gen = self.node_consumer_helper(node, structure_has_changed, consumed_nodes)
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
                            self._do_reset(node)
                            break
                        elif ignore_node and not reset:
                            perform_second_step = False
                            again = False
                            break
                        elif reset:
                            perform_second_step = True
                            again = True
                            self._do_reset(node)
                            break
                        else:
                            perform_second_step = True
                            again = False

                        if value_not_yielded_yet:
                            yield consumed_node, orig_node_val # YIELD
                        else:
                            value_not_yielded_yet = True

                # We reach this case if the consumer is not interested
                # with 'node'.  Then if the node is not exhausted we
                # may have new cases where the consumer will find
                # something (assuming the consumer accepts to reset).
                elif self._consumer.need_reset(node) and not node.is_exhausted():
                    again = True
                    # Not consumed so we don't unfreeze() with recursive=True
                    self._do_reset(node)
                else:
                    again = False

                if node.is_nonterm():
                    structure_has_changed = node.cc.structure_will_change()

                if structure_has_changed and self._consumer.need_reset_when_structure_change:

                    structure_has_changed = False

                    idx = node_list.index(node)

                    gen = self.walk_graph_rec(node_list[:idx], self._consumer.yield_original_val, False, set())
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

                elif structure_has_changed and not self._consumer.need_reset_when_structure_change:
                    structure_has_changed = False
                    # print('--> ', node.name, node, node.is_attr_set(dm.NodeInternals.Mutable), 'exhausted: ', node.is_exhausted())
                    consumed_nodes = set()

        return


    def node_consumer_helper(self, node, structure_has_changed, consumed_nodes):

        def _do_if_not_interested(node, orig_node_val):
            reset = self._consumer.need_reset(node)
            if reset and not node.is_exhausted():
                return node, orig_node_val, True, True # --> x, x, reset, ignore_node
            elif reset and node.is_exhausted():
                return None, None, False, True # --> x, x, reset, ignore_node
            elif node.is_exhausted():
                return node, orig_node_val, False, True
            else:
                return node, orig_node_val, False, True

        orig_node_val = node.to_bytes()

        not_recovered = False
        consume_called_again = False

        if self._consumer.interested_by(node):
            if node in consumed_nodes:
                go_on = False
            else:
                self._consumer.save_node(node)
                go_on = self._consumer.consume_node(node)
        else:
            go_on = False

        if not go_on:
            yield _do_if_not_interested(node, orig_node_val)
            raise ValueError  # We should never return here, otherwise its a bug we want to alert on

        consumed_nodes.add(node)
        node.get_value()
        not_recovered = True

        max_steps = self._consumer.wait_for_exhaustion(node)
        again = True

        # We enter this loop only if the consumer is interested by the
        # node.
        while again:
            reset = self._consumer.need_reset(node)

            if reset and not node.is_exhausted():

                yield node, orig_node_val, True, False # --> x, x, reset, dont_ignore_node
            
            elif reset and node.is_exhausted():

                yield None, None, False, True # --> x, x, reset, ignore_node
                raise ValueError  # We should never return here, otherwise its a bug we want to alert on

            elif node.is_exhausted(): # --> (reset and node.is_exhausted()) or (not reset and node.is_exhausted())

                yield node, orig_node_val, False, False

                if self._consumer.interested_by(node):
                    if self._consumer.still_interested_by(node):
                        self._consumer.consume_node(node)
                    else:
                        self._consumer.recover_node(node)
                        yield _do_if_not_interested(node, orig_node_val)
                        raise ValueError  # We should never return here, otherwise its a bug we want to alert on

                    consume_called_again = True

                    node.get_value()
                    not_recovered = True
                else:
                    if node in consumed_nodes:
                        self._consumer.recover_node(node)
                        not_recovered = False
                    return

            else:
                yield node, orig_node_val, False, False

            if max_steps != 0 and not consume_called_again:
                max_steps -= 1
                # In this case we iterate only on the current node
                node.unfreeze(recursive=False)
                node.get_value()
            elif not consume_called_again:
                if not_recovered and (self._consumer.interested_by(node) or node in consumed_nodes):
                    self._consumer.recover_node(node)
                    if not node.is_exhausted() and self._consumer.need_reset(node):
                        yield None, None, True, True
                again = False

            else:
                consume_called_again = False

        return



class NodeConsumerStub(object):
    '''
    TOFIX (TBC since last cleanup): when respect_order=False, BasicVisitor
    behave strangely (not the same number of yielded values).
    --> to be investigated (maybe wrong implementation of BasicVisitor and NonTermVisitor)
    '''

    def __init__(self, specific_args=None, max_runs_per_node=-1, min_runs_per_node=-1, respect_order=True):
        self.yield_original_val = True
        self.need_reset_when_structure_change = False

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

        self.init_specific(specific_args)
    

    def init_specific(self, args):
        self._internals_criteria = dm.NodeInternalsCriteria(negative_node_kinds=[dm.NodeInternals_NonTerm])


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

        if self._semantics_criteria is not None:
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



class BasicVisitor(NodeConsumerStub):

    def init_specific(self, args):
        self._internals_criteria = None
        self.consumed = False
        self.consume_also_singleton = False if args is None else bool(args)

    def consume_node(self, node):
        if node.is_nonterm() and self.consumed:
            self.consumed = False

        if (node.is_exhausted() and not self.consume_also_singleton) or node.is_nonterm():
            # in this case we ignore the node
            return False

        else:
            if self.consumed:
                node.get_value()
                node.unfreeze(recursive=False)
                node.get_value()
            else:
                self.consumed = True

            return True

    def save_node(self, node):
        pass

    def recover_node(self, node):
        node.reset_state(recursive=False)
        node.get_value()

    def need_reset(self, node):
        if node.is_nonterm() and self.consumed:
            self.consumed = False

        if node.is_nonterm():
            return True
        else:
            return False

    def wait_for_exhaustion(self, node):
        if not node.is_nonterm():
            return -1 # wait until exhaustion
        else:
            return 0


class NonTermVisitor(BasicVisitor):

    def init_specific(self, args):
        self.consumed = False
        self._internals_criteria = None
        self._internals_criteria = dm.NodeInternalsCriteria(negative_node_kinds=[dm.NodeInternals_NonTerm])
        self.current_nt_node = None

    def need_reset(self, node):
        # DEBUG_PRINT('--(1)-> Node:' + node.name + ', exhausted:' + repr(node.is_exhausted()), level=0)
        if node.is_nonterm() and node is not self.current_nt_node and node.cc.structure_will_change():
            # this case is called outside node_consumer_helper(),
            # because we declared to only be interested with other
            # kinds of node. Thus it will trigger node.unfreeze()
            return True
        else:
            # Here we already have consumed the node, we don't want a reset
            return False

    def do_after_reset(self, node):
        self.consumed = False
        self.current_nt_node = node

    def consume_node(self, node):
        if not self.consumed and not node.is_nonterm():
            self.consumed = True
            return True
        else:
            return False

    def still_interested_by(self, node):
        return False

    def wait_for_exhaustion(self, node):
        return 0



class AltConfConsumer(NodeConsumerStub):
    '''
    Note: save_node()/restore_node() are not overloaded although
    default implementation can triggers overhead, because for some
    cases copying the Elt is the better (e.g., for alternate conf on nonterm
    nodes, that reuse same subnodes over the various confs).
    '''

    def init_specific(self, args):
        self.__node_backup = None

        self.yield_original_val = True
        self.need_reset_when_structure_change = True

        self._internals_criteria = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable])
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


class TermNodeDisruption(NodeConsumerStub):

    def init_specific(self, base_list):
        self._internals_criteria = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable],
                                                            negative_attrs=[dm.NodeInternals.Separator],
                                                            node_kinds=[dm.NodeInternals_Term])
        self.enforce_ascii = False
        self.determinist = True

        if base_list is None:
            self.val_list = [
                b'',
                b'\x00',
                b'AhAh%s%s%s',
                b'BBB%n%n%n%n%n',
                b'\r\n'
                ]
        else:
            self.val_list = list(base_list)

        self.orig_internals = None
        self.yield_original_val = True
        self.need_reset_when_structure_change = True


    def consume_node(self, node):
        self.orig_internal = node.cc
        orig_val = node.to_bytes()
        new_val_list = copy.copy(self.val_list)

        try:
            val = corrupt_bits(orig_val, n=1, ascii=self.enforce_ascii)
            new_val_list.insert(0, val)
        except:
            print("Problematic (empty) node '%s'" % node.name)

        val = orig_val + b"A"*30
        new_val_list.insert(0, val)

        node.set_values(val_list=new_val_list)
        node.make_finite()
        if self.determinist:
            node.make_determinist()
        else:
            node.make_random()

        return True
    
    def save_node(self, node):
        pass

    def recover_node(self, node):
        node.cc = self.orig_internal
        if node.entangled_nodes is None:
            return

        for n in node.entangled_nodes:
            if n is node:
                continue
            if isinstance(n.cc, dm.NodeInternals_TypedValue):
                n.cc.import_value_type(self.orig_internal.value_type)
            else:
                raise ValueError
        node.unfreeze(recursive=False)


class TypedNodeDisruption(NodeConsumerStub):

    def init_specific(self, args):
        self._internals_criteria = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable],
                                                            negative_attrs=[dm.NodeInternals.Separator],
                                                            node_kinds=[dm.NodeInternals_TypedValue])
        self.orig_value = None
        self.current_fuzz_vt_list = None
        self.current_node = None
        self.orig_internal = None

        self.yield_original_val = True
        self.need_reset_when_structure_change = True

    def consume_node(self, node):
        if node is not self.current_node:
            self.current_node = node
            self.current_fuzz_vt_list = None

        if not self.current_fuzz_vt_list:
            self.orig_internal = node.cc
            self.orig_value = node.to_bytes()

            self.current_fuzz_vt_list = self._create_fuzzy_vt_list(node)
            self._extend_fuzzy_vt_list(self.current_fuzz_vt_list, node)

        DEBUG_PRINT(' *** CONSUME: ' + node.name + ', ' + repr(self.current_fuzz_vt_list), level=0)

        if self.current_fuzz_vt_list:
            vt_obj = self.current_fuzz_vt_list.pop(0)

            node.set_values(value_type=vt_obj)
            node.make_finite()
            node.make_determinist()

            return True
        else:
            raise ValueError

    def save_node(self, node):
        pass

    def recover_node(self, node):
        node.cc = self.orig_internal
        if node.entangled_nodes is None:
            return

        for n in node.entangled_nodes:
            if n is node:
                continue
            if isinstance(n.cc, dm.NodeInternals_TypedValue):
                n.cc.import_value_type(self.orig_internal.value_type)
            else:
                raise ValueError

        node.unfreeze(recursive=False)


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

    @staticmethod
    def _create_fuzzy_vt_list(e):
        vt = e.cc.get_value_type()

        if issubclass(vt.__class__, vtype.VT_Alt):
            new_vt = copy.copy(vt)
            new_vt.make_private(forget_current_state=False)
            new_vt.switch_mode()
            fuzzy_vt_list = [new_vt]

        else:
            fuzzy_vt_cls = list(vt.fuzzy_cls.values())
            fuzzy_vt_list = []
            for c in fuzzy_vt_cls:
                fuzzy_vt_list.append(c(vt.endian))

        return fuzzy_vt_list

    @staticmethod
    def _extend_fuzzy_vt_list(flist, e):
        vt = e.cc.get_value_type()

        if issubclass(vt.__class__, vtype.VT_Alt):
            return

        specific_fuzzy_vals = e.cc.get_specific_fuzzy_values()

        val = vt.get_current_raw_val()
        if val is not None:
            # don't use a set to preserve determinism if needed
            supp_list = [val + 1, val - 1]

            if vt.mini is not None:
                cond1 = False
                if hasattr(vt, 'size'):
                    cond1 = (vt.mini != 0 or vt.maxi != ((1 << vt.size) - 1)) and \
                       (vt.mini != -(1 << (vt.size-1)) or vt.maxi != ((1 << (vt.size-1)) - 1))
                else:
                    cond1 = True

                if cond1:
                    if vt.mini-1 not in supp_list:
                        supp_list.append(vt.mini-1)
                    if vt.maxi+1 not in supp_list:
                        supp_list.append(vt.maxi+1)

            if specific_fuzzy_vals is not None:
                for v in specific_fuzzy_vals:
                    supp_list.append(v)

            fuzzy_vt_obj = None
            for o in flist:
                # We don't need to check with vt.mini-1 or vt.maxi+1,
                # as the following test will provide the first
                # compliant choice that will also be OK for the
                # previous values (ortherwise, no VT will be OK, and
                # these values will be filtered through the call to
                # extend_value_list())
                if o.is_compatible(val + 1) or o.is_compatible(val - 1):
                    fuzzy_vt_obj = o
                    break

            if fuzzy_vt_obj is not None:
                fuzzy_vt_obj.extend_value_list(supp_list)
                fuzzy_vt_obj.remove_value_list([val])



class SeparatorDisruption(NodeConsumerStub):

    def init_specific(self, separators):
        self._internals_criteria = \
            dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable, dm.NodeInternals.Separator],
                                     node_kinds=[dm.NodeInternals_Term])

        self.val_list = [b'']
        if separators is not None:
            self.val_list += list(separators)

        self.yield_original_val = False
        # self.need_reset_when_structure_change = True

    def consume_node(self, node):
        orig_val = node.to_bytes()
        new_val_list = copy.copy(self.val_list)

        if orig_val in new_val_list:
            new_val_list.remove(orig_val)

        node.cc.import_value_type(value_type=vtype.String(val_list=new_val_list))
        # Note, that node attributes are not altered by this
        # operation, especially usefull in our case, because we have
        # to preserve dm.NodeInternals.Separator

        node.make_finite()
        node.make_determinist()

        return True


def fuzz_data_tree(top_node, paths_regexp=None):

    c = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable],
                             node_kinds=[dm.NodeInternals_NonTerm])

    if paths_regexp:
        node_list = top_node.get_reachable_nodes(path_regexp=paths_regexp)
    else:
        node_list = [top_node]

    for node in node_list:
        l = node.get_reachable_nodes(internals_criteria=c)
        for e in l:
            e.cc.change_subnodes_csts([('*', 'u=.')])

