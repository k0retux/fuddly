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
        self._root_node = root_node #Elt(root_node.name, base_node=root_node)
        self._root_node.make_finite(all_conf=True, recursive=True)
        
        if make_determinist:
            assert(not make_random)
            self._root_node.make_determinist(all_conf=True, recursive=True)
        elif make_random:
            assert(not make_determinist)
            self._root_node.make_random(all_conf=True, recursive=True)

        self._root_node.get_value()

        self._max_steps = int(max_steps)
        self._initial_step = int(initial_step)
        
        assert(self._max_steps > 0 or self._max_steps == -1)

        self.ic = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable, dm.NodeInternals.Finite])

        self.set_consumer(node_consumer)

    def set_consumer(self, node_consumer):
        self._consumer = node_consumer


    def __iter__(self):

        self._cpt = 1

        gen = self.walk_graph_rec([self._root_node], self._consumer.yield_original_val,
                                  structure_has_changed=False, consumed_nodes=set())
        for consumed_node, orig_node_val in gen:
            self._root_node.get_value()

            if self._cpt >= self._initial_step:
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
            yield self._root_node, consumed_node, orig_node_val, self._cpt-1

        return


    def walk_graph_rec(self, node_list, value_not_yielded_yet, structure_has_changed, consumed_nodes):

        reset = False
        guilty = None

        # We iterate over the children nodes of a parent node which is
        # in a frozen state (which means that it may have some
        # children in other states that are not dealt with in this current call)
        for node in node_list:

            perform_sencond_step = True
            again = True

            DEBUG_PRINT('--(1)-> Node:' + node.name + ', exhausted:' + repr(node.is_exhausted()), level=2)

            # We enter here at least once, and if a reset on the same
            # node has been triggered (typically for a non-terminal
            # node)

            while again:
                again = False                  

                if not value_not_yielded_yet:
                    value_not_yielded_yet = False

                if reset or value_not_yielded_yet:
                    value_not_yielded_yet = self._consumer.yield_original_val

                ### STEP 1 ###

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
                if perform_sencond_step:
                    
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
                            perform_sencond_step = False
                            again = True
                            break
                        elif ignore_node and not reset:
                            perform_sencond_step = False
                            again = False
                            break
                        elif reset:
                            perform_sencond_step = True
                            again = True
                            break
                        else:
                            perform_sencond_step = True
                            again = False

                        if value_not_yielded_yet:
                            yield consumed_node, orig_node_val # YIELD
                        else:
                            value_not_yielded_yet = True

                elif self._consumer.need_reset(node) and not node.is_exhausted():
                    again = True
                    # Not consumed so we don't unfreeze() with recursive=True
                    # node.reset_state(recursive=True, exclude_self=True)
                    # node.unfreeze(recursive=False)
                    node.unfreeze(recursive=True, dont_change_state=True)
                    node.unfreeze(recursive=False)

                else:
                    again = False

                if node.is_nonterm():
                    length = node.cc.count_of_possible_cases()
                    structure_has_changed = False if length == 1 else True

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

        orig_node_val = node.get_flatten_value()

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

        if go_on:
            consumed_nodes.add(node)
            node.get_value()
            not_recovered = True
        else:
            # that means forget what has been saved (don't recover)
            not_recovered = False

        max_steps = self._consumer.wait_for_exhaustion(node)
        again = True

        # We enter this loop only if the consumer is interested by the node
        while again:
            reset = self._consumer.need_reset(node)

            if reset and not node.is_exhausted():

                if go_on:
                    yield node, orig_node_val, True, False # --> x, x, reset, dont_ignore_node
                else:
                    # node.reset_state(recursive=True, exclude_self=True)
                    # node.unfreeze(recursive=False)
                    node.unfreeze(recursive=True, dont_change_state=True)
                    node.unfreeze(recursive=False)

                    yield node, orig_node_val, True, True # --> x, x, reset, ignore_node
                    raise ValueError
            
            elif reset and node.is_exhausted():

                yield None, None, False, True # --> x, x, reset, ignore_node
                raise ValueError

            elif node.is_exhausted(): # --> (reset and node.is_exhausted()) or (not reset and node.is_exhausted())

                if go_on:
                    yield node, orig_node_val, False, False
                else:
                    yield node, orig_node_val, False, True
                    raise ValueError

                if self._consumer.interested_by(node):
                    # if not_recovered:
                    #     # We have exhausted the consumed node, so recover it
                    #     self._consumer.recover_node(node)
                    #     not_recovered = True

                    if self._consumer.still_interested_by(node):
                        go_on = self._consumer.consume_node(node)
                    else:
                        go_on = False

                    consume_called_again = True

                    if go_on:
                        node.get_value()
                        not_recovered = True
                    else:
                        self._consumer.recover_node(node)
                        # that means forget what has been saved (don't recover)
                        not_recovered = False
                else:
                    return

            else:
                if go_on:
                    yield node, orig_node_val, False, False
                else:
                    yield node, orig_node_val, False, True
                    raise ValueError

            if max_steps != 0 and not consume_called_again:
                max_steps -= 1
                # In this case we iterate only on the current node
                node.unfreeze(recursive=False)
                node.get_value()
            elif not consume_called_again:
                if not_recovered and self._consumer.interested_by(node):
                    self._consumer.recover_node(node)
                    if not node.is_exhausted() and self._consumer.need_reset(node):
                        # node.reset_state(recursive=True, exclude_self=True)
                        # node.unfreeze(recursive=False)
                        node.unfreeze(recursive=True, dont_change_state=True)
                        node.unfreeze(recursive=False)

                        yield None, None, True, True
                again = False

            else:
                consume_called_again = False

        return



class NodeConsumerStub(object):
    '''
    TOFIX: when respect_order=False, BasicVisitor & NonTermVisitor
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
        
        --> Return True to say that you have correctly consumed the node.
        --> Return False, if despite your current criteria for node interest,
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

    def need_reset(self, node):
        if node.is_nonterm():
            self.consumed = False
            return True
        else:
            return False

    def consume_node(self, node):
        if not self.consumed and not node.is_nonterm():
            self.consumed = True
            return True
        else:
            return False

    def still_interested_by(self, node):
        return False

    def wait_for_exhaustion(self, node):
        if node.is_nonterm():
            return -1 # wait until exhaustion
        else:
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
            DEBUG_PRINT(' *** CONSUME: ' + node.name + ', ' + repr(node.c.keys()))
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
        orig_val = node.get_flatten_value()
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
            self.orig_value = node.get_flatten_value()

            self.current_fuzz_vt_list = self._create_fuzzy_vt_list(node)
            self._extend_fuzzy_vt_list(self.current_fuzz_vt_list, node)

        DEBUG_PRINT(' *** CONSUME: ' + node.name + ', ' + repr(self.current_fuzz_vt_list))

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


def rand_string(size=None, mini=1, maxi=10, str_set=string.printable):

    out = ""
    if size is None:
        size = random.randint(mini, maxi)
    while len(out) < size:
        val = random.choice(str_set)
        out += val

    if sys.version_info[0] > 2:
        out = bytes(out, 'latin_1')
    else:
        out = bytes(out)

    return out


import array

def corrupt_bytes(s, p=0.01, n=None, ctrl_char=False):
    """Corrupt a given percentage or number of bytes from a string"""
    s = bytearray(s)
    l = len(s)
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(range(l), n):
        if ctrl_char:
            s[i] = random.choice([x for x in range(0,32)] + [0x7f])
        else:
            s[i] = (s[i]+random.randint(1,255))%256

    return bytes(s)

def corrupt_bits(s, p=0.01, n=None, ascii=False):
    """Flip a given percentage or number of bits from a string"""
    s = bytearray(s)
    l = len(s)*8
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(range(l), n):
        s[i//8] ^= 1 << (i%8)
        if ascii:
            s[i//8] &= 0x7f

    return bytes(s)



######## OBSOLETE FUNCTIONS #########

# OBSOLETE
def fuzz_typed_values(mem, top_node, paths_regexp=None):

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


    def _extend_fuzzy_vt_list(flist, e):
        vt = e.cc.get_value_type()

        if issubclass(vt.__class__, vtype.VT_Alt):
            return

        specific_fuzzy_vals = e.cc.get_specific_fuzzy_values()

        val = vt.get_current_raw_val()
        if val is not None:
            supp_list = [val + 1, val - 1]
            if specific_fuzzy_vals is not None:
                for v in specific_fuzzy_vals:
                    supp_list.insert(0, v)

            if vt.mini is not None:
                supp_list.append(vt.mini-1)
                supp_list.append(vt.maxi+1)

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

            fuzzy_vt_obj.extend_value_list(supp_list)

    def prepare_new_fuzzy_vt(e):
        mem.current_node_fuzzy_vt_obj = _create_fuzzy_vt_list(e)
        _extend_fuzzy_vt_list(mem.current_node_fuzzy_vt_obj, e)
        
    def save_orig_vt_and_val(e):
        mem.orig_node_vt = e.cc.get_value_type()
        mem.orig_node_val = e.get_flatten_value()

    def restore_orig_vt_and_val(e):
        e.cc.import_value_type(value_type=mem.orig_node_vt)
        e.set_frozen_value(mem.orig_node_val)
        mem.orig_node_vt = None
        mem.orig_node_val = None

    def change_value_type(e):
        vt_obj = mem.current_node_fuzzy_vt_obj.pop(0)
        e.cc.import_value_type(value_type=vt_obj)

        if e.env != mem._env:
            print('\n*** DEBUG - e.env:', e.env)
            raise ValueError


    if mem.new:
        mem.new = False

        mem.tval_nodes_list = []

        mem.internals_criteria = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable],
                                                      node_kinds=[dm.NodeInternals_TypedValue])

        mem.orig_node_vt = None
        mem.orig_node_val = None
        mem.current_node = None
        mem.current_node_fuzzy_vt_obj = None

        top_node.make_finite(all_conf=True, recursive=True)
        top_node.get_value()
        top_node.env.clear_all_exhausted_nodes()

        mem._env = top_node.env

        if paths_regexp:
            node_list = top_node.get_reachable_nodes(path_regexp=paths_regexp)
            if not node_list:
                return None, None, None
        else:
            node_list = [top_node]

        mem.tval_nodes_list = []
        for e in node_list:
            mem.tval_nodes_list += e.get_reachable_nodes(internals_criteria=mem.internals_criteria)

        if len(mem.tval_nodes_list) == 0:
            # if no typed value Node
            return None, None, None

        mem.current_node = mem.tval_nodes_list[0]
        prepare_new_fuzzy_vt(mem.current_node)
        save_orig_vt_and_val(mem.current_node)
        change_value_type(mem.current_node)

    if len(mem.tval_nodes_list) == 0:
        return None, None, None

    exhausted = top_node.env.exhausted_node_exists()

    if len(mem.current_node_fuzzy_vt_obj) != 0 and exhausted:
        top_node.env.clear_exhausted_node(mem.current_node)
        change_value_type(mem.current_node)

    elif len(mem.current_node_fuzzy_vt_obj) != 0 and not exhausted:
        pass

    elif len(mem.current_node_fuzzy_vt_obj) == 0 and exhausted:
        assert(len(mem.tval_nodes_list) != 0)

        top_node.env.clear_exhausted_node(mem.current_node)
        restore_orig_vt_and_val(mem.current_node)

        mem.tval_nodes_list.pop(0)
        if len(mem.tval_nodes_list) == 0:
            return None, None, None

        mem.current_node = mem.tval_nodes_list[0]
        prepare_new_fuzzy_vt(mem.current_node)
        save_orig_vt_and_val(mem.current_node)
        change_value_type(mem.current_node)

    elif len(mem.current_node_fuzzy_vt_obj) == 0 and not exhausted:
        pass

    else:
        raise ValueError('Implementation Error')

    mem.current_node.unfreeze(ignore_entanglement=True)
    mem.current_node.get_value()
    
    return mem.current_node, mem.orig_node_val, len(mem.tval_nodes_list)


# OBSOLETE
def get_node_from_attr(mem, top_node, internals_criteria, paths_regexp=None):

    if mem.new:
        mem.new = False

        mem.val_nodes_list = []
        mem.internals_criteria=internals_criteria

    if paths_regexp:
        mem.val_nodes_list = []

    if len(mem.val_nodes_list) == 0:
        top_node.unfreeze(ignore_entanglement=True)
        top_node.get_value()

        if paths_regexp:
            node_list = top_node.get_reachable_nodes(path_regexp=paths_regexp)
            if not node_list:
                return None, None
        else:
            node_list = [top_node]

        mem.val_nodes_list = []
        for e in node_list:
            mem.val_nodes_list += e.get_reachable_nodes(internals_criteria=mem.internals_criteria)

        random.shuffle(mem.val_nodes_list)
        mem.prev_node_val = None

    if mem.prev_node_val:
        mem.prev_node.set_frozen_value(mem.prev_node_val)

    node = mem.val_nodes_list.pop(0)

    mem.prev_node_val = node.get_value()
    mem.prev_node = node

    return node, len(mem.val_nodes_list)


# OBSOLETE
def get_terminal_node(mem, top_node, paths_regexp=None):

    if mem.new:        
        mem.internals_criteria = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable],
                                                      node_kinds=[dm.NodeInternals_Term])

    return get_node_from_attr(mem, top_node, internals_criteria=mem.internals_criteria, paths_regexp=paths_regexp)



# OBSOLETE
def get_node_with_alt_conf(mem, top_node, conf, paths_regexp=None):

    if mem.new:
        mem.new = False

        mem.val_nodes_list = []
        mem.c = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Mutable])

    if paths_regexp:
        mem.val_nodes_list = []

    if len(mem.val_nodes_list) == 0:
        top_node.make_finite(all_conf=True, recursive=True)
        top_node.unfreeze_all(ignore_entanglement=True)
        top_node.get_value()

        if paths_regexp:
            node_list = top_node.get_reachable_nodes(path_regexp=paths_regexp)
            if not node_list:
                return None, None
        else:
            node_list = [top_node]

        mem.val_nodes_list = []

        for e in node_list:
            mem.val_nodes_list += e.get_reachable_nodes(internals_criteria=mem.c, owned_conf=conf)

        if mem.val_nodes_list == []:
            return None, None

        mem.val_nodes_list = sorted(mem.val_nodes_list, key=lambda x: -x.depth)
        mem.prev_node = None

    if mem.prev_node:
        mem.prev_node.set_current_conf(conf='MAIN', reverse=True, recursive=False)
        mem.prev_node.unfreeze(conf, ignore_entanglement=True)

    node = mem.val_nodes_list.pop(0)
    node.unfreeze(conf, ignore_entanglement=True)

    mem.prev_node = node

    node.set_current_conf(conf=conf, recursive=False)

    return node, len(mem.val_nodes_list)


