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
import sys
import functools
import itertools
import random
import copy
import re
import binascii
import collections
import traceback

sys.path.append('.')

from fuzzfmk.basic_primitives import *
from libs.external_modules import *
from fuzzfmk.global_resources import *

DEBUG = False


class Data(object):

    def __init__(self, data=''):
        self.node = None
        self.raw = None
        self.__type = None

        self._dm = None

        self.__exportable = False
        self.__unusable = False

        self.info_list = []
        self.info = {}
        self.__info_idx = {}

        self._history = None

        if isinstance(data, bytes):
            self.update_from_str_or_bytes(data)
        elif isinstance(data, Node):
            self.update_from_node(data)
        else:
            self.update_from_str_or_bytes(data)

    def set_initial_dmaker(self, t):
        self.__type = t

    def get_initial_dmaker(self):
        return self.__type

    def flatten_copy(self):
        d = Data(self.to_bytes())
        d._dm = self._dm
        d.__exportable = self.__exportable
        d.__unusable = self.__unusable
        d.info = copy.copy(self.info)

        return d

    def update_from_str_or_bytes(self, data_str):
        if sys.version_info[0] > 2 and not isinstance(data_str, bytes):
            data_str = bytes(data_str, 'latin_1')

        self.raw = data_str
        self.node = None

    def update_from_node(self, node):
        self.node = node
        self._dm = node.env.get_data_model()

    def get_data_model(self):
        return self._dm

    def to_bytes(self):
        if self.node:
            val = self.node.to_bytes()
            self.raw = val

        return self.raw


    def make_unusable(self):
        self.__unusable = True

    def is_unusable(self):
        if self.__unusable:
            return True
        else:
            return False

    # Only taken into account if the Logger has been set to
    # export data only when requested (explicit_export == True)
    def make_exportable(self):
        self.__exportable = True

    def is_exportable(self):
        return self.__exportable

    def add_info(self, info_str):
        self.info_list.append(info_str)

    def bind_info(self, data_maker_name, dmaker_type):
        key = (data_maker_name, dmaker_type)
        if key in self.info:
            self.info[key].append(self.info_list)
        else:
            self.info[key] = [self.info_list]

        self.info_list = []

    def init_read_info(self):
        for k in self.info:
            self.__info_idx[k] = 0

    def read_info(self, data_maker_name, dmaker_type):
        key = (data_maker_name, dmaker_type)
        try:
            info_l = self.info[key]
        except KeyError:
            print("\n*** The key " \
                      "({:s}, {:s}) does not exist! ***\n".format(data_maker_name, dmaker_type))
            print("self.info contents: ", self.info)
            return ['']

        try:
            ret = info_l[self.__info_idx[key]]
        except IndexError:
            print("\n**** No more info associated to the key " \
                      "({:s}, {:s})! ***\n".format(data_maker_name, dmaker_type))
            ret = ['']

        self.__info_idx[key] += 1
        return ret

    def set_history(self, hist):
        self._history = hist

    def get_history(self):
        return self._history

    def get_length(self):
        if self.node:
            self.raw = self.node.to_bytes()
        return len(self.raw)

    def materialize(self):
        if self.node is not None:
            self.node.get_value()

    def get_contents(self, copy=False):
        if self.node is not None:
            # we freeze the contents before exporting it
            self.node.get_value()
            if copy:
                contents = Node(self.node.name, base_node=self.node, ignore_frozen_state=False)
            else:
                contents = self.node
        else:
            if copy:
                contents = copy.copy(self.raw)
            else:
                contents = self.raw

        return contents

    def pretty_print(self, log_func=lambda x: x):
        if self.node is not None:
            self.node.show(raw_limit=200, log_func=log_func)
        else:
            print(self.raw)

    def __copy__(self):
        new_data = type(self)()
        new_data.__dict__.update(self.__dict__)
        new_data.info_list = copy.copy(self.info_list)
        new_data.info = copy.copy(self.info)
        new_data.__info_idx = copy.copy(self.__info_idx)
        new_data._history = copy.copy(self._history)
        new_data.__type = copy.copy(self.__type)

        if self.node is not None:
            e = Node(self.node.name, base_node=self.node, ignore_frozen_state=False)
            new_data._dm.set_new_env(e)
            new_data.update_from_node(e)
        return new_data

    def __str__(self):
        if self.node:
            self.raw = self.node.to_bytes()
        return str(self.raw)

    def __repr__(self):
        if self.node:
            self.raw = self.node.to_bytes()
        return repr(self.raw)



def split_with(predicate, iterable):
    l = []
    first = True
    delim = None
    for x in iterable:
        if predicate(x):
            if first:
                first = False
                delim = x
            else:
                yield delim, l
                l = []
                delim = x
        else:
            l.append(x)

    yield delim, l


def split_verbose_with(predicate, iterable):
    l = []
    first = True
    delim = None
    idx = 0

    for x in iterable:
        if predicate(x):
            if first:
                first = False
                prev_idx = idx
                delim = x
            else:
                yield prev_idx, delim, l
                l = []
                delim = x
                prev_idx = idx
        else:
            l.append(x)

        idx += 1

    yield prev_idx, delim, l


def flatten(nested):
    for x in nested:
        if hasattr(x, '__iter__') and not isinstance(x, str) and not isinstance(x, bytes):
            for y in flatten(x):
                yield y
        else:
            yield x


def convert_to_internal_repr(val):
    if isinstance(val, int):
        val = bytes(val)
    else:
        if not isinstance(val, str) and not isinstance(val, bytes):
            val = repr(val)
        if sys.version_info[0] > 2 and not isinstance(val, bytes):
            val = bytes(val, 'latin_1')
    return val


nodes_weight_re = re.compile('(.*?)\((.*)\)')


class AbsorbStatus:

    Accept = 1
    Reject = 2
    Absorbed = 3
    FullyAbsorbed = 4


# List of constraints that rules blob absorption
class AbsCsts(object):

    Size = 1
    Contents = 2
    Regexp = 3
    Structure = 4

    def __init__(self, size=True, contents=True, regexp=True, struct=True):
        self.constraints = {
            AbsCsts.Size: size,
            AbsCsts.Contents: contents,
            AbsCsts.Regexp: regexp,
            AbsCsts.Structure: struct
        }

    def __bool__(self):
        return True in self.constraints.values()

    def __nonzero__(self):
        return True in self.constraints.values()

    def set(self, cst):
        if cst in self.constraints:
            self.constraints[cst] = True
        else:
            raise ValueError

    def clear(self, cst):
        if cst in self.constraints:
            self.constraints[cst] = False
        else:
            raise ValueError

    def __copy__(self):
        new_csts = type(self)()
        new_csts.__dict__.update(self.__dict__)
        new_csts.constraints = copy.copy(self.constraints)

        return new_csts

    def __getitem__(self, key):
        return self.constraints[key]

class AbsNoCsts(AbsCsts):

    def __init__(self, size=False, contents=False, regexp=False, struct=False):
        AbsCsts.__init__(self, size=size, contents=contents, regexp=regexp, struct=struct)


class AbsFullCsts(AbsCsts):

    def __init__(self, size=True, contents=True, regexp=True, struct=True):
        AbsCsts.__init__(self, size=size, contents=contents, regexp=regexp, struct=struct)


class SyncScope:
    Qty = 1
    Existence = 2
    Inexistence = 3

class NodeInternals(object):
    '''Base class for implementing the contents of a node.
    '''

    Freezable = 1
    Mutable = 2
    Determinist = 3
    Finite = 4
    AcceptConfChange = 5
    
    Abs_Postpone = 6

    CloneExtNodeArgs = 7
    ResetOnUnfreeze = 8

    def __init__(self, defaults=True, arg=None):
        self.private = None
        self.absorb_helper = None
        self.absorb_constraints = None

        self.__attrs = {
            NodeInternals.Freezable: True,
            NodeInternals.Mutable: True,
            NodeInternals.Determinist: False,
            NodeInternals.Finite: False,
            NodeInternals.AcceptConfChange: True,

            # Used for absorption
            NodeInternals.Abs_Postpone: False,
            # Used for Gen and Func
            NodeInternals.CloneExtNodeArgs: False,
            # Used for Gen
            NodeInternals.ResetOnUnfreeze: True
            }

        self._sync_with = None
        self._init_specific(arg)

    def _init_specific(self, arg):
        pass

    def has_subkinds(self):
        return False

    def get_current_subkind(self):
        raise NotImplementedError

    def set_node_sync(self, node, scope):
        if self._sync_with is None:
            self._sync_with = {}
        self._sync_with[scope] = node

    def get_node_sync(self, scope):
        if self._sync_with is None:
            return None
        else:
            return self._sync_with.get(scope, None)

    def make_private(self, ignore_frozen_state, accept_external_entanglement, delayed_node_internals):
        if self.private is not None:
            self.private = copy.copy(self.private)
        self.absorb_constraints = copy.copy(self.absorb_constraints)
        self.__attrs = copy.copy(self.__attrs)

        if self._sync_with:
            delayed_node_internals.add(self)
        self._sync_with = copy.copy(self._sync_with)

        self._make_private_specific(ignore_frozen_state, accept_external_entanglement)

    # Called near the end of Node copy (Node.set_contents) to update
    # node references inside the NodeInternals
    def _update_node_refs(self, node_dico, debug):
        sync_nodes = copy.copy(self._sync_with)

        for scope, node in sync_nodes.items():
            new_node = node_dico.get(node, None)
            if new_node is not None:
                self._sync_with[scope] = new_node
            else:
                # this case only triggers during a call to
                # NonTerm.get_subnodes_with_csts(), that is when new
                # subnodes are created during a
                # Node.get_value(). Indeed, when making copies of a
                # node within the NonTerm.subnodes_set, the node_dico
                # of the copies may miss upper nodes. In such a case,
                # no update needs to be done, as the node ref exist
                # and is correct for the base_node, and has no meaning
                # for the copy.
                pass
                # print("\n*** WARNING: node refs not updatable for node '%r'!\n" \
                #       " \_ name: '%s' \n" \
                #       " \_ updated_node: '%s', scope: '%r'\n" % (node, node.name, debug, scope))


    def _make_private_specific(self, ignore_frozen_state, accept_external_entanglement):
        pass


    def absorb(self, blob, constraints, conf):
        raise NotImplementedError

    def set_absorb_helper(self, helper):
        self.absorb_helper = helper

    def enforce_absorb_constraints(self, csts):
        assert(isinstance(csts, AbsCsts))
        self.absorb_constraints = csts

    def set_attr(self, name):
        if name not in self.__attrs:
            raise ValueError
        if self._make_specific(name):
            self.__attrs[name] = True
           
    def clear_attr(self, name):
        if name not in self.__attrs:
            raise ValueError
        if self._unmake_specific(name):
            self.__attrs[name] = False

    # To be used on very specific case only
    def _set_attr_direct(self, name):
        if name not in self.__attrs:
            raise ValueError
        self.__attrs[name] = True

    # To be used on very specific case only
    def _clear_attr_direct(self, name):
        if name not in self.__attrs:
            raise ValueError
        self.__attrs[name] = False

    def is_attr_set(self, name):
        if name not in self.__attrs:
            raise ValueError
        return self.__attrs[name]

    def _make_specific(self, name):
        if name in [NodeInternals.Determinist, NodeInternals.Finite]:
            return False
        else:
            return True

    def _unmake_specific(self, name):
        if name in [NodeInternals.Determinist, NodeInternals.Finite]:
            return False
        else:
            return True

    def _match_mandatory_attrs(self, criteria):
        if criteria is None:
            return True

        for c in criteria:
            if not self.__attrs[c]:
                return False
        return True

    def _match_negative_attrs(self, criteria):
        if criteria is None:
            return True

        for c in criteria:
            if self.__attrs[c]:
                return False
        return True

    def _match_node_kinds(self, criteria):
        if criteria is None:
            return True

        for c in criteria:
            if issubclass(self.__class__, c):
                return True
        return False

    def _match_negative_node_kinds(self, criteria):
        if criteria is None:
            return True

        for c in criteria:
            if issubclass(self.__class__, c):
                return False
        return True

    def _match_node_subkinds(self, criteria):
        if criteria is None:
            return True

        if self.has_subkinds():
            skind = self.get_current_subkind()
            for c in criteria:
                if skind == c:
                    ret = True
                    break
            else:
                ret = False
        else:
            ret = True            

        return ret

    def _match_negative_node_subkinds(self, criteria):
        if criteria is None:
            return True

        if self.has_subkinds():
            skind = self.get_current_subkind()
            for c in criteria:
                if skind == c:
                    ret = False
                    break
            else:
                ret = True
        else:
            ret = True

        return ret

    def match(self, internals_criteria):
        c1 = self._match_mandatory_attrs(internals_criteria.get_mandatory_attrs())
        if not c1:
            return False

        c2 = self._match_negative_attrs(internals_criteria.get_negative_attrs())
        if not c2:
            return False

        c3 = self._match_node_kinds(internals_criteria.get_node_kinds())
        if not c3:
            return False

        c4 = self._match_negative_node_kinds(internals_criteria.get_negative_node_kinds())
        if not c4:
            return False

        c5 = self._match_node_subkinds(internals_criteria.get_node_subkinds())
        if not c5:
            return False

        c6 = self._match_negative_node_subkinds(internals_criteria.get_negative_node_subkinds())
        if not c6:
            return False

        return True

    def set_private(self, val):
        self.private = val

    def get_private(self):
        return self.private

    def set_clone_info(self, info):
        '''
        Report to Node._set_clone_info() some information about graph
        internals

        '''
        pass

    def is_exhausted(self):
        return False

    def is_frozen(self):
        raise NotImplementedError

    def pretty_print(self):
        return None

    def get_value(self, conf=None, recursive=True):
        raise NotImplementedError

    def reset_depth_specific(self, depth):
        pass


class NodeInternalsCriteria(object):

    def __init__(self, mandatory_attrs=None, negative_attrs=None, node_kinds=None,
                 negative_node_kinds=None, node_subkinds=None, negative_node_subkinds=None):
        self.set_mandatory_attrs(mandatory_attrs)
        self.set_negative_attrs(negative_attrs)
        self.set_node_kinds(node_kinds)
        self.set_negative_node_kinds(negative_node_kinds)
        self.set_node_subkinds(node_subkinds)
        self.set_negative_node_subkinds(negative_node_subkinds)

    def extend(self, ic):
        crit = ic.get_mandatory_attrs()
        if crit:
            if self.__mandatory_attrs is None:
                self.__mandatory_attrs = []
            self.__mandatory_attrs.extend(crit)

        crit = ic.get_negative_attrs()
        if crit:
            if self.__negative_attrs is None:
                self.__negative_attrs = []
            self.__negative_attrs.extend(crit)

        crit = ic.get_node_kinds()
        if crit:
            if self.__node_kinds is None:
                self.__node_kinds = []
            self.__node_kinds.extend(crit)

        crit = ic.get_negative_node_kinds()
        if crit:
            if self.__negative_node_kinds is None:
                self.__negative_node_kinds = []
            self.__negative_node_kinds.extend(crit)

        crit = ic.get_node_subkinds()
        if crit:
            if self.__node_subkinds is None:
                self.__node_subkinds = []
            self.__node_subkinds.extend(crit)

        crit = ic.get_negative_node_subkinds()
        if crit:
            if self.__negative_node_subkinds is None:
                self.__negative_node_subkinds = []
            self.__negative_node_subkinds.extend(crit)


    def set_mandatory_attrs(self, attrs):
        self.__mandatory_attrs = attrs

    def get_mandatory_attrs(self):
        return self.__mandatory_attrs

    def set_negative_attrs(self, attrs):
        self.__negative_attrs = attrs

    def get_negative_attrs(self):
        return self.__negative_attrs

    def set_node_kinds(self, node_kinds):
        self.__node_kinds = node_kinds

    def get_node_kinds(self):
        return self.__node_kinds

    def set_negative_node_kinds(self, negative_node_kinds):
        self.__negative_node_kinds = negative_node_kinds

    def get_negative_node_kinds(self):
        return self.__negative_node_kinds

    def set_node_subkinds(self, node_subkinds):
        self.__node_subkinds = node_subkinds

    def get_node_subkinds(self):
        return self.__node_subkinds

    def set_negative_node_subkinds(self, negative_node_subkinds):
        self.__negative_node_subkinds = negative_node_subkinds

    def get_negative_node_subkinds(self):
        return self.__negative_node_subkinds


class DynNode_Helpers(object):
    
    def __init__(self):
        self.graph_info = []

    def __copy__(self):
        new_obj = type(self)()
        new_obj.graph_info = copy.copy(self.graph_info)
        return new_obj


class NodeInternals_Empty(NodeInternals):
    def get_value(self, conf=None, recursive=True):
        return b'<EMPTY>', True

    def set_child_env(self, env):
        print('Empty:', hex(id(self)))
        raise AttributeError


class NodeInternals_GenFunc(NodeInternals):
    def _init_specific(self, arg):
        self.__generated_node = None
        self.generator_func = None
        self.generator_arg = None
        self.node_arg = None
        self.env = None
        self.pdepth = 0
        self._node_helpers = DynNode_Helpers()
        self.provide_helpers = False
        # self._clear_attr_direct(NodeInternals.AcceptConfChange)
        # self.enforce_absorb_constraints(AbsNoCsts())

    def get_node_args(self):
        if issubclass(self.node_arg.__class__, NodeAbstraction):
            nodes = self.node_arg.get_concrete_nodes()
            for n in nodes:
                yield n
        elif isinstance(self.node_arg, list):
            for n in self.node_arg:
                yield n
        elif isinstance(self.node_arg, Node):
            yield self.node_arg
        else:
            return

    def _make_specific(self, name):
        # We don't propagate Mutable & Freezable to the generated_node,
        # because these attributes are used to change the behaviour of
        # the GenFunc.
        if name not in [NodeInternals.Mutable, NodeInternals.Freezable]:
            if self.__generated_node is not None:
                self.generated_node.set_attr(name)
        return True

    def _unmake_specific(self, name):
        if name not in [NodeInternals.Mutable, NodeInternals.Freezable]:
            if self.__generated_node is not None:
                self.generated_node.clear_attr(name)
        return True

    def _make_private_specific(self, ignore_frozen_state, accept_external_entanglement):
        # Note that the 'node_arg' attribute is directly dealt with in
        # Node.__init__() during copy (which calls self.make_args_private()),
        # because the new Node to point to is unknown at this local
        # stage.
        if self.__generated_node is None or ignore_frozen_state:
            self.__generated_node = None
        else:
            self.__generated_node = Node(self.__generated_node.name, base_node=self.__generated_node,
                                       ignore_frozen_state=ignore_frozen_state,
                                       accept_external_entanglement=accept_external_entanglement)
            self.__generated_node._reset_depth(parent_depth=self.pdepth)
            self.__generated_node.set_env(self.env)
        self.generator_arg = copy.copy(self.generator_arg)
        self._node_helpers = copy.copy(self._node_helpers)

    def make_args_private(self, node_dico, entangled_set, ignore_frozen_state, accept_external_entanglement):

        if self.node_arg is None:
            return

        if issubclass(self.node_arg.__class__, NodeAbstraction):
            self.node_arg = copy.copy(self.node_arg)
            self.node_arg.make_private()
            func_node_arg = self.node_arg.get_concrete_nodes()
        else:
            func_node_arg = self.node_arg

        if isinstance(func_node_arg, Node):
            if func_node_arg not in node_dico:
                if DEBUG:
                    print("/!\\ WARNING /!\\ [Copy of a NonTerm Node]\n" \
                              " A copied Func_Elt has its 'node_arg' attribute" \
                              " that does not point to an Node of the copied Node tree")
                    print("--> guilty: ", func_node_arg.name)
                    print("NOTE: Often a normal behavior if the generator is duplicated" \
                          " within a nonterm node that does not contain the node args.")

                if self.is_attr_set(NodeInternals.CloneExtNodeArgs):
                    node = Node(func_node_arg.name, base_node=func_node_arg,
                                copy_dico=node_dico, accept_external_entanglement=False)
                else:
                    node = func_node_arg

                node_dico[func_node_arg] = node
                new_node = node
            else:
                new_node = node_dico[func_node_arg]

            if issubclass(self.node_arg.__class__, NodeAbstraction):
                self.node_arg.set_concrete_nodes(new_node)
            else:
                self.node_arg = new_node

            if new_node.entangled_nodes is not None and ((not ignore_frozen_state) or accept_external_entanglement):
                entangled_set.add(new_node)
            else:
                new_node.entangled_nodes = None

        # old_node is thus either a NodeAbstraction or a list
        else:
            l = []
            for e in func_node_arg:
                if e is not None:
                    if e not in node_dico:
                        if DEBUG:
                            print("/!\\ WARNING /!\\ [Copy of a NonTerm Node]\n" \
                                      " A copied Func_Elt has its 'node_arg' attribute" \
                                      " that does not point to an Node of the copied Node tree")
                            print("--> guilty: ", e.name)
                            print("NOTE: Often a normal behavior if the generator is duplicated" \
                                  " within a nonterm node that does not contain the node args.")
                        if self.is_attr_set(NodeInternals.CloneExtNodeArgs):
                            node = Node(e.name, base_node=e, copy_dico=node_dico,
                                      accept_external_entanglement=False)
                        else:
                            node = e

                        node_dico[e] = node
                        l.append(node)
                    else:
                        l.append(node_dico[e])
                else:
                    l.append(None)

                if node_dico[e].entangled_nodes is not None and ((not ignore_frozen_state) or accept_external_entanglement):
                    entangled_set.add(node_dico[e])
                else:
                    node_dico[e].entangled_nodes = None

            if issubclass(self.node_arg.__class__, NodeAbstraction):
                self.node_arg.set_concrete_nodes(l)
            else:
                self.node_arg = l


    def reset_generator(self):
        self.__generated_node = None

    def __get_generated_node(self):
        if self.__generated_node is None:
            
            if self.generator_arg is not None and self.node_arg is not None:
                if self.provide_helpers:
                    ret = self.generator_func(self.node_arg,
                                              self.generator_arg, self._node_helpers)
                else:
                    ret = self.generator_func(self.node_arg, self.generator_arg)
            elif self.node_arg is not None:
                if self.provide_helpers:
                    ret = self.generator_func(self.node_arg, self._node_helpers)
                else:
                    ret = self.generator_func(self.node_arg)
            elif self.generator_arg is not None:
                if self.provide_helpers:
                    ret = self.generator_func(self.generator_arg, self._node_helpers)
                else:
                    ret = self.generator_func(self.generator_arg)
            else:
                if self.provide_helpers:
                    ret = self.generator_func(self._node_helpers)
                else:
                    ret = self.generator_func()

            if isinstance(ret, tuple):
                ret, private_val = ret
                self.set_private(private_val)

            self.__generated_node = ret
            self.__generated_node._reset_depth(parent_depth=self.pdepth)
            self.__generated_node.set_env(self.env)

            if self.is_attr_set(NodeInternals.Determinist):
                self.__generated_node.make_determinist(all_conf=True, recursive=True)
            if self.is_attr_set(NodeInternals.Finite):
                self.__generated_node.make_finite(all_conf=True, recursive=True)

        return self.__generated_node

    generated_node = property(fget=__get_generated_node)

    def import_generator_func(self, generator_func,
                              generator_node_arg=None, generator_arg=None,
                              provide_helpers=False):
        self.provide_helpers = provide_helpers

        if generator_func != None:
            self.generator_func = generator_func
        else:
            raise ValueError("The 'generator_func' argument shall not be None!")

        self.node_arg = generator_node_arg
        self.generator_arg = generator_arg


    def set_generator_func_arg(self, generator_node_arg=None, generator_arg=None):
        if generator_node_arg is None and generator_arg is None:
            raise ValueError("At least an argument shall not be None!")

        if generator_node_arg is not None:
            self.node_arg = generator_node_arg
        if generator_arg is not None:
            self.generator_arg = generator_arg


    def get_value(self, conf=None, recursive=True):
        if not self.is_attr_set(NodeInternals.Freezable):
            self.reset_generator()
        ret = self.generated_node.get_value(conf=conf, recursive=recursive)
        return (ret, False)


    def absorb(self, blob, constraints, conf):
        # we make the generator freezable to be sure that get_value()
        # won't reset it after absorption
        self.set_attr(NodeInternals.Freezable)

        if self.absorb_constraints is not None:
            constraints = self.absorb_constraints

        # Will help for possible future node types, as the current
        # node types that can raise exceptions, handle them already.
        try:
            st, off, sz, name = self.generated_node.absorb(blob, constraints=constraints, conf=conf)
        except (ValueError, AssertionError) as e:
            st, off, sz = AbsorbStatus.Reject, 0, None
            print('\n***TEST')

        # if st is AbsorbStatus.Reject:
        #     self.reset_generator()

        return st, off, sz


    def reset_state(self, recursive=False, exclude_self=False, conf=None, ignore_entanglement=False):
        if self.is_attr_set(NodeInternals.Mutable):
            self.reset_generator()
        else:
            self.generated_node.reset_state(recursive, exclude_self=exclude_self, conf=conf,
                                           ignore_entanglement=ignore_entanglement)

    def is_exhausted(self):
        if self.is_attr_set(NodeInternals.Mutable) and self.is_attr_set(NodeInternals.Finite):
            # we return True because it does not make sense to return
            # self.generated_node.is_exhausted(), as self.generated_node
            # will change over unfreeze() calls
            return True
        elif self.is_attr_set(NodeInternals.Mutable) and not self.is_attr_set(NodeInternals.Finite):
            return False
        else:
            return self.generated_node.is_exhausted()

    def is_frozen(self):
        if self.is_attr_set(NodeInternals.Mutable):
            if self.__generated_node is None:
                return False
            else:
                return True
        else:
            return self.generated_node.is_frozen()

    def unfreeze(self, conf=None, recursive=True, dont_change_state=False, ignore_entanglement=False, only_generators=False):
        # if self.is_attr_set(NodeInternals.Mutable): 
        if self.is_attr_set(NodeInternals.ResetOnUnfreeze):
            # 'dont_change_state' is not supported in this case. But
            # if generator is stateless, it should not be a problem
            self.reset_generator()
        else:
            self.generated_node.unfreeze(conf, recursive=recursive, dont_change_state=dont_change_state,
                                        ignore_entanglement=ignore_entanglement, only_generators=only_generators)

    def unfreeze_all(self, recursive=True, ignore_entanglement=False):
        # if self.is_attr_set(NodeInternals.Mutable):
        if self.is_attr_set(NodeInternals.ResetOnUnfreeze):
            self.reset_generator()
        else:
            self.generated_node.unfreeze_all(recursive=recursive, ignore_entanglement=ignore_entanglement)

    def reset_fuzz_weight(self, recursive):
        if recursive:
            if self.__generated_node is not None:
                self.generated_node.reset_fuzz_weight(recursive=recursive)

    def set_child_env(self, env):
        if self.__generated_node is not None:
            self.__generated_node.set_env(env)
        self.env = env


    def set_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        if recursive:
            if self.__generated_node is not None:
                self.generated_node.set_attr(name, conf=conf, all_conf=all_conf, recursive=recursive)

    def clear_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        if recursive:
            if self.__generated_node is not None:
                self.generated_node.clear_attr(name, conf=conf, all_conf=all_conf, recursive=recursive)


    def reset_depth_specific(self, depth):
        self.pdepth = depth
        if self.__generated_node is not None:
            self.__generated_node._reset_depth(parent_depth=self.pdepth)

    def get_child_nodes_by_attr(self, internals_criteria, semantics_criteria, owned_conf, conf, path_regexp, 
                               exclude_self, respect_order, relative_depth, top_node):
        return self.generated_node.get_reachable_nodes(internals_criteria, semantics_criteria, owned_conf, conf,
                                                      path_regexp=path_regexp, exclude_self=exclude_self,
                                                      respect_order=respect_order, relative_depth=relative_depth, top_node=top_node)

    def set_child_current_conf(self, node, conf, reverse, ignore_entanglement):
        if self.is_attr_set(NodeInternals.AcceptConfChange):
            if self.__generated_node is not None:
                node._set_subtrees_current_conf(self.generated_node,
                                               conf, reverse,
                                               ignore_entanglement=ignore_entanglement)

    def get_child_all_path(self, name, htable, conf, recursive):
        self.generated_node._get_all_paths_rec(name, htable, conf, recursive=recursive, first=False)


    def set_clone_info(self, info):
        self._node_helpers.graph_info.insert(0, info)


class NodeInternals_Term(NodeInternals):
    def _init_specific(self, arg):
        self.frozen_node = None

    @staticmethod
    def _convert_to_internal_repr(val):
        if not isinstance(val, str) and not isinstance(val, bytes):
            val = repr(val)
        if sys.version_info[0] > 2 and not isinstance(val, bytes):
            val = bytes(val, 'latin_1')
        return val


    def _make_private_specific(self, ignore_frozen_state, accept_external_entanglement):
        if ignore_frozen_state:
            self.frozen_node = None
        else:
            self.frozen_node = self.frozen_node

        self._make_private_term_specific(ignore_frozen_state, accept_external_entanglement)

    def _make_private_term_specific(self, ignore_frozen_state, accept_external_entanglement):
        pass
        
    def _set_frozen_value(self, val):
        self.frozen_node = val

    def get_value(self, conf=None, recursive=True):

        if self.frozen_node is not None:
            return (self.frozen_node, False)

        val = self._get_value_specific(conf, recursive)

        if self.is_attr_set(NodeInternals.Freezable):
            self.frozen_node = val

        return (val, True)

    def _get_value_specific(self, conf, recursive):
        raise NotImplementedError


    def absorb(self, blob, constraints, conf):
        status = None
        size = None

        if self.absorb_constraints is not None:
            constraints = self.absorb_constraints

        if self.absorb_helper is not None:
            try:
                status, off, size = self.absorb_helper(blob, constraints, self)
            except:
                print("Warning: absorb_helper '{!r}' has crashed! (thus, use default values)".format(self.absorb_helper))
                status, off, size = AbsorbStatus.Accept, 0, None
        else:
            status, off, size = self.absorb_auto_helper(blob, constraints=constraints)

        if status == AbsorbStatus.Reject:
            st = status
            self.frozen_node = b''
        elif status == AbsorbStatus.Accept:
            try:
                self.frozen_node, off, size = self.do_absorb(blob, constraints=constraints, off=off, size=size)
            except (ValueError, AssertionError) as e:
                st = AbsorbStatus.Reject
                self.frozen_node = b''
            else:
                st = AbsorbStatus.Absorbed
        else:
            raise ValueError

        return st, off, size

    def absorb_auto_helper(self, blob, constraints):
        raise NotImplementedError

    def do_absorb(self, blob, constraints, off, size):
        raise NotImplementedError

    def reset_state(self, recursive=False, exclude_self=False, conf=None, ignore_entanglement=False):
        self._reset_state_specific(recursive, exclude_self, conf, ignore_entanglement)
        if not exclude_self:
            self.frozen_node = None

    def _reset_state_specific(self, recursive, exclude_self, conf, ignore_entanglement):
        raise NotImplementedError

    def is_exhausted(self):
        return False

    def is_frozen(self):
        return self.frozen_node is not None

    def unfreeze(self, conf=None, recursive=True, dont_change_state=False, ignore_entanglement=False, only_generators=False):
        if only_generators:
            return
        if dont_change_state and self.frozen_node is not None:
            self._unfreeze_without_state_change(self.frozen_node)
        self.frozen_node = None

    def _unfreeze_without_state_change(self, current_val):
        pass

    def unfreeze_all(self, recursive=True, ignore_entanglement=False):
        self.frozen_node = None

    def reset_fuzz_weight(self, recursive):
        pass

    def set_child_env(self, env):
        pass

    def set_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        pass

    def clear_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        pass

    def reset_depth_specific(self, depth):
        pass

    def get_child_nodes_by_attr(self, internals_criteria, semantics_criteria, owned_conf, conf, path_regexp,
                               exclude_self, respect_order, relative_depth, top_node):
        return None

    def set_child_current_conf(self, node, conf, reverse, ignore_entanglement):
        pass

    def get_child_all_path(self, name, htable, conf, recursive):
        pass


class NodeInternals_TypedValue(NodeInternals_Term):
    def _init_specific(self, arg):
        NodeInternals_Term._init_specific(self, arg)
        self.value_type = None
        self.__fuzzy_values = None

    def _make_specific(self, name):
        if name == NodeInternals.Determinist:
            self.value_type.make_determinist()
        return True

    def _unmake_specific(self, name):
        if name == NodeInternals.Determinist:
            self.value_type.make_random()
        return True

    def import_value_type(self, value_type):
        self.value_type = value_type
        if self.is_attr_set(NodeInternals.Determinist):
            self.value_type.make_determinist()
        else:
            self.value_type.make_random()

    def has_subkinds(self):
        return True

    def get_current_subkind(self):
        return self.value_type.__class__

    def get_value_type(self):
        return self.value_type

    def set_specific_fuzzy_values(self, vals):
        self.__fuzzy_values = vals

    def get_specific_fuzzy_values(self):
        return self.__fuzzy_values

    def _make_private_term_specific(self, ignore_frozen_state, accept_external_entanglement):
        self.value_type = copy.copy(self.value_type)
        self.value_type.make_private(forget_current_state=ignore_frozen_state)
        if self.is_attr_set(NodeInternals.Determinist):
            self.value_type.make_determinist()
        else:
            self.value_type.make_random()
        self.__fuzzy_values = copy.copy(self.__fuzzy_values)

    def _get_value_specific(self, conf=None, recursive=True):
        ret = self.value_type.get_value()
        return NodeInternals_Term._convert_to_internal_repr(ret)

    def get_raw_value(self):
        return self.value_type.get_current_raw_val()
        
    def absorb_auto_helper(self, blob, constraints):
        return self.value_type.absorb_auto_helper(blob, constraints)

    def do_absorb(self, blob, constraints, off, size):
        return self.value_type.do_absorb(blob=blob, constraints=constraints, off=off, size=size)

    def _unfreeze_without_state_change(self, current_val):
        self.value_type.rewind()

    def _reset_state_specific(self, recursive, exclude_self, conf, ignore_entanglement):
        self.value_type.reset_state()

    def is_exhausted(self):
        if self.is_attr_set(NodeInternals.Finite):
            return self.value_type.is_exhausted()
        else:
            return False

    def pretty_print(self):
        return self.value_type.pretty_print()

    def __getattr__(self, name):
        vt = self.__getattribute__('value_type')
        if hasattr(vt, name):
            # to avoid looping in __getattr__
            return vt.__getattribute__(name)
        else:
            return object.__getattribute__(self, name)

class NodeInternals_Func(NodeInternals_Term):
    def _init_specific(self, arg):
        NodeInternals_Term._init_specific(self, arg)
        self.fct = None
        self.node_arg = None
        self.fct_arg = None

        self.__mode = None
        self._node_helpers = DynNode_Helpers()
        self.provide_helpers = False
        self.set_mode(1)
        
    def import_func(self, fct, fct_node_arg=None, fct_arg=None,
                    provide_helpers=False):

        self.provide_helpers = provide_helpers

        if fct != None:
            self.fct = fct
        else:
            raise ValueError("The 'fct' argument shall not be None!")

        if fct_node_arg is not None:
            self.node_arg = fct_node_arg
        if fct_arg is not None:
            self.fct_arg = fct_arg

    def get_node_args(self):
        if issubclass(self.node_arg.__class__, NodeAbstraction):
            nodes = self.node_arg.get_concrete_nodes()
            for n in nodes:
                yield n
        elif isinstance(self.node_arg, list):
            for n in self.node_arg:
                yield n
        elif isinstance(self.node_arg, Node):
            yield self.node_arg
        else:
            return

    def set_func_arg(self, node=None, fct_arg=None):
        if node is None and fct_arg is None:
            raise ValueError("At least an argument shall not be None!")

        if node is not None:
            self.node_arg = node
        if fct_arg is not None:
            self.fct_arg = fct_arg


    def set_mode(self, mode):
        self.__mode = mode

        if mode == 1:
            self._get_value_specific = self.__get_value_specific_mode1
        elif mode == 2:
            self._get_value_specific = self.__get_value_specific_mode2
        else:
            raise ValueError

    def set_clone_info(self, info):
        self._node_helpers.graph_info.insert(0, info)

    def make_args_private(self, node_dico, entangled_set, ignore_frozen_state, accept_external_entanglement):
        if self.node_arg is None:
            return

        if issubclass(self.node_arg.__class__, NodeAbstraction):
            self.node_arg = copy.copy(self.node_arg)
            self.node_arg.make_private()
            func_node_arg = self.node_arg.get_concrete_nodes()
        else:
            func_node_arg = self.node_arg

        if isinstance(func_node_arg, Node):
            if func_node_arg not in node_dico:
                if DEBUG:
                    print("/!\\ WARNING /!\\ [Copy of a NonTerm Node]\n" \
                              " A copied Func_Elt has its 'node_arg' attribute" \
                              " that does not point to an Node of the copied Node tree")
                    print("--> guilty: ", func_node_arg.name)
                    print("NOTE: Often a normal behavior if the function is duplicated" \
                          " within a nonterm node that does not contain the node args.")
                if self.is_attr_set(NodeInternals.CloneExtNodeArgs):
                    node = Node(func_node_arg.name, base_node=func_node_arg,
                              copy_dico=node_dico, accept_external_entanglement=False)
                else:
                    node = func_node_arg

                node_dico[func_node_arg] = node
                new_node = node
            else:
                new_node = node_dico[func_node_arg]

            if issubclass(self.node_arg.__class__, NodeAbstraction):
                self.node_arg.set_concrete_nodes(new_node)
            else:
                self.node_arg = new_node

            if new_node.entangled_nodes is not None and ((not ignore_frozen_state) or accept_external_entanglement):
                entangled_set.add(new_node)
            else:
                new_node.entangled_nodes = None

        # old_node is thus either a NodeAbstraction or a list
        else:
            l = []
            for e in func_node_arg:
                if e is not None:
                    if e not in node_dico:
                        if DEBUG:
                            print("/!\\ WARNING /!\\ [Copy of a NonTerm Node]\n" \
                                      " A copied Func_Elt has its 'node_arg' attribute" \
                                      " that does not point to an Node of the copied Node tree")
                            print("--> guilty: ", e.name)
                            print("NOTE: Often a normal behavior if the function is duplicated" \
                                  " within a nonterm node that does not contain the node args.")
                        if self.is_attr_set(NodeInternals.CloneExtNodeArgs):
                            node = Node(e.name, base_node=e, copy_dico=node_dico,
                                      accept_external_entanglement=False)
                        else:
                            node = e

                        node_dico[e] = node
                        l.append(node)
                    else:
                        l.append(node_dico[e])
                else:
                    l.append(None)

                if node_dico[e].entangled_nodes is not None and ((not ignore_frozen_state) or accept_external_entanglement):
                    entangled_set.add(node_dico[e])
                else:
                    node_dico[e].entangled_nodes = None

            if issubclass(self.node_arg.__class__, NodeAbstraction):
                self.node_arg.set_concrete_nodes(l)
            else:
                self.node_arg = l


    def _make_private_term_specific(self, ignore_frozen_state, accept_external_entanglement):
        # Note that the 'node_arg' attribute is directly dealt with in
        # Node.__init__() during copy (which calls
        # self.make_args_private()), because the new Node to point to
        # is unknown at this local stage.
        self.fct_arg = copy.copy(self.fct_arg)

        # This is MANDATORY, because when this object is copied, the
        # new _get_value_specific() still points to the bounded method
        # of the copied object, and thus the bounded 'node_arg'
        # attribute used by this function is not what we want for the new object
        self.set_mode(self.__mode)

        self._node_helpers = copy.copy(self._node_helpers)


    def absorb(self, blob, constraints, conf):
        # we make the generator freezable to be sure that get_value()
        # won't reset it after absorption
        self.set_attr(NodeInternals.Freezable)

        sz = len(convert_to_internal_repr(self.get_value()))

        self._set_frozen_value(blob[:sz])

        return AbsorbStatus.Absorbed, 0, sz


    def _get_value_specific(self, conf, recursive):
        raise NotImplementedError

    def _unfreeze_without_state_change(self, current_val):
        # 'dont_change_state' is not supported in this case. But
        # if the function is stateless, it should not be a problem
        pass

    def _reset_state_specific(self, recursive, exclude_self, conf, ignore_entanglement):
        pass

    def __get_value_specific_mode1(self, conf, recursive):
        '''
        In mode1, we freeze 'node_arg' attribute and give the value to the function
        '''
        if self.node_arg is not None:
            if issubclass(self.node_arg.__class__, NodeAbstraction):
                func_node_arg = self.node_arg.get_concrete_nodes()
            else:
                func_node_arg = self.node_arg

            if isinstance(func_node_arg, Node):
                val = func_node_arg.to_bytes(conf=conf, recursive=recursive)
            # if not an Node it is either a NodeAbstraction or a list
            else:
                val = []
                for e in func_node_arg:
                    if e is not None:
                        val.append(e.to_bytes(conf=conf, recursive=recursive))
                    else:
                        val.append(b'')

        if self.fct_arg is not None and self.node_arg is not None:
            if self.provide_helpers:
                ret = self.fct(val, self.fct_arg, self._node_helpers)
            else:
                ret = self.fct(val, self.fct_arg)
        elif self.node_arg is not None:
            if self.provide_helpers:
                ret = self.fct(val, self._node_helpers)
            else:
                ret = self.fct(val)
        elif self.fct_arg is not None:
            if self.provide_helpers:
                ret = self.fct(self.fct_arg, self._node_helpers)
            else:
                ret = self.fct(self.fct_arg)
        else:
            if self.provide_helpers:
                ret = self.fct(self._node_helpers)
            else:
                ret = self.fct()

        if isinstance(ret, tuple):
            ret, private_val = ret
            self.set_private(private_val)

        return NodeInternals_Term._convert_to_internal_repr(ret)


    def __get_value_specific_mode2(self, conf, recursive):
        '''
        In mode2, we give the 'node_arg' to the function and let it do whatever it wants
        '''

        if self.fct_arg is not None and self.node_arg is not None:
            if self.provide_helpers:
                ret = self.fct(self.node_arg, self.fct_arg, self._node_helpers)
            else:
                ret = self.fct(self.node_arg, self.fct_arg)
        elif self.node_arg is not None:
            if self.provide_helpers:
                ret = self.fct(self.node_arg, self._node_helpers)
            else:
                ret = self.fct(self.node_arg)
        elif self.fct_arg is not None:
            if self.provide_helpers:
                ret = self.fct(self.fct_arg, self._node_helpers)
            else:
                ret = self.fct(self.fct_arg)
        else:
            if self.provide_helpers:
                ret = self.fct(self._node_helpers)
            else:
                ret = self.fct()

        if isinstance(ret, tuple):
            ret, private_val = ret
            self.set_private(private_val)

        return NodeInternals_Term._convert_to_internal_repr(ret)



class NodeInternals_NonTerm(NodeInternals):
    '''It is a kind of node internals that enable to structure the graph
    through a specific grammar...
    '''

    def _init_specific(self, arg):
        self.reset()

    def reset(self, nodes_drawn_qty=None, mode=None, exhaust_info=None):
        self.frozen_node_list = None
        self.subnodes_set = set()
        self.subnodes_csts = []
        self.subnodes_csts_total_weight = 0

        if exhaust_info is None:
            self.exhausted = False
            self.excluded_components = []
        else:
            self.exhausted = exhaust_info[0]
            self.excluded_components = exhaust_info[1]

        if mode is None:
            self.mode = 1
        else:
            self.mode = mode
        if nodes_drawn_qty is None:
            self._nodes_drawn_qty = {}
        else:
            self._nodes_drawn_qty = nodes_drawn_qty

    def set_mode(self, m):
        if 2 >= m >= 1:
            self.mode = m
        else:
            raise ValueError

    def __iter_csts(self, node_list):
        for delim, sublist in node_list:
            yield delim, sublist

    def __iter_csts_verbose(self, node_list):
        idx = 0
        for delim, sublist in node_list:
            yield idx, delim, sublist
            idx += 1

    def import_subnodes_basic(self, node_list):
        self.reset()

        tmp_list = ['u>']

        l = []
        for e in node_list:
            l.append([e, 1])

        tmp_list.append(l)

        self.subnodes_csts = [1, [tmp_list]]
        self.subnodes_csts_total_weight = 1

        for e in node_list:
            self.subnodes_set.add(e)


    def import_subnodes_with_csts(self, wlnode_list):
        self.reset()

        for weight, lnode_list in split_with(lambda x: isinstance(x, int), wlnode_list):
            self.subnodes_csts.append(weight)
            self.subnodes_csts_total_weight += weight
            
            subnode_list = []
            for delim, sublist in split_with(lambda x: isinstance(x, str), lnode_list[0]):

                for e in sublist:
                    self.subnodes_set.add(e[0])

                chunk = []

                if delim[:3] == 'u=+' or delim[:3] == 's=+':

                    weight_l = None
                    weight = nodes_weight_re.search(delim)
                    if weight:
                        weight_total = 0
                        weight_l = []
                        l = weight.group(2).split(',')
                        for i in l:
                            w = int(i)
                            weight_l.append(w)
                            weight_total += w

                    if weight_l:
                        new_l = []
                        for w, etp in zip(weight_l, sublist):
                            new_l.append(w)
                            new_l.append(etp)
                        sublist = new_l
                    else:
                        weight_total = -1

                    chunk.append(delim[:3])
                    chunk.append([weight_total, list(sublist)])

                else:
                    chunk.append(delim)
                    chunk.append(list(sublist))

                subnode_list.append(chunk)

            self.subnodes_csts.append(subnode_list)


    def import_subnodes_full_format(self, subnodes_csts=None, frozen_node_list=None, internals=None,
                                   nodes_drawn_qty=None, mode=None, exhaust_info=None):
        self.reset(nodes_drawn_qty=nodes_drawn_qty, mode=mode, exhaust_info=exhaust_info)

        if internals is not None:
            self.subnodes_csts = internals.subnodes_csts
            self.frozen_node_list = internals.frozen_node_list
        elif subnodes_csts is not None:
            self.subnodes_csts = subnodes_csts
            self.frozen_node_list = frozen_node_list
        else:
            raise ValueError
        
        for weight, lnode_list in split_with(lambda x: isinstance(x, int), self.subnodes_csts):
            self.subnodes_csts_total_weight += weight
            for delim, sublist in self.__iter_csts(lnode_list[0]):
                if delim[:3] == 'u=+' or delim[:3] == 's=+':
                    for w, etp in split_with(lambda x: isinstance(x, int), sublist[1]):
                        for n in etp:
                            self.subnodes_set.add(n[0])
                else:
                    for e in sublist:
                        self.subnodes_set.add(e[0])


    def change_subnodes_csts(self, csts_ch):

        modified_csts = {}

        for orig, new in csts_ch:
            for weight, lnode_list in split_with(lambda x: isinstance(x, int),
                                                 self.subnodes_csts):

                node_list = lnode_list[0]

                if id(node_list) not in modified_csts:
                    modified_csts[id(node_list)] = []
                
                for idx, delim, sublist in self.__iter_csts_verbose(node_list):

                    if delim == orig or orig == '*':
                        if idx not in modified_csts[id(node_list)]:
                            if delim == 'u=+' and delim != new:
                                new_l = []
                                for w, etp in split_with(lambda x: isinstance(x, int), sublist[1]):
                                    new_l.append(etp[0])

                                node_list[idx] = [new, new_l]
                            else:
                                node_list[idx][0] = new

                            modified_csts[id(node_list)].append(idx)


    def make_private_subnodes(self, node_dico, func_nodes, env, ignore_frozen_state,
                              accept_external_entanglement, entangled_set, delayed_node_internals):

        subnodes_csts = self.get_subnodes_csts_copy(node_dico)

        # copy the 'frozen_node_list' if it is not None
        if self.frozen_node_list is None or ignore_frozen_state:
            new_fl = None
            new_nodes_drawn_qty = None
            new_exhaust_info = None
        else:
            new_exhaust_info = [self.exhausted, copy.copy(self.excluded_components)]
            new_nodes_drawn_qty = copy.copy(self._nodes_drawn_qty)
            new_fl = []
            for e in self.frozen_node_list:
                if e not in node_dico:
                    new_e = copy.copy(e)
                    new_e.internals = copy.copy(e.internals)
                    for c in e.internals:
                        new_e.internals[c] = copy.copy(e.internals[c])
                        # make_private() call is postponed 
                    node_dico[e] = new_e
                new_fl.append(node_dico[e])


        self.import_subnodes_full_format(subnodes_csts=subnodes_csts, frozen_node_list=new_fl,
                                         nodes_drawn_qty=new_nodes_drawn_qty, mode=self.mode,
                                         exhaust_info=new_exhaust_info)

        if self.frozen_node_list is None or ignore_frozen_state:
            iterable = self.subnodes_set
        else:
            iterable = set()
            iterable.update(self.subnodes_set)
            iterable.update(self.frozen_node_list)

        # iterable shall only have unique nodes
        for e in iterable:
            e.env = env

            if e.entangled_nodes is not None and ((not ignore_frozen_state) or accept_external_entanglement):
                entangled_set.add(e)
            else:
                e.entangled_nodes = None

            for c in e.internals:
                if e.is_nonterm(c):
                    e.internals[c].make_private_subnodes(node_dico, func_nodes, env,
                                                         ignore_frozen_state=ignore_frozen_state,
                                                         accept_external_entanglement=accept_external_entanglement,
                                                         entangled_set=entangled_set,
                                                         delayed_node_internals=delayed_node_internals)
                    e.internals[c].make_private(ignore_frozen_state=ignore_frozen_state,
                                                accept_external_entanglement=accept_external_entanglement,
                                                delayed_node_internals=delayed_node_internals)

                elif e.is_func(c) or e.is_genfunc(c):
                    if e.internals[c].node_arg is not None:
                        func_nodes.add(e)
                    e.internals[c].make_private(ignore_frozen_state=ignore_frozen_state,
                                                accept_external_entanglement=accept_external_entanglement,
                                                delayed_node_internals=delayed_node_internals)

                else:
                    e.internals[c].make_private(ignore_frozen_state=ignore_frozen_state,
                                                accept_external_entanglement=accept_external_entanglement,
                                                delayed_node_internals=delayed_node_internals)


    def get_subnodes_csts_copy(self, node_dico={}):
        csts_copy = []
        old2new_node = node_dico

        for weight, lnode_list in split_with(lambda x: isinstance(x, int), \
                                                self.subnodes_csts):
            csts_copy.append(weight)
            l = []

            for delim, sublist in self.__iter_csts(lnode_list[0]):
                # sublist can be in one of the 2 following forms:                
                # * [3, [1, [<fuzzfmk.data_model.Node object at 0x7fc49fc56ad0>, 2], 2, [<fuzzfmk.data_model.Node object at 0x7fc49fc56510>, 1, 2]]]
                # * [[<fuzzfmk.data_model.Node object at 0x7fc49fdb0090>, 1, 3], [<fuzzfmk.data_model.Node object at 0x7fc49fc56ad0>, 3]]

                new_sublist = []
                if isinstance(sublist[0], list):
                    for sslist in sublist:
                        if sslist[0] not in old2new_node:
                            old2new_node[sslist[0]] = copy.copy(sslist[0])
                        new_node = old2new_node[sslist[0]]

                        new_node.internals = copy.copy(new_node.internals)
                        for c in new_node.internals:
                            new_node.internals[c] = copy.copy(new_node.internals[c])

                        if len(sslist) == 2:
                            new_sublist.append([new_node, sslist[1]])
                        else:
                            new_sublist.append([new_node, sslist[1], sslist[2]])

                elif isinstance(sublist[0], int):
                    new_sublist.append(sublist[0]) # add the total weight
                    new_sslist = []
                    for sss in sublist[1]:
                        if isinstance(sss, int):
                            new_sslist.append(sss) # add the relative weight
                        else:   # it is a list like [<fuzzfmk.data_model.Node object at 0x7fc49fc56ad0>, 2]
                            if sss[0] not in old2new_node:
                                old2new_node[sss[0]] = copy.copy(sss[0])
                            new_node = old2new_node[sss[0]]
                            
                            new_node.internals = copy.copy(new_node.internals)
                            for c in new_node.internals:
                                new_node.internals[c] = copy.copy(new_node.internals[c])

                            if len(sss) == 2:
                                new_sslist.append([new_node, sss[1]])
                            else:
                                new_sslist.append([new_node, sss[1], sss[2]])

                    new_sublist.append(new_sslist)
                else:
                    raise ValueError

                l.append([copy.copy(delim), new_sublist])

            csts_copy.append(l)

        return csts_copy


    def get_subnodes_collection(self):
        return self.subnodes_set


    def _set_drawn_node_attrs(self, node, nb, sz):
        self._nodes_drawn_qty[node.name] = nb
        if node.env is not None:
            node.env.set_drawn_node_attrs(id(node), nb=nb, sz=sz)
        else:
            if DEBUG:
                print("\n*** WARNING: no Env() is provided yet for node '%s'! " \
                      "Thus cannot call methods on it!" % node.name)

    def get_drawn_node_qty(self, node_ref):
        if isinstance(node_ref, Node):
            name = node_ref.name
        elif isinstance(node_ref, str):
            name = node_ref
        else:
            raise ValueError

        try:
            return self._nodes_drawn_qty[name]
        except KeyError:
            self.get_subnodes_with_csts()
            if name in self._nodes_drawn_qty:
                return self._nodes_drawn_qty[name]
            else:
                raise ValueError("Node with name '%s' has not been drawn" % name)



    @staticmethod
    def _get_random_component(comp_list, total_weight):
        r = random.uniform(0, total_weight)
        s = 0

        for weight, csts in split_with(lambda x: isinstance(x, int), comp_list):
            s += weight
            if s >= r:
                return csts[0]
        else: # Might occur because of floating point inaccuracies (TBC)
            return csts[0]

    @staticmethod
    def _get_heavier_component(comp_list):
        current_weight = -1
        current_comp = None
        for weight, comp in split_with(lambda x: isinstance(x, int), comp_list):
            if weight > current_weight:
                current_weight = weight
                current_comp = comp[0]

        return current_comp

    @staticmethod
    def _get_next_heavier_component(comp_list, excluded_idx=[]):
        current_weight = -1
        current_comp = None
        current_idx = None
        for idx, weight, comp in split_verbose_with(lambda x: isinstance(x, int), comp_list):
            if idx in excluded_idx:
                continue
            if weight > current_weight:
                current_weight = weight
                current_comp = comp[0]
                current_idx = idx

        if current_weight == -1:
            return None, None
        else:
            return current_comp, current_idx

    @staticmethod
    def _get_next_random_component(comp_list, excluded_idx=[]):
        total_weight = 0
        for idx, weight, comp in split_verbose_with(lambda x: isinstance(x, int), comp_list):
            if idx in excluded_idx:
                continue
            total_weight += weight

        r = random.uniform(0, total_weight)
        s = 0
        for idx, weight, comp in split_verbose_with(lambda x: isinstance(x, int), comp_list):
            if idx in excluded_idx:
                continue
            s += weight
            if s >= r:
                return comp[0], idx
        else:
            return None, None

    # to be used only in Finite mode
    def count_of_possible_cases(self):
        return len(self.subnodes_csts) // 2


    def get_subnodes_with_csts(self):
        '''Generate the structure of the non terminal node.
        '''

        def construct_subnodes(node, subnode_list, mode):
            if self.is_attr_set(NodeInternals.Determinist):
                if len(node) == 3:
                    nb = (node[1] + node[2]) // 2
                else:
                    nb = node[1]
            else:
                if len(node) == 3:
                    nb = random.randint(node[1], node[2])
                else:
                    nb = node[1]

            node = node[0]

            qty = self._qty_from_node(node)
            if qty is not None:
                nb = qty

            shall_exist = self._existence_from_node(node)
            if shall_exist is not None:
                if not shall_exist:
                    nb = 0

            to_entangle = set()

            base_node = node
            external_entangled_nodes = [] if base_node.entangled_nodes is None else list(base_node.entangled_nodes)

            for i in range(nb):
                # 'unique' mode
                if mode == 'u':
                    if i == 0 and base_node.tmp_ref_count == 1:
                        new_node = base_node
                    else:
                        base_node.tmp_ref_count += 1
                        nid = base_node.name + ':' + str(base_node.tmp_ref_count)
                        if base_node.is_frozen():
                            ignore_fstate = False
                        else:
                            ignore_fstate = True

                        # ignore_fstate = True

                        new_node = Node(nid, base_node=base_node, ignore_frozen_state=ignore_fstate,
                                      accept_external_entanglement=True,
                                      acceptance_set=(external_entangled_nodes + subnode_list))
                        new_node._reset_depth(parent_depth=base_node.depth-1)

                        # For dynamically created Node(), don't propagate the fuzz weight
                        if self.mode == 1:
                            new_node.reset_fuzz_weight(recursive=True)
                            new_node.clear_attr(NodeInternals.Mutable, all_conf=True, recursive=True)
                            # print('\nname: %s, %s' % (base_node.name, new_node.name),
                            #       '\nfinite: %r, %r' % (base_node.is_attr_set(NodeInternals.Finite), new_node.is_attr_set(NodeInternals.Finite)),
                            #       '\nmutable: %r, %r' % (base_node.is_attr_set(NodeInternals.Mutable), new_node.is_attr_set(NodeInternals.Mutable)))

                            # if isinstance(base_node.cc, NodeInternals_NonTerm):
                            #     print('contents 1: ', base_node.cc.frozen_node_list)
                            #     print('contents 2: ', new_node.cc.frozen_node_list)
                            #     if base_node.cc.frozen_node_list and new_node.cc.frozen_node_list:
                            #         for e1, e2 in zip(base_node.cc.frozen_node_list, new_node.cc.frozen_node_list):
                            #             print('name: %s, %s' % (e1.name, e2.name),
                            #                   '\nfinite: %r, %r' % (e1.is_attr_set(NodeInternals.Finite), e2.is_attr_set(NodeInternals.Finite)),
                            #                   '\nmutable: %r, %r' % (e1.is_attr_set(NodeInternals.Mutable), e2.is_attr_set(NodeInternals.Mutable)))

                        elif self.mode == 2:
                            if new_node.is_nonterm():
                                new_node.cc.set_mode(2)
                        else:
                            raise ValueError

                    new_node._set_clone_info((base_node.tmp_ref_count-1, nb))

                # 'same' mode
                elif mode == 's':
                    new_node = base_node
                else:
                    raise ValueError

                subnode_list.append(new_node)
                to_entangle.add(new_node)

            # We need to call set_clone_info() only once for 's' mode
            # as there is only one instance.
            if mode == 's':
                new_node._set_clone_info((0,nb))

            if len(to_entangle) > 1:
                make_entangled_nodes(to_entangle)

            # node.to_bytes() has to be called after the
            # previous copy process, to avoid copying frozen node
            self._set_drawn_node_attrs(node, nb, len(node.to_bytes()))


        if self.frozen_node_list is not None:
            return (self.frozen_node_list, False)
        
        self.frozen_node_list = []

        determinist = self.is_attr_set(NodeInternals.Determinist)
        
        if determinist:
            node_list, idx = NodeInternals_NonTerm._get_next_heavier_component(self.subnodes_csts,
                                                                             excluded_idx=self.excluded_components)
            self.excluded_components.append(idx)
            # 'len(self.subnodes_csts)' is always even
            if len(self.excluded_components) == len(self.subnodes_csts) // 2:
                # in this case we have exhausted all components
                # note that self.excluded_components is reset in a lazy way (within unfreeze)
                self.exhausted = True
            else:
                self.exhausted = False

        else:
            if self.is_attr_set(NodeInternals.Finite):
                node_list, idx = NodeInternals_NonTerm._get_next_random_component(self.subnodes_csts,
                                                                                  excluded_idx=self.excluded_components)
                self.excluded_components.append(idx)
                if len(self.excluded_components) == len(self.subnodes_csts) // 2:
                    self.exhausted = True
                else:
                    self.exhausted = False
            else:
                node_list = NodeInternals_NonTerm._get_random_component(self.subnodes_csts,
                                                                        self.subnodes_csts_total_weight)


        for delim, sublist in self.__iter_csts(node_list):

            sublist_tmp = []

            if determinist:
                if delim[1] == '>':
                    for node in sublist:
                        construct_subnodes(node, sublist_tmp, delim[0])
                elif delim[1] == '=':
                    if delim[2] == '+':
                        if sublist[0] > -1:
                            node = NodeInternals_NonTerm._get_heavier_component(sublist[1])
                        else:
                            node = sublist[1][0]
                        construct_subnodes(node, sublist_tmp, delim[0])
                    else:
                        for node in sublist:
                            construct_subnodes(node, sublist_tmp, delim[0])
                else:
                    raise ValueError

            elif delim[1] == '>':
                for node in sublist:
                    construct_subnodes(node, sublist_tmp, delim[0])

            elif delim[1] == '=':

                if delim[2] == '.':
                    l = copy.copy(sublist)
                    lg = len(l)

                    # unfold the Nodes one after another
                    if delim[2:] == '..':
                        for i in range(lg):
                            node = random.choice(l)
                            l.remove(node)
                            construct_subnodes(node, sublist_tmp, delim[0])

                    # unfold all the Node and then choose randomly
                    else:
                        list_unfold = []
                        for i in range(lg):
                            node = random.choice(l)
                            l.remove(node)
                            construct_subnodes(node, list_unfold, delim[0])

                        lg = len(list_unfold)
                        for i in range(lg):
                            node = random.choice(list_unfold)
                            list_unfold.remove(node)
                            sublist_tmp.append(node)

                # choice of only one component within a list
                elif delim[2] == '+':
                    if sublist[0] > -1:
                        node = NodeInternals_NonTerm._get_random_component(comp_list=sublist[1], total_weight=sublist[0])
                    else:
                        node = random.choice(sublist[1])

                    construct_subnodes(node, sublist_tmp, delim[0])

                else:
                    raise ValueError("delim: '%s'"%delim)
            else:
                raise ValueError("delim: '%s'"%delim)

            self.frozen_node_list += sublist_tmp

        for e in self.subnodes_set:
            e.tmp_ref_count = 1

        return (self.frozen_node_list, True)


    def get_value(self, conf=None, recursive=True):
        l = []
        node_list, was_not_frozen = self.get_subnodes_with_csts()

        for e in node_list:
            val = e.get_value(conf=conf, recursive=recursive)
            l.append(val)

        return (l, was_not_frozen)

    def _precondition_subnode_ops(self):
        if self.frozen_node_list is None:
            raise ValueError('current node is not yet frozen!')

    def get_subnode(self, num):
        self._precondition_subnode_ops()
        return self.frozen_node_list[num]

    def get_subnode_off(self, num):
        self._precondition_subnode_ops()
        off = 0
        for idx in range(num):
            n = self.frozen_node_list[idx]
            off += len(n.to_bytes())

        return off

    def get_subnode_qty(self):
        self._precondition_subnode_ops()
        return len(self.frozen_node_list)

    def replace_subnode(self, old, new):
        self.subnodes_set.remove(old)
        self.subnodes_set.add(new)
                        
        for weight, lnode_list in split_with(lambda x: isinstance(x, int), self.subnodes_csts):
            for delim, sublist in self.__iter_csts(lnode_list[0]):
                if delim[:3] == 'u=+' or delim[:3] == 's=+':
                    for w, etp in split_with(lambda x: isinstance(x, int), sublist[1]):
                        for n in etp:
                            if n[0] is old:
                                n[0] = new
                else:
                    for e in sublist:
                        if e[0] == old:
                            e[0] = new


    @staticmethod
    def _parse_node_desc(node_desc):
        if len(node_desc) == 3:
            min_node = node_desc[1]
            max_node = node_desc[2]
        else:
            min_node = node_desc[1]
            max_node = node_desc[1]

        return node_desc[0], min_node, max_node

    def _clone_node(self, base_node, node_no, force_clone=False):
        if node_no > 0 or force_clone:
            base_node.tmp_ref_count += 1
            nid = base_node.name + ':' + str(base_node.tmp_ref_count)
            node = Node(nid, base_node=base_node, ignore_frozen_state=True,
                        accept_external_entanglement=False)
            node._reset_depth(parent_depth=base_node.depth-1)
            if base_node.is_nonterm() and base_node.cc.mode == 1:
                node.reset_fuzz_weight(recursive=True)
                node.clear_attr(NodeInternals.Mutable, all_conf=True, recursive=True)
        else:
            node = base_node

        return node

    def _clone_node_cleanup(self):
        for n in self.subnodes_set:
            n.tmp_ref_count = 1

    @staticmethod
    def _qty_from_node(node):
        sync_node = node.synchronized_with(SyncScope.Qty)
        if sync_node is not None:
            nb = node.env.get_drawn_node_qty(id(sync_node))
            if nb is not None:
                return nb
            else:
                print("\n*** WARNING: synchronization is not possible " \
                      "for node '{:s}' (id: {:d})!".format(node.name, id(node)))
                return None
                
        return None

    @staticmethod
    def _existence_from_node(node):
        sync_node = node.synchronized_with(SyncScope.Existence)
        if sync_node is not None:
            exist = node.env.node_exists(id(sync_node))
            return True if exist else False

        sync_node = node.synchronized_with(SyncScope.Inexistence)
        if sync_node is not None:
            inexist = not node.env.node_exists(id(sync_node))
            return True if inexist else False

        return None


    def absorb(self, blob, constraints, conf):
        abs_excluded_components = []
        abs_exhausted = False
        status = AbsorbStatus.Reject

        if self.absorb_constraints is not None:
            constraints = self.absorb_constraints
            
        # Helper function
        def _try_absorption_with(base_node, min_node, max_node, blob, consumed_size,
                                 postponed_node_desc, force_clone=False):

            DEBUG = False

            consumed_nb = 0

            if constraints[AbsCsts.Structure]:
                qty = self._qty_from_node(base_node)
                if qty is not None:
                    max_node = min_node = qty

                shall_exist = self._existence_from_node(base_node)
                if shall_exist is not None:
                    if not shall_exist:
                        max_node = min_node = 0

            if max_node == 0:
                # base_node.reset_state(recursive=True, conf=conf)
                return None, blob, consumed_size, consumed_nb
            elif min_node == max_node:
                itr = range(max_node)
            else:
                itr = range(1, max_node+1)

            orig_blob = blob
            orig_consumed_size = consumed_size
            abort = False
            tmp_list = []
            for i, node_no in zip(itr, range(len(itr))):
                node = self._clone_node(base_node, node_no, force_clone)

                ignore_last_absorption = False

                # We try to absorb the blob
                st, off, sz, name = node.absorb(blob, constraints, conf=conf)

                if st == AbsorbStatus.Reject:
                    if DEBUG:
                        print('REJECT: %s, blob: %r ...' % (node.name, blob[:4]))
                    if min_node == 0:
                        # abort = False
                        break
                    if i <= min_node:
                        abort = True
                        break
                    else:
                        break
                elif st == AbsorbStatus.Absorbed or st == AbsorbStatus.FullyAbsorbed:
                    if DEBUG:
                        print('\nABSORBED: %s, abort: %r, blob: %r ... , consumed: %d' \
                              % (node.name, abort, blob[:sz][:50], sz))

                    sz2 = 0
                    if postponed_node_desc is not None:
                        # we only support one postponed node between two nodes
                        st2, off2, sz2, name2 = postponed_node_desc[0].absorb(blob[:off], constraints, conf=conf)
                        if st2 == AbsorbStatus.Reject:
                            postponed_node_desc = None
                            abort = True
                            break
                        elif st2 == AbsorbStatus.Absorbed or st2 == AbsorbStatus.FullyAbsorbed:
                            tmp_list.append(postponed_node_desc[0])
                            postponed_node_desc = None
                        else:
                            raise ValueError
                    else:
                        if off != 0:
                            # In this case, no postponed node exist
                            # but the node finds something that match
                            # its expectation at off>0.
                            # We need to reject this absorption as
                            # accepting it could prevent finding a
                            # good non-terminal shape.
                            ignore_last_absorption = True

                    if not ignore_last_absorption:
                        blob = blob[off+sz:]
                        assert(sz2 == off)
                        consumed_size += sz+sz2 # off+sz
                        consumed_nb = i+1 if min_node == max_node else i
                        tmp_list.append(node)
                        # self.frozen_node_list.append(node)
                else:
                    raise ValueError

            if abort:
                blob = orig_blob
                consumed_size = orig_consumed_size
                for n in tmp_list:
                    # Resetting all Generator nodes
                    ic = NodeInternalsCriteria(node_kinds=[NodeInternals_GenFunc])
                    nlist = n.get_reachable_nodes(internals_criteria=ic)
                    for nd in nlist:
                        nd.reset_state(conf=conf)
            else:
                nb_nodes = len(tmp_list)
                self._set_drawn_node_attrs(base_node, nb=nb_nodes, sz=len(base_node.to_bytes()))
                for n, idx in zip(tmp_list, range(nb_nodes)):
                    n._set_clone_info((idx, nb_nodes))
                self.frozen_node_list += tmp_list

            return abort, blob, consumed_size, consumed_nb


        while not abs_exhausted and status == AbsorbStatus.Reject:

            abort = False
            consumed_size = 0
            tmp_list = []

            node_list, idx = NodeInternals_NonTerm._get_next_heavier_component(self.subnodes_csts,
                                                                              excluded_idx=abs_excluded_components)

            abs_excluded_components.append(idx)
            # 'len(self.subnodes_csts)' is always even
            if len(abs_excluded_components) == len(self.subnodes_csts) // 2:
                # in this case we have exhausted all components
                abs_exhausted = True
            else:
                abs_exhausted = False

            self.frozen_node_list = []

            postponed_node_desc = None
            for delim, sublist in self.__iter_csts(node_list):

                if delim[1] == '>':

                    for node_desc in sublist:
                        abort = False
                        base_node, min_node, max_node = NodeInternals_NonTerm._parse_node_desc(node_desc)

                        if base_node.is_attr_set(NodeInternals.Abs_Postpone):
                            if postponed_node_desc:
                                raise ValueError("\nERROR: Only one node at a time (current:%s) delaying" \
                                                 " its dissection is supported!" % postponed_node_desc)
                            postponed_node_desc = node_desc
                            continue
                        else:
                            abort, blob, consumed_size, consumed_nb = _try_absorption_with(base_node,
                                                                              min_node, max_node,
                                                                              blob, consumed_size,
                                                                              postponed_node_desc)

                            if abort is None:
                                continue

                            # if _try_absorption_with() return a
                            # tuple, then the postponed node is
                            # handled (either because absorption
                            # succeeded or because it didn't work and
                            # we need to abort and try another high
                            # level component)
                            postponed_node_desc = None

                        if abort:
                            break

                elif delim[1] == '=':

                    # '=..' means: no particular orders between each kind of nodes
                    # '=.' means: no particular orders between all the nodes (fully random)

                    if delim[2] == '.':
                        node_desc_list = copy.copy(sublist)
                        list_sz = len(node_desc_list)
                        cpt = list_sz

                        if delim[2:] == '..':
                            while node_desc_list:

                                if cpt == 0 and len(node_desc_list) == list_sz:
                                    # if we enter here it means no
                                    # node has been able to absorb
                                    # anything
                                    abort = True
                                    break

                                elif cpt == 0:
                                    list_sz = len(node_desc_list)
                                    cpt = list_sz

                                cpt -= 1

                                node_desc = node_desc_list.pop(0)
                                base_node, min_node, max_node = NodeInternals_NonTerm._parse_node_desc(node_desc)

                                # postponed_node_desc is not supported here as it does not make sense
                                abort, blob, consumed_size, consumed_nb = _try_absorption_with(base_node, min_node, max_node,
                                                                                        blob, consumed_size,
                                                                                        postponed_node_desc=postponed_node_desc)
                                if abort is None:
                                    continue

                                if abort:
                                    # we give a new chance to this node because it is maybe not at the right place
                                    node_desc_list.append(node_desc)

                        else: # case delim[2:] == '.'

                            l = []
                            qty_list = []
                            for node_desc in node_desc_list:
                                base_node, min_node, max_node = NodeInternals_NonTerm._parse_node_desc(node_desc)
                                l.append([base_node, min_node, False]) # (bn, min, force_clone)
                                qty_list.append([max_node])

                            prev_qty_list = copy.deepcopy(qty_list)
                            stop_cpt = 0
                            next_l = l
                            next_qty_list = qty_list
                            while True:
                                l = copy.copy(next_l)
                                qty_list = copy.copy(next_qty_list)
                                list_sz = len(l)

                                if stop_cpt == list_sz:
                                    for node_tuple, qty_obj in zip(l, qty_list):
                                        if node_tuple[1] > 0:
                                            abort = True
                                            break
                                    else:
                                        abort = False

                                    break
                                        

                                for node_tuple, qty_obj in zip(l, qty_list):
                                    base_node, min_node, force_clone = node_tuple
                                    max_node = qty_obj[0]
                                    # we force min_node to 0 as we don't want _try_absorption_with()
                                    # to check that condition, as we do it within the caller.
                                    fake_min_node = 0
                                
                                    if max_node != 0:
                                        # postponed_node_desc is not supported here as it does not make sense
                                        tmp_abort, blob, consumed_size, consumed_nb = _try_absorption_with(base_node, fake_min_node,
                                                                                        max_node,
                                                                                        blob, consumed_size,
                                                                                        postponed_node_desc=postponed_node_desc,
                                                                                        force_clone=force_clone)

                                    if not tmp_abort and consumed_nb > 0:
                                        assert(qty_obj[0] - consumed_nb >= 0)
                                        qty_obj[0] = qty_obj[0] - consumed_nb # update max_node
                                        # We now set force_clone to True as we already consumed the base_node
                                        # but _try_absorption_with() will not know that if we recall it with
                                        # the same base_node at a later time
                                        node_tuple[2] = True
                                        if node_tuple[1] > 0:
                                            node_tuple[1] = max(0, node_tuple[1] - consumed_nb) # update min_node
                                        if qty_obj[0] == 0:
                                            next_l.remove(node_tuple)
                                            next_qty_list.remove(qty_obj)

                                if qty_list == prev_qty_list:
                                    stop_cpt += 1
                                else:
                                    stop_cpt = 0
                                    prev_qty_list = copy.deepcopy(qty_list)


                    elif delim[2] == '+':

                        t_weight = sublist[0]
                        node_desc_list = list(sublist[1])
                        excl_comp = []
                        dont_stop = True

                        while dont_stop:

                            if t_weight > -1:
                                node_desc, idx = NodeInternals_NonTerm._get_next_heavier_component(comp_list=node_desc_list, excluded_idx=excl_comp)
                                if node_desc is None:
                                    break
                                excl_comp.append(idx)
                            else:
                                try:
                                    node_desc = node_desc_list.pop(0)
                                except IndexError:
                                    break

                            base_node, min_node, max_node = NodeInternals_NonTerm._parse_node_desc(node_desc)

                            if base_node.is_attr_set(NodeInternals.Abs_Postpone):
                                if postponed_node_desc:
                                    raise ValueError("\nERROR: Only one node at a time (current:%s) delaying" \
                                                     " its dissection is supported!" % postponed_node_desc)
                                postponed_node_desc = node_desc
                                continue

                            else:
                                abort, blob, consumed_size, consumed_nb = _try_absorption_with(base_node, min_node, max_node,
                                                                                               blob, consumed_size,
                                                                                               postponed_node_desc)

                                if abort is None or abort:
                                    continue
                                else:
                                    dont_stop = False
                                    postponed_node_desc = None

                    else:
                        raise ValueError
                else:
                    raise ValueError

                if abort:
                    break

            if not abort:
                status = AbsorbStatus.Absorbed

        # clean up
        if status != AbsorbStatus.Absorbed and status != AbsorbStatus.FullyAbsorbed:
            self.frozen_node_list = None

        self._clone_node_cleanup()

        return status, 0, consumed_size


    def is_exhausted(self):
        if self.is_attr_set(NodeInternals.Finite):
            return self.exhausted
        else:
            return False

    def is_frozen(self):
        return self.frozen_node_list is not None

    def _make_specific(self, name):
        return True

    def _unmake_specific(self, name):
        return True

    def _cleanup_entangled_nodes(self):
        for n in self.subnodes_set:
            if n.entangled_nodes is not None:
                l = []
                for e in n.entangled_nodes:
                    if e in self.frozen_node_list:
                        l.append(e)
                n.entangled_nodes.symmetric_difference_update(l)
                if len(n.entangled_nodes) <= 1:
                    n.entangled_nodes = None


    def unfreeze(self, conf=None, recursive=True, dont_change_state=False, ignore_entanglement=False, only_generators=False):
        if recursive:
            if dont_change_state or only_generators:
                iterable = self.frozen_node_list
            else:
                iterable = self.subnodes_set

            for e in iterable:
                if e.is_frozen(conf):
                    e.unfreeze(conf=conf, recursive=True, dont_change_state=dont_change_state,
                               ignore_entanglement=ignore_entanglement, only_generators=only_generators)

        if not dont_change_state and not only_generators:
            self._cleanup_entangled_nodes()

            self.frozen_node_list = None
            self._nodes_drawn_qty = {}

        if self.exhausted:
            self.excluded_components = []


    def unfreeze_all(self, recursive=True, ignore_entanglement=False):
        if recursive:
            iterable = self.subnodes_set

            for e in iterable:
                e.unfreeze_all(recursive=True, ignore_entanglement=ignore_entanglement)

        self._cleanup_entangled_nodes()

        self.frozen_node_list = None
        self._nodes_drawn_qty = {}

        if self.exhausted:
            self.excluded_components = []


    def reset_state(self, recursive=False, exclude_self=False, conf=None, ignore_entanglement=False):
        if recursive:
            iterable = self.subnodes_set

            for e in iterable:
                e.reset_state(recursive=True, exclude_self=exclude_self, conf=conf, ignore_entanglement=ignore_entanglement)

        if not exclude_self:
            self._cleanup_entangled_nodes()

            self.frozen_node_list = None
            self.exhausted = False
            self._nodes_drawn_qty = {}
            self.excluded_components = []


    def reset_fuzz_weight(self, recursive):
        iterable = copy.copy(self.subnodes_set)
        if self.frozen_node_list is not None:
            iterable.update(self.frozen_node_list)

        for e in iterable:
            e.reset_fuzz_weight(recursive=recursive)

    def set_child_env(self, env):
        iterable = copy.copy(self.subnodes_set)
        if self.frozen_node_list is not None:
            iterable.update(self.frozen_node_list)

        for e in iterable:
            e.set_env(env)

    def set_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        if recursive:
            iterable = copy.copy(self.subnodes_set)
            if self.frozen_node_list is not None:
                iterable.update(self.frozen_node_list)

            for e in iterable:
                e.set_attr(name, conf=conf, all_conf=all_conf, recursive=recursive)

    def clear_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        if recursive:
            iterable = copy.copy(self.subnodes_set)
            if self.frozen_node_list is not None:
                iterable.update(self.frozen_node_list)

            for e in iterable:
                e.clear_attr(name, conf=conf, all_conf=all_conf, recursive=recursive)

    def set_clone_info(self, info):
        iterable = self.subnodes_set
        if self.frozen_node_list:
            iterable = iterable.union(self.frozen_node_list)
        for e in iterable:
            e._set_clone_info(info)

    def reset_depth_specific(self, depth):
        iterable = copy.copy(self.subnodes_set)
        if self.frozen_node_list is not None:
            iterable.update(self.frozen_node_list)
        for e in iterable:
            e._reset_depth(depth)

    def get_child_nodes_by_attr(self, internals_criteria, semantics_criteria, owned_conf, conf, path_regexp,
                               exclude_self, respect_order, relative_depth, top_node):

        if self.frozen_node_list is not None:
            iterable = self.frozen_node_list
        else:
            self.get_subnodes_with_csts()
            iterable = self.frozen_node_list

        if respect_order:
            s = []
        else:
            s = set()

        for e in iterable:
            ret = e.get_reachable_nodes(internals_criteria, semantics_criteria, owned_conf, conf,
                                        path_regexp=path_regexp,
                                        exclude_self=exclude_self, respect_order=respect_order,
                                        relative_depth=relative_depth, top_node=top_node)
            if respect_order:
                for e in ret:
                    if e not in s:
                        s.append(e)
            else:
                s = s.union(ret)

        return s


    def set_child_current_conf(self, node, conf, reverse, ignore_entanglement):
        iterable = self.subnodes_set

        for e in iterable:
            node._set_subtrees_current_conf(e, conf, reverse, ignore_entanglement=ignore_entanglement)


    def get_child_all_path(self, name, htable, conf, recursive):
        if self.frozen_node_list:
            iterable = self.frozen_node_list
        else:
            iterable = self.subnodes_set

        for e in iterable:
            e._get_all_paths_rec(name, htable, conf, recursive=recursive, first=False)



########### Node() High Level Facilities ##############

class NodeAbstraction(object):
    '''
    This class can be used in place of an node_arg for Func and GenFunc
    Nodes. It enables you to define in your data model higher level
    classes upon Nodes to facilitate Nodes manipulation within Func and
    GenFunc Nodes, with regards to your data model paradigm.
    '''

    def get_concrete_nodes(self):
        '''
        Shall return an Node or a list of Nodes
        '''
        raise NotImplementedError

    def set_concrete_nodes(self, nodes_args):
        '''
        Shall save an Node or a list of Nodes (depending on what returns
        get_concrete_nodes())
        '''
        raise NotImplementedError

    def make_private(self):
        '''
        This method is called during Node copy process. It aims to make
        all your metadata private (if needed).
        Note that you don't have to deal with your Nodes.
        '''
        pass


class NodeSemantics(object):
    '''
    To be used while defining a data model as a means to associate
    semantics to an Node.
    '''
    def __init__(self, attrs=[]):
        self.__attrs = attrs

    def add_attributes(self, attrs):
        self.__attrs += attrs

    def _match_optionalbut1_criteria(self, criteria):
        if criteria is None:
            return True

        for c in criteria:
            if c in self.__attrs:
                return True

        return False

    def _match_mandatory_criteria(self, criteria):
        if criteria is None:
            return True

        for c in criteria:
            if c not in self.__attrs:
                return False

        return True

    def _match_exclusive_criteria(self, criteria):
        if criteria is None:
            return True

        match_nb = 0
        for c in criteria:
            if c in self.__attrs:
                match_nb += 1

        if match_nb == 0 or match_nb > 1:
            return False
        else:
            return True

    def _match_negative_criteria(self, criteria):
        if criteria is None:
            return True

        for c in criteria:
            if c in self.__attrs:
                return False

        return True


    def match(self, semantics_criteria):
        '''
        This method is called within get_reachable_nodes() (when the
        'semantics' parameter is provided) to select Node that match
        the given semantics.
        '''
        c1 = self._match_optionalbut1_criteria(semantics_criteria.get_optionalbut1_criteria())
        if not c1:
            return False

        c2 = self._match_mandatory_criteria(semantics_criteria.get_mandatory_criteria())
        if not c2:
            return False

        c3 = self._match_exclusive_criteria(semantics_criteria.get_exclusive_criteria())
        if not c3:
            return False

        c4 = self._match_negative_criteria(semantics_criteria.get_negative_criteria())
        if not c4:
            return False

        return True


    def make_private(self):
        '''
        This method is called during Node copy process. It aims to make
        all your metadata private (if needed).
        '''
        self.__attrs = copy.copy(self.__attrs)


class NodeSemanticsCriteria(object):

    def __init__(self, optionalbut1_criteria=None, mandatory_criteria=None, exclusive_criteria=None,
                 negative_criteria=None):
        self.set_optionalbut1_criteria(optionalbut1_criteria)
        self.set_mandatory_criteria(mandatory_criteria)
        self.set_exclusive_criteria(exclusive_criteria)
        self.set_negative_criteria(negative_criteria)

    def extend(self, sc):
        crit = sc.get_exclusive_criteria()
        if crit:
            if self.__exclusive is None:
                self.__exclusive = []
            self.__exclusive.extend(crit)
        crit = sc.get_mandatory_criteria()
        if crit:
            if self.__mandatory is None:
                self.__mandatory = []
            self.__mandatory.extend(crit)
        crit = sc.get_optionalbut1_criteria()
        if crit:
            if self.__optionalbut1 is None:
                self.__optionalbut1 = []
            self.__optionalbut1.extend(crit)
        crit = sc.get_negative_criteria()
        if crit:
            if self.__negative is None:
                self.__negative = []
            self.__negative.extend(crit)

    def set_exclusive_criteria(self, criteria):
        self.__exclusive = criteria

    def set_mandatory_criteria(self, criteria):
        self.__mandatory = criteria

    def set_optionalbut1_criteria(self, criteria):
        self.__optionalbut1 = criteria

    def set_negative_criteria(self, criteria):
        self.__negative = criteria

    def get_exclusive_criteria(self):
        return self.__exclusive

    def get_mandatory_criteria(self):
        return self.__mandatory

    def get_optionalbut1_criteria(self):
        return self.__optionalbut1

    def get_negative_criteria(self):
        return self.__negative



##########################
# Node func/class helpers #
##########################


def make_wrapped_node(name, vals=None, node=None, prefix=None, suffix=None, key_node_name='KEY_ELT'):
    
    pre = Node('prefix', values=prefix) if prefix is not None else None
    suf = Node('suffix', values=suffix) if suffix is not None else None
    
    if vals is not None:
        node = Node(key_node_name, values=vals)
        
    elif node is None:
        raise ValueError
    
    if pre is None and suf is None:
        raise ValueError
    elif pre is None:
        e = Node(name, subnodes=[node, suf])
    elif suf is None:
        e = Node(name, subnodes=[pre, node])
    else:
        e = Node(name, subnodes=[pre, node, suf])

    return e


def make_entangled_nodes(node_list):
    s = set(node_list)

    for n in node_list:
        if n.entangled_nodes is not None:
            s.update(n.entangled_nodes)

    ### DOC ###
    # Note that the entangled nodes share the same set. It is needed
    # to keep consistency when nodes are removed from the set from any
    # node. It may imply some strange behavior on data models that
    # have forget to clone nodes when it make sense (for instance,
    # when using in different non terminal nodes, a same node on which
    # apply dynamic duplication)
    for n in s:
        n.entangled_nodes = s




########### Node Class ##############


class Node(object):
    '''A Node is the basic building-block used within a graph-based data model.

    Attributes:
      internals (dict: str --> :class:`NodeInternals`): Contains all the configuration of a
        node. A configuration is associated to the internals/contents
        of a node, which can live independently of the other
        configuration.
      current_conf (str): Identifier to a configuration. Every usable node use at least one main
        configuration, namely ``'MAIN'``.
      name (str): Identifier of a node. Defined at instantiation.
        Shall be unique from its parent perspective.
      env (Env): One environment object is added to all the nodes of a node
        graph when the latter is registered within a data model
        (cf. :func:`DataModel.register_nodes()`). It is used for sharing
        global resources between nodes.
      entangled_nodes (set(:class:`Node`)): Collection of all the nodes entangled with this one. All
        the entangled nodes will react the same way as one of their
        peers (within some extent) if this peer is subjected to a
        stimuli. The node's properties related to entanglement are
        only the ones that directly define a node. For instance,
        changing a node's NodeInternals will propagate to its
        entangled peers but changing the state of a node's
        NodeInternals won't propagate. It is used for dealing with
        multiple instance of a same node (within the scope of a
        NonTerm
        node---cf. :func:`NodeInternals_NonTerm.get_subnodes_with_csts()`).
        But this mechanism can also be used for your own specific purpose. 
      semantics (:class:`NodeSemantics`): (optional) Used to associate a semantics to a
        node. Can be used during graph traversal in order to perform
        actions related to semantics.
      fuzz_weight (int): The fuzz weight is an optional attribute of Node() which
        express Data Model designer's hints for prioritizing the nodes
        to fuzz. If set, this attribute is used by some generic
        *disruptors* (the ones that rely on a ModelWalker object---refer to
        fuzzing_primitives.py)
      depth (int): Depth of the node wwithin the graph from a specific given
        root. Will be computed lazily (only when requested).
      tmp_ref_count (int): (internal use) Temporarily used during the creation of multiple
        instance of a same node, especially in order to generate unique names.
      _post_freeze_handler (function): Is executed just after a node is frozen (which
        is the result of requesting its value when it is not
        freezed---e.g., at its creation).
    '''
   
    def __init__(self, name, base_node=None, copy_dico=None, ignore_frozen_state=False,
                 accept_external_entanglement=False, acceptance_set=None,
                 subnodes=None, values=None, value_type=None):
        '''
        Args:
          name (str): Name of the node. Every children node of a node shall have a unique name.
            Useful to look for specific nodes within a graph.
          subnodes (list): (Optional) List of subnodes.
            If provided the Node will be created as a non-terminal node.
          values (list): (Optional) List of strings.
            If provided the instantiated node will be a  String-typed leaf node (taking its possible
            values from the parameter).
          value_type (VT): (Optional) The value type that characterize the node. Defined within
            `value_types.py` and inherits from either `VT` or `VT_Alt`. If provided the instantiated
            node will be a value_type-typed leaf node.
          base_node (Node): (Optional) If provided, it will be used as a template to create the new node.
          ignore_frozen_state (bool): [If `base_node` provided] If True, the clone process of
            base_node will ignore its current state.
          accept_external_entanglement (bool): [If `base_node` provided] If True, during the cloning
            process of base_node, every entangled nodes outside the current graph will be referenced
            within the new node without being copied. Otherwise, a *Warning* message will be raised.
          acceptance_set (set): [If `base_node` provided] If provided, will be used as a set of
            entangled nodes that could be referenced within the new node during the cloning process.
          copy_dico (dict): [If `base_node` provided] It is used internally during the cloning process,
           and should not be used for any functional purpose.
        '''

        self.internals = {}
        self.name = name
        self.env = None

        self.entangled_nodes = None

        self.semantics = None
        self.fuzz_weight = None

        self._post_freeze_handler = None 

        self.depth = 0
        self.tmp_ref_count = 1

        if base_node is not None and subnodes is None and values is None and value_type is None:

            # self.env = base_node.env
            self.env = copy.copy(base_node.env)
        
            node_dico = self.set_contents(base_node,
                                          copy_dico=copy_dico, ignore_frozen_state=ignore_frozen_state,
                                          accept_external_entanglement=accept_external_entanglement,
                                          acceptance_set=acceptance_set)
            
            if self.env is not None:
                self.env.update_node_refs(node_dico, ignore_frozen_state=ignore_frozen_state)
            elif DEBUG:
                print("\n*** WARNING: the copied node '%s' don't have an Env() " \
                      "associated with it!\n" % base_node.name)

        else:
            self.add_conf('MAIN')
            self.set_current_conf('MAIN')

            self.reset_fuzz_weight()

            if subnodes is not None:
                self.set_subnodes_basic(subnodes)

            elif values is not None:
                self.set_values(val_list=values)

            elif value_type is not None:
                self.set_values(value_type=value_type)

            else:
                self.make_empty()

    def get_clone(self, name, ignore_frozen_state=False):
        '''Create a new node. To be used wihtin a graph-based data model.
        
        Args:
          name (str): name of the new Node instance
          ignore_frozen_state (bool): if set to False, the clone function will produce
            a Node with the same state as the duplicated Node. Otherwise, the only the state won't be kept.

        Returns:
          Node: duplicated Node object
        '''

        return Node(name, base_node=self, ignore_frozen_state=ignore_frozen_state)


    def set_contents(self, base_node,
                     copy_dico=None, ignore_frozen_state=False,
                     accept_external_entanglement=False, acceptance_set=None):
        '''Set the contents of the node based on the one provided within
        `base_node`. This method performs a deep copy of `base_node`,
        but some parameters can change the behavior of the copy.

        .. note:: python deepcopy() is not used for perfomance reason
          (10 to 20 times slower).

        Args:
          base_node (Node): (Optional) Used as a template to create the new node.
          ignore_frozen_state (bool): If True, the clone process of
            base_node will ignore its current state.
          accept_external_entanglement (bool): If True, during the cloning
            process of base_node, every entangled nodes outside the current graph will be referenced
            within the new node without being copied. Otherwise, a *Warning* message will be raised.
          acceptance_set (set): If provided, will be used as a set of
            entangled nodes that could be referenced within the new node during the cloning process.
          copy_dico (dict): It is used internally during the cloning process,
            and should not be used for any functional purpose.

        Returns:
          dict: For each subnodes of `base_node` (keys), reference the
            corresponding subnodes within the new node.
        '''

        self._post_freeze_handler = base_node._post_freeze_handler
        
        if self.internals:
            self.internals = {}
        if self.entangled_nodes:
            self.entangled_nodes = None

        if copy_dico is not None:
            node_dico = copy_dico
        else:
            node_dico = {}

        func_nodes = set()
        entangled_set = set()
        delayed_node_internals = set()

        self.fuzz_weight = base_node.fuzz_weight

        if base_node.semantics is not None:
            self.semantics = copy.copy(base_node.semantics)
            self.semantics.make_private()

        for conf in base_node.internals:
            self.add_conf(conf)

            self.internals[conf] = copy.copy(base_node.internals[conf])
            self.internals[conf].make_private(ignore_frozen_state=ignore_frozen_state,
                                              accept_external_entanglement=accept_external_entanglement,
                                              delayed_node_internals=delayed_node_internals)

            if base_node.is_nonterm(conf):
                self.internals[conf].import_subnodes_full_format(internals=base_node.internals[conf])
                self.internals[conf].make_private_subnodes(node_dico, func_nodes, self.env,
                                                           ignore_frozen_state=ignore_frozen_state,
                                                           accept_external_entanglement=accept_external_entanglement,
                                                           entangled_set=entangled_set,
                                                           delayed_node_internals=delayed_node_internals)
                self.internals[conf].make_private(ignore_frozen_state=ignore_frozen_state,
                                                  accept_external_entanglement=accept_external_entanglement,
                                                  delayed_node_internals=delayed_node_internals)

                self._finalize_nonterm_node(conf)

        # Once node_dico has been populated from the node tree,
        # we deal with 'nodes' argument of Func and GenFunc that does not belong to this
        # tree. And we complete the node_dico.
        for conf in base_node.internals:
            if base_node.is_func(conf) or base_node.is_genfunc(conf):
                self.internals[conf].make_args_private(node_dico, entangled_set, ignore_frozen_state=ignore_frozen_state,
                                                       accept_external_entanglement=accept_external_entanglement)

        # Now we deal with the 'nodes' argument of the Func and
        # GenFunc Nodes within the copied tree, that has been let
        # aside
        for e in func_nodes:
            for conf in e.confs:
                if e.is_func(conf) or e.is_genfunc(conf):
                    e.internals[conf].make_args_private(node_dico, entangled_set, ignore_frozen_state=ignore_frozen_state,
                                                        accept_external_entanglement=accept_external_entanglement)

        # We deal with node refs within NodeInternals, once the node_dico is complete
        for n in delayed_node_internals:
            n._update_node_refs(node_dico, debug=n)

        if base_node.entangled_nodes is not None and ((not ignore_frozen_state) or accept_external_entanglement):
            entangled_set.add(base_node)

        # all nodes in entangled_set are already private nodes
        for node in entangled_set:
            intrics = set()
            for e in node.entangled_nodes:
                if e in node_dico:
                    intrics.add(node_dico[e])
                elif e is base_node:
                    intrics.add(self)
                elif e is node:
                    intrics.add(e)
                elif accept_external_entanglement:
                    intrics.add(e)
                elif acceptance_set is not None and e in acceptance_set:
                    intrics.add(e)
                else:
                    DEBUG = True
                    # TOFIX: the dynamically created subnodes by a
                    # Non terminal node, may have in their
                    # entangled list some mirror subnodes from
                    # another Non terminal node containing copies
                    # of these subnodes, or maybe subnodes (not
                    # removed) of the node in previous frozen
                    # state
                    if DEBUG:
                        print("\n*** WARNING: detection of entangled node outside the current graph, " \
                                  "whereas 'accept_external_entanglement' parameter is set to False!")
                        print("[ accept_external_entanglement = %r, ignore_frozen_state = %r, current copied node: %s ]" \
                                  % (accept_external_entanglement, ignore_frozen_state, self.name))
                        print(' --> Node: ', node.name, repr(node))
                        print(' --> Entangled with external node: ', e.name, repr(e))
                        print(" --> Entangled nodes of node '%s':" % node.name)
                        for e in node.entangled_nodes:
                            print('  -', e.name, repr(e),
                                  " [in node_dico.keys(): %r / .values(): %r]" % (e in node_dico, e in node_dico.values()))
                        # raise ValueError

            if node is base_node:
                self.entangled_nodes = intrics
            else:
                node.entangled_nodes = intrics

        self.current_conf = copy.copy(base_node.current_conf)

        self._reset_depth(parent_depth=self.depth-1)

        return node_dico

    def set_fuzz_weight(self, w):
        '''Set the fuzzing weight of the node to `w`.

        The fuzz weight is an optional attribute of Node() which
        express Data Model designer's hints for prioritizing the nodes
        to fuzz. If set, this attribute is used by some generic
        *disruptors* (the ones that rely on a ModelWalker object---refer to
        fuzzing_primitives.py)

        Args:
          w (int): Value of the weight (by default every nodes has a weight of 1)

        Returns:
          None
        '''
        self.fuzz_weight = int(w)

    def get_fuzz_weight(self):
        '''Return the fuzzing weight of the node.

        Returns:
          int: the fuzzing weight
        '''
        return self.fuzz_weight

    def reset_fuzz_weight(self, recursive=False):
        '''Reset to standard (1) the fuzzing weight that is associated to this
        node, and all its subnodes if `recursive` parameter is set to `True`.

        .. _test:

        Args:
          recursive (bool): if set to `True`, reset also every subnodes (all reachable nodes from this one).

        Returns:
          None
        '''
        self.fuzz_weight = 1
        if recursive:
            for conf in self.internals:
                self.internals[conf].reset_fuzz_weight(recursive=recursive)

    def add_conf(self, conf):
        # @conf could not be None or the empty string
        if conf and conf not in self.internals:
            self.internals[conf] = None
            return True
        else:
            return False

    def remove_conf(self, conf):
        if conf != 'MAIN':
            del self.internals[conf]

    def is_conf_existing(self, conf):
        return conf in self.internals

    def __get_confs(self):
        return self.internals.keys()

    confs = property(fget=__get_confs)
    '''Property giving all node's configurations (read only)'''

    def _set_subtrees_current_conf(self, node, conf, reverse, ignore_entanglement=False):
        if node.is_conf_existing(conf):
            conf2 = conf
        else:
            conf2 = node.current_conf

        if not reverse:
            node.current_conf = conf2

        if node.internals[node.current_conf]: # When an Node is created empty, there is None internals
            node.internals[node.current_conf].set_child_current_conf(node, conf, reverse,
                                                                   ignore_entanglement=ignore_entanglement)

        if not ignore_entanglement and node.entangled_nodes is not None:
            for e in node.entangled_nodes:
                e.internals[e.current_conf].set_child_current_conf(e, conf, reverse,
                                                                   ignore_entanglement=True)

        if reverse:
            node.current_conf = conf2


    def set_current_conf(self, conf, recursive=True, reverse=False, root_regexp=None, ignore_entanglement=False):

        if root_regexp is not None:
            node_list = self.get_reachable_nodes(path_regexp=root_regexp)
        else:
            node_list = [self]
        
        for e in node_list:
            if recursive:
                self._set_subtrees_current_conf(e, conf, reverse, ignore_entanglement=ignore_entanglement)
            else:
                if e.is_conf_existing(conf):
                    e.current_conf = conf

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_current_conf(conf, recursive=recursive, reverse=reverse, root_regexp=root_regexp,
                                   ignore_entanglement=True)


    def get_current_conf(self):
        return self.current_conf

    def gather_alt_confs(self):
        cfs = set()

        for c in self.confs:
            if c != 'MAIN':
                cfs.add(c)
        for c in self.confs:
            if self.is_nonterm(c):
                for e in self.c[c].subnodes_set:
                    cfs = cfs.union(e.gather_alt_confs())

        return cfs

    def entangle_with(self, node):
        assert(node is not self)

        if self.entangled_nodes is None:
            self.entangled_nodes = set([self])

        if node.entangled_nodes is None:
            node.entangled_nodes = set([node])

        self.entangled_nodes = self.entangled_nodes.union(node.entangled_nodes)
        node.entangled_nodes = self.entangled_nodes

        for e in self.entangled_nodes:
            if e is not self and e is not node:
                e.entangled_nodes = self.entangled_nodes


    def __get_current_internals(self):
        return self.internals[self.current_conf]

    def __set_current_internals(self, internal):
        self.internals[self.current_conf] = internal

    def __get_internals(self):
        return self.internals

    cc = property(fget=__get_current_internals, fset=__set_current_internals)
    '''Property linked to the current node's `internals` (read / write)'''

    c = property(fget=__get_internals)
    '''Property linked to `self.internals` (read only)'''
    
    def get_internals_backup(self):
        return Node(self.name, base_node=self, accept_external_entanglement=True)

    def set_internals(self, backup):
        self.name = backup.name
        self.env = backup.env
        self.semantics = backup.semantics
        self.fuzz_weight = backup.fuzz_weight
        self.depth = backup.depth
        self.tmp_ref_count = backup.tmp_ref_count
        self.internals = backup.internals
        self.current_conf = backup.current_conf
        self.entangled_nodes = backup.entangled_nodes

    def __check_conf(self, conf):
        if conf is None:
            conf = self.current_conf
        elif not self.is_conf_existing(conf):
            raise ValueError
        return conf

    def is_genfunc(self, conf=None):
        conf = self.__check_conf(conf)
        return isinstance(self.internals[conf], NodeInternals_GenFunc)

    def is_func(self, conf=None):
        conf = self.__check_conf(conf)
        return isinstance(self.internals[conf], NodeInternals_Func)

    def is_typed_value(self, conf=None):
        conf = self.__check_conf(conf)
        return isinstance(self.internals[conf], NodeInternals_TypedValue)

    def is_nonterm(self, conf=None):
        conf = self.__check_conf(conf)
        return isinstance(self.internals[conf], NodeInternals_NonTerm)

    def is_term(self, conf=None):
        conf = self.__check_conf(conf)
        return issubclass(self.internals[conf].__class__, NodeInternals_Term)


    def compliant_with(self, internals_criteria=None, semantics_criteria=None, conf=None):
        conf = self.__check_conf(conf)

        if internals_criteria:
            cond1 = self.internals[conf].match(internals_criteria)
        else:
            cond1 = True

        if semantics_criteria:
            if self.semantics is None:
                cond2 = False
            else:
                cond2 = self.semantics.match(semantics_criteria)
        else:
            cond2 = True

        return cond1 and cond2


    def _reset_depth(self, parent_depth):
        self.depth = parent_depth + 1

        for c in self.internals:
            self.internals[c].reset_depth_specific(self.depth)

    def _finalize_nonterm_node(self, conf, depth=None):
        if not depth:
            depth = self.depth

        check_err = set()
        for e in self.internals[conf].subnodes_set:
            check_err.add(e.name)
            e._reset_depth(depth)

        if len(check_err) != len(self.internals[conf].subnodes_set):
            print('\n*** /!\\ ERROR /!\\\n')
            l = []
            guilty = []
            for e in self.internals[conf].subnodes_set:
                print("*** |- node:  ", repr(e))
                print("*** |- name: ", e.name)
                if e.name in l:
                    guilty.append(e.name)
                else:
                    l.append(e.name)

            if guilty:
                print("\n*** You shall not use the same name for Nodes " + \
                          "that share a common parent (%s in conf : '%s')." % (self.name, conf))
                print("*** Duplicated Node name: '%s'" % guilty)
                print('\n*** /!\\ END /!\\\n')
            else:
                print('*** Bug in Node implementation...')

            raise ValueError


    def set_subnodes_basic(self, node_list, conf=None, ignore_entanglement=False):
        conf = self.__check_conf(conf)

        self.internals[conf] = NodeInternals_NonTerm()
        self.internals[conf].import_subnodes_basic(node_list)
        self._finalize_nonterm_node(conf)
   
        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_subnodes_basic(node_list=node_list, conf=conf, ignore_entanglement=True)



    def set_subnodes_with_csts(self, wlnode_list, conf=None, ignore_entanglement=False):
        conf = self.__check_conf(conf)

        self.internals[conf] = NodeInternals_NonTerm()
        self.internals[conf].import_subnodes_with_csts(wlnode_list)
        self._finalize_nonterm_node(conf)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_subnodes_basic(wlnode_list=wlnode_list, conf=conf, ignore_entanglement=True)


    def set_subnodes_full_format(self, full_list, conf=None):
        conf = self.__check_conf(conf)

        self.internals[conf] = NodeInternals_NonTerm()
        self.internals[conf].import_subnodes_full_format(subnodes_csts=full_list)
        self._finalize_nonterm_node(conf)


    def set_values(self, val_list=None, value_type=None, conf=None, ignore_entanglement=False):
        conf = self.__check_conf(conf)

        if val_list is not None:
            from fuzzfmk.value_types import String

            self.internals[conf] = NodeInternals_TypedValue()
            self.internals[conf].import_value_type(value_type=String(val_list=val_list))

        elif value_type is not None:
            self.internals[conf] = NodeInternals_TypedValue()
            self.internals[conf].import_value_type(value_type)

        else:
            raise ValueError

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                if value_type is not None:
                    value_type = copy.copy(value_type)
                    value_type.make_private(forget_current_state=True)
                e.set_values(val_list=copy.copy(val_list), value_type=value_type, conf=conf, ignore_entanglement=True)


    def set_func(self, func, func_node_arg=None, func_arg=None,
                 conf=None, ignore_entanglement=False, provide_helpers=False):
        conf = self.__check_conf(conf)

        self.internals[conf] = NodeInternals_Func()
        self.internals[conf].import_func(func,
                                         fct_node_arg=func_node_arg, fct_arg=func_arg,
                                         provide_helpers=provide_helpers)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_func(func, func_node_arg=func_node_arg,
                           func_arg=func_arg, conf=conf,
                           ignore_entanglement=True)


    def set_generator_func(self, gen_func, func_node_arg=None,
                           func_arg=None, conf=None, ignore_entanglement=False,
                           provide_helpers=False):
        conf = self.__check_conf(conf)

        self.internals[conf] = NodeInternals_GenFunc()
        self.internals[conf].import_generator_func(gen_func,
                                                   generator_node_arg=func_node_arg, generator_arg=func_arg,
                                                   provide_helpers=provide_helpers)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_func(gen_func, func_node_arg=func_node_arg, func_arg=func_arg, conf=conf, ignore_entanglement=True)


    def make_empty(self, conf=None):
        conf = self.__check_conf(conf)
        self.internals[conf] = NodeInternals_Empty()
        

    def absorb(self, blob, constraints=AbsCsts(), conf=None):
        conf, next_conf = self._compute_confs(conf=conf, recursive=True)
        blob = convert_to_internal_repr(blob)
        status, off, sz = self.internals[conf].absorb(blob, constraints=constraints, conf=next_conf)
        if len(blob) == sz and status == AbsorbStatus.Absorbed:
            status = AbsorbStatus.FullyAbsorbed
        return status, off, sz, self.name

    def set_absorb_helper(self, helper, conf=None):
        conf = self.__check_conf(conf)
        self.internals[conf].set_absorb_helper(helper)

    def enforce_absorb_constraints(self, csts, conf=None):
        conf = self.__check_conf(conf)
        self.internals[conf].enforce_absorb_constraints(csts)

    # Does not affect function/generator Nodes
    def make_determinist(self, conf=None, all_conf=False, recursive=False):
        self.set_attr(NodeInternals.Determinist, conf, all_conf=all_conf, recursive=recursive)

    # Does not affect function/generator Nodes
    def make_random(self, conf=None, all_conf=False, recursive=False):
        self.clear_attr(NodeInternals.Determinist, conf, all_conf=all_conf, recursive=recursive)

    # Does not affect function/generator & nonterm Nodes
    def make_finite(self, conf=None, all_conf=False, recursive=False):
        self.set_attr(NodeInternals.Finite, conf, all_conf=all_conf, recursive=recursive)

    # Does not affect function/generator & nonterm Nodes
    def make_infinite(self, conf=None, all_conf=False, recursive=False):
        self.clear_attr(NodeInternals.Finite, conf, all_conf=all_conf, recursive=recursive)

    def _compute_confs(self, conf, recursive):
        if recursive:
            next_conf = conf
        else:
            next_conf = None

        if not self.is_conf_existing(conf):
            current_conf = self.current_conf
        else:
            current_conf = conf

        if self.is_genfunc(current_conf):
            next_conf = conf

        return current_conf, next_conf

    def _set_clone_info(self, info):
        '''Used to propagate random draw results when a NonTerm node is frozen
        to the dynamic nodes of its attached subgraphs, namely
        GenFunc/Func nodes which are the only ones which can act
        dynamically.
        '''
        for c in self.internals:
            self.internals[c].set_clone_info(info)

    def make_synchronized_with(self, node, scope, conf=None):
        conf = self.__check_conf(conf)
        self.internals[conf].set_node_sync(node, scope=scope)

    def synchronized_with(self, scope, conf=None):
        conf = self.__check_conf(conf)
        return self.internals[conf].get_node_sync(scope)

    def set_attr(self, name, conf=None, all_conf=False, recursive=False):
        if all_conf:
            for c in self.internals:
                self.internals[c].set_attr(name)
                self.internals[c].set_child_attr(name, all_conf=True, recursive=recursive)

        else:
            conf, next_conf = self._compute_confs(conf, recursive)
            self.internals[conf].set_attr(name)
            self.internals[conf].set_child_attr(name, conf=next_conf, recursive=recursive)


    def clear_attr(self, name, conf=None, all_conf=False, recursive=False):
        if all_conf:
            for c in self.internals:
                self.internals[c].clear_attr(name)
                self.internals[c].clear_child_attr(name, all_conf=True, recursive=recursive)
        else:
            conf, next_conf = self._compute_confs(conf, recursive)
            self.internals[conf].clear_attr(name)
            self.internals[conf].clear_child_attr(name, conf=next_conf, recursive=recursive)

    def is_attr_set(self, name, conf=None):
        conf = self.__check_conf(conf)
        return self.internals[conf].is_attr_set(name)

    def set_private(self, val, conf=None):
        conf = self.__check_conf(conf)
        self.internals[conf].set_private(val)

    def get_private(self, conf=None):
        conf = self.__check_conf(conf)
        return self.internals[conf].get_private()

    def set_semantics(self, val):
        self.semantics = val

    def get_semantics(self):
        return self.semantics


    def get_reachable_nodes(self, internals_criteria=None, semantics_criteria=None,
                            owned_conf=None, conf=None, path_regexp=None, exclude_self=False,
                            respect_order=False, relative_depth=-1, top_node=None):
        
        def __compliant(node, config, top_node):
            if node is top_node and exclude_self:
                return False

            if internals_criteria:
                cond1 = node.internals[config].match(internals_criteria)
            else:
                cond1 = True

            if semantics_criteria:
                if node.semantics is None:
                    cond2 = False
                else:
                    cond2 = node.semantics.match(semantics_criteria)
            else:
                cond2 = True

            if path_regexp is not None:
                paths = node.get_all_paths_from(top_node)
                for p in paths:
                    if re.search(path_regexp, p):
                        cond3 = True
                        break
                else:
                    cond3 = False
            else:
                cond3 = True

            return cond1 and cond2 and cond3

        def get_reachable_nodes_rec(node, config, rdepth, top_node):
            s = []
            # if respect_order:
            #     s = []
            # else:
            #     s = set()

            if config == None:
                config = self.current_conf
                next_conf = None
            else:
                next_conf = config

            if not node.is_conf_existing(config):
                config = node.current_conf

            internal = node.internals[config]

            if node.is_conf_existing(owned_conf) or (owned_conf == None):
                if __compliant(node, config, top_node):
                    s.append(node)
                    # if respect_order:
                    #     s.append(node)
                    # else:
                    #     s.add(node)

            if rdepth <= -1 or rdepth > 0:
                s2 = internal.get_child_nodes_by_attr(internals_criteria=internals_criteria,
                                                      semantics_criteria=semantics_criteria,
                                                      owned_conf=owned_conf, conf=next_conf,
                                                      path_regexp=path_regexp,
                                                      exclude_self=exclude_self,
                                                      respect_order=respect_order,
                                                      relative_depth = rdepth - 1,
                                                      top_node=top_node)
                if s2:
                    for e in s2:
                        if e not in s:
                            s.append(e)
                    # if respect_order:
                    #     for e in s2:
                    #         if e not in s:
                    #             s.append(e)
                    # else:
                    #     s = s.union(s2)

            return s

        if top_node is None:
            nodes = get_reachable_nodes_rec(node=self, config=conf, rdepth=relative_depth,
                                                    top_node=self)
        else:
            nodes = get_reachable_nodes_rec(node=self, config=conf, rdepth=relative_depth,
                                                    top_node=top_node)

        if respect_order:
            return nodes
        else:
            l1 = []
            l2 = []
            for e in nodes:
                if e.get_fuzz_weight() > 1:
                    l1.append(e)
                else:
                    l2.append(e)
            l1 = sorted(l1, key=lambda x: -x.get_fuzz_weight())

            return l1 + sorted(l2, key=lambda x: x.name)


    def get_node_by_path(self, path_regexp=None, path=None, conf=None):
        '''
        The set of nodes that is used to perform the search include
        the node itself and all the subnodes behind it.
        '''
        htable = self.get_all_paths(conf=conf)

        if path is None:
            assert(path_regexp is not None)
            # Find *one* Node whose path match the regexp
            for n, e in htable.items():
                if re.search(path_regexp, n):
                    ret = e
                    break
            else:
                ret = None
        else:
            # Find the Node through exact path
            try:
                ret = htable[path]
            except KeyError:
                ret = None

        return ret


    def _get_all_paths_rec(self, pname, htable, conf, recursive, first=True):

        if recursive:
            next_conf = conf
        else:
            next_conf = None

        if not self.is_conf_existing(conf):
            conf = self.current_conf
        internal = self.internals[conf]

        if first:
            name = self.name
        else:
            name = pname + '/' + self.name

        htable[name] = self

        internal.get_child_all_path(name, htable, conf=next_conf, recursive=recursive)


    def get_all_paths(self, conf=None, recursive=True, depth_min=None, depth_max=None):
        htable = collections.OrderedDict()
        self._get_all_paths_rec('', htable, conf, recursive=recursive)

        if depth_min is not None or depth_max is not None:
            depth_min = int(depth_min) if depth_min is not None else 0
            depth_max = int(depth_max) if depth_max is not None else -1
            paths = copy.copy(htable)
            for k in paths:
                depth = len(k.split('/'))
                if depth < depth_min:
                    del htable[k]
                elif depth_max != -1 and depth > depth_max:
                    del htable[k]
                
        return htable


    def get_path_from(self, node, conf=None):
        htable = node.get_all_paths(conf=conf)
        for n, e in htable.items():
            if e == self:
                return n
        else:
            return "*** ERROR: get_path_from() --> Node '{:s}' " \
                "not reachable from '{:s}'***".format(self.name, node.name)


    def get_all_paths_from(self, node, conf=None):
        htable = node.get_all_paths(conf=conf)
        l = []
        for n, e in htable.items():
            if e == self:
                l.append(n)
        return l

    
    def get_hkeys(self, conf=None):
        return set(self.get_all_paths(conf=conf).keys())

    def __set_env_rec(self, env):
        self.env = env
        for c in self.internals:
            self.internals[c].set_child_env(env)

    def set_env(self, env):
        self.__set_env_rec(env)

    def get_env(self):
        return self.env


    def get_value(self, conf=None, recursive=True):
        
        if recursive:
            next_conf = conf
        else:
            next_conf = None

        if not self.is_conf_existing(conf):
            conf2 = self.current_conf
        else:
            conf2 = conf

        if self.is_genfunc(conf2):
            next_conf = conf

        internal = self.internals[conf2]
        if internal is None:
            print("\n*** The Node named '{:s}' is used while it has not " \
                      "been completely specified!\n (no NodeInternals has " \
                      "been associted to the Node.)".format(self.name))
            raise ValueError

        ret, was_not_frozen = internal.get_value(conf=next_conf, recursive=recursive)

        if was_not_frozen:
            self._post_freeze(internal)
            # We need to test self.env because an Node can be freezed
            # before being registered in the data model. It triggers
            # for instance when a generator Node is freezed
            # (get_value() is called on it) during data model
            # construction.
            if internal.is_exhausted() and self.env is not None:
                self.env.notify_exhausted_node(self)

        return ret


    def _post_freeze(self, node_internals):
        if self._post_freeze_handler is not None:
            self._post_freeze_handler(node_internals)
        
    def register_post_freeze_handler(self, func):
        self._post_freeze_handler = func

    def is_exhausted(self, conf=None):
        conf = self.__check_conf(conf)
        return self.internals[conf].is_exhausted()

    def is_frozen(self, conf=None):
        conf = self.__check_conf(conf)
        return self.internals[conf].is_frozen()

    def reset_state(self, recursive=False, exclude_self=False, conf=None, ignore_entanglement=False):
        current_conf, next_conf = self._compute_confs(conf=conf, recursive=recursive)
        self.internals[current_conf].reset_state(recursive=recursive, exclude_self=exclude_self, conf=next_conf,
                                                 ignore_entanglement=ignore_entanglement)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.reset_state(recursive=recursive, exclude_self=exclude_self, conf=next_conf,
                              ignore_entanglement=True)

    def to_bytes(self, conf=None, recursive=True):
        val = self.get_value(conf=conf, recursive=recursive)

        if not isinstance(val, bytes):
            val = list(flatten(val))
            val = b''.join(val)

        return val

    get_flatten_value = to_bytes

    def set_frozen_value(self, value, conf=None):
        conf = self.__check_conf(conf)

        if self.is_term(conf):
            value = convert_to_internal_repr(value)
            self.internals[conf]._set_frozen_value(value)
        else:
            raise ValueError


    def unfreeze(self, conf=None, recursive=True, dont_change_state=False, ignore_entanglement=False, only_generators=False):
        if conf is not None:
            next_conf = conf
        else:
            next_conf = None

        if not self.is_conf_existing(conf):
            conf = self.current_conf

        if self.is_frozen(conf):
            self.internals[conf].unfreeze(next_conf, recursive=recursive, dont_change_state=dont_change_state,
                                          ignore_entanglement=ignore_entanglement, only_generators=only_generators)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.unfreeze(conf=next_conf, recursive=recursive, dont_change_state=dont_change_state,
                           ignore_entanglement=True, only_generators=only_generators)


    def unfreeze_all(self, recursive=True, ignore_entanglement=False):
        
        for conf in self.internals:
            if self.is_frozen(conf):
                self.internals[conf].unfreeze_all(recursive=recursive)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.unfreeze_all(recursive=recursive, ignore_entanglement=True)



    def pretty_print(self, conf=None):
        conf = self.__check_conf(conf)
        return self.internals[conf].pretty_print()

    def get_nodes_names(self, conf=None, verbose=False, terminal_only=False):

        htable = self.get_all_paths(conf=conf)

        l = []
        for n, e in htable.items():
            if terminal_only:
                conf = e.__check_conf(conf)
                if not e.is_term(conf):
                    continue

            if verbose:
                l.append((n, e.depth, e.to_bytes()))
            else:
                l.append((n, e.depth))

            if e.env is None:
                print(n + ' (' + str(e.depth) + ')' + ' ' + str(e.env))
                print('Node value: ', e.to_bytes())
                print("The 'env' attr of this Node is NONE")
                raise ValueError

        return l


    @staticmethod
    def _print(msg, rgb, style='', nl=True, log_func=lambda x: x):
        end = '\n' if nl else ''
        sys.stdout.write(style)
        sys.stdout.write(colorize(msg, rgb=rgb))
        log_func(msg + end)
        if style:
            sys.stdout.write(FontStyle.END+end)
        else:
            sys.stdout.write(end)
        sys.stdout.flush()

    @staticmethod
    def _print_name(msg, style='', nl=True, log_func=lambda x: x):
        Node._print(msg, rgb=Color.ND_NAME, style=style, nl=nl, log_func=log_func)

    @staticmethod
    def _print_type(msg, style=FontStyle.BOLD, nl=True, log_func=lambda x: x):
        Node._print(msg, rgb=Color.ND_TYPE, style=style, nl=nl, log_func=log_func)

    @staticmethod
    def _print_contents(msg, style='', nl=True, log_func=lambda x: x):
        Node._print(msg, rgb=Color.ND_CONTENTS, style=style, nl=nl, log_func=log_func)

    @staticmethod
    def _print_nonterm(msg, style=FontStyle.BOLD, nl=True, log_func=lambda x: x):
        Node._print(msg, rgb=Color.ND_NONTERM, style=style, nl=nl, log_func=log_func)

    @staticmethod
    def _print_raw(msg, style='', nl=True, hlight=False, log_func=lambda x: x):
        if hlight:
            st = FontStyle.BOLD if style == '' else style
            Node._print(msg, rgb=Color.ND_RAW_HLIGHT, style=st, nl=nl, log_func=log_func)
        else:
            Node._print(msg, rgb=Color.ND_RAW, style=style, nl=nl, log_func=log_func)

    def show(self, conf=None, verbose=True, print_name_func=None, print_contents_func=None,
             print_raw_func=None, print_nonterm_func=None, print_type_func=None, alpha_order=False,
             raw_limit=None, log_func=lambda x: x):

        if print_name_func is None:
            print_name_func = self._print_name
        if print_nonterm_func is None:
            print_nonterm_func = self._print_nonterm
        if print_contents_func is None:
            print_contents_func = self._print_contents
        if print_raw_func is None:
            print_raw_func = self._print_raw
        if print_type_func is None:
            print_type_func = self._print_type

        def get_args(node, conf):
            args = ''
            first = True
            for n in node.c[conf].get_node_args():
                if first:
                    first = False
                    args += n.get_path_from(self, conf=conf)
                else:
                    args += ', ' + n.get_path_from(self, conf=conf)
            if args is '':
                args = 'None'
            return args

        def get_all_smaller_depth(nodes_nb, i, depth, conf):
            smaller_depth = []
            prev_depth = l[i][0].count('/')

            for j in range(i, nodes_nb):
                current = l[j][1]
                sep_nb = l[j][0].count('/')
                if current.depth != sep_nb:
                    # case when the same node is used at different depth
                    if not hasattr(current, '_seen'):
                        current._seen = True
                        current.depth = sep_nb

                if current.depth != prev_depth:
                    break

                prev_depth = current.depth


            for j in range(i, nodes_nb):
                current = l[j][1]
                if hasattr(current, '_seen'):
                    del current._seen

            for j in range(i+1, nodes_nb):
                delta = depth - l[j][1].depth
                if delta > 0:
                    d = l[j][1].depth
                    if d not in smaller_depth:
                        if not smaller_depth or (smaller_depth and d < smaller_depth[-1]):
                            smaller_depth.append(d)

            return smaller_depth

        # in case the node is not frozen
        self.get_value()

        htable = self.get_all_paths(conf=conf)
        l = []
        for n, e in htable.items():
            l.append((n, e))

        if alpha_order:
            l = sorted(l, key=lambda x: x[0])

        name = '[' + self.name + ']'
        print_name_func(name, log_func=log_func)
        print_name_func('-' * len(name), log_func=log_func)

        nodes_nb = len(l)

        if verbose:
            prev_depth = 0
            for n, i in zip(l, range(nodes_nb)):
                name, node = n

                conf_tmp = node.__check_conf(conf)
                if isinstance(node.c[conf_tmp], NodeInternals_TypedValue):
                    node_type = node.c[conf_tmp].get_value_type().__class__.__name__
                else:
                    node_type = node.c[conf_tmp].__class__.__name__[len('NodeInternals_'):]

                depth = node.depth
                sep_nb = name.count('/')
                if depth != sep_nb:
                    # detection that the same node is used multiple
                    # times at different level. Thus it is a graph
                    depth = sep_nb
                    node.depth = sep_nb

                def is_node_used_more_than_once(name):
                    node_list = []
                    for item in l:
                        if re.search(name+'$', item[0]):
                            node_list.append(item[1])
                    if len(node_list) != len(set(node_list)):
                        return True
                    else:
                        return False

                if is_node_used_more_than_once(node.name):
                    graph_deco = ' --> M'
                else:
                    graph_deco = ''

                if depth == 0:
                    indent_nonterm = ''
                    indent_spc = ''
                    indent_term = ''
                else:
                    all_smaller_depth = get_all_smaller_depth(nodes_nb, i, depth, conf_tmp)
                    # if i != nodes_nb-1:
                    #     print('DBG1: ', l[i+1][1].depth, l[i+1][0], repr(l[i+1][1]))

                    prefix = ''
                    sz = len(all_smaller_depth)
                    idx = 0
                    for bar in range(depth-1, 0, -1):
                        if idx < sz and bar == all_smaller_depth[idx]:
                            idx += 1
                            prefix = ' |  ' + prefix
                        else:
                            prefix = '    ' + prefix
                    indent_nonterm = prefix + ' \__'
                    indent_term = prefix + ' \__'

                    # l[i+1][1].depth is not reliable in case the node is used at different level
                    if i == nodes_nb-1 or depth != l[i+1][0].count('/'):
                        # if i != nodes_nb-1:
                        #     print('DBG2: ', l[i+1][1].depth, l[i+1][0], repr(l[i+1][1]), i+1)
                        indent_spc = prefix + '    ' + '    '
                    else:
                        indent_spc = prefix + ' |  ' + '    '

                prev_depth = depth

                if node.is_term(conf_tmp):
                    raw = node.to_bytes()
                    raw_len = len(raw)
                    val = node.pretty_print()

                    prefix = "{:s}".format(indent_term)
                    name = "{:s} ".format(name)
                    if isinstance(node.c[conf_tmp], NodeInternals_Func):
                        args = get_args(node, conf_tmp)
                        type_and_args = '[{:s} | node_args: {:s}] size={:d}B' \
                            .format(node_type, args, raw_len)
                    else:
                        type_and_args = '[{:s}] size={:d}B'.format(node_type, raw_len)
                    print_nonterm_func(prefix, nl=False, log_func=log_func)
                    print_name_func('({:d}) {:s}'.format(depth, name), nl=False, log_func=log_func)
                    print_type_func(type_and_args, nl=False, log_func=log_func)
                    self._print(graph_deco, rgb=Color.ND_DUPLICATED, style=FontStyle.BOLD,
                                log_func=log_func)
                    if val is not None:
                        print_nonterm_func("{:s}  ".format(indent_spc) , nl=False, log_func=log_func)
                        print_contents_func("\_ {:s}".format(val), log_func=log_func)
                    print_nonterm_func("{:s}  ".format(indent_spc) , nl=False, log_func=log_func)
                    if raw_limit and raw_len > raw_limit:
                        print_raw_func("\_raw: {:s}".format(repr(raw[:raw_limit])), nl=False,
                                       log_func=log_func)
                        print_raw_func(" ...", hlight=True, log_func=log_func)
                    else:
                        print_raw_func("\_raw: {:s}".format(repr(raw)), log_func=log_func)
                else:
                    print_nonterm_func("{:s}[{:d}] {:s}".format(indent_nonterm, depth, name), nl=False,
                                       log_func=log_func)
                    if isinstance(node.c[conf_tmp], NodeInternals_GenFunc):
                        args = get_args(node, conf_tmp)
                        print_nonterm_func(' [{:s} | node_args: {:s}]'.format(node_type, args),
                                           nl=False, log_func=log_func)
                        self._print(graph_deco, rgb=Color.ND_DUPLICATED, style=FontStyle.BOLD,
                                    log_func=log_func)
                    else:
                        print_nonterm_func(' [{:s}]'.format(node_type), nl=False, log_func=log_func)
                        self._print(graph_deco, rgb=Color.ND_DUPLICATED, style=FontStyle.BOLD,
                                    log_func=log_func)

        else:
            for name, node in l:
                print_name_func("{:s} [{:d}]".format(name, node.depth), log_func=log_func)


    def __lt__(self, other):
        return self.depth < other.depth


    def __hash__(self):
        return id(self)

    def __str__(self):
        # NEVER return something with self.to_bytes() as side
        # effects are not welcomed
        return repr(self)


    def __getitem__(self, key):
        # self.get_value()
        if isinstance(key, str):
            return self.get_node_by_path(key)
        elif isinstance(key, NodeInternalsCriteria):
            return self.get_reachable_nodes(internals_criteria=key)
        elif isinstance(key, NodeSemanticsCriteria):
            return self.get_reachable_nodes(semantics_criteria=key)
        else:
            raise ValueError

    def __setitem__(self, key, val):
        if isinstance(val, Node):
            self[key].set_contents(val)
        elif isinstance(val, NodeSemantics):
            self[key].set_semantics(val)
        elif isinstance(val, int):
            # Method defined by INT object (within TypedValue nodes)
            self[key].set_raw_values(val)
        else:
            status, off, size, name = self[key].absorb(convert_to_internal_repr(val),
                                                       constraints=AbsNoCsts())
            if status != AbsorbStatus.FullyAbsorbed:
                raise ValueError


    def __getattr__(self, name):
        internals = self.__getattribute__('internals')[self.current_conf]
        if hasattr(internals, name):
            return getattr(internals, name)
        else:
            return object.__getattribute__(self, name)
    
class Env4NT(object):
    ''' 
    Define methods for non-terminal nodes
    '''
    def __init__(self):
        self.drawn_node_attrs = {}

    def set_drawn_node_attrs(self, node_id, nb, sz):
        self.drawn_node_attrs[node_id] = (nb, sz)

    def get_drawn_node_qty(self, node_id):
        return self.drawn_node_attrs.get(node_id, (None, None))[0]

    def get_drawn_node_sz(self, node_id):
        return self.drawn_node_attrs.get(node_id, (None, None))[1]

    def node_exists(self, node_id):
        qty, sz = self.drawn_node_attrs.get(node_id, (0, 0))
        if qty > 0 and sz > 0:
            return True
        else:
            return False

    # not currently used
    def clear_drawn_node_attrs(self, node_id):
        del self.drawn_node_attrs[node_id]

    def update_node_ids(self, id_list):
        if not self.drawn_node_attrs:
            return

        new_attrs = {}
        for old_id, new_id in id_list:
            obj = self.drawn_node_attrs.get(old_id, None)
            if obj is not None:
                new_attrs[new_id] = obj

        self.drawn_node_attrs = new_attrs

    def is_empty(self):
        return not self.drawn_node_attrs

    def reset(self):
        self.drawn_node_attrs = {}

    def __copy__(self):
        new_env = type(self)()
        new_env.__dict__.update(self.__dict__)
        new_env.drawn_node_attrs = copy.copy(self.drawn_node_attrs)
        return new_env


class Env(object):

    def __init__(self):
        self.exhausted_nodes = []
        self.env4NT = Env4NT()

    def __getattr__(self, name):
        if hasattr(self.env4NT, name):
            return self.env4NT.__getattribute__(name)
        else:
            raise AttributeError

    def is_empty(self):
        return not self.exhausted_nodes and self.env4NT.is_empty()

    def set_data_model(self, dm):
        self.__dm = dm

    def get_data_model(self):
        return self.__dm

    def exhausted_node_exists(self):
        return False if len(self.exhausted_nodes) == 0 else True

    def get_exhausted_nodes(self):
        return copy.copy(self.exhausted_nodes)

    def notify_exhausted_node(self, node):
        self.exhausted_nodes.append(node)

    def is_node_exhausted(self, node):
        if node in self.exhausted_nodes:
            return True
        else:
            return False

    def clear_exhausted_node(self, node):
        try:
            self.exhausted_nodes.remove(node)
        except:
            print('*** requested node.name:       ', node.name)
            print('*** requested node:            ', node)
            print('*** current exhausted list:')
            for i in self.exhausted_nodes:
                print('  * exhausted_node.name:  ', i.name)
                print('  * exhausted_node:       ', i)
            if not self.exhausted_nodes:
                print('  * no exhausted node')

            raise

    def exhausted_nodes_amount(self):
        return len(self.exhausted_nodes)

    def clear_all_exhausted_nodes(self):
        self.exhausted_nodes = []

    def update_node_refs(self, node_dico, ignore_frozen_state):

        if self.is_empty():
            return

        if ignore_frozen_state:
            self.exhausted_nodes = []
            self.env4NT.reset()
            return

        exh_nodes = []
        id_list = []
        for old_node, new_node in node_dico.items():
            id_list.append((id(old_node), id(new_node)))
            if old_node in self.exhausted_nodes:
                exh_nodes.append(new_node)

        self.exhausted_nodes = exh_nodes
        self.env4NT.update_node_ids(id_list)


    def __copy__(self):
        new_env = type(self)()
        new_env.__dict__.update(self.__dict__)
        new_env.exhausted_nodes = copy.copy(self.exhausted_nodes)
        new_env.env4NT = copy.copy(self.env4NT)
        return new_env



if __name__ == "__main__":



    csts = ['>', ['fpn_h', 1], ['rp', 1, 2], ['ra', 1], '=', ['fpn_h', 1, 3], ['ra', 3]]

    csts_l = [
        1, ['u>', ['fpn_h', 1], ['rp', 1, 2], ['ra', 1], '=', ['fpn_h', 1, 3], ['ra', 3]],
        3, ['s=.(1,3)', ['fpn_h', 1], ['rp', 1, 2], 'u=.', ['fpn_h', 1, 3], 'u>', ['ra', 3]],
        5, ['u=.', ['fpn_h', 4, 7], 'u>', ['ra', 8]]
        ]

    print(csts_l)

    for weight, csts in split_with(lambda x: isinstance(x, int), csts_l):
        for delim, nodes_l in split_with(lambda x: isinstance(x, str), csts[0]):
            print(weight, delim, nodes_l)


    print('\n******\n')

    for weight, csts in split_with(lambda x: isinstance(x, int), csts_l):
        for idx, delim, nodes_l in split_verbose_with(lambda x: isinstance(x, str), csts[0]):
            print(weight, idx, delim, nodes_l)


    print('\n******\n')

    for idx, weight, csts in split_verbose_with(lambda x: isinstance(x, int), csts_l):
            print(idx, weight, csts)

    print('\n*** TEST:')

    val = [b'*', [b'+', b'$']]
    print(val)

    val = list(flatten(val))
    val = b''.join(val)
    print(val)

