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
import uuid
import struct
import math
import time

from pprint import pprint as pp

from enum import Enum
from random import shuffle

sys.path.append(".")

from fuddly.framework.basic_primitives import *
from fuddly.libs.external_modules import *
from fuddly.framework.global_resources import *
from fuddly.framework.error_handling import *
from fuddly.framework.constraint_helpers import CSP, ConstraintError

from fuddly.framework import value_types as fvt
from fuddly.framework import encoders as enc

from fuddly.libs import debug_facility as dbg
from fuddly.libs.utils import chunk_lines

DEBUG = dbg.DM_DEBUG
DEBUG_PRINT = dbg.DEBUG_PRINT


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
        if hasattr(x, "__iter__") and not isinstance(x, (str, bytes)):
            for y in flatten(x):
                yield y
        else:
            yield x


nodes_weight_re = re.compile(r'(.*?)\((.*)\)')

### Debug Means ###

def print_node_list(node_list):
    s = f'['
    for i, node in enumerate(node_list):
        s += f'\n {i} {node.name} {node.cc} {id(node)},'
    s += f'\n]'
    print(s)

### Materials for Node Synchronization ###

# WARNING: If new SyncObj are created or evolve, don't forget to update
# NodeInternals.set_contents_from() accordingly.


class SyncScope(Enum):
    Qty = 1
    QtyFrom = 2
    Existence = 10
    Inexistence = 11
    Size = 20


class SyncObj(object):
    def get_node_containers(self):
        """
        Shall return either a :class:`Node` or a list of ``Nodes`` or a list of ``(Node, param)``
        where ``param`` should provide ``__copy__`` method if needed.
        """
        raise NotImplementedError

    def put_node_containers(self, new_containers):
        """
        This method will be called to provide updated containers that should
        replace the old ones.

        Args:
            new_containers: the updated containers
        """
        raise NotImplementedError

    def make_private(self, node_dico):
        node_containers = self.get_node_containers()
        if node_containers:
            if isinstance(node_containers, Node):
                new_node = node_dico.get(node_containers, None)
                if new_node is not None:
                    self.put_node_containers(new_node)
                else:
                    # refer to comments of NodeInternals._update_node_refs()
                    pass
            elif isinstance(node_containers, (tuple, list)):
                new_node_containers = []
                for ctr in node_containers:
                    if isinstance(ctr, Node):
                        node, param = ctr, None
                    else:
                        assert isinstance(ctr, (tuple, list)) and len(ctr) == 2
                        node, param = ctr
                    new_node = node_dico.get(node, None)
                    if new_node is not None:
                        if param is None:
                            new_node_containers.append(new_node)
                        else:
                            new_param = copy.copy(param)
                            new_node_containers.append((new_node, new_param))
                    else:
                        # refer to comments of NodeInternals._update_node_refs()
                        pass
                self.put_node_containers(new_node_containers)
            else:
                raise TypeError

    def synchronize_nodes(self, src_node):
        self._sync_nodes_specific(src_node)

    def _sync_nodes_specific(self, src_node):
        pass


class SyncQtyFromObj(SyncObj):
    def __init__(self, node, base_qty=0):
        assert node.is_typed_value()
        self._node = node
        self._base_qty = base_qty

    def get_node_containers(self):
        return self._node

    def put_node_containers(self, new_containers):
        self._node = new_containers

    @property
    def qty(self):
        return max(0, self._node.get_raw_value() + self._base_qty)


class SyncSizeObj(SyncObj):
    def __init__(self, node, base_size=0, apply_to_enc_size=False):
        assert node.is_typed_value()
        self._node = node
        self.base_size = base_size
        self.apply_to_enc_size = apply_to_enc_size

    def get_node_containers(self):
        return self._node

    def put_node_containers(self, new_containers):
        self._node = new_containers

    @property
    def size_for_absorption(self):
        return max(0, self._node.get_raw_value() - self.base_size)

    def set_size_on_source_node(self, size):
        ok = self._node.update_raw_value(size)
        if not ok:
            print(
                "\n*** WARNING: The node '{:s}' is not compatible with the integer"
                " '{:d}'".format(self._node.name, size)
            )
        self._node.set_frozen_value(self._node.get_current_value())

    def _sync_nodes_specific(self, src_node):
        if self.apply_to_enc_size:
            sz = len(src_node.to_bytes())
        else:
            if src_node.is_typed_value(subkind=fvt.String):
                # We need to get the str form to be agnostic to any low-level encoding
                # that may change the size ('utf8', ...).
                decoded_val = src_node.get_raw_value(str_form=True)
            else:
                decoded_val = src_node.get_raw_value()
                if not isinstance(decoded_val, bytes):
                    # In this case, this is a BitField or an INT-based object, which are
                    # fixed size object
                    raise DataModelDefinitionError(
                        "size sync should not be used for fixed sized object!"
                    )
            sz = len(decoded_val)
        sz += self.base_size
        self.set_size_on_source_node(
            NodeInternals_NonTerm.sizesync_corrupt_hook(src_node, sz)
        )


class SyncExistenceObj(SyncObj):
    def __init__(self, sync_list, and_junction=True):
        self.sync_list = sync_list
        self.and_clause = and_junction

    def get_node_containers(self):
        return self.sync_list

    def put_node_containers(self, new_containers):
        self.sync_list = new_containers

    def check(self):
        if self.and_clause:
            for node, cond in self.sync_list:
                if not self._condition_satisfied(node, cond):
                    return False
            else:
                return True
        else:
            for node, cond in self.sync_list:
                if self._condition_satisfied(node, cond):
                    return True
            else:
                return False

    def _condition_satisfied(self, node, condition):
        exist = node.env.node_exists(id(node))
        crit_1 = exist
        crit_2 = True
        if exist and condition is not None:
            try:
                crit_2 = condition.check(node)
            except Exception as e:
                print(
                    "\n*** ERROR: existence condition is not verifiable "
                    "for node '{:s}' (id: {:d})!\n"
                    "*** The condition checker raise an exception!".format(
                        node.name, id(node)
                    )
                )
                raise
        return crit_1 and crit_2


class NodeCondition(object):
    """
    Base class for every node-related conditions. (Note that NodeCondition
    may be copied many times. If some attributes need to be fully copied,
    handle this through __copy__() overriding).
    """

    def _check_int(self, val, gt_val=None, lt_val=None):
        result = True
        if gt_val is not None:
            result = val >= gt_val
        if lt_val is not None:
            result = val <= lt_val
        return result

    def _check_inclusion(self, curr_val, val=None, neg_val=None):
        result = True
        if val is not None:
            if isinstance(val, (tuple, list)):
                result = curr_val in val
            else:
                result = curr_val == val
        if neg_val is not None:
            if isinstance(neg_val, (tuple, list)):
                result = result and curr_val not in neg_val
            else:
                result = result and curr_val != neg_val
        return result

    def check(self, node):
        raise NotImplementedError


class RawCondition(NodeCondition):
    def __init__(self, val=None, neg_val=None, cond_func=None, case_sensitive=True):
        """
        Args:
          val (bytes/:obj:`list` of bytes): value(s) that satisfies the condition
          neg_val (bytes/:obj:`list` of bytes): value(s) that does NOT satisfy the condition (AND clause)
          cond_func: function that takes the node value and return a boolean
          case_sensitive: if False, ignore case for performing comparison
        """
        self.case_sensitive = case_sensitive
        self.val = self._handle_cond(val) if val is not None else None
        self.neg_val = self._handle_cond(neg_val) if neg_val is not None else None
        self.cond_func = cond_func

    def _handle_cond(self, val):
        if isinstance(val, (tuple, list)):
            normed_val = []
            for v in val:
                normed_v = (
                    convert_to_internal_repr(v)
                    if self.case_sensitive
                    else convert_to_internal_repr(v).lower()
                )
                normed_val.append(normed_v)
        else:
            normed_val = convert_to_internal_repr(val)
            normed_val = normed_val if self.case_sensitive else normed_val.lower()

        return normed_val

    def check(self, node):
        node_val = node._tobytes()

        if Node.DEFAULT_DISABLED_VALUE:
            node_val = node_val.replace(Node.DEFAULT_DISABLED_VALUE, b"")

        if not self.case_sensitive:
            node_val = node_val.lower()
        result = self._check_inclusion(node_val, val=self.val, neg_val=self.neg_val)
        if self.cond_func:
            result = result and self.cond_func(node_val)

        return result


class IntCondition(NodeCondition):
    def __init__(self, val=None, neg_val=None, gt_val=None, lt_val=None):
        """
        Args:
          val (int/:obj:`list` of int): integer(s) that satisfies the condition
          neg_val (int/:obj:`list` of int): integer(s) that does NOT satisfy the condition (AND clause)
          gt_val (int): condition met if greater than or equal to this value (AND clause)
          lt_val (int): condition met if lesser than or equal to this value (AND clause)
        """
        assert (
            val is not None
            or neg_val is not None
            or gt_val is not None
            or lt_val is not None
        )

        self.val = val
        self.neg_val = neg_val
        self.gt_val = gt_val
        self.lt_val = lt_val

    def check(self, node):
        if node.is_genfunc():
            node = node.generated_node

        assert node.is_typed_value(subkind=fvt.INT)

        curr_val = node.get_current_raw_val()

        result = self._check_inclusion(curr_val, val=self.val, neg_val=self.neg_val)

        return result and self._check_int(
            curr_val, gt_val=self.gt_val, lt_val=self.lt_val
        )


class BitFieldCondition(NodeCondition):
    def __init__(self, sf, val=None, neg_val=None, gt_val=None, lt_val=None):
        """
        Args:
          sf (int/:obj:`list` of int): subfield(s) of the BitField() on which the condition apply
          val (int/:obj:`list` of int/:obj:`list` of :obj:`list` of int): integer(s) that
            satisfies the condition(s)
          neg_val (int/:obj:`list` of int/:obj:`list` of :obj:`list` of int): integer(s) that
            does NOT satisfy the condition(s) (AND clause)
          gt_val (int/:obj:`list` of int/:obj:`list` of :obj:`list` of int): condition met if
            subfield(s) greater than or equal to values in this field (AND clause)
          lt_val (int/:obj:`list` of int/:obj:`list` of :obj:`list` of int): condition met if
            subfield(s) lesser than or equal to values in this field (AND clause)
        """

        assert (
            val is not None
            or neg_val is not None
            or gt_val is not None
            or lt_val is not None
        )

        if isinstance(sf, (tuple, list)):
            assert len(sf) != 0
            if val is not None:
                assert isinstance(val, (tuple, list)) and len(sf) == len(val)

            if neg_val is not None:
                assert isinstance(neg_val, (tuple, list)) and len(sf) == len(neg_val)
        else:
            sf = [sf]
            if val is not None:
                val = [val]

            if neg_val is not None:
                neg_val = [neg_val]

        self.sf = sf

        for sf in self.sf:
            assert sf is not None

        self.val = val if val is not None else [None for _ in self.sf]
        self.neg_val = neg_val if neg_val is not None else [None for _ in self.sf]

        if val is not None or neg_val is not None:
            for v, nv in zip(self.val, self.neg_val):
                assert v is not None or nv is not None

        self.gt_val = gt_val if gt_val is not None else [None for _ in self.sf]
        self.lt_val = lt_val if lt_val is not None else [None for _ in self.sf]

    def check(self, node):
        if node.is_genfunc():
            node = node.generated_node

        assert node.is_typed_value(subkind=fvt.BitField)

        result = True
        for sf, val, neg_val, gt_val, lt_val in zip(
            self.sf, self.val, self.neg_val, self.gt_val, self.lt_val
        ):
            curr_val = node.get_subfield(idx=sf)
            if val is not None:
                if not isinstance(val, (tuple, list)):
                    val = [val]
                result = result and curr_val in val
            if neg_val is not None:
                if not isinstance(neg_val, (tuple, list)):
                    neg_val = [neg_val]
                result = result and curr_val not in neg_val

            result = result and self._check_int(curr_val, gt_val=gt_val, lt_val=lt_val)

        return result


class NodeCustomization(object):
    """
    Base class for node cutomization
    """

    _custo_items = {}

    def __init__(self, items_to_set=None, items_to_clear=None, transform_func=None):
        self._transform_func = transform_func
        self._custo_items = copy.copy(self._custo_items)
        if items_to_set is not None:
            self.set_items(items_to_set)
        if items_to_clear is not None:
            self.clear_items(items_to_clear)

    def __getitem__(self, key):
        if key in self._custo_items:
            return self._custo_items[key]
        else:
            return None

    def set_items(self, items_to_set):
        if isinstance(items_to_set, int):
            assert items_to_set in self._custo_items
            self._custo_items[items_to_set] = True
        elif isinstance(items_to_set, list):
            for item in items_to_set:
                assert item in self._custo_items
                self._custo_items[item] = True
        else:
            raise ValueError

    def clear_items(self, items_to_clear):
        if isinstance(items_to_clear, int):
            assert items_to_clear in self._custo_items
            self._custo_items[items_to_clear] = False
        elif isinstance(items_to_clear, list):
            for item in items_to_clear:
                assert item in self._custo_items
                self._custo_items[item] = False
        else:
            raise ValueError

    def copy_from(self, node_custo):
        self._custo_items = copy.copy(node_custo._custo_items)

    @property
    def transform_func(self):
        return self._transform_func

    @transform_func.setter
    def transform_func(self, func):
        self._transform_func = func

    def __copy__(self):
        new_custo = type(self)()
        new_custo.__dict__.update(self.__dict__)
        new_custo._custo_items = copy.copy(self._custo_items)
        return new_custo


class NonTermCusto(NodeCustomization):
    """
    Non-terminal node behavior-customization
    To be provided to :meth:`NodeInternals.customize`
    """

    MutableClone = 1
    CycleClone = 2
    FrozenCopy = 3
    CollapsePadding = 4
    DelayCollapsing = 5

    FullCombinatory = 6
    StickToDefault = 7

    _custo_items = {
        MutableClone: True,
        CycleClone: False,
        FrozenCopy: True,
        CollapsePadding: False,
        DelayCollapsing: False,
        FullCombinatory: False,
        StickToDefault: False,
    }

    @property
    def mutable_clone_mode(self):
        return self._custo_items[self.MutableClone]

    @property
    def cycle_clone_mode(self):
        return self._custo_items[self.CycleClone]

    @property
    def frozen_copy_mode(self):
        return self._custo_items[self.FrozenCopy]

    @property
    def collapse_padding_mode(self):
        return self._custo_items[self.CollapsePadding]

    @property
    def delay_collapsing(self):
        return self._custo_items[self.DelayCollapsing]

    @property
    def full_combinatory_mode(self):
        return self._custo_items[self.FullCombinatory]

    @full_combinatory_mode.setter
    def full_combinatory_mode(self, val: bool):
        self._custo_items[self.FullCombinatory] = val

    @property
    def stick_to_default_mode(self):
        return self._custo_items[self.StickToDefault]


class GenFuncCusto(NodeCustomization):
    """
    Generator node behavior-customization
    To be provided to :meth:`NodeInternals.customize`
    """

    ForwardConfChange = 1
    CloneExtNodeArgs = 2
    ResetOnUnfreeze = 3
    TriggerLast = 4

    _custo_items = {
        ForwardConfChange: True,
        CloneExtNodeArgs: False,
        ResetOnUnfreeze: True,
        TriggerLast: False,
    }

    @property
    def forward_conf_change_mode(self):
        return self._custo_items[self.ForwardConfChange]

    @property
    def clone_ext_node_args_mode(self):
        return self._custo_items[self.CloneExtNodeArgs]

    @property
    def reset_on_unfreeze_mode(self):
        return self._custo_items[self.ResetOnUnfreeze]

    @property
    def trigger_last_mode(self):
        return self._custo_items[self.TriggerLast]


class FuncCusto(NodeCustomization):
    """
    Function node behavior-customization
    To be provided to :meth:`NodeInternals.customize`
    """

    FrozenArgs = 1
    CloneExtNodeArgs = 2

    _custo_items = {
        FrozenArgs: True,
        CloneExtNodeArgs: False,
    }

    @property
    def frozen_args_mode(self):
        return self._custo_items[self.FrozenArgs]

    @property
    def clone_ext_node_args_mode(self):
        return self._custo_items[self.CloneExtNodeArgs]


class NodeInternals(object):
    """
    Base class for implementing the contents of a node.
    """

    Freezable = 1
    Mutable = 2
    Determinist = 3
    Finite = 4

    Abs_Postpone = 6
    Separator = 15
    AutoSeparator = 16

    Highlight = 30
    DEBUG = 40
    LOCKED = 50

    DISABLED = 100

    default_custo = None

    def __hash__(self):
        return id(self)

    def __init__(self, arg=None):
        # if new attributes are added, set_contents_from() have to be updated
        self.private = None
        self.absorb_helper = None
        self.absorb_constraints = None
        self.custo = None
        self._env = None

        self.__attrs = {
            ### GENERIC ###
            NodeInternals.Freezable: True,
            NodeInternals.Mutable: True,
            NodeInternals.Determinist: True,
            NodeInternals.Finite: False,
            # Used for absorption
            NodeInternals.Abs_Postpone: False,
            # Used to distinguish separator
            NodeInternals.Separator: False,
            NodeInternals.AutoSeparator: False,
            # Used to display visual effect when the node is printed on the console
            NodeInternals.Highlight: False,
            # Used for debugging purpose
            NodeInternals.DEBUG: False,
            # Used to express that someone (a disruptor for instance) is
            # currently doing something with the node and doesn't want
            # that someone else modify it.
            NodeInternals.LOCKED: False,
            ### INTERNAL USAGE ###
            NodeInternals.DISABLED: False,
        }

        self._sync_with = None
        self.customize(self.default_custo)
        self._init_specific(arg)

    def set_contents_from(self, node_internals):
        if node_internals is None or node_internals.__class__ == NodeInternals_Empty:
            return

        self._env = node_internals._env
        self.private = node_internals.private
        self.__attrs = node_internals.__attrs
        self._sync_with = node_internals._sync_with
        self.absorb_constraints = node_internals.absorb_constraints

        if self.__class__ == node_internals.__class__:
            self.custo = node_internals.custo
            self.absorb_helper = node_internals.absorb_helper
        else:
            if self._sync_with is not None and SyncScope.Size in self._sync_with:
                # This SyncScope is currently only supported by String-based
                # NodeInternals_TypedValue
                del self._sync_with[SyncScope.Size]

    def get_attrs_copy(self):
        return (copy.copy(self.__attrs), copy.copy(self.custo))

    def set_attrs_from(self, all_attrs):
        self.__attrs = all_attrs[0]
        self.custo = all_attrs[1]

    def _init_specific(self, arg):
        pass

    def _get_value(
        self, conf=None, recursive=True, return_node_internals=False, restrict_csp=False
    ):
        raise NotImplementedError

    def get_raw_value(self, **kwargs):
        raise NotImplementedError

    def customize(self, custo):
        self.custo = copy.copy(custo)

    @property
    def env(self):
        return self._env

    @env.setter
    def env(self, src):
        self._env = src

    def has_subkinds(self):
        return False

    def has_no_children(self):
        return False

    def get_current_subkind(self):
        raise NotImplementedError

    def set_node_sync(self, scope, node=None, param=None, sync_obj=None):
        if self._sync_with is None:
            self._sync_with = {}
        if sync_obj is not None:
            assert node is None and param is None
            self._sync_with[scope] = sync_obj
        else:
            # assert node is not None
            self._sync_with[scope] = (node, param)

    def get_node_sync(self, scope):
        if self._sync_with is None:
            return None
        else:
            return self._sync_with.get(scope, None)

    def synchronize_nodes(self, src_node):
        if self._sync_with is None:
            return

        for scope, obj in self._sync_with.items():
            if isinstance(obj, SyncObj):
                obj.synchronize_nodes(src_node)

    def make_private(
        self,
        ignore_frozen_state,
        accept_external_entanglement,
        delayed_node_internals,
        forget_original_sync_objs=False,
    ):
        if self.private is not None:
            self.private = copy.copy(self.private)
        self.absorb_constraints = copy.copy(self.absorb_constraints)
        self.__attrs = copy.copy(self.__attrs)

        if forget_original_sync_objs:
            self._sync_with = None
        else:
            if self._sync_with:
                delayed_node_internals.add(self)
            self._sync_with = copy.copy(self._sync_with)

        self._make_private_specific(ignore_frozen_state, accept_external_entanglement)
        self.custo = copy.copy(self.custo)

    # Called near the end of Node copy (Node.set_contents) to update
    # node references inside the NodeInternals
    def _update_node_refs(self, node_dico, debug):
        sync_nodes = copy.copy(self._sync_with)

        for scope, obj in sync_nodes.items():
            if isinstance(obj, SyncObj):
                new_obj = copy.copy(obj)
                new_obj.make_private(node_dico)
                self._sync_with[scope] = new_obj
            else:
                node, param = obj
                new_node = node_dico.get(node, None)
                new_param = copy.copy(param)
                if new_node is not None:
                    self._sync_with[scope] = (new_node, new_param)
                else:
                    # this case only triggers during a call to
                    # NonTerm.get_subnodes_with_csts(), that is when new
                    # subnodes are created during a
                    # Node._get_value(). Indeed, when making copies of a
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

    def absorb(self, blob, constraints, conf, pending_postpone_desc=None):
        raise NotImplementedError

    def set_absorb_helper(self, helper):
        self.absorb_helper = helper

    def enforce_absorb_constraints(self, csts):
        assert isinstance(csts, AbsCsts)
        self.absorb_constraints = csts

    def set_size_from_constraints(self, size, encoded_size):
        raise NotImplementedError

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

    def set_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        pass

    def clear_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        pass

    @property
    def highlight(self):
        return self.is_attr_set(NodeInternals.Highlight)

    @highlight.setter
    def highlight(self, val):
        if val:
            self.set_attr(NodeInternals.Highlight)
        else:
            self.clear_attr(NodeInternals.Highlight)

    @property
    def debug(self):
        return self.is_attr_set(NodeInternals.DEBUG)

    def _make_specific(self, name):
        return name not in [NodeInternals.Determinist, NodeInternals.Finite]

    def _unmake_specific(self, name):
        return name not in [NodeInternals.Determinist, NodeInternals.Finite]

    def _match_mandatory_attrs(self, criteria):
        if criteria is None:
            return True

        for c in criteria:
            if not self.__attrs[c]:
                return False
        return True

    def _match_negative_custo(self, criteria):
        if criteria is None:
            return True

        # if None the node does not support customization
        # thus we return False as we cannot be compliant
        if self.custo is None:
            return False

        for c in criteria:
            if self.custo[c]:
                return False
        return True

    def _match_mandatory_custo(self, criteria):
        if criteria is None:
            return True

        # if None the node does not support customization
        # thus we return False as we cannot be compliant
        if self.custo is None:
            return False

        for c in criteria:
            if not self.custo[c]:
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

    def _match_node_constraints(self, criteria):
        # precond: criteria is not empty

        for scope, required in criteria.items():
            if required is None:
                continue

            if self._sync_with is None:
                if required:
                    return False
                else:
                    continue

            if scope in self._sync_with and not required:
                return False
            elif scope not in self._sync_with and required:
                return False

        return True

    def match(self, internals_criteria):
        if not self._match_mandatory_attrs(internals_criteria.mandatory_attrs):
            return False

        if not self._match_negative_attrs(internals_criteria.negative_attrs):
            return False

        if not self._match_mandatory_custo(internals_criteria.mandatory_custo):
            return False

        if not self._match_negative_custo(internals_criteria.negative_custo):
            return False

        if not self._match_node_kinds(internals_criteria.node_kinds):
            return False

        if not self._match_negative_node_kinds(internals_criteria.negative_node_kinds):
            return False

        if not self._match_node_subkinds(internals_criteria.node_subkinds):
            return False

        if not self._match_negative_node_subkinds(
            internals_criteria.negative_node_subkinds
        ):
            return False

        if internals_criteria.has_node_constraints():
            if not self._match_node_constraints(
                internals_criteria.get_all_node_constraints()
            ):
                return False

        return True

    def set_private(self, val):
        self.private = val

    def get_private(self):
        return self.private

    def set_clone_info(self, info, node):
        """
        Report to Node._set_clone_info() some information about graph
        internals

        """
        pass

    def clear_clone_info_since(self, node):
        """
        Cleanup obsolete graph internals information prior to what has been
        registered with the node given as parameter.
        """
        pass

    def is_exhausted(self):
        return False

    def is_frozen(self):
        raise NotImplementedError

    def pretty_print(self, max_size=None):
        return None

    def reset_depth_specific(self, depth):
        pass


class NodeInternalsCriteria(object):
    def __init__(
        self,
        mandatory_attrs=None,
        negative_attrs=None,
        node_kinds=None,
        negative_node_kinds=None,
        node_subkinds=None,
        negative_node_subkinds=None,
        mandatory_custo=None,
        negative_custo=None,
        required_csts=None,
        negative_csts=None,
    ):
        self.mandatory_attrs = self._handle_user_input(mandatory_attrs)
        self.negative_attrs = self._handle_user_input(negative_attrs)
        self.mandatory_custo = self._handle_user_input(mandatory_custo)
        self.negative_custo = self._handle_user_input(negative_custo)
        self.node_kinds = self._handle_user_input(node_kinds)
        self.negative_node_kinds = self._handle_user_input(negative_node_kinds)
        self.node_subkinds = self._handle_user_input(node_subkinds)
        self.negative_node_subkinds = self._handle_user_input(negative_node_subkinds)
        self._node_constraints = None
        if required_csts is not None:
            req_csts = self._handle_user_input(required_csts)
            for cst in req_csts:
                self.set_node_constraint(cst, True)
        if negative_csts is not None:
            neg_csts = self._handle_user_input(negative_csts)
            for cst in neg_csts:
                self.set_node_constraint(cst, False)

    def _handle_user_input(self, crit):
        return crit if crit is None or isinstance(crit, (list, tuple)) else [crit]

    def extend(self, ic):
        crit = ic.mandatory_attrs
        if crit:
            if self.mandatory_attrs is None:
                self.mandatory_attrs = []
            self.mandatory_attrs.extend(crit)

        crit = ic.negative_attrs
        if crit:
            if self.negative_attrs is None:
                self.negative_attrs = []
            self.negative_attrs.extend(crit)

        crit = ic.mandatory_custo
        if crit:
            if self.mandatory_custo is None:
                self.mandatory_custo = []
            self.mandatory_custo.extend(crit)

        crit = ic.negative_custo
        if crit:
            if self.negative_custo is None:
                self.negative_custo = []
            self.negative_custo.extend(crit)

        crit = ic.node_kinds
        if crit:
            if self.node_kinds is None:
                self.node_kinds = []
            self.node_kinds.extend(crit)

        crit = ic.negative_node_kinds
        if crit:
            if self.negative_node_kinds is None:
                self.negative_node_kinds = []
            self.negative_node_kinds.extend(crit)

        crit = ic.node_subkinds
        if crit:
            if self.node_subkinds is None:
                self.node_subkinds = []
            self.node_subkinds.extend(crit)

        crit = ic.negative_node_subkinds
        if crit:
            if self.negative_node_subkinds is None:
                self.negative_node_subkinds = []
            self.negative_node_subkinds.extend(crit)

        crit = ic.get_all_node_constraints()
        if crit:
            for cst, required in crit.items():
                self.set_node_constraint(cst, required)

    def set_node_constraint(self, cst, required):
        if self._node_constraints is None:
            self._node_constraints = {}
        self._node_constraints[cst] = required

    def get_node_constraint(self, cst):
        return self._node_constraints[cst] if cst in self._node_constraints else None

    def clear_node_constraint(self, cst):
        if self._node_constraints is None:
            self._node_constraints = {}
        self._node_constraints[cst] = None

    def get_all_node_constraints(self):
        return self._node_constraints

    def has_node_constraints(self):
        if self._node_constraints is None:
            return False

        for k, v in self._node_constraints.items():
            if v is not None:
                return True

        return False


class DynNode_Helpers(object):
    determinist = True

    def __init__(self):
        self.reset_graph_info()

    def __copy__(self):
        new_obj = type(self)()
        new_obj._graph_info = copy.copy(self._graph_info)
        # new_obj._node_ids = copy.copy(self._node_ids)
        new_obj._node_pos = copy.copy(self._node_pos)
        new_obj._curr_pos = self._curr_pos
        return new_obj

    def reset_graph_info(self):
        self._graph_info = []
        # self._node_ids = []
        self._node_pos = {}
        self._curr_pos = 0

    def set_graph_info(self, node, info):
        if id(node) not in self._node_pos.keys():
            self._curr_pos -= 1
            self._node_pos[id(node)] = self._curr_pos
            self._graph_info.insert(0, (info, node.name))
            # self._node_ids.insert(0,id(node))
        else:
            pos = self._node_pos[id(node)]
            self._graph_info[pos] = (info, node.name)
            # self._node_ids[pos] = id(node)

    def clear_graph_info_since(self, node):
        # TOFIX: node.name is not a reliable ID. Should use id(node),
        # but some bug prevent it from working. (self._node_ids was
        # used for this purpose)

        # nids = self._node_ids
        # if id(node) in nids:
        #     idx = nids.index(id(node))
        # else:
        #     print('\nNot present here!', node.name, id(node), nids)
        #     return

        curr_len = len(self._graph_info)
        nids = [y for x, y in reversed(self._graph_info)]
        if node.name in nids:
            # print('\nD:',  node.name, id(node), self._node_ids)
            # print('Pos:', self._node_pos)
            # print('Name:', self._graph_info)
            # if id(node) not in self._node_ids:
            #     raise ValueError
            idx = nids.index(node.name)
            idx = curr_len - idx - 1
        else:
            return

        self._graph_info = self._graph_info[idx + 1 :]
        # self._node_ids = self._node_ids[idx+1:]
        node_pos = {}
        for id_node, pos in self._node_pos.items():
            if pos > -(curr_len - idx):
                node_pos[id_node] = pos
        self._node_pos = node_pos
        self._curr_pos += idx + 1

    def make_private(self, env=None):
        if env and env.id_list is None:
            env.register_basic_djob(
                self._update_dyn_helper, args=[env], prio=Node.DJOBS_PRIO_dynhelpers
            )
        elif env:
            self._update_dyn_helper(env)
        else:
            pass

    def _update_dyn_helper(self, env):
        if env.id_list is not None:
            # print('*** DynHelper: delayed update')
            new_node_pos = {}
            # new_node_ids = {}
            for old_id, new_id in env.id_list:
                pos = self._node_pos.get(old_id, None)
                if pos is not None:
                    # print('*** DynHelper: updated')
                    new_node_pos[new_id] = pos
                    # idx = self._node_ids.index(old_id)
                    # new_node_ids[idx] = new_id

            # new_node_ids = [new_node_ids[k] for k in sorted(new_node_ids.keys())]
            if new_node_pos:
                self._node_pos = new_node_pos
                # self._node_ids = new_node_ids
        else:
            pass

    def _get_graph_info(self):
        return self._graph_info

    graph_info = property(fget=_get_graph_info)


class NodeInternals_Empty(NodeInternals):
    def _get_value(
        self, conf=None, recursive=True, return_node_internals=False, restrict_csp=False
    ):
        if return_node_internals:
            return (Node.DEFAULT_DISABLED_NODEINT, True)
        else:
            return (Node.DEFAULT_DISABLED_VALUE, True)

    def get_raw_value(self, **kwargs):
        return Node.DEFAULT_DISABLED_VALUE

    def set_child_env(self, env):
        self.env = env
        print("\n*** Empty Node: {!s}".format(hex(id(self))))
        # raise AttributeError

    def get_child_nodes_by_attr(
        self,
        internals_criteria,
        semantics_criteria,
        owned_conf,
        conf,
        path_regexp,
        exclude_self,
        respect_order,
        relative_depth,
        top_node,
        ignore_fstate,
        resolve_generator=False,
    ):
        return None


class NodeInternals_GenFunc(NodeInternals):
    default_custo = GenFuncCusto()

    def _init_specific(self, arg):
        self._generated_node = None
        self.generator_func = None
        self.generator_arg = None
        self.node_arg = None
        self.pdepth = 0
        self._node_helpers = DynNode_Helpers()
        self.provide_helpers = False
        self._trigger_registered = False
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
        if name in [
            NodeInternals.Determinist,
            NodeInternals.Finite,
            NodeInternals.Abs_Postpone,
            NodeInternals.Separator,
            NodeInternals.Highlight,
        ]:
            if name == NodeInternals.Determinist:
                self._node_helpers.determinist = True
            if self._generated_node is not None:
                self.generated_node.set_attr(name, recursive=True)
        return True

    def _unmake_specific(self, name):
        if name in [
            NodeInternals.Determinist,
            NodeInternals.Finite,
            NodeInternals.Abs_Postpone,
            NodeInternals.Separator,
            NodeInternals.Highlight,
        ]:
            if name == NodeInternals.Determinist:
                self._node_helpers.determinist = False
            if self._generated_node is not None:
                self.generated_node.clear_attr(name, recursive=True)
        return True

    def _make_private_specific(self, ignore_frozen_state, accept_external_entanglement):
        # Note that the 'node_arg' attribute is directly dealt with in
        # Node.__init__() during copy (which calls self.make_args_private()),
        # because the new Node to point to is unknown at this local
        # stage.
        if self._generated_node is None or ignore_frozen_state:
            self._generated_node = None
            self._trigger_registered = False
        else:
            self._generated_node = Node(
                self._generated_node.name,
                base_node=self._generated_node,
                ignore_frozen_state=ignore_frozen_state,
                accept_external_entanglement=accept_external_entanglement,
            )
            self._generated_node._reset_depth(parent_depth=self.pdepth)
            self._generated_node.set_env(self.env)
        self.generator_arg = copy.copy(self.generator_arg)
        self._node_helpers = copy.copy(self._node_helpers)
        # The call to 'self._node_helpers.make_private()' is performed
        # the latest that is during self.make_args_private()

    def make_args_private(
        self,
        node_dico,
        entangled_set,
        ignore_frozen_state,
        accept_external_entanglement,
    ):
        self._node_helpers.make_private(self.env)

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
                    print(
                        "/!\\ WARNING /!\\ [Copy of a NonTerm Node]\n"
                        " A copied Func_Elt has its 'node_arg' attribute"
                        " that does not point to an Node of the copied Node tree"
                    )
                    print("--> guilty: ", func_node_arg.name)
                    print(
                        "NOTE: Often a normal behavior if the generator is duplicated"
                        " within a nonterm node that does not contain the node args."
                    )

                if self.custo.clone_ext_node_args_mode:
                    node = Node(
                        func_node_arg.name,
                        base_node=func_node_arg,
                        copy_dico=node_dico,
                        accept_external_entanglement=False,
                    )
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

            if new_node.entangled_nodes is not None and (
                (not ignore_frozen_state) or accept_external_entanglement
            ):
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
                            print(
                                "/!\\ WARNING /!\\ [Copy of a NonTerm Node]\n"
                                " A copied Func_Elt has its 'node_arg' attribute"
                                " that does not point to an Node of the copied Node tree"
                            )
                            print("--> guilty: ", e.name)
                            print(
                                "NOTE: Often a normal behavior if the generator is duplicated"
                                " within a nonterm node that does not contain the node args."
                            )
                        if self.custo.clone_ext_node_args_mode:
                            node = Node(
                                e.name,
                                base_node=e,
                                copy_dico=node_dico,
                                accept_external_entanglement=False,
                            )
                        else:
                            node = e

                        node_dico[e] = node
                        l.append(node)
                    else:
                        l.append(node_dico[e])
                else:
                    l.append(None)

                if node_dico[e].entangled_nodes is not None and (
                    (not ignore_frozen_state) or accept_external_entanglement
                ):
                    entangled_set.add(node_dico[e])
                else:
                    node_dico[e].entangled_nodes = None

            if issubclass(self.node_arg.__class__, NodeAbstraction):
                self.node_arg.set_concrete_nodes(l)
            else:
                self.node_arg = l

    def reset_generator(self):
        self._generated_node = None

    @property
    def generated_node(self):
        if self._generated_node is None:
            enable_color = False
            if self.env and self.env._color_enabled:
                self.env._color_enabled = False
                enable_color = True

            if self.generator_arg is not None and self.node_arg is not None:
                if self.provide_helpers:
                    ret = self.generator_func(self.node_arg, self.generator_arg, self._node_helpers)
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

            if enable_color:
                self.env._color_enabled = True

            if isinstance(ret, tuple):
                ret, private_val = ret
                self.set_private(private_val)

            self._generated_node = ret
            self._generated_node._reset_depth(parent_depth=self.pdepth)
            self._generated_node.set_env(self.env)

            if self.is_attr_set(NodeInternals.Determinist):
                self._generated_node.make_determinist(all_conf=True, recursive=True)
            if self.is_attr_set(NodeInternals.Finite):
                self._generated_node.make_finite(all_conf=True, recursive=True)
            if self.is_attr_set(NodeInternals.Highlight):
                self._generated_node.set_attr(NodeInternals.Highlight, recursive=True)

        return self._generated_node

    # generated_node = property(fget=_get_generated_node)

    def import_generator_func(
        self,
        generator_func,
        generator_node_arg=None,
        generator_arg=None,
        provide_helpers=False,
    ):
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

    def _get_value(self, conf=None, recursive=True, return_node_internals=False, restrict_csp=False):
        if self.custo.trigger_last_mode and not self._trigger_registered:
            assert self.env is not None
            self._trigger_registered = True
            self.env.register_basic_djob(
                self._get_delayed_value,
                args=[conf, recursive, restrict_csp],
                prio=Node.DJOBS_PRIO_genfunc,
            )

            if return_node_internals:
                return (Node.DEFAULT_DISABLED_NODEINT, False)
            else:
                return (Node.DEFAULT_DISABLED_VALUE, False)

        if not self.is_attr_set(NodeInternals.Freezable):
            self.reset_generator()

        ret = self.generated_node._get_value(
            conf=conf,
            recursive=recursive,
            return_node_internals=return_node_internals,
            restrict_csp=restrict_csp,
        )

        return (ret, False)

    def _get_delayed_value(self, conf=None, recursive=True, restrict_csp=False):
        self.reset_generator()
        ret = self.generated_node._get_value(conf=conf, recursive=recursive,
                                             restrict_csp=restrict_csp)

        return (ret, False)

    def get_raw_value(self, **kwargs):
        return self.generated_node.get_raw_value(**kwargs)

    def absorb(self, blob, constraints, conf, pending_postpone_desc=None):
        # We make the generator freezable to be sure that _get_value()
        # won't reset it after absorption
        self.set_attr(NodeInternals.Freezable)

        if self.absorb_constraints is not None:
            constraints = self.absorb_constraints

        # Will help for possible future node types, as the current
        # node types that can raise exceptions, handle them already.
        try:
            st, off, sz, name = self.generated_node.absorb(
                blob,
                constraints=constraints,
                conf=conf,
                pending_postpone_desc=pending_postpone_desc,
            )
        except (ValueError, AssertionError) as e:
            st, off, sz = AbsorbStatus.Reject, 0, None

        # if st is AbsorbStatus.Reject:
        #     self.reset_generator()

        return st, off, sz, None

    def cancel_absorb(self):
        self.generated_node.reset_state()
        # self.generated_node.cancel_absorb()

    def confirm_absorb(self):
        self.generated_node.confirm_absorb()

    def reset_state(
        self, recursive=False, exclude_self=False, conf=None, ignore_entanglement=False
    ):
        if self.is_attr_set(NodeInternals.Mutable):
            self._trigger_registered = False
            self.reset_generator()
        else:
            if self._generated_node is not None:
                self.generated_node.reset_state(
                    recursive,
                    exclude_self=exclude_self,
                    conf=conf,
                    ignore_entanglement=ignore_entanglement,
                )
            else:
                pass

    def is_exhausted(self):
        if self.is_attr_set(NodeInternals.Mutable) and self.is_attr_set(
            NodeInternals.Finite
        ):
            # we return True because it does not make sense to return
            # self.generated_node.is_exhausted(), as self.generated_node
            # will change over unfreeze() calls
            return True
        elif self.is_attr_set(NodeInternals.Mutable) and not self.is_attr_set(
            NodeInternals.Finite
        ):
            return False
        else:
            return (
                False
                if self._generated_node is None
                else self.generated_node.is_exhausted()
            )

    def is_frozen(self):
        if self.is_attr_set(NodeInternals.Mutable):
            return self._generated_node is not None
        else:
            return (
                None
                if self._generated_node is None
                else self.generated_node.is_frozen()
            )

    def unfreeze(
        self,
        conf=None,
        recursive=True,
        dont_change_state=False,
        ignore_entanglement=False,
        only_generators=False,
        reevaluate_constraints=False,
    ):
        # if self.is_attr_set(NodeInternals.DEBUG):
        #     print('\n*** DBG Gen:', self.custo.reset_on_unfreeze_mode)
        if self.custo.reset_on_unfreeze_mode:
            # 'dont_change_state' is not supported in this case. But
            # if generator is stateless, it should not be a problem.
            # And if there is a state, ResetOnUnfreeze should be cleared anyway.
            self._trigger_registered = False
            self.reset_generator()
        else:
            if self._generated_node is not None:
                self.generated_node.unfreeze(
                    conf,
                    recursive=recursive,
                    dont_change_state=dont_change_state,
                    ignore_entanglement=ignore_entanglement,
                    only_generators=only_generators,
                    reevaluate_constraints=reevaluate_constraints,
                )
            else:
                pass

    def unfreeze_all(self, recursive=True, ignore_entanglement=False):
        # if self.is_attr_set(NodeInternals.Mutable):
        if self.custo.reset_on_unfreeze_mode:
            self._trigger_registered = False
            self.reset_generator()
        else:
            if self._generated_node is not None:
                self.generated_node.unfreeze_all(
                    recursive=recursive, ignore_entanglement=ignore_entanglement
                )
            else:
                pass

    def reset_fuzz_weight(self, recursive):
        if recursive:
            if self._generated_node is not None:
                self.generated_node.reset_fuzz_weight(recursive=recursive)

    def set_child_env(self, env):
        self.env = env

    @NodeInternals.env.setter
    def env(self, env):
        NodeInternals.env.fset(self, env)
        if self._generated_node is not None:
            self._generated_node.set_env(env)

    def set_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        if recursive:
            if self._generated_node is not None:
                self.generated_node.set_attr(
                    name, conf=conf, all_conf=all_conf, recursive=recursive
                )

    def clear_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        if recursive:
            if self._generated_node is not None:
                self.generated_node.clear_attr(
                    name, conf=conf, all_conf=all_conf, recursive=recursive
                )

    def reset_depth_specific(self, depth):
        self.pdepth = depth
        if self._generated_node is not None:
            self._generated_node._reset_depth(parent_depth=self.pdepth)

    def get_child_nodes_by_attr(
        self,
        internals_criteria,
        semantics_criteria,
        owned_conf,
        conf,
        path_regexp,
        exclude_self,
        respect_order,
        relative_depth,
        top_node,
        ignore_fstate,
        resolve_generator=False,
    ):
        return self.generated_node.get_reachable_nodes(
            internals_criteria,
            semantics_criteria,
            owned_conf,
            conf,
            path_regexp=path_regexp,
            exclude_self=False,
            respect_order=respect_order,
            relative_depth=relative_depth,
            top_node=top_node,
            ignore_fstate=ignore_fstate,
            resolve_generator=resolve_generator,
        )

    def set_child_current_conf(self, node, conf, reverse, ignore_entanglement):
        if self.custo.forward_conf_change_mode:
            if self._generated_node is not None:
                node._set_subtrees_current_conf(
                    self.generated_node,
                    conf,
                    reverse,
                    ignore_entanglement=ignore_entanglement,
                )

    def get_child_all_path(
        self, name, htable, conf, recursive, resolve_generator=False
    ):
        if self.env is not None:
            self.generated_node._get_all_paths_rec(
                name,
                htable,
                conf,
                recursive=recursive,
                first=False,
                resolve_generator=resolve_generator,
            )
        else:
            # If self.env is None, that means that a node graph is not fully constructed
            # thus we avoid a freeze side-effect (by resolving 'generated_node') of the
            # graph while it is currently manipulated in some way.
            pass

    def set_clone_info(self, info, node):
        self._node_helpers.set_graph_info(node, info)
        # self._node_helpers.graph_info.insert(0, info)

    def clear_clone_info_since(self, node):
        self._node_helpers.clear_graph_info_since(node)

    def set_size_from_constraints(self, size, encoded_size):
        if self.env is not None:
            self.generated_node.set_size_from_constraints(
                size=size, encoded_size=encoded_size
            )
        else:
            # look at .get_child_all_path() comments
            pass

    def __getattr__(self, name):
        gen_node = self.__getattribute__("_generated_node")
        if gen_node is not None:
            # to avoid looping in __getattr__
            return getattr(gen_node, name)
        else:
            return object.__getattribute__(self, name)


class NodeInternals_Term(NodeInternals):
    def _init_specific(self, arg):
        self.frozen_node = None

    @staticmethod
    def _convert_to_internal_repr(val):
        return convert_to_internal_repr(val)

    def _make_private_specific(self, ignore_frozen_state, accept_external_entanglement):
        if ignore_frozen_state:
            self.frozen_node = None
        else:
            self.frozen_node = self.frozen_node

        self._make_private_term_specific(
            ignore_frozen_state, accept_external_entanglement
        )

    def _make_private_term_specific(
        self, ignore_frozen_state, accept_external_entanglement
    ):
        pass

    def _set_frozen_value(self, val):
        self.frozen_node = val

    def _set_default_value(self, val):
        self.frozen_node = None
        self._set_default_value_specific(val)

    def _set_default_value_specific(self, val):
        raise NotImplementedError

    def _get_value(
        self, conf=None, recursive=True, return_node_internals=False, restrict_csp=False
    ):
        def format_val(val):
            fval = (
                FontStyle.BOLD
                + colorize(val.decode("latin-1"), rgb=Color.ND_HLIGHT)
                + FontStyle.END
            )
            fval = fval.encode("latin-1")
            return fval

        if self.frozen_node is not None:
            if self.env and self.env.color_enabled and self.highlight:
                fval = format_val(self.frozen_node)
            else:
                fval = self.frozen_node
            return (self, False) if return_node_internals else (fval, False)

        val = self._get_value_specific(conf, recursive)

        if self.is_attr_set(NodeInternals.Freezable):
            self.frozen_node = val

        if self.highlight:
            val = format_val(val)

        return (self, True) if return_node_internals else (val, True)

    def _get_value_specific(self, conf, recursive):
        raise NotImplementedError

    def get_raw_value(self, **kwargs):
        return self._get_value()

    def absorb(self, blob, constraints, conf, pending_postpone_desc=None):
        status = None
        size = None

        if self.absorb_constraints is not None:
            constraints = self.absorb_constraints

        if self.absorb_helper is not None:
            try:
                status, off, size = self.absorb_helper(blob, constraints, self)
            except:
                print(
                    "Warning: absorb_helper '{!r}' has crashed! (thus, use default values)".format(
                        self.absorb_helper
                    )
                )
                status, off, size = AbsorbStatus.Accept, 0, None
        else:
            status, off, size = self.absorb_auto_helper(blob, constraints=constraints)

        if status == AbsorbStatus.Reject:
            st = status
            self.frozen_node = b""
        elif status == AbsorbStatus.Accept:
            try:
                self.frozen_node, off, size = self.do_absorb(
                    blob, constraints=constraints, off=off, size=size
                )
            except (ValueError, AssertionError) as e:
                st = AbsorbStatus.Reject
                self.frozen_node = b""
            else:
                st = AbsorbStatus.Absorbed
        else:
            raise ValueError

        return st, off, size, None

    def cancel_absorb(self):
        self.do_revert_absorb()
        self.do_cleanup_absorb()

    def confirm_absorb(self):
        self.do_cleanup_absorb()

    def absorb_auto_helper(self, blob, constraints):
        raise NotImplementedError

    def do_absorb(self, blob, constraints, off, size):
        raise NotImplementedError

    def do_revert_absorb(self):
        raise NotImplementedError

    def do_cleanup_absorb(self):
        raise NotImplementedError

    def reset_state(
        self, recursive=False, exclude_self=False, conf=None, ignore_entanglement=False
    ):
        self._reset_state_specific(recursive, exclude_self, conf, ignore_entanglement)
        if not exclude_self:
            self.frozen_node = None

    def _reset_state_specific(self, recursive, exclude_self, conf, ignore_entanglement):
        raise NotImplementedError

    def is_exhausted(self):
        return False

    def is_frozen(self):
        return self.frozen_node is not None

    def unfreeze(
        self,
        conf=None,
        recursive=True,
        dont_change_state=False,
        ignore_entanglement=False,
        only_generators=False,
        reevaluate_constraints=False,
    ):
        if only_generators:
            return
        if dont_change_state and self.frozen_node is not None:
            self._unfreeze_without_state_change(self.frozen_node)
        elif reevaluate_constraints and self.frozen_node is not None:
            self._unfreeze_reevaluate_constraints(self.frozen_node)
        self.frozen_node = None

    def _unfreeze_without_state_change(self, current_val):
        pass

    def _unfreeze_reevaluate_constraints(self, current_val):
        pass

    def unfreeze_all(self, recursive=True, ignore_entanglement=False):
        self.frozen_node = None

    def update_value(self, value):
        self.frozen_node = self._update_value_specific(value)

    def _update_value_specific(self, value):
        pass

    def reset_fuzz_weight(self, recursive):
        pass

    def set_child_env(self, env):
        self.env = env

    def reset_depth_specific(self, depth):
        pass

    def get_child_nodes_by_attr(
        self,
        internals_criteria,
        semantics_criteria,
        owned_conf,
        conf,
        path_regexp,
        exclude_self,
        respect_order,
        relative_depth,
        top_node,
        ignore_fstate,
        resolve_generator=False,
    ):
        return None

    def set_child_current_conf(self, node, conf, reverse, ignore_entanglement):
        pass

    def get_child_all_path(
        self, name, htable, conf, recursive, resolve_generator=False
    ):
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

    def _set_default_value_specific(self, val):
        self.value_type.set_default_value(val)

    def import_value_type(self, value_type):
        self.value_type = value_type
        # if self.env is not None:
        #     self.value_type.knowledge_source = self.env.knowledge_source
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

    def set_size_from_constraints(self, size, encoded_size):
        self.value_type.set_size_from_constraints(size=size, encoded_size=encoded_size)

    def set_specific_fuzzy_values(self, vals):
        self.__fuzzy_values = vals
        self.value_type.add_specific_fuzzy_vals(vals)

    def get_specific_fuzzy_values(self):
        return self.__fuzzy_values

    def _make_private_term_specific(
        self, ignore_frozen_state, accept_external_entanglement
    ):
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

    def get_raw_value(self, **kwargs):
        if not self.is_frozen():
            self._get_value()
        return self.value_type.get_current_raw_val(**kwargs)

    def absorb_auto_helper(self, blob, constraints):
        return self.value_type.absorb_auto_helper(blob, constraints)

    def do_absorb(self, blob, constraints, off, size):
        return self.value_type.do_absorb(
            blob=blob, constraints=constraints, off=off, size=size
        )

    def do_revert_absorb(self):
        self.value_type.do_revert_absorb()

    def do_cleanup_absorb(self):
        self.value_type.do_cleanup_absorb()

    def _update_value_specific(self, value):
        if isinstance(value, int) and isinstance(self.value_type, (fvt.INT, fvt.BitField)):
            if not self.value_type.update_raw_value(value):
                print(f"\n[Warning] {type(self.value_type)} is not compatible with the integer {value}")
        else:
            val, off, size = self.value_type.do_absorb(
                convert_to_internal_repr(value), constraints=AbsNoCsts()
            )

        return self.value_type.get_current_value()

    def _unfreeze_without_state_change(self, current_val):
        self.value_type.rewind()

    def _unfreeze_reevaluate_constraints(self, current_val):
        self.value_type.rewind()

    def _reset_state_specific(self, recursive, exclude_self, conf, ignore_entanglement):
        self.value_type.reset_state()

    def is_exhausted(self):
        if self.is_attr_set(NodeInternals.Finite):
            return self.value_type.is_exhausted()
        else:
            return False

    def pretty_print(self, max_size=None):
        return self.value_type.pretty_print(max_size=max_size)

    def __getattr__(self, name):
        vt = self.__getattribute__("value_type")
        if hasattr(vt, name):
            # to avoid looping in __getattr__
            return vt.__getattribute__(name)
        else:
            return object.__getattribute__(self, name)


class NodeInternals_Func(NodeInternals_Term):
    default_custo = FuncCusto()

    def _init_specific(self, arg):
        NodeInternals_Term._init_specific(self, arg)
        self.fct = None
        self.node_arg = None
        self.fct_arg = None
        self._node_helpers = DynNode_Helpers()
        self.provide_helpers = False

    def import_func(self, fct, fct_node_arg=None, fct_arg=None, provide_helpers=False):
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

    def customize(self, custo):
        if custo is None:
            self.custo = copy.copy(self.default_custo)
        else:
            self.custo = copy.copy(custo)

        if self.custo.frozen_args_mode:
            self._get_value_specific = self.__get_value_specific_mode1
        else:
            self._get_value_specific = self.__get_value_specific_mode2

    def set_clone_info(self, info, node):
        self._node_helpers.set_graph_info(node, info)

    def clear_clone_info_since(self, node):
        self._node_helpers.clear_graph_info_since(node)

    def make_args_private(
        self,
        node_dico,
        entangled_set,
        ignore_frozen_state,
        accept_external_entanglement,
    ):
        self._node_helpers.make_private(self.env)

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
                    print(
                        "/!\\ WARNING /!\\ [Copy of a NonTerm Node]\n"
                        " A copied Func_Elt has its 'node_arg' attribute"
                        " that does not point to an Node of the copied Node tree"
                    )
                    print("--> guilty: ", func_node_arg.name)
                    print(
                        "NOTE: Often a normal behavior if the function is duplicated"
                        " within a nonterm node that does not contain the node args."
                    )
                if self.custo.clone_ext_node_args_mode:
                    node = Node(
                        func_node_arg.name,
                        base_node=func_node_arg,
                        copy_dico=node_dico,
                        accept_external_entanglement=False,
                    )
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

            if new_node.entangled_nodes is not None and (
                (not ignore_frozen_state) or accept_external_entanglement
            ):
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
                            print(
                                "/!\\ WARNING /!\\ [Copy of a NonTerm Node]\n"
                                " A copied Func_Elt has its 'node_arg' attribute"
                                " that does not point to an Node of the copied Node tree"
                            )
                            print("--> guilty: ", e.name)
                            print(
                                "NOTE: Often a normal behavior if the function is duplicated"
                                " within a nonterm node that does not contain the node args."
                            )
                        if self.custo.clone_ext_node_args_mode:
                            node = Node(
                                e.name,
                                base_node=e,
                                copy_dico=node_dico,
                                accept_external_entanglement=False,
                            )
                        else:
                            node = e

                        node_dico[e] = node
                        l.append(node)
                    else:
                        l.append(node_dico[e])
                else:
                    l.append(None)

                if node_dico[e].entangled_nodes is not None and (
                    (not ignore_frozen_state) or accept_external_entanglement
                ):
                    entangled_set.add(node_dico[e])
                else:
                    node_dico[e].entangled_nodes = None

            if issubclass(self.node_arg.__class__, NodeAbstraction):
                self.node_arg.set_concrete_nodes(l)
            else:
                self.node_arg = l

    def _make_private_term_specific(
        self, ignore_frozen_state, accept_external_entanglement
    ):
        # Note that the 'node_arg' attribute is directly dealt with in
        # Node.__init__() during copy (which calls
        # self.make_args_private()), because the new Node to point to
        # is unknown at this local stage.
        self.fct_arg = copy.copy(self.fct_arg)

        # This is MANDATORY, because when this object is copied, the
        # new _get_value_specific() still points to the bounded method
        # of the copied object, and thus the bounded 'node_arg'
        # attribute used by this function is not what we want for the new object
        self.customize(self.custo)

        self._node_helpers = copy.copy(self._node_helpers)
        # The call to 'self._node_helpers.make_private()' is performed
        # the latest that is during self.make_args_private()

    def absorb(self, blob, constraints, conf, pending_postpone_desc=None):
        # we make the generator freezable to be sure that _get_value()
        # won't reset it after absorption
        self.set_attr(NodeInternals.Freezable)

        sz = len(convert_to_internal_repr(self._get_value()))

        self._set_frozen_value(blob[:sz])

        return AbsorbStatus.Absorbed, 0, sz, None

    def cancel_absorb(self):
        self._set_frozen_value(None)

    def confirm_absorb(self):
        pass

    def _get_value_specific(self, conf, recursive):
        raise NotImplementedError

    def _unfreeze_without_state_change(self, current_val):
        # 'dont_change_state' is not supported in this case. But
        # if the function is stateless, it should not be a problem
        pass

    def _unfreeze_reevaluate_constraints(self, current_val):
        pass

    def _reset_state_specific(self, recursive, exclude_self, conf, ignore_entanglement):
        pass

    def __get_value_specific_mode1(self, conf, recursive):
        """
        In mode1, we freeze 'node_arg' attribute and give the value to the function
        """
        if self.node_arg is not None:
            if issubclass(self.node_arg.__class__, NodeAbstraction):
                func_node_arg = self.node_arg.get_concrete_nodes()
            else:
                func_node_arg = self.node_arg

            if isinstance(func_node_arg, Node):
                val = func_node_arg._tobytes(conf=conf, recursive=recursive)
            # if not an Node it is either a NodeAbstraction or a list
            else:
                val = []
                for e in func_node_arg:
                    if e is not None:
                        val.append(e._tobytes(conf=conf, recursive=recursive))
                    else:
                        val.append(b"")

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
        """
        In mode2, we give the 'node_arg' to the function and let it do whatever it wants
        """

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

    def set_size_from_constraints(self, size, encoded_size):
        # not supported
        raise DataModelDefinitionError


class NodeSeparator(object):
    """A node separator is used (optionnaly) by a non-terminal node
    as a separator between each subnode.

    Attributes:
      make_private (function): used for full copy
    """

    def __init__(self, node, prefix=True, suffix=True, unique=False, always=False):
        """
        Args:
          node (Node): node to be used for separation.
          prefix (bool): if `True`, a serapator will also be placed at the begining.
          suffix (bool): if `True`, a serapator will also be placed at the end.
          unique (bool): if `False`, the same node will be used for each separation,
            otherwise a new node will be generated.
          always (bool): if `True`, the separator will be always generated even if the
            subnodes it separates are not generated because their evaluated quantity is 0.
        """
        self.node = node
        self.node.set_attr(NodeInternals.Separator)
        self.node.set_attr(NodeInternals.AutoSeparator)
        self.prefix = prefix
        self.suffix = suffix
        self.unique = unique
        self.always = always

    def make_private(self, node_dico, ignore_frozen_state):
        if self.node in node_dico:
            self.node = node_dico[self.node]
        else:
            orig_node = self.node
            self.node = Node(
                self.node.name,
                base_node=self.node,
                ignore_frozen_state=ignore_frozen_state,
            )
            node_dico[orig_node] = self.node


class NodeInternals_NonTerm(NodeInternals):
    """
    It is a kind of node internals that enable to structure the graph
    through a specific grammar...
    """

    class NodeAttrs(object):
        _default_qty = None
        _min = None
        _max = None

        exhausted_seq = False
        _qty_sequence = None
        _current_qty = None
        _previous_qty = None
        _planned_reset = False
        _previous_current_qty_was_none = False

        @property
        def qty(self):
            return self._min, self._max

        @qty.setter
        def qty(self, val):
            self._min, self._max = val
            if self.default_qty is None:
                if self._max != -1:  # infinity case
                    self.default_qty = math.ceil((self._min + self._max) / 2)
                elif self._min >= 0:
                    self.default_qty = self._min + 1
                else:
                    self.default_qty = -1

        @property
        def default_qty(self):
            return self._default_qty

        @default_qty.setter
        def default_qty(self, val):
            if val is not None and self._min is not None and self._max is not None:
                if self._max != -1:
                    assert self._min <= val <= self._max
                elif self._min >= 0:
                    assert self._min <= val
                else:
                    assert val == -1

            self._default_qty = val

        @property
        def qty_sequence(self):
            if self._qty_sequence is None:
                self._qty_sequence = [self.default_qty]
                if self._max != self.default_qty:
                    self._qty_sequence.insert(0, self._max)
                # default_qty is 'guaranteed' to be between mini and maxi
                # which makes the condition sufficient (and avoid mini != maxi)
                if self._min != self.default_qty:
                    self._qty_sequence.insert(0, self._min)

            return self._qty_sequence

        def next_qty(self):
            qty = self.qty_sequence.pop(-1)
            self._previous_qty = self._current_qty
            self._current_qty = qty
            if len(self.qty_sequence) == 0:
                self.exhausted_seq = True
            return qty

        @property
        def current_qty(self):
            if self._current_qty is None:
                self.next_qty()
            return self._current_qty

        def perform_planned_reset(self):
            if self._planned_reset:
                self._planned_reset = False
                self._current_qty = None
                self._previous_qty = None
                self._qty_sequence = None
                self.exhausted_seq = False

        def plan_reset(self):
            self._planned_reset = True

        def unplan_reset(self):
            self._planned_reset = False

        def reset(self):
            self._planned_reset = True
            self.perform_planned_reset()

        def unroll(self):
            # print('\n*** DBG unrolling')
            if self.exhausted_seq:
                self._qty_sequence = None
                self._qty_sequence = [self.qty_sequence[0]]
                self.exhausted_seq = False
            else:
                if self._current_qty is not None:
                    self._qty_sequence.append(self._current_qty)
                else:
                    # we have been copied without being used first
                    pass

            self._current_qty = self._previous_qty
            self.unplan_reset()

        def __copy__(self):
            node_attrs = type(self)()
            node_attrs.__dict__.update(self.__dict__)
            node_attrs._qty_sequence = copy.copy(self._qty_sequence)
            return node_attrs

    INFINITY_LIMIT = 30  # Used to limit the number of created nodes
    # when the max quantity is specified to be
    # infinite (-1). "Infinite quantity" makes
    # sense only for absorption operation.

    default_custo = NonTermCusto()

    def _init_specific(self, arg):
        self.encoder: enc.Encoder = None
        self.subnodes_set = None
        self.subnodes_order = None
        self.subnodes_attrs = None
        self._reevaluation_pending = None

        self.current_flattened_nodelist = None
        self.cursor_min = None
        self.cursor_maj = None
        self.previous_cursor_min = None
        self.previous_cursor_maj = None
        self.current_pick_section = None
        self.current_picked_node_idx = None

        self.reset()

    def reset(
        self, nodes_drawn_qty=None, custo=None, exhaust_info=None, preserve_node=False
    ):
        self.subnodes_set = set()
        self.subnodes_order = []
        self.subnodes_order_total_weight = 0
        self.subnodes_attrs = {}
        self.separator = None
        self._reevaluation_pending = False

        if self.encoder:
            self.encoder.reset()

        self._reset_state_info(new_info=exhaust_info, nodes_drawn_qty=nodes_drawn_qty)

        if preserve_node:
            pass
        elif custo is None:
            # if self.debug:
            #     print('\n*** DEBUG: set default custo')
            self.customize(self.default_custo)
        else:
            self.customize(custo)

    def set_encoder(self, encoder):
        self.encoder = encoder
        encoder.reset()

    def __iter_csts(self, node_list):
        for delim, sublist in node_list:
            yield delim, sublist

    def __iter_csts_verbose(self, node_list):
        idx = 0
        for delim, sublist in node_list:
            yield idx, delim, sublist
            idx += 1

    def flatten_node_list(self, node_list):
        """
        Return a list of the form: [subnode1, subnode2, subnode3,  ....]
        In case of Pick-type sections within the parent node, sublists are included within
        the previous one and include the alternative subnodes, so that the list looks like:
        [subnode1, [snode21, snode22, ...], subnode3,  ....]

        Args:
            node_list:

        Returns:

        """

        flatten_list = []
        pick_section_amount = 0
        for idx, delim, sublist in self.__iter_csts_verbose(node_list):
            if delim[1] == ">" or delim[1:3] == "=.":
                for i, node in enumerate(sublist):
                    flatten_list.append(node)

            elif delim[1:3] == "=+":
                node_sublist = []
                if sublist[0] > -1:  # it means weights exist
                    for _, comp in split_with(lambda x: isinstance(x, int), sublist[1]):
                        # sublist[1] is already ordered correctly (by weight)
                        node = comp[0]
                        shall_exist = self._existence_from_node(node)
                        if shall_exist is None or shall_exist:
                            node_sublist.append(node)

                else:
                    for node in sublist[1]:
                        shall_exist = self._existence_from_node(node)
                        if shall_exist is None or shall_exist:
                            node_sublist.append(node)

                pick_section_amount += 1
                flatten_list.append(node_sublist)

            else:
                raise ValueError

        return flatten_list, pick_section_amount

    def import_subnodes_basic(self, node_list, separator=None, preserve_node=False):
        self.reset(preserve_node=preserve_node)

        self.separator = separator

        self.subnodes_order = [1, [["u>", copy.copy(node_list)]]]
        self.subnodes_order_total_weight = 1

        for node in node_list:
            self.subnodes_set.add(node)
            self.subnodes_attrs[node] = NodeInternals_NonTerm.NodeAttrs()
            self.subnodes_attrs[node].qty = [1, 1]

    def import_subnodes_with_csts(
        self, wlnode_list, separator=None, preserve_node=False
    ):
        self.reset(preserve_node=preserve_node)

        self.separator = separator

        for weight, lnode_list in split_with(lambda x: isinstance(x, int), wlnode_list):
            self.subnodes_order.append(weight)
            self.subnodes_order_total_weight += weight

            subnode_list = []
            for delim, sublist in split_with(
                lambda x: isinstance(x, str), lnode_list[0]
            ):
                new_sublist = []
                for n in sublist:
                    (
                        node,
                        mini,
                        maxi,
                        default_qty,
                    ) = self._get_info_from_subnode_description(n)
                    self.subnodes_set.add(node)
                    if node in self.subnodes_attrs:
                        prev_min, prev_max = self.subnodes_attrs[node].qty
                        if prev_min != mini or prev_max != maxi:
                            raise DataModelDefinitionError(
                                'Node "{:s}" is used twice in the same '
                                "non-terminal node with "
                                "different min/max values!".format(node.name)
                            )
                    else:
                        self.subnodes_attrs[node] = NodeInternals_NonTerm.NodeAttrs()
                    self.subnodes_attrs[node].default_qty = default_qty
                    self.subnodes_attrs[node].qty = [mini, maxi]
                    new_sublist.append(node)

                sublist = new_sublist
                chunk = []

                if delim[:3] == "u=+" or delim[:3] == "s=+":
                    weight_l = None
                    weight = nodes_weight_re.search(delim)
                    if weight:
                        weight_total = 0
                        weight_l = []
                        l = weight.group(2).split(",")
                        for i in l:
                            w = int(i)
                            weight_l.append(w)
                            weight_total += w

                    if weight_l:
                        if len(weight_l) != len(sublist):
                            raise DataModelDefinitionError(
                                "Wrong number of relative weights ({:d})!"
                                " Expected: {:d}".format(len(weight_l), len(sublist))
                            )
                        new_l = [
                            (w, node_desc) for w, node_desc in zip(weight_l, sublist)
                        ]
                        new_l.sort(key=lambda x: -x[0])
                        new_l2 = []
                        for w, node_desc in new_l:
                            new_l2.append(w)
                            new_l2.append(node_desc)

                        sublist = new_l2
                    else:
                        weight_total = -1

                    chunk.append(delim[:3])
                    chunk.append([weight_total, list(sublist)])

                else:
                    chunk.append(delim)
                    chunk.append(list(sublist))

                subnode_list.append(chunk)

            self.subnodes_order.append(subnode_list)

    def import_subnodes_full_format(
        self,
        subnodes_order=None,
        subnodes_attrs=None,
        frozen_node_list=None,
        current_flat_nodelist=None,
        internals=None,
        nodes_drawn_qty=None,
        custo=None,
        exhaust_info=None,
        separator=None,
    ):
        if internals is not None:
            # This case is only for Node.set_contents() usage

            self.subnodes_order = internals.subnodes_order
            self.subnodes_attrs = internals.subnodes_attrs
            self.current_flattened_nodelist = internals.current_flattened_nodelist
            self.frozen_node_list = internals.frozen_node_list
            self.separator = internals.separator
            self.subnodes_set = internals.subnodes_set
            self.customize(internals.custo)

        elif subnodes_order is not None:
            # This case is used by self.make_private_subnodes()

            # In this case, we can call reset() as self.make_private_subnodes() provide us with
            # the parameters we need.
            self.reset(
                nodes_drawn_qty=nodes_drawn_qty, custo=custo, exhaust_info=exhaust_info
            )

            self.subnodes_order = subnodes_order
            self.subnodes_attrs = subnodes_attrs
            self.current_flattened_nodelist = current_flat_nodelist
            self.frozen_node_list = frozen_node_list
            if separator is not None:
                self.separator = separator

            for weight, lnode_list in split_with(
                lambda x: isinstance(x, int), self.subnodes_order
            ):
                self.subnodes_order_total_weight += weight
                for delim, sublist in self.__iter_csts(lnode_list[0]):
                    if delim[:3] == "u=+" or delim[:3] == "s=+":
                        for w, etp in split_with(
                            lambda x: isinstance(x, int), sublist[1]
                        ):
                            for n in etp:
                                node, mini, maxi = self._get_node_and_minmax_from(n)
                                self.subnodes_set.add(node)
                    else:
                        for n in sublist:
                            node, mini, maxi = self._get_node_and_minmax_from(n)
                            self.subnodes_set.add(node)

        else:
            raise ValueError

    def change_subnodes_csts(self, csts_ch):
        modified_csts = {}

        for orig, new in csts_ch:
            for weight, lnode_list in split_with(
                lambda x: isinstance(x, int), self.subnodes_order
            ):
                node_list = lnode_list[0]

                if id(node_list) not in modified_csts:
                    modified_csts[id(node_list)] = []

                for idx, delim, sublist in self.__iter_csts_verbose(node_list):
                    if delim == orig or orig == "*":
                        if idx not in modified_csts[id(node_list)]:
                            if delim == "u=+" and delim != new:
                                new_l = []
                                for w, etp in split_with(
                                    lambda x: isinstance(x, int), sublist[1]
                                ):
                                    new_l.append(etp[0])

                                node_list[idx] = [new, new_l]
                            else:
                                node_list[idx][0] = new

                            modified_csts[id(node_list)].append(idx)

    def _make_private_specific(self, ignore_frozen_state, accept_external_entanglement):
        if self.encoder:
            self.encoder = copy.copy(self.encoder)
            if ignore_frozen_state:
                self.encoder.reset()

    def make_private_subnodes(
        self,
        node_dico,
        func_nodes,
        env,
        ignore_frozen_state,
        accept_external_entanglement,
        entangled_set,
        delayed_node_internals,
    ):
        subnodes_order, subnodes_attrs = self.get_subnodes_csts_copy(node_dico)

        if self.separator is not None:
            new_separator = copy.copy(self.separator)
            new_separator.make_private(
                node_dico, ignore_frozen_state=ignore_frozen_state
            )
        else:
            new_separator = None

        # copy the 'frozen_node_list' if it is not None
        if self.frozen_node_list is None or ignore_frozen_state:
            new_fl = None
            new_nodes_drawn_qty = None
            new_exhaust_info = None
        else:
            # new_exhaust_info = [self.exhausted, copy.copy(self.excluded_components),
            #                     self.shape_exhausted, self.current_nodelist_sz, self.expanded_nodelist_origsz,
            #                     self.component_seed, self._perform_first_step]

            new_exhaust_info = [
                self.exhausted_shapes,
                copy.copy(self.excluded_components),
                self.combinatory_complete,
                self.component_seed,
                self.exhausted_pick_cases,
            ]

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

        if self.current_flattened_nodelist is None or ignore_frozen_state:
            new_current_fnlist = None
        else:
            new_current_fnlist = [
                node_dico[nd] for nd in self.current_flattened_nodelist
            ]

        self.import_subnodes_full_format(
            subnodes_order=subnodes_order,
            subnodes_attrs=subnodes_attrs,
            frozen_node_list=new_fl,
            current_flat_nodelist=new_current_fnlist,
            nodes_drawn_qty=new_nodes_drawn_qty,
            custo=self.custo,
            exhaust_info=new_exhaust_info,
            separator=new_separator,
        )

        if self.frozen_node_list is None or ignore_frozen_state:
            iterable = self.subnodes_set
        else:
            iterable = set()
            iterable.update(self.subnodes_set)
            iterable.update(self.frozen_node_list)

        # iterable shall only have unique nodes
        for e in iterable:
            e.env = env

            if e.entangled_nodes is not None and (
                (not ignore_frozen_state) or accept_external_entanglement
            ):
                entangled_set.add(e)
            else:
                e.entangled_nodes = None

            for c in e.internals:
                e.internals[c].env = env
                if e.is_nonterm(c):
                    e.internals[c].make_private_subnodes(
                        node_dico,
                        func_nodes,
                        env,
                        ignore_frozen_state=ignore_frozen_state,
                        accept_external_entanglement=accept_external_entanglement,
                        entangled_set=entangled_set,
                        delayed_node_internals=delayed_node_internals,
                    )
                    e.internals[c].make_private(
                        ignore_frozen_state=ignore_frozen_state,
                        accept_external_entanglement=accept_external_entanglement,
                        delayed_node_internals=delayed_node_internals,
                    )

                elif e.is_func(c) or e.is_genfunc(c):
                    if e.internals[c].node_arg is not None:
                        func_nodes.add(e)
                    e.internals[c].make_private(
                        ignore_frozen_state=ignore_frozen_state,
                        accept_external_entanglement=accept_external_entanglement,
                        delayed_node_internals=delayed_node_internals,
                    )

                else:
                    e.internals[c].make_private(
                        ignore_frozen_state=ignore_frozen_state,
                        accept_external_entanglement=accept_external_entanglement,
                        delayed_node_internals=delayed_node_internals,
                    )

    def get_subnodes_csts_copy(self, node_dico=None):
        node_dico = (
            {} if node_dico is None else node_dico
        )  # node_dico[old_node] --> new_node
        csts_copy = []
        for weight, lnode_list in split_with(
            lambda x: isinstance(x, int), self.subnodes_order
        ):
            csts_copy.append(weight)
            l = []

            for delim, sublist in self.__iter_csts(lnode_list[0]):
                # sublist can be in one of the 2 following forms:
                # * [3, [1, <framework.data_model.Node object at 0x7fc49fc56ad0>, 2, <framework.data_model.Node object at 0x7fc49fc56510>]]
                # * [<framework.data_model.Node object at 0x7fc49fdb0090>, <framework.data_model.Node object at 0x7fc49fc56ad0>]

                new_sublist = []
                if isinstance(sublist[0], Node):
                    for node in sublist:
                        if node not in node_dico:
                            node_dico[node] = copy.copy(node)
                        new_node = node_dico[node]

                        new_node.internals = copy.copy(new_node.internals)
                        for c in new_node.internals:
                            new_node.internals[c] = copy.copy(new_node.internals[c])
                        new_sublist.append(new_node)

                elif isinstance(sublist[0], int):
                    new_sublist.append(sublist[0])  # add the total weight
                    new_sslist = []
                    for node in sublist[1]:
                        if isinstance(
                            node, int
                        ):  # it is not a node but the weight of the node
                            new_sslist.append(node)  # add the relative weight
                        else:
                            if node not in node_dico:
                                node_dico[node] = copy.copy(node)
                            new_node = node_dico[node]
                            new_node.internals = copy.copy(new_node.internals)
                            for c in new_node.internals:
                                new_node.internals[c] = copy.copy(new_node.internals[c])
                            new_sslist.append(new_node)

                    new_sublist.append(new_sslist)
                else:
                    raise ValueError("{!r}".format(sublist[0]))

                l.append([copy.copy(delim), new_sublist])

            csts_copy.append(l)

        new_subnodes_attrs = {}
        for node, attrs in self.subnodes_attrs.items():
            new_node = node_dico[node]
            new_subnodes_attrs[new_node] = copy.copy(attrs)

        return csts_copy, new_subnodes_attrs

    def get_subnodes_collection(self):
        return self.subnodes_set

    def _set_drawn_node_attrs(self, node, nb, sz):
        self._nodes_drawn_qty[node.name] = nb
        if node.env is not None:
            node.env.set_drawn_node_attrs(id(node), nb=nb, sz=sz)
        else:
            if DEBUG:
                print(
                    "\n*** WARNING: no Env() is provided yet for node '%s'! "
                    "Thus cannot call methods on it!" % node.name
                )

    def _clear_drawn_node_attrs(self, node):
        if self._nodes_drawn_qty and node.name in self._nodes_drawn_qty:
            del self._nodes_drawn_qty[node.name]
        if node.env is not None:
            node.env.clear_drawn_node_attrs(id(node))
        else:
            if DEBUG:
                print(
                    "\n*** WARNING: no Env() is provided yet for node '%s'! "
                    "Thus cannot call methods on it!" % node.name
                )

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

    def get_subnode_minmax(self, node):
        if node in self.subnodes_attrs:
            return self.subnodes_attrs[node].qty
        else:
            return None

    def set_subnode_minmax(self, node, min=None, max=None):
        assert node in self.subnodes_attrs

        if min is not None and max is None:
            assert min > -2
            self.subnodes_attrs[node].qty[0] = min
        elif max is not None and min is None:
            assert max > -2
            self.subnodes_attrs[node].qty[1] = max
        elif min is not None and max is not None:
            assert min > -2 and max > -2 and (max >= min or max == -1)
            self.subnodes_attrs[node].qty = [min, max]
        else:
            raise ValueError("No values are provided!")

        self.reset_state(recursive=False, exclude_self=False)

    def get_subnode_default_qty(self, node):
        if node in self.subnodes_attrs:
            return self.subnodes_attrs[node].default_qty
        else:
            return None

    def set_subnode_default_qty(self, node, default_qty=None):
        assert node in self.subnodes_attrs
        mini, maxi = self.subnodes_attrs[node].qty
        assert mini <= default_qty <= maxi
        self.subnodes_attrs[node].default_qty = default_qty

        self.reset_state(recursive=False, exclude_self=False)

    def _get_random_component(self, comp_list, total_weight, check_existence=False):
        r = random.uniform(0, total_weight)
        s = 0

        for weight, comp in split_with(lambda x: isinstance(x, int), comp_list):
            s += weight
            if check_existence:
                shall_exist = self._existence_from_node(self._get_node_from(comp[0]))
                if shall_exist is not None and not shall_exist:
                    continue
            if s >= r:  # if check_existence is False, we always return here
                return comp[0]
        else:
            return None

    def _get_heavier_component(self, comp_list, check_existence=False):
        current_weight = -1
        current_comp = None
        for weight, comp in split_with(lambda x: isinstance(x, int), comp_list):
            if check_existence:
                shall_exist = self._existence_from_node(self._get_node_from(comp[0]))
                if shall_exist is not None and not shall_exist:
                    continue
            if weight > current_weight:
                current_weight = weight
                current_comp = comp[0]

        return current_comp

    @staticmethod
    def _get_next_heavier_component(comp_list, excluded_idx):
        current_weight = -1
        for idx, weight, comp in split_verbose_with(
            lambda x: isinstance(x, int), comp_list
        ):
            if idx in excluded_idx:
                continue
            if weight > current_weight:
                current_weight = weight
                current_comp = comp[0]
                current_idx = idx

        if current_weight == -1:
            return [], None
        else:
            return current_comp, current_idx

    @staticmethod
    def _get_next_random_component(comp_list, excluded_idx, seed=None):
        total_weight = 0
        for idx, weight, comp in split_verbose_with(
            lambda x: isinstance(x, int), comp_list
        ):
            if idx in excluded_idx:
                continue
            total_weight += weight

        if seed is None:
            r = random.uniform(0, total_weight)
        else:
            r = seed
        s = 0
        for idx, weight, comp in split_verbose_with(
            lambda x: isinstance(x, int), comp_list
        ):
            if idx in excluded_idx:
                continue
            s += weight
            if s >= r:
                ret = comp[0], idx, r
                break
        else:
            ret = [], None, r

        return ret

    def structure_will_change(self):
        """
        To be used only in Finite mode.
        Return True if the structure will change the next time _get_value() will be called.

        Returns: bool
        """

        if self.current_flattened_nodelist is None:
            # In this case we have never been frozen
            self.get_subnodes_with_csts()

        return not self.is_exhausted()

    def _get_node_from(self, node_desc):
        if isinstance(node_desc, Node):
            return node_desc
        else:  # node_desc is either (Node, min, max) or (Node, qty)
            return node_desc[0]

    def _get_node_and_minmax_from(self, node_desc):
        if isinstance(node_desc, Node):
            # This case exists for two situations:
            #   - import_subnodes_full_format()
            #   - _construct_subnodes() when the non-terminal node is in random mode
            node = node_desc
            mini, maxi = self.subnodes_attrs[node_desc].qty
            if maxi == -1 and mini >= 0:  # infinite case
                # for generation we limit to min+INFINITY_LIMIT
                maxi = mini + NodeInternals_NonTerm.INFINITY_LIMIT
            elif maxi == -1 and mini == -1:
                mini = maxi = NodeInternals_NonTerm.INFINITY_LIMIT
        else:  # node_desc is either (Node, min, max) or (Node, qty)
            node = node_desc[0]
            if len(node_desc) == 3:
                assert node_desc[1] > -2 and node_desc[2] > -2
                if node_desc[2] == -1 and node_desc[1] >= 0:  # infinite case
                    mini = node_desc[1]
                    # for generation we limit to min+INFINITY_LIMIT
                    maxi = mini + NodeInternals_NonTerm.INFINITY_LIMIT
                elif node_desc[2] == -1 and node_desc[1] == -1:
                    mini = maxi = NodeInternals_NonTerm.INFINITY_LIMIT
                else:
                    mini = node_desc[1]
                    maxi = node_desc[2]
            else:
                assert node_desc[1] > -2
                mini = maxi = (
                    NodeInternals_NonTerm.INFINITY_LIMIT
                    if node_desc[1] == -1
                    else node_desc[1]
                )

        return node, mini, maxi

    def _get_info_from_subnode_description(self, node_desc):
        nd_len = len(node_desc)
        if nd_len == 3 or nd_len == 4:
            mini = node_desc[1]
            maxi = node_desc[2]
            assert mini > -2 and maxi > -2 and (maxi >= mini or maxi == -1)
            if nd_len == 4:
                default = node_desc[3]
                assert mini <= default <= maxi, f'guilty node --> "{node_desc[0].name}"'
            else:
                default = None
        else:
            assert node_desc[1] > -2
            mini = maxi = node_desc[1]
            default = None

        return node_desc[0], mini, maxi, default

    def _copy_nodelist(self, node_list):
        new_list = []
        for delim, sublist in self.__iter_csts(node_list):
            if delim[1] == ">" or delim[1:3] == "=.":
                new_list.append([delim, copy.copy(sublist)])
            elif delim[1:3] == "=+":
                new_list.append([delim, [sublist[0], copy.copy(sublist[1])]])
        return new_list

    def _construct_subnodes(
        self,
        node_desc,
        subnode_list,
        mode,
        ignore_sep_fstate,
        ignore_separator=False,
        lazy_mode=True,
    ):
        def _sync_size_handling(node):
            obj = node.synchronized_with(SyncScope.Size)
            if obj is not None:
                obj.synchronize_nodes(node)

        node, mini, maxi = self._get_node_and_minmax_from(node_desc)
        # if self.debug:
        #     print('\n*** construct:', node.name, mini, maxi, node_desc)

        shall_exist = self._existence_from_node(node)
        if shall_exist is not None:
            if not shall_exist:
                if node.env and node.env.delayed_jobs_enabled and lazy_mode:
                    node.set_attr(NodeInternals.DISABLED)
                    node.set_private((self, mode, ignore_sep_fstate, ignore_separator))
                    subnode_list.append(node)

                # Before returning we add a separator if ever it is mandatory ('always')
                if self.separator is not None and self.separator.always and not ignore_separator:
                    new_sep = self._clone_separator(self.separator.node,
                                                    unique=self.separator.unique,
                                                    ignore_frozen_state=ignore_sep_fstate)
                    subnode_list.append(new_sep)

                return

        mini, maxi, corrupted = self.nodeqty_corrupt_hook(node, mini, maxi)

        if corrupted or self.is_attr_set(NodeInternals.Determinist):
            nb = math.ceil((mini + maxi) / 2)
        else:
            if self._reevaluation_pending:
                nb = self._nodes_drawn_qty.get(node.name)
                if nb is None:
                    print(
                        f"\n*** Warning[_construct_subnodes]: {node.name} node has no reference "
                        f"in self._nodes_drawn_qty, thus fallback to random qty"
                    )
                    nb = random.randint(mini, maxi)
            else:
                nb = random.randint(mini, maxi)

        if not corrupted:
            qty = self._qty_from_node(node)
            if qty is not None:
                nb = qty

        to_entangle = set()

        base_node = node
        external_entangled_nodes = (
            [] if base_node.entangled_nodes is None else list(base_node.entangled_nodes)
        )

        if nb == 0:
            if (
                self.separator is not None
                and self.separator.always
                and not ignore_separator
            ):
                new_sep = self._clone_separator(
                    self.separator.node,
                    unique=self.separator.unique,
                    ignore_frozen_state=ignore_sep_fstate,
                )
                subnode_list.append(new_sep)

        new_node = None
        transformed_node = None
        for i in range(nb):
            # 'unique' mode
            if mode == "u":
                if i == 0 and base_node.tmp_ref_count == 1:
                    new_node = base_node
                else:
                    base_node.tmp_ref_count += 1
                    nid = base_node.name + ":" + str(base_node.tmp_ref_count)
                    # if self.is_attr_set(NodeInternals.Determinist):
                    ignore_fstate = not self.custo.frozen_copy_mode

                    node_to_copy = (
                        base_node if transformed_node is None else transformed_node
                    )
                    new_node = Node(
                        nid,
                        base_node=node_to_copy,
                        ignore_frozen_state=ignore_fstate,
                        accept_external_entanglement=True,
                        acceptance_set=set(external_entangled_nodes + subnode_list),
                    )
                    new_node._reset_depth(parent_depth=base_node.depth - 1)

                    # For dynamically created Node(), don't propagate the fuzz weight
                    if not self.custo.mutable_clone_mode:
                        new_node.reset_fuzz_weight(recursive=True)
                        new_node.clear_attr(
                            NodeInternals.Mutable, all_conf=True, recursive=True
                        )
                    else:
                        pass

                    if base_node.custo and base_node.custo.transform_func is not None:
                        try:
                            transformed_node = base_node.custo.transform_func(new_node)
                        except:
                            print(
                                "\n*** ERROR: User-provided NodeCustomization.transform_func()"
                                " raised an exception. We ignore it."
                            )
                        else:
                            if isinstance(new_node, Node):
                                new_node = transformed_node
                            else:
                                print(
                                    "\n*** ERROR: User-provided NodeCustomization.transform_func()"
                                    " should return a Node. Thus we ignore its production."
                                )

                    elif self.custo.cycle_clone_mode:
                        new_node.freeze()
                        new_node.walk(steps_num=1)
                        transformed_node = new_node

                new_node._set_clone_info((base_node.tmp_ref_count - 1, nb), base_node)
                _sync_size_handling(new_node)

            # 'same' mode
            elif mode == "s":
                new_node = base_node
            else:
                raise ValueError

            subnode_list.append(new_node)
            to_entangle.add(new_node)

            # if new_node.is_nonterm():   ### TODO debug
            #     print(new_node.name, new_node.frozen_node_list)

            if self.separator is not None and not ignore_separator:
                new_sep = self._clone_separator(
                    self.separator.node,
                    unique=self.separator.unique,
                    ignore_frozen_state=ignore_sep_fstate,
                )
                subnode_list.append(new_sep)

        # set_clone_info() and other methods are applied for 's' mode
        # only once as there is no node copy.
        if new_node is not None and mode == "s":
            new_node._set_clone_info((0, nb), base_node)
            _sync_size_handling(new_node)

        if len(to_entangle) > 1:
            make_entangled_nodes(to_entangle)

        # node._tobytes() has to be called after the
        # previous copy process, to avoid copying frozen node
        self._set_drawn_node_attrs(node, nb, len(node._tobytes()))

        return

    def get_subnodes_with_csts(self):
        """
        Generate the structure of the non terminal node.
        """

        def compute_next_shape(determinist, finite):
            if not self.exhausted_pick_cases:
                self.excluded_components.pop(-1)

            if determinist:
                node_list, idx = self._get_next_heavier_component(
                    self.subnodes_order, excluded_idx=self.excluded_components
                )
                self.excluded_components.append(idx)
                # 'len(self.subnodes_order)' is always even
                exhausted_shape = (
                    len(self.excluded_components) == len(self.subnodes_order) // 2
                )
                # Note that self.excluded_components is reset in a lazy way (within unfreeze)

            else:
                if finite:
                    (
                        node_list,
                        idx,
                        self.component_seed,
                    ) = self._get_next_random_component(
                        self.subnodes_order, excluded_idx=self.excluded_components
                    )
                    self.excluded_components.append(idx)
                    exhausted_shape = (
                        len(self.excluded_components) == len(self.subnodes_order) // 2
                    )

                else:
                    node_list = self._get_random_component(
                        self.subnodes_order, self.subnodes_order_total_weight
                    )
                    exhausted_shape = False

            if determinist:
                node_list, pick_section_amount = self.flatten_node_list(node_list)
                if pick_section_amount > 0:
                    self.exhausted_pick_cases = False
                    new_node_list = []
                    pick_section = 0
                    next_pick_section = None
                    self.exhausted_pick_cases = False
                    for obj in node_list:
                        if isinstance(obj, Node):
                            new_node_list.append(obj)
                        else:
                            if pick_section == self.current_pick_section:
                                new_node_list.append(obj[self.current_picked_node_idx])
                                self.current_picked_node_idx += 1
                                if len(obj) <= self.current_picked_node_idx:
                                    # we need to move on to the next pick section and if there is no
                                    # more then we are exhausted.
                                    next_pick_section = self.current_pick_section + 1
                                    self.current_picked_node_idx = 1
                                    if pick_section_amount == next_pick_section:
                                        self.exhausted_pick_cases = True
                            else:
                                new_node_list.append(obj[0])
                            pick_section += 1

                    if self.exhausted_pick_cases:
                        self.current_pick_section = 0
                        self.current_picked_node_idx = 0
                    elif next_pick_section is not None:
                        self.current_pick_section = next_pick_section

                    node_list = new_node_list

            self.exhausted_shapes = exhausted_shape and self.exhausted_pick_cases

            return node_list

        # In this case we return directly the frozen state
        if self.frozen_node_list is not None:
            self._reevaluation_pending = False
            return (self.frozen_node_list, False)

        if self.separator is not None:
            ignore_sep_fstate = not self.separator.node.is_frozen()

            if self.separator.prefix:
                new_sep = self._clone_separator(
                    self.separator.node,
                    unique=self.separator.unique,
                    ignore_frozen_state=ignore_sep_fstate,
                )
                self.frozen_node_list = [new_sep]
            else:
                self.frozen_node_list = []
        else:
            ignore_sep_fstate = None
            self.frozen_node_list = []

        determinist = self.is_attr_set(NodeInternals.Determinist)
        finite = self.is_attr_set(NodeInternals.Finite)

        if determinist:
            if self.combinatory_complete or self.custo.stick_to_default_mode:
                self.current_flattened_nodelist = node_list = compute_next_shape(
                    determinist, finite
                )
                self.cursor_min = 0
                self.cursor_maj = 0
                self.previous_cursor_min = 0
                self.previous_cursor_maj = 0
                self.combinatory_complete = False
                # self.current_flattened_nodelist = self.flatten_node_list(node_list)

            elif self.current_flattened_nodelist is None:
                # This case happens when we have been cloned with 'ignore_frozen_state'
                # and not frozen since then, or cloned from a node that has never been frozen.
                # The parameters are already initialized by the cloning procedure.
                self.current_flattened_nodelist = node_list = compute_next_shape(
                    determinist, finite
                )
                # self.current_flattened_nodelist = self.flatten_node_list(node_list)

            for nd in self.current_flattened_nodelist:
                self.subnodes_attrs[nd].perform_planned_reset()

            next_cursor_min = None
            next_cursor_maj = None
            first_pass_done = False
            perform_reset = False

            current_nodelist_sz = len(self.current_flattened_nodelist)
            for idx, nd in enumerate(self.current_flattened_nodelist):
                expanded_nodes = []
                nd_attrs = self.subnodes_attrs[nd]

                if self.custo.full_combinatory_mode:
                    if idx == self.cursor_min:
                        if nd_attrs._current_qty is None:
                            first_pass_done = True
                        qty = nd_attrs.current_qty

                        if nd_attrs.exhausted_seq:
                            # print('\n  ## case 1 ***')
                            self.cursor_min = self.cursor_min + 1
                            first_pass_done = False
                            if self.cursor_min == self.cursor_maj:
                                for idx in range(self.cursor_maj, current_nodelist_sz):
                                    next_nd = self.current_flattened_nodelist[idx]
                                    next_nd_attrs = self.subnodes_attrs[next_nd]
                                    if not next_nd_attrs.exhausted_seq:
                                        self.cursor_maj += 1
                                        break
                                else:
                                    self.combinatory_complete = True
                            elif self.cursor_min > self.cursor_maj:
                                if self.cursor_maj + 1 >= current_nodelist_sz:
                                    self.combinatory_complete = True
                                else:
                                    self.cursor_maj += 1
                            else:
                                pass

                        else:
                            if not first_pass_done:
                                qty = nd_attrs.next_qty()
                            else:
                                first_pass_done = False
                            if nd_attrs.exhausted_seq:
                                if self.cursor_maj - self.cursor_min > 0:
                                    for idx in range(0, self.cursor_maj):
                                        next_nd = self.current_flattened_nodelist[idx]
                                        next_nd_attrs = self.subnodes_attrs[next_nd]
                                        if not next_nd_attrs.exhausted_seq:
                                            next_cursor_min = idx
                                            perform_reset = True
                                            break
                                    else:
                                        for idx in range(
                                            self.cursor_maj, current_nodelist_sz
                                        ):
                                            next_nd = self.current_flattened_nodelist[
                                                idx
                                            ]
                                            next_nd_attrs = self.subnodes_attrs[next_nd]
                                            if not next_nd_attrs.exhausted_seq:
                                                next_cursor_min = idx
                                                next_cursor_maj = idx
                                                perform_reset = True
                                                break
                                        else:
                                            self.combinatory_complete = True

                                elif self.cursor_min == self.cursor_maj:
                                    if self.cursor_maj == current_nodelist_sz - 1:
                                        next_cursor_min = 0
                                    else:
                                        next_cursor_maj = self.cursor_maj + 1
                                        if self.cursor_min > 0:
                                            next_cursor_min = 0
                                        else:
                                            next_cursor_min = self.cursor_min + 1
                                            perform_reset = True
                                else:
                                    # We should never reach this case
                                    raise NotImplementedError
                            else:
                                next_cursor_min = 0

                    else:
                        qty = nd_attrs.current_qty

                else:
                    if idx == self.cursor_min:
                        if nd_attrs._current_qty is None:
                            first_pass_done = True
                        qty = nd_attrs.current_qty

                        if nd_attrs.exhausted_seq:
                            # print('\n  ## case 1 ***')
                            self.cursor_min = self.cursor_min + 1
                            first_pass_done = False
                            if self.cursor_min == current_nodelist_sz:
                                self.combinatory_complete = True
                        else:
                            if not first_pass_done:
                                # print('\n  ## case 2.a ***')
                                qty = nd_attrs.next_qty()
                            else:
                                # print('\n  ## case 2.b ***')
                                first_pass_done = False
                            if nd_attrs.exhausted_seq:
                                for idx in range(self.cursor_min, current_nodelist_sz):
                                    next_nd = self.current_flattened_nodelist[idx]
                                    next_nd_attrs = self.subnodes_attrs[next_nd]
                                    if not next_nd_attrs.exhausted_seq:
                                        next_cursor_min = idx
                                        perform_reset = True
                                        break
                                else:
                                    self.combinatory_complete = True
                            else:
                                pass

                    else:
                        qty = nd_attrs.current_qty

                # if self.debug:
                #     print(f'*** {qty} :{nd.name} {self.subnodes_attrs[nd].qty_sequence}')

                self._construct_subnodes(
                    (nd, qty),
                    expanded_nodes,
                    mode="u",
                    ignore_sep_fstate=ignore_sep_fstate,
                )

                self.frozen_node_list += expanded_nodes

            # When self.cursor_min is updated within the walking algorithms, this does not change
            # the resulting data, it is just a shortcut in the algorithm. This is generally safe
            # to use self.previous_cursor_m* to restore previous state. But, there is a corner
            # case when the shape is exhausted, as self.cursor_m* will be incremented and will be
            # longer than current_nodelist_sz.
            if self.cursor_min >= current_nodelist_sz:
                self.previous_cursor_min = current_nodelist_sz - 1
            else:
                self.previous_cursor_min = self.cursor_min

            if self.cursor_maj >= current_nodelist_sz:
                self.previous_cursor_maj = current_nodelist_sz - 1
            else:
                self.previous_cursor_maj = self.cursor_maj

            if next_cursor_maj is not None:
                self.cursor_maj = next_cursor_maj
            if next_cursor_min is not None:
                self.cursor_min = next_cursor_min

            if self.combinatory_complete or self.custo.stick_to_default_mode:
                for nd in self.current_flattened_nodelist:
                    self.subnodes_attrs[nd].plan_reset()

            elif perform_reset:
                for nd in self.current_flattened_nodelist[: self.cursor_min]:
                    self.subnodes_attrs[nd].plan_reset()

        else:  # random
            node_list = compute_next_shape(determinist, finite)

            for delim, sublist in self.__iter_csts(node_list):
                sublist_tmp = []

                if delim[1] == ">":
                    for i, node in enumerate(sublist):
                        self._construct_subnodes(
                            node, sublist_tmp, delim[0], ignore_sep_fstate
                        )

                elif delim[1] == "=":
                    if delim[2] == ".":
                        l = copy.copy(sublist)
                        lg = len(l)

                        # unfold the Nodes one after another
                        if delim[2:] == "..":
                            for i in range(lg):
                                node = random.choice(l)
                                l.remove(node)
                                self._construct_subnodes(
                                    node, sublist_tmp, delim[0], ignore_sep_fstate
                                )

                        # unfold all the Node and then choose randomly
                        else:
                            # In this case, NodeSeparator(always=True) have no meaning and
                            # thus 'always' is always considered to be False.
                            list_unfold = []
                            for i in range(lg):
                                node = random.choice(l)
                                l.remove(node)
                                self._construct_subnodes(
                                    node,
                                    list_unfold,
                                    delim[0],
                                    ignore_sep_fstate,
                                    ignore_separator=True,
                                )

                            lg = len(list_unfold)
                            for i in range(lg):
                                node = random.choice(list_unfold)
                                list_unfold.remove(node)
                                sublist_tmp.append(node)
                                if self.separator is not None:
                                    new_sep = self._clone_separator(
                                        self.separator.node,
                                        unique=self.separator.unique,
                                        ignore_frozen_state=ignore_sep_fstate,
                                    )
                                    sublist_tmp.append(new_sep)

                    # choice of only one component within a list
                    elif delim[2] == "+":
                        if sublist[0] > -1:
                            node = self._get_random_component(
                                comp_list=sublist[1],
                                total_weight=sublist[0],
                                check_existence=True,
                            )
                        else:
                            ndesc_list = []
                            for ndesc in sublist[1]:
                                n, _, _ = self._get_node_and_minmax_from(ndesc)
                                shall_exist = self._existence_from_node(n)
                                if shall_exist is None or shall_exist:
                                    ndesc_list.append(ndesc)
                            node = random.choice(ndesc_list) if ndesc_list else None
                        if node is None:
                            continue
                        else:
                            self._construct_subnodes(
                                node, sublist_tmp, delim[0], ignore_sep_fstate
                            )

                    else:
                        raise ValueError(f"delim: '{delim}'")
                else:
                    raise ValueError(f"delim: '{delim}'")

                self.frozen_node_list += sublist_tmp

        for e in self.subnodes_set:
            e.tmp_ref_count = 1

        if self.separator is not None:
            if (
                not self.separator.suffix
                and self.frozen_node_list
                and self.frozen_node_list[-1].is_attr_set(NodeInternals.AutoSeparator)
            ):
                self.frozen_node_list.pop(-1)
            self._clone_separator_cleanup()

        self._reevaluation_pending = False
        return (self.frozen_node_list, True)

    def _get_value(
        self,
        conf=None,
        recursive=True,
        after_encoding=True,
        return_node_internals=False,
        restrict_csp=False,
    ):
        """
        The parameter return_node_internals is not used for non terminal nodes,
        only for terminal nodes. However, keeping it also for non terminal nodes
        avoid additional checks in the code.
        """

        def tobytes_helper(node_internals):
            if isinstance(node_internals, bytes):
                return node_internals
            else:
                return node_internals._get_value(
                    conf=conf,
                    recursive=recursive,
                    return_node_internals=False,
                    restrict_csp=restrict_csp,
                )[0]

        def handle_encoding(list_to_enc):
            if self.custo.collapse_padding_mode and not self.custo.delay_collapsing:
                list_to_enc = list(flatten(list_to_enc))
                if list_to_enc and isinstance(list_to_enc[0], bytes):
                    return list_to_enc

                while True:
                    list_sz = len(list_to_enc)
                    for i in range(list_sz):
                        if i < list_sz - 1:
                            item1 = list_to_enc[i]
                            item2 = list_to_enc[i + 1]
                            c1 = (
                                isinstance(item1, NodeInternals_TypedValue)
                                and item1.get_current_subkind() == fvt.BitField
                                and item1.get_value_type().padding_size != 0
                            )
                            c2 = (
                                isinstance(item2, NodeInternals_TypedValue)
                                and item2.get_current_subkind() == fvt.BitField
                            )
                            if c1 and c2:
                                new_item = NodeInternals_TypedValue()
                                new_item1vt = copy.copy(item1.get_value_type())
                                new_item1vt.make_private(forget_current_state=False)
                                new_item2vt = copy.copy(item2.get_value_type())
                                new_item2vt.make_private(forget_current_state=False)
                                new_item1vt.extend_left(new_item2vt)
                                new_item.import_value_type(new_item1vt)
                                new_item.frozen_node = (
                                    new_item.get_value_type().get_current_value()
                                )
                                if i > 0:
                                    new_list = list_to_enc[:i]
                                    new_list.append(new_item)
                                    if i < list_sz - 2:
                                        new_list += list_to_enc[i + 2 :]
                                else:
                                    new_list = list_to_enc[2:]
                                    new_list.insert(0, new_item)
                                list_to_enc = new_list
                                break
                    else:
                        break

                list_to_enc = list(map(tobytes_helper, list_to_enc))

            if self.encoder and after_encoding:
                if not self.custo.collapse_padding_mode:
                    list_to_enc = list(flatten(list_to_enc))

                if list_to_enc:
                    if issubclass(list_to_enc[0].__class__, NodeInternals):
                        list_to_enc = list(map(tobytes_helper, list_to_enc))
                    blob = b"".join(list_to_enc)
                else:
                    blob = b""

                blob = self.encoder.encode(blob)
                return blob
            else:
                return list_to_enc

        l = []
        node_list, was_not_frozen = self.get_subnodes_with_csts()

        djob_group_created = False
        disabled_node = False
        node_with_no_children = False
        removed_cpt = 0

        for idx, n in enumerate(copy.copy(node_list)):
            if n.is_attr_set(NodeInternals.DISABLED):
                val = Node.DEFAULT_DISABLED_NODEINT
                if not n.env.is_djob_registered(
                    key=id(n), prio=Node.DJOBS_PRIO_nterm_existence
                ):
                    if not djob_group_created:
                        djob_group_created = True
                        djob_group = DJobGroup(node_list)
                    n.env.register_djob(
                        NodeInternals_NonTerm._expand_delayed_nodes,
                        group=djob_group,
                        key=id(n),
                        cleanup=NodeInternals_NonTerm._cleanup_delayed_nodes,
                        args=[n, node_list, len(l), conf, recursive],
                        prio=Node.DJOBS_PRIO_nterm_existence,
                    )
                    disabled_node = True
            else:
                val = n._get_value(conf=conf, recursive=recursive,
                                   return_node_internals=True, restrict_csp=restrict_csp)

                if node_with_no_children and n.is_attr_set(NodeInternals.AutoSeparator):
                    # print(f'\nNode with no children - step 2 / {idx} {n.name}')
                    # print_node_list(self.frozen_node_list)
                    node_with_no_children = False
                    self.frozen_node_list.pop(idx)
                    continue
                elif (self.separator is not None and not self.separator.always
                        and not n.is_attr_set(NodeInternals.AutoSeparator)
                        and n.is_nonterm() and n.has_no_children()):
                    # print(f'\nNode with no children - step 1 / {idx} {n.name}')
                    # print_node_list(self.frozen_node_list)
                    node_with_no_children = True
                    continue
                else:
                    node_with_no_children = False

            if disabled_node and self.separator is not None and isinstance(val, NodeInternals) and val.is_attr_set(NodeInternals.AutoSeparator) \
                    and not self.separator.always: # and not self.separator.suffix

                # TODO: The case "suffix False and always True" should be already handled at
                #  self.get_subnodes_with_csts()
                #  --> TBC
                disabled_node = False
                self.frozen_node_list.pop(idx - removed_cpt)
                removed_cpt += 1
                continue

            disabled_node = False

            # 'val' is always a NodeInternals except if non-term encoding has been carried out
            l.append(val)

        # if self.debug:
        #     print(f'\nEND LOOP {last_idx}')

        if self.separator is not None and l:
            if (not self.separator.always and not self.separator.suffix
                    and isinstance(l[-1], NodeInternals) and l[-1].is_attr_set(NodeInternals.AutoSeparator)):
                l.pop(-1)
                self.frozen_node_list.pop(-1)

        if node_list:
            node_env = node_list[0].env
        else:
            return (handle_encoding(l), was_not_frozen)

        # We avoid reentrancy that could trigger recursive loop with
        # self._existence_from_node()
        if node_env and node_env._reentrancy_cpt > 0:
            node_env._reentrancy_cpt = 0
            return (handle_encoding(l), was_not_frozen)

        if (
            node_env
            and node_env.delayed_jobs_enabled
            and node_env.djobs_exists(Node.DJOBS_PRIO_nterm_existence)
        ):
            groups = node_env.get_all_djob_groups(prio=Node.DJOBS_PRIO_nterm_existence)
            if groups is not None:
                for gr in groups:
                    for n in gr:
                        if n.is_attr_set(NodeInternals.DISABLED):
                            # Reentrancy is counted at this location,
                            # because self._existence_from_node() can
                            # trigger a recursive loop
                            node_env._reentrancy_cpt += 1
                            shall_exist = self._existence_from_node(n)
                            node_env._reentrancy_cpt = 0

                            if shall_exist:
                                djobs = node_env.get_djobs_by_gid(
                                    id(gr), prio=Node.DJOBS_PRIO_nterm_existence
                                )
                                func, args, cleanup = djobs[id(n)]
                                job_idx = args[2]
                                node_qty = func(*args)
                                if node_qty > 0:
                                    node_env.remove_djob(
                                        gr, id(n), prio=Node.DJOBS_PRIO_nterm_existence
                                    )
                                if node_qty > 1:
                                    for func, args, cleanup in djobs.values():
                                        if args[2] > job_idx:
                                            args[2] += node_qty - 1

        return (handle_encoding(l), was_not_frozen)

    def get_raw_value(self, **kwargs):
        raw_list = self._get_value(after_encoding=False)[0]
        raw_list = list(flatten(raw_list))

        def tobytes_helper(node_internals):
            return node_internals._get_value(return_node_internals=False)[0]

        if raw_list:
            if issubclass(raw_list[0].__class__, NodeInternals):
                raw_list = list(map(tobytes_helper, raw_list))
            raw = b"".join(raw_list)
        else:
            raw = b""

        return raw

    @staticmethod
    def _expand_delayed_nodes(node, node_list, idx, conf, rec):
        node_internals, mode, ignore_sep_fstate, ignore_separator = node.get_private()
        node.set_private(None)
        node.clear_attr(NodeInternals.DISABLED)
        expand_list = []
        node_internals._construct_subnodes(
            node,
            expand_list,
            mode,
            ignore_sep_fstate,
            ignore_separator,
            lazy_mode=False,
        )
        if expand_list:
            if node_internals.separator is not None and len(node_list) == idx - 1:
                if not node_internals.separator.suffix and expand_list[-1].is_attr_set(
                    NodeInternals.AutoSeparator
                ):
                    expand_list.pop(-1)
                node_internals._clone_separator_cleanup()

            node_list.pop(idx)
            for i, n in enumerate(expand_list):
                node_list.insert(idx + i, n)

        return len(expand_list)

    @staticmethod
    def _cleanup_delayed_nodes(node, node_list, idx, conf, rec):
        node.set_private(None)
        node.clear_attr(NodeInternals.DISABLED)
        if idx < len(node_list):
            node_list.pop(idx)

    def set_separator_node(
        self, sep_node, prefix=True, suffix=True, unique=False, always=False
    ):
        check_err = set()
        for n in self.subnodes_set:
            check_err.add(n.name)
        if sep_node.name in check_err:
            print(
                "\n*** The separator node name shall not be used by a subnode "
                + "of this non-terminal node"
            )
            raise ValueError
        self.separator = NodeSeparator(
            sep_node, prefix=prefix, suffix=suffix, unique=unique, always=always
        )

    def get_separator_node(self):
        if self.separator is not None:
            sep = self.separator.node
        else:
            sep = None
        return sep

    def _precondition_subnode_ops(self):
        if self.frozen_node_list is None:
            raise ValueError("current node is not yet frozen!")

    def get_subnode(self, num):
        self._precondition_subnode_ops()
        return self.frozen_node_list[num]

    def get_subnode_off(self, num):
        self._precondition_subnode_ops()
        off = 0
        for idx in range(num):
            n = self.frozen_node_list[idx]
            off += len(n._tobytes())

        return off

    def get_subnode_idx(self, node):
        self._precondition_subnode_ops()
        return self.frozen_node_list.index(node)

    def get_subnode_qty(self):
        self._precondition_subnode_ops()
        return len(self.frozen_node_list)

    def replace_subnode(self, old, new):
        self.subnodes_set.remove(old)
        self.subnodes_set.add(new)

        self.subnodes_attrs[new] = self.subnodes_attrs[old]
        del self.subnodes_attrs[old]

        for weight, lnode_list in split_with(
            lambda x: isinstance(x, int), self.subnodes_order
        ):
            for delim, sublist in self.__iter_csts(lnode_list[0]):
                if delim[:3] == "u=+" or delim[:3] == "s=+":
                    for w, etp in split_with(lambda x: isinstance(x, int), sublist[1]):
                        for idx, n in enumerate(etp):
                            if n is old:
                                etp[idx] = new
                else:
                    for idx, n in enumerate(sublist):
                        if n is old:
                            sublist[idx] = new

    def add(
        self, node, min=1, max=1, default_qty=None, after=None, before=None, idx=None
    ):
        """
        This method add a new node to this non-terminal. The location and the quantity can be configured
        through the parameters.

        Args:
            node (Node): The node to add
            min: The minimum number of repetition of this node within the non-terminal node
            max: The maximum number of repetition of this node within the non-terminal node
            default_qty: the default number of repetition of this node within the non-terminal node
            after: If not None, it should be the node (within the non-terminal) *after* which
              the new node will be inserted.
            before: If not None, it should be the node (within the non-terminal) *before* which
              the new node will be inserted.
            idx: If not None, it should provide the position in the list of subnodes where the new
              node will be inserted.

        """

        assert (
            (after is not None and before is None and idx is None)
            or (before is not None and after is None and idx is None)
            or (idx is not None and before is None and after is None)
            or (after is None and before is None and idx is None)
        )

        self.subnodes_set.add(node)
        self.subnodes_attrs[node] = NodeInternals_NonTerm.NodeAttrs()
        self.subnodes_attrs[node].default_qty = default_qty
        self.subnodes_attrs[node].qty = [min, max]

        if after is not None:
            pivot = after
        elif before is not None:
            pivot = before
        else:
            pivot = None

        insert_before = after is None

        def add_to_node_list(new_node, node_list, index):
            node_cpt = 0
            for delim, sublist in self.__iter_csts(node_list):
                if delim[:3] == "u=+" or delim[:3] == "s=+":
                    for w, etp in split_with(lambda x: isinstance(x, int), sublist[1]):
                        if pivot is None and node_cpt == index:
                            etp.insert(index, new_node)
                        else:
                            for i, ndesc in enumerate(etp):
                                n, _, _ = self._get_node_and_minmax_from(ndesc)
                                if n is pivot:
                                    index = i if insert_before else i + 1
                                    ndesc = new_node
                                    etp.insert(index, ndesc)
                                    break
                        node_cpt += 1
                else:
                    if pivot is None and node_cpt == index:
                        sublist.insert(index, new_node)
                    else:
                        for i, ndesc in enumerate(sublist):
                            n, _, _ = self._get_node_and_minmax_from(ndesc)
                            if n is pivot:
                                index = i if insert_before else i + 1
                                ndesc = new_node
                                sublist.insert(index, ndesc)
                                break
                    node_cpt += 1

        for weight, lnode_list in split_with(
            lambda x: isinstance(x, int), self.subnodes_order
        ):
            if pivot is None and idx is None:
                lnode_list[0].append(["u>", [node]])
                continue
            add_to_node_list(node, lnode_list[0], idx)

        if self.current_flattened_nodelist is not None:
            if pivot is not None:
                cf_idx = self.current_flattened_nodelist.index(pivot)
                cf_idx = cf_idx if insert_before else cf_idx + 1
            elif idx is None:
                cf_idx = len(self.current_flattened_nodelist)
            else:
                cf_idx = idx

            self.current_flattened_nodelist.insert(cf_idx, node)

        if self.frozen_node_list:
            if pivot is not None:
                f_idx = self.frozen_node_list.index(pivot)
                f_idx = f_idx if insert_before else f_idx + 1
            elif idx is None:
                f_idx = len(self.frozen_node_list)
            else:
                f_idx = idx

            for _ in range(default_qty if default_qty is not None else min):
                self.frozen_node_list.insert(f_idx, node)

    def _parse_node_desc(self, node_desc):
        mini, maxi = self.subnodes_attrs[node_desc].qty
        return node_desc, mini, maxi

    def _clone_node(
        self, base_node, node_no, force_clone=False, ignore_frozen_state=True
    ):
        if node_no > 0 or force_clone:
            base_node.tmp_ref_count += 1
            nid = base_node.name + ":" + str(base_node.tmp_ref_count)
            node = Node(
                nid,
                base_node=base_node,
                ignore_frozen_state=ignore_frozen_state,
                accept_external_entanglement=False,
            )
            node._reset_depth(parent_depth=base_node.depth - 1)
            if base_node.is_nonterm() and not base_node.cc.custo.mutable_clone_mode:
                node.reset_fuzz_weight(recursive=True)
                node.clear_attr(NodeInternals.Mutable, all_conf=True, recursive=True)
        else:
            node = base_node

        return node

    def _clone_node_cleanup(self):
        for n in self.subnodes_set:
            n.tmp_ref_count = 1

    def _clone_separator(
        self, sep_node, unique, force_clone=False, ignore_frozen_state=True
    ):
        if (sep_node.tmp_ref_count > 1 and unique) or force_clone:
            nid = sep_node.name + ":" + str(sep_node.tmp_ref_count)
            sep_node.tmp_ref_count += 1
            node = Node(
                nid,
                base_node=sep_node,
                ignore_frozen_state=ignore_frozen_state,
                accept_external_entanglement=False,
            )
            node._reset_depth(parent_depth=sep_node.depth - 1)
        else:
            sep_node.tmp_ref_count += 1
            node = sep_node

        return node

    def _clone_separator_cleanup(self):
        if self.separator is not None:
            self.separator.node.tmp_ref_count = 1

    @staticmethod
    def _size_from_node(node, for_encoded_size=False):
        # This method is only used for absorption. For generation, dealing with size
        # is performed by the function _sync_size_handling() that is nested within
        # the method self._construct_subnodes()
        obj = node.synchronized_with(SyncScope.Size)
        if obj is not None:
            assert isinstance(obj, SyncSizeObj)
            size = obj.size_for_absorption
            if size is not None:
                if obj.apply_to_enc_size == for_encoded_size:
                    return size  # Corrupt hook is not called because only used for absorption.
                    # To be reconsidered if usage is extended
                else:
                    return None
            else:
                print(
                    "\n*** WARNING: synchronization is not possible "
                    "for node '{:s}' (id: {:d})!".format(node.name, id(node))
                )
                return None

        return None

    @staticmethod
    def _qty_from_node(node):
        obj = node.synchronized_with(SyncScope.Qty)
        if obj is not None:
            sync_node, param = obj
            nb = node.env.get_drawn_node_qty(id(sync_node))
            if nb is not None:
                return NodeInternals_NonTerm.qtysync_corrupt_hook(node, nb)
            else:
                print(
                    "\n*** WARNING: synchronization is not possible "
                    "for node '{:s}' (id: {:d})!".format(node.name, id(node))
                )
                return None

        obj = node.synchronized_with(SyncScope.QtyFrom)
        if obj is not None:
            assert isinstance(obj, SyncQtyFromObj)
            nb = obj.qty
            if nb is not None:
                return NodeInternals_NonTerm.qtysync_corrupt_hook(node, nb)
            else:
                print(
                    "\n*** WARNING: synchronization is not possible "
                    "for node '{:s}' (id: {:d})!".format(node.name, id(node))
                )
                return None

        return None

    @staticmethod
    def _existence_from_node(node):
        obj = node.synchronized_with(SyncScope.Existence)
        if obj is not None:
            if isinstance(obj, SyncExistenceObj):
                correct_reply = obj.check()
            else:
                sync_node, condition = obj
                if sync_node is None:
                    correct_reply = bool(condition)
                else:
                    exist = node.env.node_exists(id(sync_node))
                    crit_1 = exist
                    crit_2 = True

                    if DEBUG:
                        print(
                            f'\n*** [Existence Check requested by "{node.name}"]\n'
                            f'  --> Does the node "{sync_node.name}" exist? {exist}'
                        )
                        if not exist:
                            print(
                                f'  --> The node "{sync_node.name}" is either really not existing or not\n'
                                f"      registered in node.env.drawn_node_attrs because of a bug..."
                            )

                        print(f"\n --> condition existing? {bool(condition)}")

                    if exist and condition is not None:
                        try:
                            crit_2 = condition.check(sync_node)

                            if DEBUG:
                                print(f"\n --> condition satisfied? {crit_2}")
                        except Exception as e:
                            print(
                                "\n*** ERROR: existence condition is not verifiable "
                                "for node '{:s}' (id: {:d})!\n"
                                "*** The condition checker raise an exception!".format(
                                    node.name, id(node)
                                )
                            )
                            raise
                    correct_reply = crit_1 and crit_2

            return NodeInternals_NonTerm.existence_corrupt_hook(node, correct_reply)

        obj = node.synchronized_with(SyncScope.Inexistence)
        if obj is not None:
            sync_node, _ = obj  # condition is not checked for this scope
            correct_reply = not node.env.node_exists(id(sync_node))
            return NodeInternals_NonTerm.existence_corrupt_hook(node, correct_reply)

        return None

    @staticmethod
    def existence_corrupt_hook(node, exist):
        # print('\n** corrupt list', node.entangled_nodes, node.env.nodes_to_corrupt)
        # if node.env.nodes_to_corrupt:
        #     for n in node.env.nodes_to_corrupt.keys():
        #         print('entangled: ', n.entangled_nodes)
        if node in node.env.nodes_to_corrupt:
            corrupt_type, corrupt_op = node.env.nodes_to_corrupt[node]
            if corrupt_type == Node.CORRUPT_EXIST_COND or corrupt_type is None:
                return not exist
            else:
                return exist
        else:
            return exist

    @staticmethod
    def qtysync_corrupt_hook(node, qty):
        if node in node.env.nodes_to_corrupt:
            corrupt_type, corrupt_op = node.env.nodes_to_corrupt[node]
            if corrupt_type == Node.CORRUPT_QTY_SYNC or corrupt_type is None:
                return corrupt_op(qty)
            else:
                return qty
        else:
            return qty

    @staticmethod
    def nodeqty_corrupt_hook(node, mini, maxi):
        if node.env and node in node.env.nodes_to_corrupt:
            corrupt_type, corrupt_op = node.env.nodes_to_corrupt[node]
            if corrupt_type == Node.CORRUPT_NODE_QTY or corrupt_type is None:
                return *corrupt_op(mini, maxi), True
            else:
                return mini, maxi, False
        else:
            return mini, maxi, False

    @staticmethod
    def sizesync_corrupt_hook(node, length):
        if node in node.env.nodes_to_corrupt:
            corrupt_type, corrupt_op = node.env.nodes_to_corrupt[node]
            if corrupt_type == Node.CORRUPT_SIZE_SYNC or corrupt_type is None:
                return corrupt_op(length)
            else:
                return length
        else:
            return length

    def absorb(self, blob, constraints, conf, pending_postpone_desc=None):
        """
        TOFIX: Checking existence condition independently of data
               description order is not supported. Only supported
               within the same non-terminal node. Use delayed job
               infrastructure to cover all cases (TBC).
        """

        if self.encoder:
            original_blob_size = len(blob)
            if isinstance(self.encoder, enc.EncoderAbsorptionHelper):
                try:
                    determined_encoded_size = (
                        self.encoder.how_much_can_be_consumed_from(blob)
                    )
                except enc.EncoderUnrecognizedValueError as e:
                    if dbg.ABS_DEBUG:
                        print(
                            f"\n*** Exception {type(e)} raised while calling {type(self.encoder)} absorption helper"
                        )
                    return AbsorbStatus.Reject, 0, 0, pending_postpone_desc
                except (enc.EncoderSizeNotFoundError, NotImplementedError) as e:
                    if dbg.ABS_DEBUG:
                        print(
                            f"\n*** Size of the encoding part cannot be determined:"
                            f"\n    |_ {type(e)} has been raised"
                        )
                    determined_encoded_size = None
            else:
                determined_encoded_size = None

            if determined_encoded_size is not None:
                original_encoded_blob = blob[:determined_encoded_size]
                try:
                    blob = self.encoder.decode(original_encoded_blob)
                except enc.EncoderUnrecognizedValueError as e:
                    if dbg.ABS_DEBUG:
                        print(
                            f"\n*** Exception {type(e)} raised while decoding with {type(self.encoder)} "
                            f'{determined_encoded_size} byte(s) of the input "{blob[:4]}..."'
                        )
                    return AbsorbStatus.Reject, 0, 0, pending_postpone_desc
                else:
                    size_of_decoded_object = len(blob)
            else:
                original_encoded_blob = blob
                try:
                    blob = self.encoder.decode(blob)
                except enc.EncoderUnrecognizedValueError as e:
                    if dbg.ABS_DEBUG:
                        print(
                            f"\n*** Exception {type(e)} raised while decoding with {type(self.encoder)} "
                            f'the whole input "{blob[:4]}..."'
                        )
                    return AbsorbStatus.Reject, 0, 0, pending_postpone_desc
                else:
                    size_of_decoded_object = len(blob)

            original_decoded_blob = blob

        abs_excluded_components = []
        abs_exhausted = False
        status = AbsorbStatus.Reject

        if self.absorb_constraints is not None:
            constraints = self.absorb_constraints

        def _try_separator_absorption_with(blob, consumed_size):
            DEBUG = dbg.ABS_DEBUG

            new_sep = self._clone_separator(self.separator.node, unique=True)
            abort = False

            orig_blob = blob
            orig_consumed_size = consumed_size

            # We try to absorb the separator
            st, off, sz, name = new_sep.absorb(blob, constraints, conf=conf)
            # if DEBUG:
            #     print(f'SEPARATOR absorb attempt, st:{st}, off:{off}, sz:{sz}, blob:{blob[:4]} ...')

            if st == AbsorbStatus.Reject:
                if DEBUG:
                    print("REJECTED: SEPARATOR, blob: %r ..." % blob[:4])
                abort = True
            elif st == AbsorbStatus.Absorbed or st == AbsorbStatus.FullyAbsorbed:
                if off != 0:
                    abort = True
                    new_sep.cancel_absorb()
                else:
                    if DEBUG:
                        print(
                            "ABSORBED: SEPARATOR, blob: %r ..., consumed: %d"
                            % (blob[:4], sz)
                        )
                    blob = blob[sz:]
                    consumed_size += sz
            else:
                raise ValueError

            if abort:
                blob = orig_blob
                consumed_size = orig_consumed_size

            return abort, blob, consumed_size, new_sep

        # Helper function
        def _try_absorption_with(
            base_node,
            min_node,
            max_node,
            blob,
            consumed_size,
            postponed_node_desc,
            force_clone=False,
            pending_upper_postpone=pending_postpone_desc,
        ):
            DEBUG = dbg.ABS_DEBUG

            consumed_nb = 0

            if constraints[AbsCsts.Structure]:
                qty = self._qty_from_node(base_node)
                if qty is not None:
                    max_node = min_node = qty

                size = self._size_from_node(base_node)
                if size is not None:
                    base_node.set_size_from_constraints(size=size)
                else:
                    enc_size = self._size_from_node(base_node, for_encoded_size=True)
                    if enc_size is not None:
                        base_node.set_size_from_constraints(encoded_size=enc_size)

                shall_exist = self._existence_from_node(base_node)
                if shall_exist is not None:
                    if not shall_exist:
                        max_node = min_node = 0

            if max_node == 0:
                return None, blob, consumed_size, consumed_nb, None

            orig_blob = blob
            orig_consumed_size = consumed_size
            nb_absorbed = 0
            abort = False
            tmp_list = []

            first_pass = True
            if postponed_node_desc is not None or pending_upper_postpone is not None:
                postponed = (
                    postponed_node_desc
                    if postponed_node_desc is not None
                    else pending_upper_postpone
                )
            else:
                postponed = None

            pending_postponed_to_send_back = None
            prepend_postponed = None
            postponed_appended = None

            base_node_len = None

            reject_with_min_null = False

            node_no = 1
            while node_no <= max_node or max_node < 0:  # max_node < 0 means infinity
                node = self._clone_node(base_node, node_no - 1, force_clone)

                # We try to absorb the blob
                st, off, sz, name = node.absorb(
                    blob, constraints, conf=conf, pending_postpone_desc=postponed
                )
                postponed_sent_back = node.abs_postpone_sent_back
                node.abs_postpone_sent_back = None

                if st == AbsorbStatus.Reject:
                    nb_absorbed = node_no - 1
                    if DEBUG:
                        print(
                            "\nREJECT: %s, size: %d, blob: %r ..."
                            % (node.name, len(blob), blob[:4])
                        )
                    if min_node == 0:
                        # if DEBUG:
                        #     print(' --> min node == 0 (No abort)')
                        reject_with_min_null = True
                        # abort = False
                        break
                    if node_no <= min_node:
                        abort = True
                        break
                    else:
                        break
                elif st == AbsorbStatus.Absorbed or st == AbsorbStatus.FullyAbsorbed:
                    if DEBUG:
                        print(
                            "\nABSORBED: %s, abort: %r, off: %d, consumed_sz: %d, blob: %r..."
                            % (node.name, abort, off, sz, blob[off : off + sz][:100])
                        )
                        print(
                            f'\nPostpone Node: {postponed.name if postponed else "N/A"} ({postponed!r})'
                        )

                    nb_absorbed = node_no
                    sz2 = 0

                    if postponed_sent_back is not None:
                        if postponed_node_desc is not None:
                            prepend_postponed = postponed_sent_back
                            postponed = None
                        else:
                            pending_postponed_to_send_back = postponed_sent_back
                            postponed = None

                    elif postponed is not None:
                        # we first set metadata related to the successful absorption as the absorbed
                        # node could be leveraged while trying to absorb the postponed node
                        # (e.g., node existence verification).

                        base_node_len = len(base_node._tobytes())
                        # this call is necessary for base_node existence check to work
                        self._set_drawn_node_attrs(
                            base_node, nb=nb_absorbed, sz=base_node_len
                        )

                        # we only support one postponed node between two nodes
                        st2, off2, sz2, name2 = postponed.absorb(
                            blob[:off],
                            constraints,
                            conf=conf,
                            pending_postpone_desc=None,
                        )

                        if st2 == AbsorbStatus.Reject:
                            postponed = None
                            abort = True
                            break
                        elif (
                            st2 == AbsorbStatus.Absorbed
                            or st2 == AbsorbStatus.FullyAbsorbed
                        ):
                            if DEBUG:
                                print('\nABSORBED (of postponed): %s, off: %d, consumed_sz: %d, blob: %r ...' \
                                    % (postponed.name, off2, sz2, blob[off2:sz2][:150]))

                            if (
                                pending_upper_postpone is not None
                            ):  # meaning postponed_node_desc is None
                                pending_postponed_to_send_back = postponed
                            else:
                                postponed_appended = postponed
                                tmp_list.append(postponed_appended)
                            postponed = None
                        else:
                            raise ValueError
                    else:
                        if off != 0 and (
                            not first_pass or pending_upper_postpone is None
                        ):
                            # In this case, no postponed node exist
                            # but the node finds something that match
                            # its expectation at off>0.
                            # We need to reject this absorption as
                            # accepting it could prevent finding a
                            # good non-terminal shape.

                            nb_absorbed = node_no - 1
                            if node_no == 1 and min_node == 0:  # this case is OK
                                # abort = False
                                reject_with_min_null = True
                                break
                            elif node_no <= min_node:  # reject in this case
                                if DEBUG:
                                    print("\n--> Ignore previous absorption!")
                                abort = True
                                node.cancel_absorb()
                                break
                            else:  # no need to check max_node, the loop stop at it
                                # abort = False
                                break

                    if sz2 == off:
                        blob = blob[off + sz :]
                        consumed_size += sz + sz2  # off+sz
                        consumed_nb = nb_absorbed
                        tmp_list.append(node)

                        if self.separator is not None:
                            (
                                abort,
                                blob,
                                consumed_size,
                                new_sep,
                            ) = _try_separator_absorption_with(blob, consumed_size)
                            if abort:
                                if nb_absorbed >= min_node:
                                    abort = False
                                break
                            else:
                                tmp_list.append(new_sep)
                    else:
                        abort = True

                else:
                    raise ValueError

                node_no += 1

                if first_pass:
                    # considering a postpone node desc from a parent node only in the first loop
                    first_pass = False

            if reject_with_min_null and self.separator is not None and self.separator.always:
                if DEBUG:
                    print(f'\n Try absorb separator\n  - {blob}\n  - {consumed_size}')

                abort, blob, consumed_size, new_sep = _try_separator_absorption_with(blob, consumed_size)
                if DEBUG:
                    print(f'\n Try absorb separator, success={not abort}, cons_sz={consumed_size}, blob={blob}')
                if not abort:
                    tmp_list.append(new_sep)
                abort = False

            if abort:
                blob = orig_blob
                consumed_size = orig_consumed_size
                for n in tmp_list:
                    # Resetting all Generator nodes
                    ic = NodeInternalsCriteria(node_kinds=[NodeInternals_GenFunc])
                    nlist = n.get_reachable_nodes(internals_criteria=ic)
                    for nd in nlist:
                        nd.reset_state(conf=conf)
                for n in tmp_list:
                    n.cancel_absorb()
                if pending_postponed_to_send_back is not None:
                    pending_postponed_to_send_back.cancel_absorb()
                    pending_postponed_to_send_back = None
                self._clear_drawn_node_attrs(base_node)
            else:
                if base_node_len is None:
                    base_node_len = len(base_node._tobytes())
                self._set_drawn_node_attrs(base_node, nb=nb_absorbed, sz=base_node_len)
                idx = 0
                for n in tmp_list:
                    if postponed_appended is not None and n is postponed_appended:
                        continue
                    n._set_clone_info((idx, nb_absorbed), base_node)
                    idx += 1
                if prepend_postponed is not None:
                    self.frozen_node_list.append(prepend_postponed)
                    pending_postponed_to_send_back = None
                self.frozen_node_list += tmp_list

            return (
                abort,
                blob,
                consumed_size,
                consumed_nb,
                pending_postponed_to_send_back,
            )

        postponed_to_send_back = None

        while not abs_exhausted and status == AbsorbStatus.Reject:
            abort = False
            consumed_size = 0
            tmp_list = []

            node_list, idx = NodeInternals_NonTerm._get_next_heavier_component(
                self.subnodes_order, excluded_idx=abs_excluded_components
            )

            abs_excluded_components.append(idx)
            # 'len(self.subnodes_order)' is always even
            if len(abs_excluded_components) == len(self.subnodes_order) // 2:
                # in this case we have exhausted all components
                abs_exhausted = True
            else:
                abs_exhausted = False

            self.frozen_node_list = []

            if self.separator is not None and self.separator.prefix:
                abort, blob, consumed_size, new_sep = _try_separator_absorption_with(
                    blob, consumed_size
                )
                if abort:
                    break
                else:
                    self.frozen_node_list.append(new_sep)

            postponed_node_desc = None
            first_pass = True

            if self.custo.collapse_padding_mode:
                if hasattr(self, "_private_collapse_mode"):  # TODO: remove ugliness
                    consumed_bits, byte_aligned = self._private_collapse_mode
                else:
                    consumed_bits = 0
                    byte_aligned = None

            # Iterate over all sub-components of the component node_list
            for delim, sublist in self.__iter_csts(node_list):
                blob_update_pending = False  # reserved for collapse_padding_mode usage

                if delim[1] == ">":
                    for idx, node_desc in enumerate(sublist):
                        abort = False
                        base_node, min_node, max_node = self._parse_node_desc(node_desc)

                        vt = (
                            base_node.get_value_type()
                            if base_node.is_typed_value()
                            else None
                        )
                        if self.custo.collapse_padding_mode and isinstance(
                            vt, fvt.BitField
                        ):
                            if (
                                min_node != 1
                                or max_node != 1
                                or self.separator is not None
                                or postponed_node_desc
                            ):
                                raise DataModelDefinitionError(
                                    "Pattern not supported for absorption"
                                )

                            if not vt.lsb_padding or vt.endian != fvt.VT.BigEndian:
                                raise DataModelDefinitionError(
                                    "Bitfield option not supported for "
                                    "absorption with CollapsePadding custo"
                                )

                            bytelen = vt.byte_length
                            if vt.padding_size != 0 or consumed_bits != 0:
                                last_idx = consumed_size + (bytelen - 1)

                                if consumed_bits != 0:
                                    byte_aligned = consumed_bits + vt.padding_size == 8

                                    bits_to_be_consumed = consumed_bits + vt.bit_length
                                    last_idx = consumed_size + int(
                                        math.ceil(bits_to_be_consumed / 8.0)
                                    )

                                    partial_blob = blob[consumed_size:last_idx]
                                    if partial_blob != b"":
                                        nb_bytes = len(partial_blob)
                                        values = list(
                                            struct.unpack("B" * nb_bytes, partial_blob)
                                        )
                                        result = 0
                                        for i, v in enumerate(
                                            values[::-1]
                                        ):  # big endian
                                            if i == len(values) - 1:
                                                v = (
                                                    v
                                                    & fvt.BitField.padding_one[
                                                        8 - consumed_bits
                                                    ]
                                                )
                                            result += v << (i * 8)

                                        bits_to_consume = consumed_bits + vt.bit_length
                                        mask_size = (
                                            int(math.ceil(bits_to_consume / 8.0)) * 8
                                            - bits_to_consume
                                        )

                                        if not byte_aligned:
                                            if vt.padding == 0:
                                                result = (
                                                    result >> mask_size << mask_size
                                                )
                                            else:
                                                result |= fvt.BitField.padding_one[
                                                    mask_size
                                                ]

                                        result <<= consumed_bits
                                        if vt.padding == 1:
                                            result |= fvt.BitField.padding_one[
                                                consumed_bits
                                            ]

                                        l = []
                                        for i in range(
                                            nb_bytes - 1, -1, -1
                                        ):  # big-endian
                                            bval = result // (1 << i * 8)
                                            result = result % (1 << i * 8)  # remainder
                                            l.append(bval)
                                        partial_blob = struct.pack(
                                            "{:d}s".format(nb_bytes), bytes(l)
                                        )
                                else:
                                    partial_blob = blob[consumed_size:last_idx]
                                    last_byte = blob[last_idx : last_idx + 1]
                                    if last_byte != b"":
                                        val = struct.unpack("B", last_byte)[0]
                                        if vt.padding == 0:
                                            val = (
                                                val
                                                >> vt.padding_size
                                                << vt.padding_size
                                            )
                                        else:
                                            val |= fvt.BitField.padding_one[
                                                vt.padding_size
                                            ]
                                        partial_blob += struct.pack("B", val)
                                        byte_aligned = False
                                    else:
                                        byte_aligned = True
                            else:
                                partial_blob = blob[
                                    consumed_size : consumed_size + bytelen
                                ]
                                byte_aligned = True

                            (
                                abort,
                                remaining_blob,
                                consumed_size,
                                consumed_nb,
                                postponed_sent_back,
                            ) = _try_absorption_with(
                                base_node,
                                1,
                                1,
                                partial_blob,
                                consumed_size,
                                None,
                                pending_upper_postpone=pending_postpone_desc,
                            )

                            if partial_blob == b"" and abort is not None:
                                abort = True
                                break

                            elif abort is not None and not abort:
                                consumed_bits = consumed_bits + vt.bit_length
                                consumed_bits = (
                                    0 if consumed_bits == 8 else consumed_bits % 8
                                )

                                # if vt is byte-aligned, then the consumed_size is correct
                                # otherwise we decrease it
                                if vt.padding_size != 0 and consumed_bits > 0:
                                    consumed_size -= 1

                                blob_update_pending = True
                                # if we reach the end we should update the blob
                                if idx == len(sublist) - 1:
                                    blob_update_pending = False
                                    blob = blob[consumed_size:]

                        elif base_node.is_attr_set(NodeInternals.Abs_Postpone) or (
                            idx < len(sublist) - 1
                            and base_node.is_nonterm()
                            and base_node.encoder is not None
                            and not isinstance(
                                base_node.encoder, enc.EncoderAbsorptionHelper
                            )
                        ):
                            if postponed_node_desc or pending_postpone_desc:
                                raise ValueError(
                                    "\n*** ERROR: Only one node at a time can have its "
                                    "absorption delayed [current:{!s}]".format(
                                        postponed_node_desc
                                    )
                                )
                            postponed_node_desc = node_desc
                            continue

                        else:
                            if self.custo.collapse_padding_mode:
                                bnode_to_be_cleaned = False
                                aligned = consumed_bits % 8 == 0
                                if blob_update_pending and aligned:
                                    # When some Bitfield were collapsed in the NT sublist
                                    # but in this sublist other nodes are not Bitfield.
                                    # Thus, we need to update the blob and reinit
                                    # the "collapse_mode state" for a potential future collapse
                                    blob_update_pending = False
                                    blob = blob[consumed_size:]
                                    consumed_bits = 0
                                    byte_aligned = None
                                elif not aligned:
                                    bnode_to_be_cleaned = True
                                    conf = base_node._check_conf(conf)
                                    base_node.c[conf]._private_collapse_mode = (
                                        consumed_bits,
                                        byte_aligned,
                                    )

                            # pending_upper_postpone = pending_postpone_desc
                            (
                                abort,
                                blob,
                                consumed_size,
                                consumed_nb,
                                postponed_sent_back,
                            ) = _try_absorption_with(
                                base_node,
                                min_node,
                                max_node,
                                blob,
                                consumed_size,
                                postponed_node_desc,
                                pending_upper_postpone=pending_postpone_desc,
                            )
                            if self.custo.collapse_padding_mode and bnode_to_be_cleaned:
                                bnode_to_be_cleaned = False
                                del base_node.c[conf]._private_collapse_mode

                        # In this case max_node is 0
                        if abort is None:
                            continue

                        # if _try_absorption_with() return a
                        # tuple, then the postponed node is
                        # handled (either because absorption
                        # succeeded or because it didn't work and
                        # we need to abort and try another high
                        # level component)
                        if postponed_sent_back is not None:
                            postponed_to_send_back = postponed_sent_back
                        postponed_node_desc = None
                        pending_postpone_desc = None

                        if abort:
                            break

                elif delim[1] == "=":
                    # '=..' means: no particular orders between each kind of nodes
                    # '=.' means: no particular orders between all the nodes (fully random)

                    if delim[2] == ".":
                        node_desc_list = copy.copy(sublist)
                        list_sz = len(node_desc_list)
                        cpt = list_sz

                        # No particular orders between each kind of nodes
                        if delim[2:] == "..":
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
                                base_node, min_node, max_node = self._parse_node_desc(
                                    node_desc
                                )

                                # postponed_node_desc is not supported here as it does not make sense
                                (
                                    abort,
                                    blob,
                                    consumed_size,
                                    consumed_nb,
                                    _,
                                ) = _try_absorption_with(
                                    base_node,
                                    min_node,
                                    max_node,
                                    blob,
                                    consumed_size,
                                    postponed_node_desc=postponed_node_desc,
                                )
                                # if abort is None:
                                #     continue

                                if abort or abort is None:
                                    # We give a new chance to this node because it is maybe not at the right place
                                    # Note: existence condition can be False if not checked in right order
                                    node_desc_list.append(node_desc)

                        # No particular orders between all the nodes (fully random)
                        else:  # case delim[2:] == '.'
                            l = []
                            qty_list = []
                            for node_desc in node_desc_list:
                                base_node, min_node, max_node = self._parse_node_desc(
                                    node_desc
                                )
                                l.append(
                                    [base_node, min_node, False]
                                )  # (bn, min, force_clone)
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
                                        if (
                                            node_tuple[1] > 0
                                        ):  # check for min constraint
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
                                        (
                                            tmp_abort,
                                            blob,
                                            consumed_size,
                                            consumed_nb,
                                            _,
                                        ) = _try_absorption_with(
                                            base_node,
                                            fake_min_node,
                                            max_node,
                                            blob,
                                            consumed_size,
                                            postponed_node_desc=postponed_node_desc,
                                            force_clone=force_clone,
                                        )

                                    if not tmp_abort and consumed_nb > 0:
                                        # assert(qty_obj[0] - consumed_nb >= 0)

                                        # Note that qty_obj[0] can be < 0 if max_node is set
                                        # to -1 (for specifying infinity)
                                        qty_obj[0] = (
                                            qty_obj[0] - consumed_nb
                                        )  # update max_node

                                        # We now set force_clone to True as we already consumed the base_node
                                        # but _try_absorption_with() will not know that if we recall it with
                                        # the same base_node at a later time
                                        node_tuple[2] = True
                                        if node_tuple[1] > 0:
                                            node_tuple[1] = max(
                                                0, node_tuple[1] - consumed_nb
                                            )  # update min_node
                                        if qty_obj[0] == 0:
                                            next_l.remove(node_tuple)
                                            next_qty_list.remove(qty_obj)

                                if qty_list == prev_qty_list:
                                    stop_cpt += 1
                                else:
                                    stop_cpt = 0
                                    prev_qty_list = copy.deepcopy(
                                        qty_list
                                    )  # deepcopy is OK here

                    elif delim[2] == "+":
                        t_weight = sublist[0]
                        node_desc_list = list(sublist[1])
                        excl_comp = []
                        dont_stop = True

                        while dont_stop:
                            if t_weight > -1:
                                (
                                    node_desc,
                                    idx,
                                ) = NodeInternals_NonTerm._get_next_heavier_component(
                                    comp_list=node_desc_list, excluded_idx=excl_comp
                                )
                                if node_desc is None:
                                    break
                                excl_comp.append(idx)
                            else:
                                try:
                                    node_desc = node_desc_list.pop(0)
                                except IndexError:
                                    break

                            base_node, min_node, max_node = self._parse_node_desc(
                                node_desc
                            )

                            if base_node.is_attr_set(NodeInternals.Abs_Postpone) or (
                                idx < len(sublist) - 1
                                and base_node.is_nonterm()
                                and base_node.encoder is not None
                                and not isinstance(
                                    base_node.encoder, enc.EncoderAbsorptionHelper
                                )
                            ):
                                if postponed_node_desc or pending_postpone_desc:
                                    raise ValueError(
                                        "\nERROR: Only one node at a time (current:%s) delaying"
                                        " its dissection is supported!"
                                        % postponed_node_desc
                                    )
                                postponed_node_desc = node_desc
                                continue

                            else:
                                # pending_upper_postpone = pending_postpone_desc
                                (
                                    abort,
                                    blob,
                                    consumed_size,
                                    consumed_nb,
                                    postponed_sent_back,
                                ) = _try_absorption_with(
                                    base_node,
                                    min_node,
                                    max_node,
                                    blob,
                                    consumed_size,
                                    postponed_node_desc,
                                    pending_upper_postpone=pending_postpone_desc,
                                )

                                if abort is None or abort:
                                    continue
                                else:
                                    dont_stop = False
                                    # postponed_node_desc = None
                                    if postponed_sent_back is not None:
                                        postponed_to_send_back = postponed_sent_back
                                    postponed_node_desc = None
                                    pending_postpone_desc = None
                                    # pending_upper_postpone = None

                    else:
                        raise ValueError
                else:
                    raise ValueError

                if abort:
                    break

            if (
                self.separator is not None
                and self.frozen_node_list
                and self.frozen_node_list[-1].is_attr_set(NodeInternals.AutoSeparator)
            ):
                if not self.separator.suffix and not self.separator.always:
                    # TODO: check self.separator.always is maybe not always enough
                    sep = self.frozen_node_list.pop(-1)
                    data = sep._tobytes()
                    consumed_size = consumed_size - len(data)
                    blob = blob + data

            if not abort:
                status = AbsorbStatus.Absorbed

        # clean up
        if status != AbsorbStatus.Absorbed:
            self.cancel_absorb()
        else:
            if self.encoder:
                if determined_encoded_size is not None:
                    assert size_of_decoded_object == consumed_size
                    consumed_size = determined_encoded_size
                else:
                    orig_dec_blob_sz = len(original_decoded_blob)
                    orig_enc_blob_sz = len(original_encoded_blob)

                    if orig_dec_blob_sz != orig_enc_blob_sz:
                        if orig_dec_blob_sz == consumed_size:
                            consumed_size = orig_enc_blob_sz
                        else:
                            if dbg.ABS_DEBUG:
                                print(
                                    f"\nAbsorption of encoded part was not possible with {self.encoder}"
                                )
                    else:
                        if orig_dec_blob_sz == consumed_size:
                            pass
                        else:
                            print(
                                "\n*** Warning: the decoding by  did not is able to ignore the tail "
                                "of the blob which is not to be consumed by it ***"
                            )

        self._clone_node_cleanup()
        self._clone_separator_cleanup()

        return status, 0, consumed_size, postponed_to_send_back

    def cancel_absorb(self):
        for n in self.subnodes_set:
            n.cancel_absorb()
        if self.separator is not None:
            self.separator.node.cancel_absorb()
        self.frozen_node_list = None

    def confirm_absorb(self):
        iterable = copy.copy(self.subnodes_set)
        if self.separator is not None:
            iterable.add(self.separator.node)
        if self.frozen_node_list is not None:
            iterable.update(self.frozen_node_list)

        for n in iterable:
            n.confirm_absorb()

    def is_exhausted(self):
        if not self.is_attr_set(NodeInternals.Mutable):
            return True
        elif self.custo.stick_to_default_mode:
            return self.exhausted_shapes
        elif self.is_attr_set(NodeInternals.Finite):
            return self.exhausted_shapes and self.combinatory_complete
        else:
            return False

    def is_frozen(self):
        return self.frozen_node_list is not None

    def has_no_children(self):
        assert self.is_frozen()  # attr.current_qty would change the state of attr if not node not frozen
        # TODO: current_qty call next_qty() if not defined.
        #   But current qty should be stateless to avoid some side effects
        for nd, attr in self.subnodes_attrs.items():
            if attr.current_qty != 0:
                return False
        return True

    def _make_specific(self, name):
        if name == NodeInternals.Highlight:
            for node in self.subnodes_set:
                node.set_attr(name, recursive=True)
            if self.frozen_node_list:
                for node in self.frozen_node_list:
                    node.set_attr(name, recursive=True)

        return True

    def _unmake_specific(self, name):
        if name == NodeInternals.Determinist:
            self.current_flattened_nodelist = None

        elif name == NodeInternals.Highlight:
            for node in self.subnodes_set:
                node.clear_attr(name, recursive=True)
            if self.frozen_node_list:
                for node in self.frozen_node_list:
                    node.clear_attr(name, recursive=True)

        return True

    def _cleanup_entangled_nodes(self):
        for n in self.subnodes_set:
            # As self.separator.content entanglement is not done (even if
            # self.separator.unique is set to True), no cleanup is
            # required.
            if n.entangled_nodes is not None:
                l = []
                for e in n.entangled_nodes:
                    if e in self.frozen_node_list:
                        l.append(e)
                n.entangled_nodes.symmetric_difference_update(l)
                if len(n.entangled_nodes) <= 1:
                    n.entangled_nodes = None

    def _cleanup_entangled_nodes_from(self, node):
        if node.entangled_nodes is not None:
            l = []
            for n in node.entangled_nodes:
                if n in self.frozen_node_list:
                    l.append(n)
            node.entangled_nodes.symmetric_difference_update(l)
            if len(node.entangled_nodes) <= 1:
                node.entangled_nodes = None

    def unfreeze(
        self,
        conf=None,
        recursive=True,
        dont_change_state=False,
        ignore_entanglement=False,
        only_generators=False,
        reevaluate_constraints=False,
    ):
        mutable = self.is_attr_set(NodeInternals.Mutable)
        # mutable = True
        if recursive:
            if reevaluate_constraints and mutable:
                # In order to re-evaluate existence condition of
                # child node we have to recompute the previous state,
                # which is the purpose of the following code. We also
                # re-evaluate generator and function.
                iterable = self.frozen_node_list
                determinist = self.is_attr_set(NodeInternals.Determinist)
                finite = self.is_attr_set(NodeInternals.Finite)

                self._reevaluation_pending = True

                if finite or determinist:
                    if self.current_flattened_nodelist is None:
                        # This case happens when we have been cloned with 'ignore_frozen_state'
                        # and not frozen since then, or cloned from a node that has never been frozen.
                        # Thus nothing to do, the parameters are correctly initialized.
                        pass
                    else:
                        self.combinatory_complete = False
                        self.cursor_maj = self.previous_cursor_maj
                        self.cursor_min = self.previous_cursor_min
                        nd = self.current_flattened_nodelist[self.previous_cursor_min]
                        self.subnodes_attrs[nd].unroll()
                        for nd in self.current_flattened_nodelist:
                            self.subnodes_attrs[nd].unplan_reset()

                else:
                    # In this case the states are random, thus we
                    # don't bother trying to recover the previous one
                    pass

                if iterable is not None:
                    for n in iterable:
                        self._cleanup_entangled_nodes_from(n)
                        if n.is_nonterm(conf) or n.is_genfunc(conf) or n.is_func(conf):
                            n.unfreeze(
                                conf=conf,
                                recursive=True,
                                dont_change_state=dont_change_state,
                                ignore_entanglement=ignore_entanglement,
                                only_generators=only_generators,
                                reevaluate_constraints=reevaluate_constraints,
                            )

                self.frozen_node_list = None
                for n in self.subnodes_set:
                    n.clear_clone_info_since(n)

            elif (dont_change_state or only_generators) and mutable:
                iterable = self.frozen_node_list
            else:
                iterable = copy.copy(self.subnodes_set)
                if self.separator is not None:
                    iterable.add(self.separator.node)

            if not reevaluate_constraints and iterable is not None:
                for n in iterable:
                    n.unfreeze(
                        conf=conf,
                        recursive=True,
                        dont_change_state=dont_change_state,
                        ignore_entanglement=ignore_entanglement,
                        only_generators=only_generators,
                        reevaluate_constraints=reevaluate_constraints,
                    )

        if (
            not dont_change_state
            and not only_generators
            and not reevaluate_constraints
            and mutable
        ):
            self._cleanup_entangled_nodes()
            self.frozen_node_list = None
            self._nodes_drawn_qty = {}
            for n in self.subnodes_set:
                self._clear_drawn_node_attrs(n)
                n.clear_clone_info_since(n)

        if self.exhausted_shapes and mutable:
            self.excluded_components = []

    def unfreeze_all(self, recursive=True, ignore_entanglement=False):
        if recursive:
            iterable = copy.copy(self.subnodes_set)
            if self.separator is not None:
                iterable.add(self.separator.node)

            for e in iterable:
                e.unfreeze_all(recursive=True, ignore_entanglement=ignore_entanglement)

        self._cleanup_entangled_nodes()

        self.frozen_node_list = None
        self._nodes_drawn_qty = {}
        for n in self.subnodes_set:
            self._clear_drawn_node_attrs(n)
            n.clear_clone_info_since(n)

        if self.exhausted_shapes:
            self.excluded_components = []

    def reset_state(
        self, recursive=False, exclude_self=False, conf=None, ignore_entanglement=False
    ):
        if recursive:
            iterable = copy.copy(self.subnodes_set)
            if self.separator is not None:
                iterable.add(self.separator.node)

            for e in iterable:
                e.reset_state(
                    recursive=True,
                    exclude_self=exclude_self,
                    conf=conf,
                    ignore_entanglement=ignore_entanglement,
                )

        if not exclude_self:
            self._cleanup_entangled_nodes()
            self._reset_state_info()

    def _reset_state_info(self, new_info=None, nodes_drawn_qty=None):
        self.frozen_node_list = None

        if new_info is None:
            self.exhausted_shapes = False
            self.excluded_components = []
            self.combinatory_complete = True
            self.exhausted_pick_cases = True
            self.component_seed = None
            self.current_pick_section = 0
            self.current_picked_node_idx = 0
            self.cursor_maj = 0
            self.cursor_min = 0
            self.previous_cursor_maj = 0
            self.previous_cursor_min = 0
            for nd in self.subnodes_attrs:
                self.subnodes_attrs[nd].reset()

        else:
            self.exhausted_shapes = new_info[0]
            self.excluded_components = new_info[1]
            self.combinatory_complete = new_info[2]
            self.component_seed = new_info[3]
            self.exhausted_pick_cases = new_info[4]

        if nodes_drawn_qty is None:
            self._nodes_drawn_qty = {}
        else:
            self._nodes_drawn_qty = nodes_drawn_qty

    def reset_fuzz_weight(self, recursive):
        iterable = copy.copy(self.subnodes_set)
        if self.separator is not None:
            iterable.add(self.separator.node)

        if self.frozen_node_list is not None:
            iterable.update(self.frozen_node_list)

        for e in iterable:
            e.reset_fuzz_weight(recursive=recursive)

    def set_child_env(self, env):
        self.env = env
        iterable = copy.copy(self.subnodes_set)
        if self.separator is not None:
            iterable.add(self.separator.node)

        if self.frozen_node_list is not None:
            iterable.update(self.frozen_node_list)

        for e in iterable:
            e.set_env(env)

    def set_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        if recursive:
            iterable = copy.copy(self.subnodes_set)
            if self.frozen_node_list is not None:
                iterable.update(self.frozen_node_list)
            if self.separator is not None:
                iterable.add(self.separator.node)

            for e in iterable:
                e.set_attr(name, conf=conf, all_conf=all_conf, recursive=recursive)

    def clear_child_attr(self, name, conf=None, all_conf=False, recursive=False):
        if recursive:
            iterable = copy.copy(self.subnodes_set)
            if self.frozen_node_list is not None:
                iterable.update(self.frozen_node_list)
            if self.separator is not None:
                iterable.add(self.separator.node)

            for e in iterable:
                e.clear_attr(name, conf=conf, all_conf=all_conf, recursive=recursive)

    def set_clone_info(self, info, node):
        iterable = self.subnodes_set
        if self.frozen_node_list:
            # union() performs a copy, so we don't touch subnodes_set
            iterable = iterable.union(self.frozen_node_list)
        if self.separator is not None:
            iterable.add(self.separator.node)

        for e in iterable:
            e._set_clone_info(info, node)

    def clear_clone_info_since(self, node):
        iterable = self.subnodes_set
        if self.frozen_node_list:
            # union() performs a copy, so we don't touch subnodes_set
            iterable = iterable.union(self.frozen_node_list)
        if self.separator is not None:
            iterable.add(self.separator.node)

        for n in iterable:
            n.clear_clone_info_since(node)

    def reset_depth_specific(self, depth):
        iterable = copy.copy(self.subnodes_set)
        if self.separator is not None:
            iterable.add(self.separator.node)
        if self.frozen_node_list is not None:
            iterable.update(self.frozen_node_list)
        for e in iterable:
            e._reset_depth(depth)

    def get_child_nodes_by_attr(
        self,
        internals_criteria,
        semantics_criteria,
        owned_conf,
        conf,
        path_regexp,
        exclude_self,
        respect_order,
        relative_depth,
        top_node,
        ignore_fstate,
        resolve_generator=False,
    ):
        if self.frozen_node_list is not None and not ignore_fstate:
            iterable = self.frozen_node_list
        else:
            iterable = self.subnodes_set
            # self.get_subnodes_with_csts()
            # iterable = self.frozen_node_list

        if respect_order:
            # if the node is not frozen, the order will not be
            # preserved as self.subnodes_set will be used as a base,
            # and it is a set()
            s = []
        else:
            s = set()

        for e in iterable:
            nlist = e.get_reachable_nodes(
                internals_criteria,
                semantics_criteria,
                owned_conf,
                conf,
                path_regexp=path_regexp,
                exclude_self=False,
                respect_order=respect_order,
                relative_depth=relative_depth,
                top_node=top_node,
                ignore_fstate=ignore_fstate,
                resolve_generator=resolve_generator,
            )

            if respect_order:
                for e in nlist:
                    if e not in s:
                        s.append(e)
            else:
                s = s.union(nlist)

        return s

    def set_child_current_conf(self, node, conf, reverse, ignore_entanglement):
        iterable = copy.copy(self.subnodes_set)
        if self.separator is not None:
            iterable.add(self.separator.node)
        for e in iterable:
            node._set_subtrees_current_conf(
                e, conf, reverse, ignore_entanglement=ignore_entanglement
            )

    def get_child_all_path(
        self, name, htable, conf, recursive, resolve_generator=False
    ):
        if self.frozen_node_list is not None:
            iterable = self.frozen_node_list
        else:
            iterable = copy.copy(self.subnodes_set)
            if self.separator is not None:
                iterable.add(self.separator.node)

        for idx, node in enumerate(iterable):
            node._get_all_paths_rec(
                name,
                htable,
                conf,
                recursive=recursive,
                first=False,
                resolve_generator=resolve_generator,
                clone_idx=idx,
            )

    def set_size_from_constraints(self, size, encoded_size):
        # not supported
        raise DataModelDefinitionError


########### Node() High Level Facilities ##############


class NodeAbstraction(object):
    """
    This class can be used in place of an node_arg for Func and GenFunc
    Nodes. It enables you to define in your data model higher level
    classes upon Nodes to facilitate Nodes manipulation within Func and
    GenFunc Nodes, with regards to your data model paradigm.
    """

    def get_concrete_nodes(self):
        """
        Shall return an Node or a list of Nodes
        """
        raise NotImplementedError

    def set_concrete_nodes(self, nodes_args):
        """
        Shall save an Node or a list of Nodes (depending on what returns
        get_concrete_nodes())
        """
        raise NotImplementedError

    def make_private(self):
        """
        This method is called during Node copy process. It aims to make
        all your metadata private (if needed).
        Note that you don't have to deal with your Nodes.
        """
        pass


class NodeSemantics(object):
    """
    To be used while defining a data model as a means to associate
    semantics to an Node.
    """

    def __init__(self, attrs=None):
        self.__attrs = attrs if isinstance(attrs, (list, tuple)) else [attrs]

    def __str__(self):
        return " ".join(self.__attrs)

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
        """
        This method is called within get_reachable_nodes() (when the
        'semantics' parameter is provided) to select Node that match
        the given semantics.
        """
        c1 = self._match_optionalbut1_criteria(
            semantics_criteria.get_optionalbut1_criteria()
        )
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

    def what_match_from(self, raw_criteria_list):
        matching = []
        for c in raw_criteria_list:
            if c in self.__attrs:
                matching.append(c)

        return matching

    def make_private(self):
        """
        This method is called during Node copy process. It aims to make
        all your metadata private (if needed).
        """
        self.__attrs = copy.copy(self.__attrs)


class NodeSemanticsCriteria(object):
    def __init__(
        self,
        optionalbut1_criteria=None,
        mandatory_criteria=None,
        exclusive_criteria=None,
        negative_criteria=None,
    ):
        self.set_optionalbut1_criteria(optionalbut1_criteria)
        self.set_mandatory_criteria(mandatory_criteria)
        self.set_exclusive_criteria(exclusive_criteria)
        self.set_negative_criteria(negative_criteria)

    def __bool__(self):
        return (
            bool(self.__optionalbut1)
            or bool(self.__mandatory)
            or bool(self.__exclusive)
            or bool(self.__negative)
        )

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

    def _handle_user_input(self, crit):
        return crit if crit is None or isinstance(crit, (list, tuple)) else [crit]

    def set_exclusive_criteria(self, criteria):
        self.__exclusive = self._handle_user_input(criteria)

    def set_mandatory_criteria(self, criteria):
        self.__mandatory = self._handle_user_input(criteria)

    def set_optionalbut1_criteria(self, criteria):
        self.__optionalbut1 = self._handle_user_input(criteria)

    def set_negative_criteria(self, criteria):
        self.__negative = self._handle_user_input(criteria)

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


def make_wrapped_node(
    name, vals=None, node=None, prefix=None, suffix=None, key_node_name="KEY_ELT"
):
    pre = Node("prefix", values=prefix) if prefix is not None else None
    suf = Node("suffix", values=suffix) if suffix is not None else None

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
    """A Node is the basic building-block used within a graph-based data model.

    Attributes:
      internals (:obj:`dict` of :obj:`str` --> :class:`NodeInternals`): Contains all the configuration of a
        node. A configuration is associated to the internals/contents
        of a node, which can live independently of the other
        configuration.
      current_conf (str): Identifier to a configuration. Every usable node use at least one main
        configuration, namely ``'MAIN'``.
      name (str): Identifier of a node. Defined at instantiation.
        Shall be unique from its parent perspective.
      env (Env): One environment object is added to all the nodes of a node
        graph when the latter is registered within a data model
        (cf. :func:`DataModel.register()`). It is used for sharing
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
      depth (int): Depth of the node within the graph from a specific given
        root. Will be computed lazily (only when requested).
      tmp_ref_count (int): (internal use) Temporarily used during the creation of multiple
        instance of a same node, especially in order to generate unique names.
      _post_freeze_handler (function): Is executed just after a node is frozen (which
        is the result of requesting its value when it is not
        freezed---e.g., at its creation).
    """

    DJOBS_PRIO_nterm_existence = 100
    DJOBS_PRIO_dynhelpers = 200
    DJOBS_PRIO_genfunc = 300

    DEFAULT_DISABLED_VALUE = b""  # b'<EMPTY::' + uuid.uuid4().bytes + b'::>'
    DEFAULT_DISABLED_NODEINT = NodeInternals_Empty()

    CORRUPT_EXIST_COND = 5
    CORRUPT_QTY_SYNC = 6
    CORRUPT_NODE_QTY = 7
    CORRUPT_SIZE_SYNC = 8

    def __init__(
        self,
        name,
        base_node=None,
        copy_dico=None,
        ignore_frozen_state=False,
        accept_external_entanglement=False,
        acceptance_set=None,
        subnodes=None,
        values=None,
        value_type=None,
        vt=None,
        new_env=False,
        description=None,
    ):
        """
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
          vt (VT): alias to `value_type`.
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
          new_env (bool): [If `base_node` provided] If True, the `base_node` attached :class:`Env()`
           will be copied. Otherwise, the same will be used. If `ignore_frozen_state` is True, a
           new :class:`Env()` will be used.
          description (str): textual description of the node
        """

        assert "/" not in name  # '/' is a reserved character

        self.internals = {}
        self.name = name
        self.description = description
        self.env = None

        self._paths_htable = None

        self.entangled_nodes = None

        self.semantics = None
        self.fuzz_weight = None

        self._post_freeze_handler = None

        self.depth = 0
        self.tmp_ref_count = 1

        self.abs_postpone_sent_back = (
            None  # used for absorption to transfer a resolved postpone
        )
        # node back to where it was defined

        if (
            base_node is not None
            and subnodes is None
            and values is None
            and value_type is None
        ):
            self._delayed_jobs_called = base_node._delayed_jobs_called

            if base_node.env is None:
                self.env = None
            else:
                if new_env:
                    self.env = (
                        Env() if ignore_frozen_state else copy.copy(base_node.env)
                    )
                    if ignore_frozen_state:
                        self.env.csp = copy.copy(base_node.env.csp)
                else:
                    self.env = base_node.env

            node_dico = self.set_contents(
                base_node,
                copy_dico=copy_dico,
                ignore_frozen_state=ignore_frozen_state,
                accept_external_entanglement=accept_external_entanglement,
                acceptance_set=acceptance_set,
                preserve_node=False,
            )

            if new_env and self.env is not None:
                self.env.update_node_refs(
                    node_dico, ignore_frozen_state=ignore_frozen_state
                )
            elif DEBUG:
                print(
                    "\n*** WARNING: the copied node '%s' don't have an Env() "
                    "associated with it!\n" % base_node.name
                )

            if self.env is not None and self.env.djobs_exists(
                Node.DJOBS_PRIO_dynhelpers
            ):
                self.env.execute_basic_djobs(Node.DJOBS_PRIO_dynhelpers)

        else:
            self._delayed_jobs_called = False

            self.add_conf("MAIN")
            self.set_current_conf("MAIN")

            self.reset_fuzz_weight()

            if subnodes is not None:
                self.set_subnodes_basic(subnodes)

            elif values is not None:
                self.set_values(values=values)

            elif value_type is not None:
                self.set_values(value_type=value_type)
            elif vt is not None:
                self.set_values(value_type=vt)

            else:
                self.make_empty()

    def get_clone(
        self,
        name=None,
        ignore_frozen_state=False,
        accept_external_entanglement=False,
        acceptance_set=None,
        new_env=True,
    ):
        """Create a new node. To be used within a graph-based data model.

        Args:
          name (str): name of the new Node instance. If ``None`` the current name will be used.
          ignore_frozen_state (bool): if set to False, the clone function will produce
            a Node with the same state as the duplicated Node. Otherwise,  only the state won't be kept.
          accept_external_entanglement (bool): refer to the corresponding Node parameter
          acceptance_set (set): refer to the corresponding Node parameter
          new_env (bool): If True, the current :class:`Env()` will be copied.
            Otherwise, the same will be used.

        Returns:
          Node: duplicated Node object
        """

        if name is None:
            name = self.name

        return Node(
            name,
            base_node=self,
            ignore_frozen_state=ignore_frozen_state,
            accept_external_entanglement=accept_external_entanglement,
            acceptance_set=acceptance_set,
            new_env=new_env,
        )

    def __copy__(self):
        # This copy is only used internally by NodeInternals_NonTerm.get_subnodes_with_csts()
        # It does not handle self.internals nor self.entangled_nodes which are copied
        # in a different way.

        new_node = type(self)(self.name)
        new_node.__dict__.update(self.__dict__)
        if self.semantics is not None:
            new_node.semantics = copy.copy(self.semantics)
            new_node.semantics.make_private()

        return new_node

    def set_contents(
        self,
        base_node,
        copy_dico=None,
        ignore_frozen_state=False,
        accept_external_entanglement=False,
        acceptance_set=None,
        preserve_node=True,
    ):
        """
        Set the contents of the node based on the one provided within
        `base_node`. This method performs a deep copy of `base_node`,
        but some parameters can change the behavior of the copy.

        .. note:: python deepcopy() is not used for performance reason
          (10 to 20 times slower) and as it does not work for all cases.

        Args:
          base_node (Node): (Optional) Used as a template to create the new node.
          ignore_frozen_state (bool): If True, the clone process of
            base_node will ignore its current state.
          preserve_node (bool): preserve the :class:`NodeInternals` attributes (making sense to preserve)
            of the possible overwritten NodeInternals.
          accept_external_entanglement (bool): If True, during the cloning
            process of base_node, every entangled nodes outside the current graph will be referenced
            within the new node without being copied. Otherwise, a *Warning* message will be raised.
          acceptance_set (set): If provided, will be used as a set of
            entangled nodes that could be referenced within the new node during the cloning process.
          copy_dico (dict): It is used internally during the cloning process,
            and should not be used for any functional purpose.

        Returns:
          dict: For each subnodes of `base_node` (keys), reference the corresponding subnodes within the new node.
        """

        self.description = base_node.description
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

            new_internals = copy.copy(base_node.internals[conf])
            if preserve_node:
                new_internals.make_private(
                    ignore_frozen_state=ignore_frozen_state,
                    accept_external_entanglement=accept_external_entanglement,
                    delayed_node_internals=delayed_node_internals,
                    forget_original_sync_objs=True,
                )
                new_internals.set_contents_from(self.internals[conf])
            else:
                new_internals.make_private(
                    ignore_frozen_state=ignore_frozen_state,
                    accept_external_entanglement=accept_external_entanglement,
                    delayed_node_internals=delayed_node_internals,
                    forget_original_sync_objs=False,
                )

            self.internals[conf] = new_internals
            self.internals[conf].env = self.env

            if base_node.is_nonterm(conf):
                self.internals[conf].import_subnodes_full_format(
                    internals=base_node.internals[conf]
                )
                self.internals[conf].make_private_subnodes(
                    node_dico,
                    func_nodes,
                    self.env,
                    ignore_frozen_state=ignore_frozen_state,
                    accept_external_entanglement=accept_external_entanglement,
                    entangled_set=entangled_set,
                    delayed_node_internals=delayed_node_internals,
                )
                self.internals[conf].make_private(
                    ignore_frozen_state=ignore_frozen_state,
                    accept_external_entanglement=accept_external_entanglement,
                    delayed_node_internals=delayed_node_internals,
                )
                self._finalize_nonterm_node(conf)

        # Once node_dico has been populated from the node tree,
        # we deal with 'nodes' argument of Func and GenFunc that does not belong to this
        # tree. And we complete the node_dico.
        for conf in base_node.internals:
            if base_node.is_func(conf) or base_node.is_genfunc(conf):
                self.internals[conf].make_args_private(
                    node_dico,
                    entangled_set,
                    ignore_frozen_state=ignore_frozen_state,
                    accept_external_entanglement=accept_external_entanglement,
                )

        # Now we deal with the 'nodes' argument of the Func and
        # GenFunc Nodes within the copied tree, that has been let
        # aside
        for e in func_nodes:
            for conf in e.confs:
                if e.is_func(conf) or e.is_genfunc(conf):
                    e.internals[conf].make_args_private(
                        node_dico,
                        entangled_set,
                        ignore_frozen_state=ignore_frozen_state,
                        accept_external_entanglement=accept_external_entanglement,
                    )

        # We deal with node refs within NodeInternals, once the node_dico is complete
        for n in delayed_node_internals:
            n._update_node_refs(node_dico, debug=n)

        if self.env is not None and self.env.csp is not None:
            for v in self.env.csp.iter_vars():
                old_nd = self.env.csp.var_mapping[v]
                new_node = node_dico.get(old_nd, None)
                if new_node is not None:
                    self.env.csp.map_var_to_node(v, new_node)
                    # print(f'\n*** DBG set_content for node "{old_nd.name}" (called from {self.name}): {v}'
                    #       f'\n   --> old node: {old_nd}'
                    #       f'\n   --> new node: {new_node}')
                else:
                    # It means we are called from a subnode which are not linked to the
                    # variables thus we can break, as it exists at least one node from which some
                    # paths exist to all the variables (and thus we will do the update from there).
                    break

        if base_node.entangled_nodes is not None and (
            (not ignore_frozen_state) or accept_external_entanglement
        ):
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
                    pass
                    # Note: If base_node has entangled nodes, chances are these entangled nodes are
                    # not part of the current node-graph. Especially, if base node is a child node
                    # of an NT-node with a `qty` attribute > 1, the siblings nodes are entangled
                    # nodes outside of the current graph. Thus they just have to be ignored.
                    # In other cases (not described here) where the entangled nodes outside of
                    # the current node-graph needs to be cloned, the user should explicitly state it
                    # through the usage of the parameter `accept_external_entanglement`
                    # or `acceptance_set`.
                    #
                    # print("\n*** WARNING: detection of entangled node outside the current graph, " \
                    #           "whereas 'accept_external_entanglement' parameter is set to False!")
                    # print("[ accept_external_entanglement = %r, ignore_frozen_state = %r, current copied node: %s ]" \
                    #           % (accept_external_entanglement, ignore_frozen_state, self.name))
                    # print(' --> Node: ', node.name, repr(node))
                    # print(' --> Entangled with external node: ', e.name, repr(e))
                    # print(" --> Entangled nodes of node '%s':" % node.name)
                    # for e in node.entangled_nodes:
                    #     print('  -', e.name, repr(e),
                    #           " [in node_dico.keys(): %r / .values(): %r]" % (e in node_dico, e in node_dico.values()))

            if node is base_node:
                self.entangled_nodes = intrics
            else:
                node.entangled_nodes = intrics

        self.current_conf = copy.copy(base_node.current_conf)

        self._reset_depth(parent_depth=self.depth - 1)

        return node_dico

    def set_fuzz_weight(self, w):
        """Set the fuzzing weight of the node to `w`.

        The fuzz weight is an optional attribute of Node() which
        express Data Model designer's hints for prioritizing the nodes
        to fuzz. If set, this attribute is used by some generic
        *disruptors* (the ones that rely on a ModelWalker object---refer to
        fuzzing_primitives.py)

        Args:
          w (int): Value of the weight (by default every nodes has a weight of 1)

        Returns:
          None
        """
        self.fuzz_weight = int(w)

    def get_fuzz_weight(self):
        """Return the fuzzing weight of the node.

        Returns:
          int: the fuzzing weight
        """
        return self.fuzz_weight

    def reset_fuzz_weight(self, recursive=False):
        """Reset to standard (1) the fuzzing weight that is associated to this
        node, and all its subnodes if `recursive` parameter is set to `True`.

        Args:
          recursive (bool): if set to `True`, reset also every subnodes (all reachable nodes from this one).

        Returns:
          None
        """
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
        if conf != "MAIN":
            del self.internals[conf]

    def is_conf_existing(self, conf):
        return conf in self.internals

    def __get_confs(self):
        return self.internals.keys()

    confs = property(fget=__get_confs)
    """Property giving all node's configurations (read only)"""

    def _set_subtrees_current_conf(
        self, node, conf, reverse, ignore_entanglement=False
    ):
        conf2 = conf if node.is_conf_existing(conf) else node.current_conf

        if not reverse:
            node.current_conf = conf2

        if node.internals[
            node.current_conf
        ]:  # When an Node is created empty, there is None internals
            node.internals[node.current_conf].set_child_current_conf(
                node, conf, reverse, ignore_entanglement=ignore_entanglement
            )

        if not ignore_entanglement and node.entangled_nodes is not None:
            for e in node.entangled_nodes:
                e.internals[e.current_conf].set_child_current_conf(
                    e, conf, reverse, ignore_entanglement=True
                )

        if reverse:
            node.current_conf = conf2

    def set_current_conf(
        self,
        conf,
        recursive=True,
        reverse=False,
        root_regexp=None,
        ignore_entanglement=False,
    ):
        if root_regexp is not None:
            node_list = self.get_reachable_nodes(path_regexp=root_regexp)
        else:
            node_list = [self]

        for e in node_list:
            if recursive:
                self._set_subtrees_current_conf(
                    e, conf, reverse, ignore_entanglement=ignore_entanglement
                )
            else:
                if e.is_conf_existing(conf):
                    e.current_conf = conf

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_current_conf(
                    conf,
                    recursive=recursive,
                    reverse=reverse,
                    root_regexp=root_regexp,
                    ignore_entanglement=True,
                )

    def get_current_conf(self):
        return self.current_conf

    def gather_alt_confs(self):
        cfs = set()

        for c in self.confs:
            if c != "MAIN":
                cfs.add(c)
        for c in self.confs:
            if self.is_nonterm(c):
                for e in self.c[c].subnodes_set:
                    cfs = cfs.union(e.gather_alt_confs())

        return cfs

    def entangle_with(self, node):
        assert node is not self

        if self.entangled_nodes is None:
            self.entangled_nodes = {self}

        if node.entangled_nodes is None:
            node.entangled_nodes = {node}

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
    """Property linked to the current node's `internals` (read / write)"""

    c = property(fget=__get_internals)
    """Property linked to `self.internals` (read only)"""

    def conf(self, conf=None):
        conf = self._check_conf(conf)
        return self.internals[conf]

    def get_internals_backup(self):
        return Node(
            self.name,
            base_node=self,
            ignore_frozen_state=False,
            accept_external_entanglement=True,
            new_env=False,
        )

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
        self._delayed_jobs_called = backup._delayed_jobs_called

    def _check_conf(self, conf):
        if conf is None:
            conf = self.current_conf
        elif not self.is_conf_existing(conf):
            raise ValueError
        return conf

    def is_genfunc(self, conf=None):
        conf = self._check_conf(conf)
        return isinstance(self.internals[conf], NodeInternals_GenFunc)

    def is_func(self, conf=None):
        conf = self._check_conf(conf)
        return isinstance(self.internals[conf], NodeInternals_Func)

    def is_typed_value(self, conf=None, subkind=None):
        conf = self._check_conf(conf)
        resp = isinstance(self.internals[conf], NodeInternals_TypedValue)
        if resp and subkind is not None:
            resp = (
                self.internals[conf].get_current_subkind() == subkind
            ) or issubclass(self.internals[conf].get_current_subkind(), subkind)
        return resp

    def is_nonterm(self, conf=None):
        conf = self._check_conf(conf)
        return isinstance(self.internals[conf], NodeInternals_NonTerm)

    def is_term(self, conf=None):
        conf = self._check_conf(conf)
        return issubclass(self.internals[conf].__class__, NodeInternals_Term)

    def compliant_with(
        self, internals_criteria=None, semantics_criteria=None, conf=None
    ):
        conf = self._check_conf(conf)

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
            print("\n*** /!\\ ERROR /!\\\n")
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
                print(
                    "\n*** You shall not use the same name for Nodes "
                    + "that share a common parent (%s in conf : '%s')."
                    % (self.name, conf)
                )
                print("*** Duplicated Node name: '%s'" % guilty)
                print("\n*** /!\\ END /!\\\n")
            else:
                print("*** Bug in Node implementation...")

            raise ValueError

        if self.internals[conf].separator is not None:
            sep_name = self.internals[conf].separator.node.name
            if sep_name in check_err:
                print(
                    "\n*** The separator node name shall not be used by a subnode "
                    + "of this non-terminal node: %s in conf : '%s'."
                    % (self.name, conf)
                )
                raise ValueError

    def set_subnodes_basic(
        self,
        node_list,
        conf=None,
        ignore_entanglement=False,
        separator=None,
        preserve_node=True,
    ):
        conf = self._check_conf(conf)

        new_internals = NodeInternals_NonTerm()
        if preserve_node:
            new_internals.set_contents_from(self.internals[conf])
        self.internals[conf] = new_internals
        self.internals[conf].import_subnodes_basic(
            node_list, separator=separator, preserve_node=preserve_node
        )
        self._finalize_nonterm_node(conf)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_subnodes_basic(
                    node_list=node_list,
                    conf=conf,
                    ignore_entanglement=True,
                    separator=separator,
                )

    def set_subnodes_with_csts(
        self,
        wlnode_list,
        conf=None,
        ignore_entanglement=False,
        separator=None,
        preserve_node=True,
    ):
        conf = self._check_conf(conf)

        new_internals = NodeInternals_NonTerm()
        if preserve_node:
            new_internals.set_contents_from(self.internals[conf])
        self.internals[conf] = new_internals
        self.internals[conf].import_subnodes_with_csts(
            wlnode_list, separator=separator, preserve_node=preserve_node
        )
        self._finalize_nonterm_node(conf)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_subnodes_basic(
                    wlnode_list=wlnode_list,
                    conf=conf,
                    ignore_entanglement=True,
                    separator=separator,
                )

    def set_subnodes_full_format(
        self,
        subnodes_order,
        subnodes_attrs,
        conf=None,
        separator=None,
        preserve_node=True,
    ):
        conf = self._check_conf(conf)

        new_internals = NodeInternals_NonTerm()
        if preserve_node:
            new_internals.set_contents_from(self.internals[conf])
        self.internals[conf] = new_internals
        self.internals[conf].import_subnodes_full_format(
            subnodes_order=subnodes_order,
            subnodes_attrs=subnodes_attrs,
            separator=separator,
        )
        self._finalize_nonterm_node(conf)

    def set_values(
        self,
        values=None,
        value_type=None,
        conf=None,
        ignore_entanglement=False,
        preserve_node=True,
    ):
        conf = self._check_conf(conf)

        new_internals = NodeInternals_TypedValue()
        if preserve_node:
            new_internals.set_contents_from(self.internals[conf])
        self.internals[conf] = new_internals

        if values is not None:
            self.internals[conf].import_value_type(value_type=fvt.String(values=values))

        elif value_type is not None:
            self.internals[conf].import_value_type(value_type)

        else:
            raise ValueError

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                if value_type is not None:
                    value_type = copy.copy(value_type)
                    value_type.make_private(forget_current_state=True)
                e.set_values(
                    values=copy.copy(values),
                    value_type=value_type,
                    conf=conf,
                    ignore_entanglement=True,
                )

    def set_func(
        self,
        func,
        func_node_arg=None,
        func_arg=None,
        conf=None,
        ignore_entanglement=False,
        provide_helpers=False,
        preserve_node=True,
    ):
        conf = self._check_conf(conf)

        new_internals = NodeInternals_Func()
        if preserve_node:
            new_internals.set_contents_from(self.internals[conf])
        self.internals[conf] = new_internals
        self.internals[conf].import_func(
            func,
            fct_node_arg=func_node_arg,
            fct_arg=func_arg,
            provide_helpers=provide_helpers,
        )

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_func(
                    func,
                    func_node_arg=func_node_arg,
                    func_arg=func_arg,
                    conf=conf,
                    ignore_entanglement=True,
                )

    def set_generator_func(
        self,
        gen_func,
        func_node_arg=None,
        func_arg=None,
        conf=None,
        ignore_entanglement=False,
        provide_helpers=False,
        preserve_node=True,
    ):
        conf = self._check_conf(conf)

        new_internals = NodeInternals_GenFunc()
        if preserve_node:
            new_internals.set_contents_from(self.internals[conf])
        self.internals[conf] = new_internals
        self.internals[conf].import_generator_func(
            gen_func,
            generator_node_arg=func_node_arg,
            generator_arg=func_arg,
            provide_helpers=provide_helpers,
        )

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.set_func(
                    gen_func,
                    func_node_arg=func_node_arg,
                    func_arg=func_arg,
                    conf=conf,
                    ignore_entanglement=True,
                )

    def make_empty(self, conf=None):
        conf = self._check_conf(conf)
        self.internals[conf] = NodeInternals_Empty()

    def is_empty(self, conf=None):
        conf = self._check_conf(conf)
        return isinstance(self.internals[conf], NodeInternals_Empty)

    def has_no_children(self, conf=None):
        conf = self._check_conf(conf)
        return self.internals[conf].has_no_children()

    def absorb(self, blob, constraints=AbsCsts(), conf=None, pending_postpone_desc=None):
        conf, next_conf = self._compute_confs(conf=conf, recursive=True)
        blob = convert_to_internal_repr(blob)
        status, off, sz, postpone_sent_back = self.internals[conf].absorb(
            blob,
            constraints=constraints,
            conf=next_conf,
            pending_postpone_desc=pending_postpone_desc,
        )
        if postpone_sent_back is not None:
            self.abs_postpone_sent_back = postpone_sent_back

        if len(blob) == sz and status == AbsorbStatus.Absorbed:
            status = AbsorbStatus.FullyAbsorbed
            self.internals[conf].confirm_absorb()

        return status, off, sz, self.name

    def set_absorb_helper(self, helper, conf=None):
        conf = self._check_conf(conf)
        self.internals[conf].set_absorb_helper(helper)

    def enforce_absorb_constraints(self, csts, conf=None):
        conf = self._check_conf(conf)
        self.internals[conf].enforce_absorb_constraints(csts)

    def set_size_from_constraints(self, size=None, encoded_size=None, conf=None):
        conf = self._check_conf(conf)
        self.internals[conf].set_size_from_constraints(
            size=size, encoded_size=encoded_size
        )

    # Does not affect function/generator Nodes
    def make_determinist(self, conf=None, all_conf=False, recursive=False):
        self.set_attr(
            NodeInternals.Determinist, conf, all_conf=all_conf, recursive=recursive
        )

    # Does not affect function/generator Nodes
    def make_random(self, conf=None, all_conf=False, recursive=False):
        self.clear_attr(
            NodeInternals.Determinist, conf, all_conf=all_conf, recursive=recursive
        )

    # Does not affect function/generator & nonterm Nodes
    def make_finite(self, conf=None, all_conf=False, recursive=False):
        self.set_attr(
            NodeInternals.Finite, conf, all_conf=all_conf, recursive=recursive
        )

    # Does not affect function/generator & nonterm Nodes
    def make_infinite(self, conf=None, all_conf=False, recursive=False):
        self.clear_attr(
            NodeInternals.Finite, conf, all_conf=all_conf, recursive=recursive
        )

    def _compute_confs(self, conf, recursive):
        next_conf = conf if recursive else None
        current_conf = conf if self.is_conf_existing(conf) else self.current_conf

        if self.is_genfunc(current_conf):
            next_conf = conf

        return current_conf, next_conf

    def _set_clone_info(self, info, node):
        """Used to propagate random draw results when a NonTerm node is frozen
        to the dynamic nodes of its attached subgraphs, namely
        GenFunc/Func nodes which are the only ones which can act
        dynamically.
        """
        for c in self.internals:
            self.internals[c].set_clone_info(info, node)

    def make_synchronized_with(
        self, scope, node=None, param=None, sync_obj=None, conf=None
    ):
        conf = self._check_conf(conf)
        self.internals[conf].set_node_sync(
            scope=scope, node=node, param=param, sync_obj=sync_obj
        )

    def synchronized_with(self, scope, conf=None):
        conf = self._check_conf(conf)
        val = self.internals[conf].get_node_sync(scope)
        return val

    def set_attr(self, name, conf=None, all_conf=False, recursive=False):
        if all_conf:
            for c in self.internals:
                self.internals[c].set_attr(name)
                self.internals[c].set_child_attr(
                    name, all_conf=True, recursive=recursive
                )

        else:
            conf, next_conf = self._compute_confs(conf, recursive)
            self.internals[conf].set_attr(name)
            self.internals[conf].set_child_attr(
                name, conf=next_conf, recursive=recursive
            )

    def clear_attr(self, name, conf=None, all_conf=False, recursive=False):
        if all_conf:
            for c in self.internals:
                self.internals[c].clear_attr(name)
                self.internals[c].clear_child_attr(
                    name, all_conf=True, recursive=recursive
                )
        else:
            conf, next_conf = self._compute_confs(conf, recursive)
            self.internals[conf].clear_attr(name)
            self.internals[conf].clear_child_attr(
                name, conf=next_conf, recursive=recursive
            )

    def is_attr_set(self, name, conf=None):
        conf = self._check_conf(conf)
        return self.internals[conf].is_attr_set(name)

    @property
    def debug(self):
        for nd_internal in self.internals.values():
            if nd_internal.is_attr_set(NodeInternals.DEBUG):
                return True
        return False

    def set_private(self, val, conf=None):
        conf = self._check_conf(conf)
        self.internals[conf].set_private(val)

    def get_private(self, conf=None):
        conf = self._check_conf(conf)
        return self.internals[conf].get_private()

    def set_semantics(self, sem):
        if isinstance(sem, NodeSemantics):
            self.semantics = sem
        else:
            assert isinstance(sem, (list, str))
            self.semantics = NodeSemantics(sem)

    def get_semantics(self):
        return self.semantics

    def get_reachable_nodes(
        self,
        internals_criteria=None,
        semantics_criteria=None,
        owned_conf=None,
        conf=None,
        path_regexp=None,
        exclude_self=False,
        respect_order=False,
        top_node=None,
        ignore_fstate=False,
        resolve_generator=False,
        relative_depth=-1,
    ):
        """

        Args:
            internals_criteria:
            semantics_criteria:
            owned_conf:
            conf:
            path_regexp:
            exclude_self:
            respect_order:
            top_node:
            ignore_fstate:
            resolve_generator: if `True`, the generator nodes will be resolved in order to perform
              the search within. But there will be side-effects on the graph, because
              some parts of the graph could end up frozen if they are used as generator parameters.
              If `False`, generator nodes won't be resolved, but they could already be in a
              resolved state before this method is called on them. It means that no side effects
              could result from the call of this method. And thus for this latter case,
              the method works as if `resolve_generator` is set to `True`.
            relative_depth: For internal use only

        Returns:

        """

        def __compliant(node, config, top_node, side_effect_risk):
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
                paths = node.get_all_paths_from(
                    top_node, flush_cache=False, resolve_generator=resolve_generator
                )
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

            if config == None:
                config = self.current_conf
                next_conf = None
            else:
                next_conf = config

            if not node.is_conf_existing(config):
                config = node.current_conf

            internal = node.internals[config]
            side_effect_risk = (
                isinstance(internal, NodeInternals_GenFunc) and not internal.is_frozen()
            )

            if (owned_conf == None) or node.is_conf_existing(owned_conf):
                if __compliant(
                    node, config, top_node, side_effect_risk=side_effect_risk
                ):
                    s.append(node)

            if not resolve_generator and side_effect_risk:
                return s

            if rdepth <= -1 or rdepth > 0:
                s2 = internal.get_child_nodes_by_attr(
                    internals_criteria=internals_criteria,
                    semantics_criteria=semantics_criteria,
                    owned_conf=owned_conf,
                    conf=next_conf,
                    path_regexp=path_regexp,
                    exclude_self=False,
                    respect_order=respect_order,
                    relative_depth=rdepth - 1,
                    top_node=top_node,
                    ignore_fstate=ignore_fstate,
                    resolve_generator=resolve_generator,
                )
                if s2:
                    for e in s2:
                        if e not in s:
                            s.append(e)

            return s

        top_node = self if top_node is None else top_node
        if relative_depth == -1:
            top_node._paths_htable = None

        nodes = get_reachable_nodes_rec(
            node=self, config=conf, rdepth=relative_depth, top_node=top_node
        )

        if relative_depth == -1:
            top_node._paths_htable = None

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

    @staticmethod
    def filter_out_entangled_nodes(node_list):
        ret = []
        while True:
            if node_list:
                n = node_list.pop()
                if n.entangled_nodes:
                    for en in n.entangled_nodes:
                        if en in node_list:
                            node_list.remove(en)
                ret.append(n)
            else:
                break
        # print('\n*** FILTERED nodes')
        # for n in ret:
        #     print(' |_ ' + n.name)
        return ret

    def iter_nodes_by_path(
        self, path_regexp, conf=None, flush_cache=True, resolve_generator=False
    ):
        """
        iterate over all the nodes that match the `path_regexp` parameter.

        Note: the set of nodes that is used to perform the search include
        the node itself and all the subnodes behind it.

        Args:
            path_regexp (str): path regexp of the requested nodes
            conf (str): Node configuration to use for the search
            flush_cache (bool): If False, and a previous search has been performed, the outcomes will
               be used for this one, which will improve the performance.

        Returns:
            generator of the nodes that match the path regexp

        """
        for p, node in self.iter_paths(
            conf=conf, flush_cache=flush_cache, resolve_generator=resolve_generator
        ):
            if re.search(path_regexp, p):
                yield node

    def get_first_node_by_path(
        self, path_regexp, conf=None, flush_cache=True, resolve_generator=False
    ):
        """
        Return the first Node that match the `path_regexp` parameter.

        Args:
            path_regexp (str): path regexp of the requested nodes
            conf (str): Node configuration to use for the search
            flush_cache (bool): If False, and a previous search has been performed, the outcomes will
               be used for this one, which will improve the performance.

        Returns:
            Node: the first Node that match the path regexp
        """
        try:
            node = next(
                self.iter_nodes_by_path(
                    path_regexp=path_regexp,
                    conf=conf,
                    flush_cache=flush_cache,
                    resolve_generator=resolve_generator,
                )
            )
        except StopIteration:
            node = None

        return node

    def get_nodes_by_paths(self, path_list):
        """
        Provide a dictionnary of the nodes referenced by the paths provided in @path_list.
        Keys of the dict are the paths provided in @path_list.

        Args:
            path_list: list of paths referencing nodes of interest

        Returns:
            dict: dictionary mapping path to nodes
        """
        node_dict = {}
        for p in path_list:
            node_dict[p] = self.get_first_node_by_path(path_regexp=p, flush_cache=False)

        return node_dict

    def _get_all_paths_rec(
        self,
        pname,
        htable,
        conf,
        recursive,
        first=True,
        resolve_generator=False,
        clone_idx=0,
    ):
        next_conf = conf if recursive else None

        if not self.is_conf_existing(conf):
            conf = self.current_conf
        internal = self.internals[conf]

        name = self.name if first else pname + "/" + self.name

        if name in htable:
            htable[(name, clone_idx)] = self
        else:
            htable[name] = self

        side_effect_risk = (
            isinstance(internal, NodeInternals_GenFunc) and not internal.is_frozen()
        )
        if resolve_generator or not side_effect_risk:
            internal.get_child_all_path(
                name,
                htable,
                conf=next_conf,
                recursive=recursive,
                resolve_generator=resolve_generator,
            )

    def get_all_paths(
        self,
        conf=None,
        recursive=True,
        depth_min=None,
        depth_max=None,
        resolve_generator=False,
        flush_cache=True,
    ):
        """
        Args:
            resolve_generator: if `True`, the generator nodes will be resolved in order to perform
              the search within. But there could be side-effects on the graph, because
              some parts of the graph could end up frozen if they are used as generator parameters.
              If `False`, generator nodes won't be resolved, but they could already be in a
              resolved state before this method is called on them. It means that no side effects
              could result from the call of this method. And thus for this latter case,
              the method works as if `resolve_generator` is set to `True`.

        Returns:
            dict: the keys are either a 'path' or a tuple ('path', int) when the path already
              exists (case of the same node used more than once within the same non-terminal)
        """

        if flush_cache or self._paths_htable is None:
            self._paths_htable = collections.OrderedDict()
            self._get_all_paths_rec(
                "",
                self._paths_htable,
                conf,
                recursive=recursive,
                resolve_generator=resolve_generator,
            )

        if depth_min is not None or depth_max is not None:
            depth_min = int(depth_min) if depth_min is not None else 0
            depth_max = int(depth_max) if depth_max is not None else -1
            paths = copy.copy(self._paths_htable)
            for k in self._paths_htable.keys():
                depth = len(k.split("/"))
                if depth < depth_min:
                    del paths[k]
                elif depth_max != -1 and depth > depth_max:
                    del paths[k]
        else:
            paths = self._paths_htable

        return paths

    def iter_paths(
        self,
        conf=None,
        recursive=True,
        depth_min=None,
        depth_max=None,
        only_paths=False,
        resolve_generator=False,
        flush_cache=True,
    ):
        htable = self.get_all_paths(
            conf=conf,
            recursive=recursive,
            depth_min=depth_min,
            depth_max=depth_max,
            resolve_generator=resolve_generator,
            flush_cache=flush_cache,
        )
        for path, node in htable.items():
            if isinstance(path, tuple):
                yield path[0] if only_paths else (path[0], node)
            else:
                yield path if only_paths else (path, node)

    def get_path_from(self, node, conf=None, flush_cache=True, resolve_generator=False):
        for path, nd in node.iter_paths(
            conf=conf, flush_cache=flush_cache, resolve_generator=resolve_generator
        ):
            if nd == self:
                return path
        else:
            return None

    def get_all_paths_from(
        self, node, conf=None, flush_cache=True, resolve_generator=False
    ):
        l = []
        for path, nd in node.iter_paths(
            conf=conf, flush_cache=flush_cache, resolve_generator=resolve_generator
        ):
            if nd == self:
                l.append(path)
        return l

    def is_path_valid(self, path, resolve_generator=False):
        htable = self.get_all_paths(
            resolve_generator=resolve_generator, flush_cache=True
        )
        for p in htable.keys():
            if re.match(path, p):
                return True
        else:
            return False

    def set_env(self, env):
        self.env = env
        for c in self.internals:
            self.internals[c].set_child_env(env)

    def get_env(self):
        return self.env

    def set_csp(self, csp: CSP):
        if self.env is None:
            print('[ERROR] set_csp() is called on a node that does not have an Env()\n'
                  '  --> node name: {!s}'.format(self.name))
            raise NodeError('No Env() object associated to the node')

        self.env.csp = copy.copy(csp)

    def get_csp(self):
        return self.env.csp

    @property
    def no_more_solution_for_csp(self):
        return self.env.csp.exhausted_solutions if self.env.csp is not None else True

    def walk(self, conf=None, recursive=True, steps_num=1):
        for _ in range(steps_num):
            self.unfreeze(conf=conf, recursive=recursive)
            self.freeze(conf=conf, recursive=recursive)

    def freeze(
        self,
        conf=None,
        recursive=True,
        return_node_internals=False,
        restrict_csp=False,
        resolve_csp=False,
    ):
        """

        Args:
            conf:
            recursive:
            return_node_internals:

            restrict_csp: Only effective when a CSP is part of the data description. When
              set to True, if the node on which this method is called is a variable of the CSP, then
              its domain will be shrunk to its current value. Thus, the node won't change when
              the CSP will be resolved.

            resolve_csp: Only effective when a CSP is part of the data description. When set to True,
              the CSP will be resolved and the data generated will comply with the solution.

        Returns:

        """

        # Step 1 - get value
        ret = self._get_value(
            conf=conf,
            recursive=recursive,
            return_node_internals=return_node_internals,
            restrict_csp=restrict_csp,
        )

        if self.env is None:
            print('[Warning] freeze() is called on a node that does not have an Env()\n'
                  '  --> node name: {!s}'.format(self.name))

        # Step 2 - DJobs resolution
        if (
            self.env is not None
            and self.env.delayed_jobs_enabled
            and (not self._delayed_jobs_called or self.env.delayed_jobs_pending)
        ):
            self._delayed_jobs_called = True

            if self.env.djobs_exists(Node.DJOBS_PRIO_nterm_existence):
                self.env.cleanup_remaining_djobs(Node.DJOBS_PRIO_nterm_existence)

            if self.env.djobs_exists(Node.DJOBS_PRIO_genfunc):
                self.env.execute_basic_djobs(Node.DJOBS_PRIO_genfunc)

            ret = self._get_value(
                conf=conf,
                recursive=recursive,
                return_node_internals=return_node_internals,
                restrict_csp=restrict_csp,
            )

        # Step 3 - CSP resolution
        if (
            resolve_csp
            and self.env.csp is not None
            and not self.env.csp.is_current_solution_queried
        ):
            try:
                solution = self.env.csp.get_solution()
            except ConstraintError:
                if not self.env.csp.var_domain_updated:
                    # in this case we let the caller handle this, as we are not responsible
                    raise
                else:
                    print(f"\n[Warning] no solution found for the current CSP, the generated data will be invalid!"
                          f"\n   --> likely culprit: node '{self.name}' with value {self.get_raw_value()}")
            else:
                if solution is not None:  # Does a solution exist?
                    for var, value in solution.items():
                        nd = self.env.csp.var_mapping[var]
                        if self.env.csp.highlight_variables:
                            nd.set_attr(NodeInternals.Highlight, conf=conf)
                        if nd == self:
                            continue
                        # nd.set_default_value(value)
                        # Note: .set_default() does disruptive stuff, like re-ordering
                        # INT.values list, and could disturb a model walker like tWALK
                        nd.update_value(value)
                else:
                    pass
                    # print(f'\n***DBG freeze: No more solution - exhausted: {self.env.csp.exhausted_solutions}')
            finally:
                if self.env.csp.var_domain_updated:
                    self.env.csp.restore_var_domains()

        return ret

    get_value = freeze

    def _get_value(
        self, conf=None, recursive=True, return_node_internals=False, restrict_csp=False
    ):
        next_conf = conf if recursive else None
        conf2 = conf if self.is_conf_existing(conf) else self.current_conf

        if self.is_genfunc(conf2):
            next_conf = conf

        internal = self.internals[conf2]
        if internal is None:
            print(
                "\n*** The Node named '{:s}' is used while it has not "
                "been completely specified!\n (no NodeInternals has "
                "been associted to the Node.)".format(self.name)
            )
            raise ValueError

        ret, was_not_frozen = internal._get_value(
            conf=next_conf,
            recursive=recursive,
            return_node_internals=return_node_internals,
            restrict_csp=restrict_csp,
        )

        if restrict_csp and self.env.csp is not None and self.is_typed_value(conf=conf):
            for v, n in self.env.csp.var_mapping.items():
                if self == n:
                    # print(f'\n***DBG _get_value: "{self.name}" {self.get_raw_value()}\n'
                    #       f'  --> {self.cc.value_type.values}')
                    self.env.csp.set_var_domain(v, [self.get_raw_value()])
                    self.env.csp.reset()
                    break

        if was_not_frozen:
            pf_ret = self._post_freeze(
                internal,
                self,
                next_conf=next_conf,
                recursive=recursive,
                return_node_internals=return_node_internals,
            )
            # post_freeze handler can perform some change on the nodes. Thus, we have to update the
            # ret value accordingly.
            if pf_ret is not None:
                ret, _ = pf_ret
            # We need to test self.env because an Node can be freezed
            # before being registered in the data model. It triggers
            # for instance when a generator Node is freezed
            # (_get_value() is called on it) during data model
            # construction.
            if internal.is_exhausted() and self.env is not None:
                self.env.notify_exhausted_node(self)

        return ret

    def _post_freeze(
        self, node_internals, wrapping_node, next_conf, recursive, return_node_internals
    ):
        if self._post_freeze_handler is not None:
            self._post_freeze_handler(node_internals, wrapping_node)
            # We need to call again _get_value(), so that we are sure to provide to the freeze()
            # caller the updated nodes further to the execution of post_freeze.
            # But even in the case there are no modifications, some bad side-effects could happen,
            # that will be resolved thanks to the new call to _get_value().
            # Indeed, in the case the post_freeze handler call Node.freeze() on its associated node, there
            # could be some side-effects linked to DJobs. If some DJobs are registered (to deal with
            # node existence for instance in non-terminal nodes), then the post_freeze handler
            # will trigger them as it will reenter Node.freeze() while step 1 of Node.freeze() is being executed.
            # It means that when this step 1 has finished, step 2 won't be executed again as it will have
            # already been executed though post_freeze. Thus, DJobs won't have a chance to be called again and a wrong
            # value will be provided to the top caller. Thus, we need in this case to call _get_value()
            # again to force potential Djobs to be registered again.
            return node_internals._get_value(
                conf=next_conf,
                recursive=recursive,
                return_node_internals=return_node_internals,
            )
        else:
            return None

    def register_post_freeze_handler(self, func):
        self._post_freeze_handler = func

    def is_exhausted(self, conf=None):
        conf = self._check_conf(conf)
        return self.internals[conf].is_exhausted()

    def is_frozen(self, conf=None):
        conf = self._check_conf(conf)
        return self.internals[conf].is_frozen()

    def reset_state(
        self, recursive=False, exclude_self=False, conf=None, ignore_entanglement=False
    ):
        self._delayed_jobs_called = False
        current_conf, next_conf = self._compute_confs(conf=conf, recursive=recursive)
        self.internals[current_conf].reset_state(
            recursive=recursive,
            exclude_self=exclude_self,
            conf=next_conf,
            ignore_entanglement=ignore_entanglement,
        )

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.reset_state(
                    recursive=recursive,
                    exclude_self=exclude_self,
                    conf=next_conf,
                    ignore_entanglement=True,
                )

    def to_bytes(self, conf=None, recursive=True):
        def tobytes_helper(node_internals):
            if isinstance(node_internals, bytes):
                return node_internals
            else:
                return node_internals._get_value(
                    conf=conf, recursive=recursive, return_node_internals=False
                )[0]

        node_internals_list = self.freeze(conf=conf, recursive=recursive)
        if isinstance(node_internals_list, list):
            node_internals_list = list(flatten(node_internals_list))
            if node_internals_list:
                # if issubclass(node_internals_list[0].__class__, NodeInternals):
                node_internals_list = list(map(tobytes_helper, node_internals_list))
                val = b"".join(node_internals_list)
            else:
                val = b""
        else:
            val = node_internals_list

        return val

    def to_str(self, conf=None, recursive=True):
        val = self.to_bytes(conf=conf, recursive=recursive)
        return unconvert_from_internal_repr(val)

    def to_formatted_str(self, conf=None, recursive=True):
        self.enable_color()
        val = self.to_bytes(conf=conf, recursive=recursive)
        self.disable_color()
        return unconvert_from_internal_repr(val)

    def to_ascii(self, conf=None, recursive=True):
        val = self.to_str(conf=conf, recursive=recursive)
        try:
            val = eval("{!a}".format(val))
        except:
            val = repr(val)
        finally:
            return val

    def _tobytes(self, conf=None, recursive=True):
        def tobytes_helper(node_internals):
            if isinstance(node_internals, bytes):
                return node_internals
            else:
                return node_internals._get_value(
                    conf=conf, recursive=recursive, return_node_internals=False
                )[0]

        node_internals_list = self._get_value(conf=conf, recursive=recursive)
        if isinstance(node_internals_list, list):
            node_internals_list = list(flatten(node_internals_list))
            if node_internals_list:
                # if issubclass(node_internals_list[0].__class__, NodeInternals):
                node_internals_list = list(map(tobytes_helper, node_internals_list))
                # print(node_internals_list)
                val = b"".join(node_internals_list)
            else:
                val = b""
        else:
            val = node_internals_list

        return val

    def set_frozen_value(self, value, conf=None):
        conf = self._check_conf(conf)

        if self.is_term(conf):
            value = convert_to_internal_repr(value)
            self.internals[conf]._set_frozen_value(value)
        else:
            raise ValueError

    def set_default_value(self, value, conf=None):
        conf = self._check_conf(conf)

        if self.is_term(conf):
            self.internals[conf]._set_default_value(value)
        else:
            raise ValueError

    def fix_synchronized_nodes(self, conf=None):
        conf = self._check_conf(conf)
        self.internals[conf].synchronize_nodes(self)

    def unfreeze(
        self,
        conf=None,
        recursive=True,
        dont_change_state=False,
        ignore_entanglement=False,
        only_generators=False,
        reevaluate_constraints=False,
        walk_csp=False,
        walk_csp_step_size=1,
    ):
        self._delayed_jobs_called = False

        next_conf = conf

        if not self.is_conf_existing(conf):
            conf = self.current_conf

        # if reevaluate_constraints:
        #     if self.env.csp is not None:
        #         print(f'\n***DBG {self.env.csp._is_solution_queried}')
        #         self.env.csp._is_solution_queried = False

        if walk_csp:
            if self.env.csp is not None and self.env.csp.is_current_solution_queried:
                for i in range(walk_csp_step_size):
                    self.env.csp.next_solution()
                    if self.env.csp.exhausted_solutions:
                        break

        # if self.is_frozen(conf):
        self.internals[conf].unfreeze(
            next_conf,
            recursive=recursive,
            dont_change_state=dont_change_state,
            ignore_entanglement=ignore_entanglement,
            only_generators=only_generators,
            reevaluate_constraints=reevaluate_constraints,
        )

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.unfreeze(
                    conf=next_conf,
                    recursive=recursive,
                    dont_change_state=dont_change_state,
                    ignore_entanglement=True,
                    only_generators=only_generators,
                    reevaluate_constraints=reevaluate_constraints,
                )

    def unfreeze_all(self, recursive=True, ignore_entanglement=False):
        self._delayed_jobs_called = False

        for conf in self.internals:
            if self.is_frozen(conf):
                self.internals[conf].unfreeze_all(recursive=recursive)

        if not ignore_entanglement and self.entangled_nodes is not None:
            for e in self.entangled_nodes:
                e.unfreeze_all(recursive=recursive, ignore_entanglement=True)

    def pretty_print(self, max_size=None, conf=None):
        conf = self._check_conf(conf)
        return self.internals[conf].pretty_print(max_size=max_size)

    def get_nodes_names(
        self, conf=None, verbose=False, terminal_only=False, flush_cache=True
    ):
        l = []
        for path, node in self.iter_paths(conf=conf, flush_cache=flush_cache):
            if terminal_only:
                conf = node._check_conf(conf)
                if not node.is_term(conf):
                    continue

            if verbose:
                l.append((path, node.depth, node._tobytes()))
            else:
                l.append((path, node.depth))

            if node.env is None:
                print(path + " (" + str(node.depth) + ")" + " " + str(node.env))
                print("Node value: ", node._tobytes())
                print("The 'env' attr of this Node is NONE")
                raise ValueError

        return l

    @staticmethod
    def _print(
        msg, rgb, style="", nl=True, log_func=sys.stdout.write, pretty_print=True
    ):
        end = "\n" if nl else ""
        if pretty_print:
            log_func(style)
            log_func(colorize(msg, rgb=rgb))
            if style:
                log_func(FontStyle.END + end)
            else:
                log_func(end)
        else:
            log_func(msg + end)

    @staticmethod
    def _print_name(
        msg, style="", nl=True, log_func=sys.stdout.write, pretty_print=True
    ):
        Node._print(
            msg,
            rgb=Color.ND_NAME,
            style=style,
            nl=nl,
            log_func=log_func,
            pretty_print=pretty_print,
        )

    @staticmethod
    def _print_type(
        msg, style=FontStyle.BOLD, nl=True, log_func=sys.stdout.write, pretty_print=True
    ):
        Node._print(
            msg,
            rgb=Color.ND_TYPE,
            style=style,
            nl=nl,
            log_func=log_func,
            pretty_print=pretty_print,
        )

    @staticmethod
    def _print_contents(
        msg, style="", nl=True, log_func=sys.stdout.write, pretty_print=True
    ):
        Node._print(
            msg,
            rgb=Color.ND_CONTENTS,
            style=style,
            nl=nl,
            log_func=log_func,
            pretty_print=pretty_print,
        )

    @staticmethod
    def _print_nonterm(
        msg, style=FontStyle.BOLD, nl=True, log_func=sys.stdout.write, pretty_print=True
    ):
        Node._print(
            msg,
            rgb=Color.ND_NONTERM,
            style=style,
            nl=nl,
            log_func=log_func,
            pretty_print=pretty_print,
        )

    @staticmethod
    def _print_raw(
        msg,
        style="",
        nl=True,
        hlight=False,
        log_func=sys.stdout.write,
        pretty_print=True,
    ):
        if hlight:
            st = FontStyle.BOLD if style == "" else style
            Node._print(
                msg,
                rgb=Color.ND_RAW_HLIGHT,
                style=st,
                nl=nl,
                log_func=log_func,
                pretty_print=pretty_print,
            )
        else:
            Node._print(
                msg,
                rgb=Color.ND_RAW,
                style=style,
                nl=nl,
                log_func=log_func,
                pretty_print=pretty_print,
            )

    def show(
        self,
        conf=None,
        verbose=True,
        print_name_func=None,
        print_contents_func=None,
        print_raw_func=None,
        print_nonterm_func=None,
        print_type_func=None,
        alpha_order=False,
        raw_limit=None,
        log_func=sys.stdout.write,
        pretty_print=True,
        display_title=True,
        display_gen_node=True,
    ):
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

        sep_deco = " [SEP]"

        def get_args(node, conf):
            args = ""
            first = True
            for n in node.c[conf].get_node_args():
                if first:
                    first = False
                    args += str(n.get_path_from(self, conf=conf))
                else:
                    args += ", " + str(n.get_path_from(self, conf=conf))
            if args == "":
                args = "None"
            return args

        def get_all_smaller_depth(nodes_nb, i, depth, conf):
            smaller_depth = []
            prev_depth = l[i][0].count("/")

            for j in range(i, nodes_nb):
                current = l[j][1]
                sep_nb = l[j][0].count("/")
                if current.depth != sep_nb:
                    # case when the same node is used at different depth
                    if "_seen" not in current.__dict__:
                        current._seen = True
                        current.depth = sep_nb

                if current.depth != prev_depth:
                    break

                prev_depth = current.depth

            for j in range(i, nodes_nb):
                current = l[j][1]
                if "_seen" in current.__dict__:
                    del current._seen

            for j in range(i + 1, nodes_nb):
                delta = depth - l[j][1].depth
                if delta > 0:
                    d = l[j][1].depth
                    if d not in smaller_depth:
                        if not smaller_depth or (
                            smaller_depth and d < smaller_depth[-1]
                        ):
                            smaller_depth.append(d)

            return smaller_depth

        # in case the node is not frozen
        self.freeze()

        l = []
        for n, e in self.iter_paths(
            conf=conf, flush_cache=True, resolve_generator=True
        ):
            l.append((n, e))

        if alpha_order:
            l = sorted(l, key=lambda x: x[0])

        name = "[" + self.name + "]"
        if display_title:
            print_name_func(name, log_func=log_func, pretty_print=pretty_print)
            print_name_func(
                "-" * len(name), log_func=log_func, pretty_print=pretty_print
            )

        nodes_nb = len(l)

        unindent_generated_node = False

        if verbose:
            prev_depth = 0
            for n, i in zip(l, range(nodes_nb)):
                name, node = n

                conf_tmp = node._check_conf(conf)
                if isinstance(node.c[conf_tmp], NodeInternals_TypedValue):
                    node_type = node.c[conf_tmp].get_value_type().__class__.__name__
                else:
                    node_type = node.c[conf_tmp].__class__.__name__[
                        len("NodeInternals_") :
                    ]

                depth = node.depth
                sep_nb = name.count("/")
                if depth != sep_nb:
                    # detection that the same node is used multiple
                    # times at different level. Thus it is a graph
                    depth = sep_nb
                    node.depth = sep_nb

                def is_node_used_more_than_once(name):
                    node_list = []
                    for item in l:
                        if re.search(name + "$", item[0]):
                            node_list.append(item[1])
                    return len(node_list) != len(set(node_list))

                if is_node_used_more_than_once(node.name):
                    graph_deco = " --> M"
                else:
                    graph_deco = ""

                if unindent_generated_node:
                    # depth always >=1
                    depth -= 1

                junction_sym = r' \__'
                junction_sym_len = len(junction_sym)
                if depth == 0:
                    indent_nonterm = ""
                    indent_spc = ""
                    indent_term = ""
                else:
                    all_smaller_depth = get_all_smaller_depth(
                        nodes_nb, i, depth, conf_tmp
                    )
                    # if i != nodes_nb-1:
                    #     print('DBG1: ', l[i+1][1].depth, l[i+1][0], repr(l[i+1][1]))

                    prefix = ""
                    sz = len(all_smaller_depth)
                    idx = 0
                    for bar in range(depth - 1, 0, -1):
                        if idx < sz and bar == all_smaller_depth[idx]:
                            idx += 1
                            prefix = " |  " + prefix
                        else:
                            prefix = "    " + prefix
                    indent_nonterm = prefix + junction_sym
                    indent_term = prefix + junction_sym

                    # l[i+1][1].depth is not reliable in case the node is used at different level
                    if i == nodes_nb - 1 or depth != l[i + 1][0].count("/"):
                        # if i != nodes_nb-1:
                        #     print('DBG2: ', l[i+1][1].depth, l[i+1][0], repr(l[i+1][1]), i+1)
                        indent_spc = prefix + "    " + "    "
                    else:
                        indent_spc = prefix + " |  " + "    "

                if unindent_generated_node:
                    unindent_generated_node = False
                    depth += 1

                node_desc_lines = (
                    chunk_lines(node.description, length=80, prefix=": ")
                    if node.description
                    else None
                )
                if node.semantics:
                    if not node_desc_lines:
                        node_desc_lines = []
                    node_desc_lines.append(": semantics = " + str(node.semantics))

                if node.is_term(conf_tmp):
                    raw = node._tobytes()
                    raw_len = len(raw)
                    val = node.pretty_print(max_size=raw_limit)

                    prefix = "{:s}".format(indent_term)
                    name = "{:s} ".format(name)
                    if isinstance(node.c[conf_tmp], NodeInternals_Func):
                        args = get_args(node, conf_tmp)
                        type_and_args = "[{:s} | node_args: {:s}] size={:d}B".format(
                            node_type, args, raw_len
                        )
                    else:
                        type_and_args = "[{:s}] size={:d}B".format(node_type, raw_len)
                    print_nonterm_func(
                        prefix, nl=False, log_func=log_func, pretty_print=pretty_print
                    )
                    print_name_func(
                        "({:d}) {:s}".format(depth, name),
                        nl=False,
                        log_func=log_func,
                        pretty_print=pretty_print,
                    )
                    print_type_func(
                        type_and_args,
                        nl=False,
                        log_func=log_func,
                        pretty_print=pretty_print,
                    )
                    if node.is_attr_set(NodeInternals.Separator):
                        self._print(
                            sep_deco,
                            rgb=Color.ND_SEPARATOR,
                            style=FontStyle.BOLD,
                            nl=False,
                            log_func=log_func,
                            pretty_print=pretty_print,
                        )
                    self._print(
                        graph_deco,
                        rgb=Color.ND_DUPLICATED,
                        style=FontStyle.BOLD,
                        log_func=log_func,
                        pretty_print=pretty_print,
                    )

                    if node_desc_lines:
                        indent_desc = (
                            indent_nonterm[:-junction_sym_len]
                            + " |  "
                            + " " * len("({:d}) ".format(depth))
                        )
                        for d in node_desc_lines:
                            print_nonterm_func(
                                "{:s}".format(indent_desc),
                                nl=False,
                                log_func=log_func,
                                pretty_print=pretty_print,
                            )
                            self._print(
                                d,
                                rgb=Color.SUBINFO,
                                style=FontStyle.BOLD,
                                log_func=log_func,
                                pretty_print=pretty_print,
                            )

                    if val is not None:
                        print_nonterm_func("{:s}  ".format(indent_spc), nl=False, log_func=log_func, pretty_print=pretty_print)
                        print_contents_func(r"\_ {:s}".format(val), log_func=log_func, pretty_print=pretty_print)
                    print_nonterm_func("{:s}  ".format(indent_spc), nl=False, log_func=log_func, pretty_print=pretty_print)
                    if raw_limit is not None and raw_len > raw_limit:
                        print_raw_func(r"\_raw: {:s}".format(repr(raw[:raw_limit])), nl=False,
                                       log_func=log_func, pretty_print=pretty_print)
                        print_raw_func(" ...", hlight=True, log_func=log_func, pretty_print=pretty_print)
                    else:
                        print_raw_func(r"\_raw: {:s}".format(repr(raw)), log_func=log_func, pretty_print=pretty_print)
                else:
                    is_gen_node = isinstance(node.c[conf_tmp], NodeInternals_GenFunc)
                    if (is_gen_node and display_gen_node) or not is_gen_node:
                        print_nonterm_func(
                            "{:s}[{:d}] {:s}".format(indent_nonterm, depth, name),
                            nl=False,
                            log_func=log_func,
                            pretty_print=pretty_print,
                        )
                    if is_gen_node:
                        if display_gen_node:
                            args = get_args(node, conf_tmp)
                            print_nonterm_func(
                                " [{:s} | node_args: {:s}]".format(node_type, args),
                                nl=False,
                                log_func=log_func,
                                pretty_print=pretty_print,
                            )
                            self._print(
                                graph_deco,
                                rgb=Color.ND_DUPLICATED,
                                style=FontStyle.BOLD,
                                log_func=log_func,
                                pretty_print=pretty_print,
                            )
                        else:
                            unindent_generated_node = True
                    else:
                        print_nonterm_func(
                            " [{:s}]".format(node_type),
                            nl=False,
                            log_func=log_func,
                            pretty_print=pretty_print,
                        )
                        if node.is_nonterm(conf_tmp) and node.encoder is not None:
                            self._print(
                                " [Encoded by {:s}]".format(
                                    node.encoder.__class__.__name__
                                ),
                                rgb=Color.ND_ENCODED,
                                style=FontStyle.BOLD,
                                nl=False,
                                log_func=log_func,
                                pretty_print=pretty_print,
                            )
                        if (
                            node.is_nonterm(conf_tmp)
                            and node.custo.collapse_padding_mode
                        ):
                            self._print(
                                " >Collapse Bitfields<",
                                rgb=Color.ND_CUSTO,
                                style=FontStyle.BOLD,
                                nl=False,
                                log_func=log_func,
                                pretty_print=pretty_print,
                            )
                        self._print(
                            graph_deco,
                            rgb=Color.ND_DUPLICATED,
                            style=FontStyle.BOLD,
                            log_func=log_func,
                            pretty_print=pretty_print,
                        )

                    if node.description:
                        if depth == 0:
                            indent_desc = indent_nonterm + " |  "
                        else:
                            indent_desc = (
                                indent_nonterm[:-junction_sym_len]
                                + " " * junction_sym_len
                                + " |  "
                            )
                        for d in node_desc_lines:
                            print_nonterm_func(
                                "{:s}".format(indent_desc),
                                nl=False,
                                log_func=log_func,
                                pretty_print=pretty_print,
                            )
                            self._print(
                                d,
                                rgb=Color.SUBINFO,
                                style=FontStyle.BOLD,
                                log_func=log_func,
                                pretty_print=pretty_print,
                            )

        else:
            for name, node in l:
                print_name_func(
                    "{:s} [{:d}]".format(name, node.depth),
                    log_func=log_func,
                    pretty_print=pretty_print,
                )

    def __lt__(self, other):
        return self.depth < other.depth

    def __hash__(self):
        return id(self)

    def __str__(self):
        # NEVER return something with self._tobytes() as side
        # effects are not welcome
        return repr(self)

    def __getitem__(self, key):
        if isinstance(key, str):
            node_list = list(self.iter_nodes_by_path(key))
            return node_list if node_list else None
        elif isinstance(key, NodeInternalsCriteria):
            node_list = self.get_reachable_nodes(internals_criteria=key)
            return node_list if node_list else None
        elif isinstance(key, NodeSemanticsCriteria):
            node_list = self.get_reachable_nodes(semantics_criteria=key)
            return node_list if node_list else None
        else:
            raise ValueError

    def __setitem__(self, key, val):
        nodes = self[key]
        if not nodes:
            raise ValueError(f'Nodes not found with the key: "{key}"')

        if isinstance(val, Node):
            if isinstance(nodes, Node):
                nodes.set_contents(val)
            else:
                for n in nodes:
                    n.set_contents(val)
        elif isinstance(val, NodeSemantics):
            if isinstance(nodes, Node):
                nodes.set_semantics(val)
            else:
                for n in nodes:
                    n.set_semantics(val)
        elif isinstance(val, int):
            if isinstance(nodes, Node):
                # Method defined by INT object (within TypedValue nodes)
                nodes.update_value(val)
            else:
                for n in nodes:
                    n.update_value(val)
        else:
            if isinstance(nodes, Node):
                status, off, size, name = nodes.absorb(
                    convert_to_internal_repr(val), constraints=AbsNoCsts()
                )
                if status != AbsorbStatus.FullyAbsorbed:
                    raise ValueError
            else:
                for n in nodes:
                    status, off, size, name = n.absorb(
                        convert_to_internal_repr(val), constraints=AbsNoCsts()
                    )
                    if status != AbsorbStatus.FullyAbsorbed:
                        raise ValueError

    def update(self, node_update_dict, stop_on_error=True):
        for node_ref, new_value in node_update_dict.items():
            if new_value is None:
                continue
            try:
                self[node_ref] = new_value
            except ValueError as err:
                if stop_on_error:
                    print(f'\n\n*** Node update raised an error: "{err}"')
                    raise

    def enable_color(self):
        assert self.env is not None
        self.env._color_enabled = True

    def disable_color(self):
        assert self.env is not None
        self.env._color_enabled = False

    @property
    def color_enabled(self):
        return self.env._color_enabled

    def __getattr__(self, name):
        internals = self.__getattribute__("internals")[self.current_conf]
        if hasattr(internals, name):
            return getattr(internals, name)
        else:
            return object.__getattribute__(self, name)


class Env4NT(object):
    """
    Define methods for non-terminal nodes
    """

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
        return qty > 0 and sz > 0

    def clear_drawn_node_attrs(self, node_id):
        if node_id in self.drawn_node_attrs:
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
    knowledge_source = None

    def __init__(self):
        self.exhausted_nodes = []
        self.nodes_to_corrupt = {}
        self.env4NT = Env4NT()
        self.delayed_jobs_enabled = True
        self._sorted_jobs = None
        self._djob_keys = None
        self._djob_groups = None
        self._dm = None
        self.id_list = None
        self._reentrancy_cpt = 0
        self._color_enabled = False
        self.csp: CSP = None

        self._decoded_blob = None

    @property
    def delayed_jobs_pending(self):
        return bool(self._sorted_jobs)

    def enable_color(self):
        self._color_enabled = True

    def disable_color(self):
        self._color_enabled = False

    @property
    def color_enabled(self):
        return self._color_enabled

    def __getattr__(self, name):
        if hasattr(self.env4NT, name):
            return self.env4NT.__getattribute__(name)
        else:
            raise AttributeError

    def is_empty(self):
        return (
            not self.exhausted_nodes
            and not self.nodes_to_corrupt
            and self.env4NT.is_empty()
        )

    def set_data_model(self, dm):
        self._dm = dm

    def get_data_model(self):
        return self._dm

    # @property
    # def knowledge_source(self):
    #     return self._knowledge_source
    #
    # @knowledge_source.setter
    # def knowledge_source(self, src):
    #     self._knowledge_source = src

    def add_node_to_corrupt(self, node, corrupt_type=None, corrupt_op=lambda x: x):
        if node.entangled_nodes:
            for n in node.entangled_nodes:
                self.nodes_to_corrupt[n] = (corrupt_type, corrupt_op)
        else:
            self.nodes_to_corrupt[node] = (corrupt_type, corrupt_op)

    def remove_node_to_corrupt(self, node):
        if node in self.nodes_to_corrupt:
            if node.entangled_nodes:
                for n in node.entangled_nodes:
                    del self.nodes_to_corrupt[n]
            else:
                del self.nodes_to_corrupt[node]

    def exhausted_node_exists(self):
        return len(self.exhausted_nodes) > 0

    def get_exhausted_nodes(self):
        return copy.copy(self.exhausted_nodes)

    def notify_exhausted_node(self, node):
        self.exhausted_nodes.append(node)

    def is_node_exhausted(self, node):
        return node in self.exhausted_nodes

    def clear_exhausted_node(self, node):
        try:
            self.exhausted_nodes.remove(node)
        except:
            print("*** requested node.name:       ", node.name)
            print("*** requested node:            ", node)
            print("*** current exhausted list:")
            for i in self.exhausted_nodes:
                print("  * exhausted_node.name:  ", i.name)
                print("  * exhausted_node:       ", i)
            if not self.exhausted_nodes:
                print("  * no exhausted node")

            raise

    def exhausted_nodes_amount(self):
        return len(self.exhausted_nodes)

    def clear_all_exhausted_nodes(self):
        self.exhausted_nodes = []

    def update_node_refs(self, node_dico, ignore_frozen_state):
        exh_nodes = []
        new_nodes_to_corrupt = {}
        self.id_list = []
        for old_node, new_node in node_dico.items():
            self.id_list.append((id(old_node), id(new_node)))
            if old_node in self.exhausted_nodes:
                exh_nodes.append(new_node)
            if old_node in self.nodes_to_corrupt.keys():
                op = self.nodes_to_corrupt[old_node]
                del self.nodes_to_corrupt[old_node]
                new_nodes_to_corrupt[new_node] = op

        self.nodes_to_corrupt = new_nodes_to_corrupt

        if self.is_empty():
            return

        if ignore_frozen_state:
            self.exhausted_nodes = []
            self.env4NT.reset()
        else:
            self.exhausted_nodes = exh_nodes
            self.env4NT.update_node_ids(self.id_list)

    # def update_id_list(self):
    #     self.id_list = []
    #     for old_node, new_node in node_dico.items():
    #         self.id_list.append((id(old_node), id(new_node)))

    def register_djob(self, func, group, key, cleanup=None, args=None, prio=1):
        if self._sorted_jobs is None:
            self._sorted_jobs = {}
        if self._djob_keys is None:  # this case trigger if basic djobs
            # have been registered first
            self._djob_keys = {}
            self._djob_groups = {}

        if self._sorted_jobs.get(prio, None) is None:
            self._sorted_jobs[prio] = {}
            self._djob_keys[prio] = set()
            self._djob_groups[prio] = set()
        if self._sorted_jobs[prio].get(id(group), None) is None:
            self._sorted_jobs[prio][id(group)] = {}

        assert key not in self._sorted_jobs[prio][id(group)]
        self._sorted_jobs[prio][id(group)][key] = (func, args, cleanup)
        assert key not in self._djob_keys[prio]
        self._djob_keys[prio].add(key)
        self._djob_groups[prio].add(group)

    def register_basic_djob(self, func, args, prio=1):
        if self._sorted_jobs is None:
            self._sorted_jobs = {}
        if self._sorted_jobs.get(prio, None) is None:
            self._sorted_jobs[prio] = []
        self._sorted_jobs[prio].append((func, args))

    def execute_basic_djobs(self, prio):
        assert prio in self._sorted_jobs
        jobs = copy.copy(self._sorted_jobs[prio])
        del self._sorted_jobs[prio]  # func() may triggers this func,
        # thus we cleanup before
        for func, args in jobs:
            func(*args)

    def get_basic_djobs(self, prio):
        assert prio in self._sorted_jobs
        return self._sorted_jobs[prio]

    def cleanup_basic_djobs(self, prio):
        if prio not in self._sorted_jobs:
            return
        del self._sorted_jobs[prio]

    def djobs_exists(self, prio):
        if self._sorted_jobs and prio in self._sorted_jobs and self._sorted_jobs[prio]:
            return True
        else:
            return False

    def is_djob_registered(self, key, prio):
        if self._djob_keys and prio in self._djob_keys:
            return key in self._djob_keys[prio]
        else:
            return False

    def get_all_djob_groups(self, prio):
        assert self._djob_groups is not None
        return copy.copy(self._djob_groups[prio])

    def get_djobs_by_gid(self, group_id, prio):
        assert self._sorted_jobs[prio] is not None
        assert self._sorted_jobs[prio][group_id] is not None
        return self._sorted_jobs[prio][group_id]

    def remove_djob(self, group, key, prio):
        self._djob_keys[prio].remove(key)
        del self._sorted_jobs[prio][id(group)][key]
        if not self._sorted_jobs[prio][id(group)]:
            self._djob_groups[prio].remove(group)

    def cleanup_remaining_djobs(self, prio):
        if prio not in self._sorted_jobs:
            return

        groups = self.get_all_djob_groups(prio=prio)
        if groups is not None:
            for gr in groups:
                gr_id = id(gr)
                if gr_id not in self._sorted_jobs[prio]:
                    continue
                for n in reversed(gr):
                    if id(n) in self._sorted_jobs[prio][gr_id]:
                        func, args, cleanup = self._sorted_jobs[prio][gr_id][id(n)]
                        cleanup(*args)

        del self._sorted_jobs[prio]
        del self._djob_keys[prio]
        del self._djob_groups[prio]

    def __copy__(self):
        new_env = type(self)()
        new_env.__dict__.update(self.__dict__)
        new_env.exhausted_nodes = copy.copy(self.exhausted_nodes)
        new_env.nodes_to_corrupt = copy.copy(self.nodes_to_corrupt)
        new_env.env4NT = copy.copy(self.env4NT)
        new_env._dm = copy.copy(self._dm)
        new_env.csp = copy.copy(self.csp)

        # DJobs are ignored in the Env copy, because they only matters
        # in the context of one node graph (Nodes + 1 unique Env) for performing delayed jobs
        # in that graph. Indeed, all delayed jobs are registered dynamically
        # (especially in the process of freezing a graph) and does not
        # provide information even in the case of a frozen graph cloning.
        # All DJobs information are ephemeral, they should only exist in the time frame of
        # a node graph operation (e.g., freezing, absorption). If DJobs exists while an Env()
        # is in the process of being copied, it is most probably a bug.
        #
        # WARNING: If DJobs need to evolve in the future to support copy, DJobGroup should be updated
        # during this copy for updating the nodes in its node_list attribute.
        # assert not self._sorted_jobs and not self._djob_keys and not self._djob_groups
        new_env._sorted_jobs = None
        new_env._djob_keys = None
        new_env._djob_groups = None
        # new_env._sorted_jobs = copy.copy(self._sorted_jobs)
        # new_env._djob_keys = copy.copy(self._djob_keys)
        # new_env._djob_groups = copy.copy(self._djob_groups)
        # new_env.id_list = copy.copy(self.id_list)
        # new_env.cpt = 0
        return new_env


class DJobGroup(object):
    def __init__(self, node_list):
        self.node_list = node_list

    def __id__(self):
        return id(self.node_list)

    def __iter__(self):
        for n in self.node_list:
            yield n

    def __reversed__(self):
        for n in reversed(self.node_list):
            yield n

    def __repr__(self):
        return str([x.name for x in self.node_list]) + " ID:" + str(id(self))


if __name__ == "__main__":
    csts = [">", ["fpn_h", 1], ["rp", 1, 2], ["ra", 1], "=", ["fpn_h", 1, 3], ["ra", 3]]

    csts_l = [
        1,
        ["u>", ["fpn_h", 1], ["rp", 1, 2], ["ra", 1], "=", ["fpn_h", 1, 3], ["ra", 3]],
        3,
        [
            "s=.(1,3)",
            ["fpn_h", 1],
            ["rp", 1, 2],
            "u=.",
            ["fpn_h", 1, 3],
            "u>",
            ["ra", 3],
        ],
        5,
        ["u=.", ["fpn_h", 4, 7], "u>", ["ra", 8]],
    ]

    print(csts_l)

    for weight, csts in split_with(lambda x: isinstance(x, int), csts_l):
        for delim, nodes_l in split_with(lambda x: isinstance(x, str), csts[0]):
            print(weight, delim, nodes_l)

    print("\n******\n")

    for weight, csts in split_with(lambda x: isinstance(x, int), csts_l):
        for idx, delim, nodes_l in split_verbose_with(
            lambda x: isinstance(x, str), csts[0]
        ):
            print(weight, idx, delim, nodes_l)

    print("\n******\n")

    for idx, weight, csts in split_verbose_with(lambda x: isinstance(x, int), csts_l):
        print(idx, weight, csts)

    print("\n*** TEST:")

    val = [b"*", [b"+", b"$"]]
    print(val)

    val = list(flatten(val))
    val = b"".join(val)
    print(val)
