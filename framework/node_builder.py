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

import inspect
import string
import sys
import six

from framework.dmhelpers.generic import MH
from framework.error_handling import DataModelDefinitionError, CharsetError, \
    InitialStateNotFoundError, QuantificationError, StructureError, InconvertibilityError, \
    EscapeError, InvalidRangeError, EmptyAlphabetError
from framework.node import Node, NodeInternals_Empty, GenFuncCusto, NonTermCusto, FuncCusto, \
    NodeSemantics, SyncScope, SyncQtyFromObj, SyncSizeObj, NodeCondition, SyncExistenceObj, Env

import framework.value_types as fvt

class NodeBuilder(object):

    HIGH_PRIO = 1
    MEDIUM_PRIO = 2
    LOW_PRIO = 3
    VERYLOW_PRIO = 4

    valid_keys = [
        # generic description keys
        'name', 'contents', 'qty', 'clone', 'type', 'alt', 'conf',
        'custo_set', 'custo_clear', 'evolution_func',
        # NonTerminal description keys
        'weight', 'shape_type', 'section_type', 'duplicate_mode', 'weights',
        'separator', 'prefix', 'suffix', 'unique',
        'encoder',
        # Generator/Function description keys
        'node_args', 'other_args', 'provide_helpers', 'trigger_last',
        # Typed-node description keys
        'specific_fuzzy_vals',
        # Import description keys
        'import_from', 'data_id',
        # node properties description keys
        'determinist', 'random', 'finite', 'infinite', 'mutable',
        'clear_attrs', 'set_attrs',
        'absorb_csts', 'absorb_helper',
        'semantics', 'fuzz_weight',
        'sync_qty_with', 'qty_from',
        'exists_if', 'exists_if_not',
        'exists_if/and', 'exists_if/or',
        'sync_size_with', 'sync_enc_size_with',
        'post_freeze', 'charset',
        # used for debugging purpose
        'debug'
    ]

    def __init__(self, dm=None, delayed_jobs=True, add_env=True):
        """
        Help the process of data description. This class is able to construct a
        :class:`framework.data_model.Node` object from a JSON-like description.

        Args:
            dm (DataModel): a DataModel object, only required if the 'import_from' statement is used
              with :meth:`create_graph_from_desc`.
            delayed_jobs (bool): Enable or disabled delayed jobs feature. Used for instance for
              delaying constraint that cannot be solved immediately.
            add_env (bool): If `True`, an :class:`framework.data_model.Env` object
              will be assigned to the generated :class:`framework.data_model.Node`
              from :meth:`create_graph_from_desc`. Should be set to ``False`` if you consider using
              the generated `Node` within another description or if you will copy it for building
              a new node type. Keeping an ``Env()`` object can be dangerous if you make some clones of
              it and don't pay attention to set a new ``Env()`` for each copy, because. A graph node
              SHALL have only one ``Env()`` shared between all the nodes and an Env() shall not be
              shared between independent graph (otherwise it could lead to
              unexpected results).
        """
        self.dm = dm
        self.delayed_jobs = delayed_jobs
        self._add_env_to_the_node = add_env

    def _verify_keys_conformity(self, desc):
        for k in desc.keys():
            if k not in self.valid_keys:
                raise KeyError("The description key '{:s}' is not recognized!".format(k))


    def create_graph_from_desc(self, desc):
        self.sorted_todo = {}
        self.node_dico = {}
        self.empty_node = Node('EMPTY')

        n = self._create_graph_from_desc(desc, None)

        if self._add_env_to_the_node:
            self._register_todo(n, self._set_env, prio=self.LOW_PRIO)

        todo = self._create_todo_list()
        while todo:
            for node, func, args, unpack_args in todo:
                if isinstance(args, tuple) and unpack_args:
                    func(node, *args)
                else:
                    func(node, args)
            todo = self._create_todo_list()

        return n

    def _handle_name(self, name_desc):
        if isinstance(name_desc, (tuple, list)):
            assert(len(name_desc) == 2)
            name = name_desc[0]
            ident = name_desc[1]
        elif isinstance(name_desc, str):
            name = name_desc
            ident = 1
        else:
            raise ValueError("Name is not recognized: '%s'!" % name_desc)

        return name, ident


    def _create_graph_from_desc(self, desc, parent_node):

        def _get_type(top_desc, contents):
            pre_ntype = top_desc.get('type', None)
            if isinstance(contents, list) and pre_ntype in [None, MH.NonTerminal]:
                ntype = MH.NonTerminal
            elif isinstance(contents, Node) and pre_ntype in [None, MH.RawNode]:
                ntype = MH.RawNode
            elif hasattr(contents, '__call__') and pre_ntype in [None, MH.Generator]:
                ntype = MH.Generator
            elif isinstance(contents, six.string_types) and pre_ntype in [None, MH.Regex]:
                ntype = MH.Regex
            else:
                ntype = MH.Leaf
            return ntype

        self._verify_keys_conformity(desc)

        contents = desc.get('contents', None)
        dispatcher = {MH.NonTerminal: self._create_non_terminal_node,
                      MH.Regex: self._create_non_terminal_node_from_regex,
                      MH.Generator:  self._create_generator_node,
                      MH.Leaf: self._create_leaf_node,
                      MH.RawNode: self._update_provided_node}

        if contents is None:
            nd = self.__handle_clone(desc, parent_node)
        else:
            # Non-terminal are recognized via its contents (avoiding
            # the user to always provide a 'type' field)
            ntype = _get_type(desc, contents)
            nd = dispatcher.get(ntype)(desc)
            self.__post_handling(desc, nd)

        alt_confs = desc.get('alt', None)
        if alt_confs is not None:
            for alt in alt_confs:
                self._verify_keys_conformity(alt)
                cts = alt.get('contents')
                if cts is None:
                    raise ValueError("Cloning or referencing an existing node"\
                                     " into an alternate configuration is not supported")
                ntype = _get_type(alt, cts)
                # dispatcher.get(ntype)(alt, None, node=nd)
                dispatcher.get(ntype)(alt, node=nd)

        return nd

    def __handle_clone(self, desc, parent_node):
        if isinstance(desc.get('contents'), Node):
            name, ident = self._handle_name(desc['contents'].name)
        else:
            name, ident = self._handle_name(desc['name'])

        exp = desc.get('import_from', None)
        if exp is not None:
            assert self.dm is not None, "NodeBuilder should be initialized with the current data model!"
            data_id = desc.get('data_id', None)
            assert data_id is not None, "Missing field: 'data_id' (to be used with 'import_from' field)"
            nd = self.dm.get_external_atom(dm_name=exp, data_id=data_id, name=name)
            assert nd is not None, "The requested data ID '{:s}' does not exist!".format(data_id)
            self.node_dico[(name, ident)] = nd
            return nd

        nd = Node(name)
        clone_ref = desc.get('clone', None)
        if clone_ref is not None:
            ref = self._handle_name(clone_ref)
            self._register_todo(nd, self._clone_from_dict, args=(ref, desc),
                                prio=self.MEDIUM_PRIO)
            self.node_dico[(name, ident)] = nd
        else:
            ref = (name, ident)
            if ref in self.node_dico.keys():
                nd = self.node_dico[ref]
            else:
                # in this case nd.cc is still set to NodeInternals_Empty
                self._register_todo(nd, self._get_from_dict, args=(ref, parent_node),
                                    prio=self.HIGH_PRIO)

        return nd

    def __pre_handling(self, desc, node):
        if node:
            if isinstance(node.cc, NodeInternals_Empty):
                raise ValueError("Error: alternative configuration"\
                                 " cannot be added to empty node ({:s})".format(node.name))
            conf = desc['conf']
            node.add_conf(conf)
            n = node
        elif isinstance(desc['contents'], Node):
            n = desc['contents']
            conf = None
        else:
            conf = None
            ref = self._handle_name(desc['name'])
            if ref in self.node_dico:
                raise ValueError("name {!r} is already used!".format(ref))
            n = Node(ref[0])

        return n, conf

    def __post_handling(self, desc, node):
        if not isinstance(node.cc, NodeInternals_Empty):
            if isinstance(desc.get('contents'), Node):
                ref = self._handle_name(desc['contents'].name)
            else:
                ref = self._handle_name(desc['name'])
            self.node_dico[ref] = node

    def _update_provided_node(self, desc, node=None):
        n, conf = self.__pre_handling(desc, node)
        self._handle_custo(n, desc, conf)
        self._handle_common_attr(n, desc, conf)
        return n

    def _create_generator_node(self, desc, node=None):

        n, conf = self.__pre_handling(desc, node)

        contents = desc.get('contents')

        if hasattr(contents, '__call__'):
            other_args = desc.get('other_args', None)
            if hasattr(contents, 'provide_helpers') and contents.provide_helpers:
                provide_helpers = True
            else:
                provide_helpers = desc.get('provide_helpers', False)
            node_args = desc.get('node_args', None)
            n.set_generator_func(contents, func_arg=other_args,
                                 provide_helpers=provide_helpers, conf=conf)

            if hasattr(contents, 'unfreezable'):
                if contents.unfreezable:
                    n.clear_attr(MH.Attr.Freezable, conf=conf)
                else:
                    n.set_attr(MH.Attr.Freezable, conf=conf)

            if hasattr(contents, 'deterministic'):
                if contents.deterministic:
                    n.set_attr(MH.Attr.Determinist, conf=conf)
                else:
                    n.clear_attr(MH.Attr.Determinist, conf=conf)

            if node_args is not None:
                # node_args interpretation is postponed after all nodes has been created
                if isinstance(node_args, dict):
                    self._register_todo(n, self._complete_generator_from_desc, args=(node_args, conf), unpack_args=True,
                                        prio=self.HIGH_PRIO)

                else:
                    self._register_todo(n, self._complete_generator, args=(node_args, conf), unpack_args=True,
                                        prio=self.HIGH_PRIO)
        else:
            raise ValueError("*** ERROR: {:s} is an invalid contents!".format(repr(contents)))

        self._handle_custo(n, desc, conf)
        self._handle_common_attr(n, desc, conf)

        return n


    def _create_non_terminal_node_from_regex(self, desc, node=None):

        n, conf = self.__pre_handling(desc, node)

        name =  desc.get('name') if desc.get('name') is not None else node.name
        if isinstance(name, tuple):
            name = name[0]
        regexp =  desc.get('contents')

        parser = RegexParser()
        nodes = parser.parse(regexp, name, desc.get('charset'))

        if len(nodes) == 2 and len(nodes[1]) == 2 and (nodes[1][1][1] == nodes[1][1][2] == 1 or
                 isinstance(nodes[1][1][0], fvt.String) and nodes[1][1][0].alphabet is not None):
            n.set_values(value_type=nodes[1][1][0].internals[nodes[1][1][0].current_conf].value_type, conf=conf)
        else:
            n.set_subnodes_with_csts(nodes, conf=conf)

        self._handle_custo(n, desc, conf)

        sep_desc = desc.get('separator', None)
        if sep_desc is not None:
            sep_node_desc = sep_desc.get('contents', None)
            assert (sep_node_desc is not None)
            sep_node = self._create_graph_from_desc(sep_node_desc, n)
            prefix = sep_desc.get('prefix', True)
            suffix = sep_desc.get('suffix', True)
            unique = sep_desc.get('unique', False)
            n.set_separator_node(sep_node, prefix=prefix, suffix=suffix, unique=unique)

        self._handle_common_attr(n, desc, conf)

        return n


    def _create_non_terminal_node(self, desc, node=None):

        n, conf = self.__pre_handling(desc, node)

        shapes = []
        cts = desc.get('contents')
        if not cts:
            raise ValueError

        if isinstance(cts[0], (list,tuple)):
            # thus contains at least something that is not a
            # node_desc, that is directly a node. Thus, only one
            # shape!
            w = None
        else:
            w = cts[0].get('weight', None)

        if w is not None:
            # in this case there are multiple shapes, as shape can be
            # discriminated by its weight attr
            for s in desc.get('contents'):
                self._verify_keys_conformity(s)
                weight = s.get('weight', 1)
                shape = self._create_nodes_from_shape(s['contents'], n)
                shapes.append(weight)
                shapes.append(shape)
        else:
            # in this case there is only one shape
            shtype = desc.get('shape_type', MH.Ordered)
            dupmode = desc.get('duplicate_mode', MH.Copy)
            shape = self._create_nodes_from_shape(cts, n, shape_type=shtype,
                                                  dup_mode=dupmode)
            shapes.append(1)
            shapes.append(shape)

        n.set_subnodes_with_csts(shapes, conf=conf)

        self._handle_custo(n, desc, conf)

        sep_desc = desc.get('separator', None)
        if sep_desc is not None:
            sep_node_desc = sep_desc.get('contents', None)
            assert(sep_node_desc is not None)
            sep_node = self._create_graph_from_desc(sep_node_desc, n)
            prefix = sep_desc.get('prefix', True)
            suffix = sep_desc.get('suffix', True)
            unique = sep_desc.get('unique', False)
            n.set_separator_node(sep_node, prefix=prefix, suffix=suffix, unique=unique)

        self._handle_common_attr(n, desc, conf)

        return n


    def _create_nodes_from_shape(self, shapes, parent_node, shape_type=MH.Ordered, dup_mode=MH.Copy):

        def _handle_section(nodes_desc, sh):
            for n in nodes_desc:
                if isinstance(n, (list,tuple)) and (len(n) == 2 or len(n) == 3):
                    sh.append(list(n))
                elif isinstance(n, dict):
                    qty = n.get('qty', 1)
                    if isinstance(qty, tuple):
                        mini = qty[0]
                        maxi = qty[1]
                    elif isinstance(qty, int):
                        mini = qty
                        maxi = qty
                    else:
                        raise ValueError
                    l = [mini, maxi]
                    node = self._create_graph_from_desc(n, parent_node)
                    l.insert(0, node)
                    sh.append(l)
                else:
                    raise ValueError('Unrecognized section type!')

        sh = []
        prev_section_exist = False
        first_pass = True
        # Note that sections are not always materialised in the description
        for section_desc in shapes:

            # check if it is directly a node
            if isinstance(section_desc, (list,tuple)):
                if prev_section_exist or first_pass:
                    prev_section_exist = False
                    first_pass = False
                    sh.append(dup_mode + shape_type)
                _handle_section([section_desc], sh)

            # check if it is a section description
            elif section_desc.get('name') is None and not isinstance(section_desc.get('contents'), Node):
                prev_section_exist = True
                self._verify_keys_conformity(section_desc)
                sec_type = section_desc.get('section_type', MH.Ordered)
                dupmode = section_desc.get('duplicate_mode', MH.Copy)
                # TODO: revamp weights
                weights = ''.join(str(section_desc.get('weights', '')).split(' '))
                sh.append(dupmode+sec_type+weights)
                _handle_section(section_desc.get('contents', []), sh)

            # if 'name' attr is present, it is not a section in the
            # shape, thus we adopt the default sequencing of nodes.
            else:
                if prev_section_exist or first_pass:
                    prev_section_exist = False
                    first_pass = False
                    sh.append(dup_mode + shape_type)
                _handle_section([section_desc], sh)

        return sh


    def _create_leaf_node(self, desc, node=None):

        n, conf = self.__pre_handling(desc, node)

        contents = desc.get('contents')

        if issubclass(contents.__class__, fvt.VT):
            if hasattr(contents, 'usable') and contents.usable == False:
                raise ValueError("ERROR: {:s} is not usable! (use a subclass of it)".format(repr(contents)))
            n.set_values(value_type=contents, conf=conf)
        elif hasattr(contents, '__call__'):
            other_args = desc.get('other_args', None)
            provide_helpers = desc.get('provide_helpers', False)
            node_args = desc.get('node_args', None)
            n.set_func(contents, func_arg=other_args,
                       provide_helpers=provide_helpers, conf=conf)

            # node_args interpretation is postponed after all nodes has been created
            self._register_todo(n, self._complete_func, args=(node_args, conf), unpack_args=True,
                                prio=self.HIGH_PRIO)

        else:
            raise ValueError("ERROR: {:s} is an invalid contents!".format(repr(contents)))

        self._handle_custo(n, desc, conf)
        self._handle_common_attr(n, desc, conf)

        return n

    def _handle_custo(self, node, desc, conf):
        custo_set = desc.get('custo_set', None)
        custo_clear = desc.get('custo_clear', None)
        transform_func = desc.get('evolution_func', None)

        if node.is_genfunc(conf=conf):
            Custo = GenFuncCusto
            trig_last = desc.get('trigger_last', None)
            if trig_last is not None:
                if trig_last:
                    if custo_set is None:
                        custo_set = []
                    elif not isinstance(custo_set, list):
                        custo_set = [custo_set]
                    custo_set.append(MH.Custo.Gen.TriggerLast)
                else:
                    if custo_clear is None:
                        custo_clear = []
                    elif not isinstance(custo_clear, list):
                        custo_clear = [custo_clear]
                    custo_clear.append(MH.Custo.Gen.TriggerLast)

        elif node.is_nonterm(conf=conf):
            Custo = NonTermCusto

        elif node.is_func(conf=conf):
            Custo = FuncCusto

        else:
            if custo_set or custo_clear:
                raise DataModelDefinitionError('Customization is not compatible with this '
                                               'node kind! [Guilty Node: {:s}]'.format(node.name))
            else:
                return

        if custo_set or custo_clear or transform_func:
            custo = Custo(items_to_set=custo_set, items_to_clear=custo_clear,
                          transform_func=transform_func)
            internals = node.conf(conf)
            internals.customize(custo)


    def _handle_common_attr(self, node, desc, conf):
        vals = desc.get('specific_fuzzy_vals', None)
        if vals is not None:
            if not node.is_typed_value(conf=conf):
                raise DataModelDefinitionError("'specific_fuzzy_vals' is only usable with Typed-nodes")
            node.conf(conf).set_specific_fuzzy_values(vals)
        param = desc.get('mutable', None)
        if param is not None:
            if param:
                node.set_attr(MH.Attr.Mutable, conf=conf)
            else:
                node.clear_attr(MH.Attr.Mutable, conf=conf)
        param = desc.get('debug', None)
        if param is not None:
            if param:
                node.set_attr(MH.Attr.DEBUG, conf=conf)
            else:
                node.clear_attr(MH.Attr.DEBUG, conf=conf)
        param = desc.get('determinist', None)
        if param is not None:
            node.make_determinist(conf=conf)
        param = desc.get('random', None)
        if param is not None:
            node.make_random(conf=conf)
        param = desc.get('finite', None)
        if param is not None:
            node.make_finite(conf=conf)
        param = desc.get('infinite', None)
        if param is not None:
            node.make_infinite(conf=conf)
        param = desc.get('clear_attrs', None)
        if param is not None:
            if isinstance(param, (list, tuple)):
                for a in param:
                    node.clear_attr(a, conf=conf)
            else:
                node.clear_attr(param, conf=conf)
        param = desc.get('set_attrs', None)
        if param is not None:
            if isinstance(param, (list, tuple)):
                for a in param:
                    node.set_attr(a, conf=conf)
            else:
                node.set_attr(param, conf=conf)
        param = desc.get('absorb_csts', None)
        if param is not None:
            node.enforce_absorb_constraints(param, conf=conf)
        param = desc.get('absorb_helper', None)
        if param is not None:
            node.set_absorb_helper(param, conf=conf)
        param = desc.get('semantics', None)
        if param is not None:
            node.set_semantics(NodeSemantics(param))
        ref = desc.get('sync_qty_with', None)
        if ref is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(ref, SyncScope.Qty, conf, None),
                                unpack_args=True)
        qty_from = desc.get('qty_from', None)
        if qty_from is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(qty_from, SyncScope.QtyFrom, conf, None),
                                unpack_args=True)

        sync_size_with = desc.get('sync_size_with', None)
        sync_enc_size_with = desc.get('sync_enc_size_with', None)
        assert sync_size_with is None or sync_enc_size_with is None
        if sync_size_with is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(sync_size_with, SyncScope.Size, conf, False),
                                unpack_args=True)
        if sync_enc_size_with is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(sync_enc_size_with, SyncScope.Size, conf, True),
                                unpack_args=True)
        condition = desc.get('exists_if', None)
        if condition is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(condition, SyncScope.Existence, conf, None),
                                unpack_args=True)
        condition = desc.get('exists_if/and', None)
        if condition is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(condition, SyncScope.Existence, conf, 'and'),
                                unpack_args=True)
        condition = desc.get('exists_if/or', None)
        if condition is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(condition, SyncScope.Existence, conf, 'or'),
                                unpack_args=True)
        condition = desc.get('exists_if_not', None)
        if condition is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(condition, SyncScope.Inexistence, conf, None),
                                unpack_args=True)
        fw = desc.get('fuzz_weight', None)
        if fw is not None:
            node.set_fuzz_weight(fw)
        pfh = desc.get('post_freeze', None)
        if pfh is not None:
            node.register_post_freeze_handler(pfh)
        encoder = desc.get('encoder', None)
        if encoder is not None:
            node.set_encoder(encoder)

    def _register_todo(self, node, func, args=None, unpack_args=True, prio=VERYLOW_PRIO):
        if self.sorted_todo.get(prio, None) is None:
            self.sorted_todo[prio] = []
        self.sorted_todo[prio].insert(0, (node, func, args, unpack_args))

    def _create_todo_list(self):
        todo = []
        tdl = sorted(self.sorted_todo.items(), key=lambda x: x[0])
        self.sorted_todo = {}
        for prio, sub_tdl in tdl:
            todo += sub_tdl
        return todo

    # Should be called at the last time to avoid side effects (e.g.,
    # when creating generator/function nodes, the node arguments are
    # provided at a later time. If set_contents()---which copy nodes---is called
    # in-between, node arguments risk to not be copied)
    def _clone_from_dict(self, node, ref, desc):
        if ref not in self.node_dico:
            raise ValueError("arguments refer to an inexistent node ({:s}, {!s})!".format(ref[0], ref[1]))
        node.set_contents(self.node_dico[ref], preserve_node=False)
        self._handle_custo(node, desc, conf=None)
        self._handle_common_attr(node, desc, conf=None)

    def _get_from_dict(self, node, ref, parent_node):
        if ref not in self.node_dico:
            raise ValueError("arguments refer to an inexistent node ({:s}, {!s})!".format(ref[0], ref[1]))
        parent_node.replace_subnode(node, self.node_dico[ref])

    def _set_sync_node(self, node, comp, scope, conf, private):
        sync_obj = None

        if scope == SyncScope.QtyFrom:
            if isinstance(comp, (tuple,list)):
                node_ref, base_qty = comp
            else:
                node_ref, base_qty = comp, 0
            sync_with = self.__get_node_from_db(node_ref)
            sync_obj = SyncQtyFromObj(sync_with, base_qty=base_qty)

        elif scope == SyncScope.Size:
            if isinstance(comp, (tuple,list)):
                node_ref, base_size = comp
            else:
                node_ref, base_size = comp, 0
            sync_with = self.__get_node_from_db(node_ref)
            sync_obj = SyncSizeObj(sync_with, base_size=base_size,
                                   apply_to_enc_size=private)
        else:
            if isinstance(comp, (tuple,list)):
                if issubclass(comp[0].__class__, NodeCondition):
                    param = comp[0]
                    sync_with = self.__get_node_from_db(comp[1])
                elif issubclass(comp[0].__class__, (tuple,list)):
                    assert private in ['and', 'or']
                    sync_list = []
                    for subcomp in comp:
                        assert isinstance(subcomp, (tuple,list)) and len(subcomp) == 2
                        param = subcomp[0]
                        sync_with = self.__get_node_from_db(subcomp[1])
                        sync_list.append((sync_with, param))
                    and_junction = private == 'and'
                    sync_obj = SyncExistenceObj(sync_list, and_junction=and_junction)
                else:  # in this case this is a node reference in the form ('node name', ID)
                    param = None
                    sync_with = self.__get_node_from_db(comp)
            else:
                param = None
                sync_with = self.__get_node_from_db(comp)

        if sync_obj is not None:
            node.make_synchronized_with(scope=scope, sync_obj=sync_obj, conf=conf)
        else:
            node.make_synchronized_with(scope=scope, node=sync_with, param=param, conf=conf)

    def _complete_func(self, node, args, conf):
        if isinstance(args, str):
            func_args = self.__get_node_from_db(args)
        else:
            assert(isinstance(args, (tuple, list)))
            func_args = []
            for name_desc in args:
                func_args.append(self.__get_node_from_db(name_desc))
        internals = node.cc if conf is None else node.c[conf]
        internals.set_func_arg(node=func_args)

    def _complete_generator(self, node, args, conf):
        if isinstance(args, str) or \
           (isinstance(args, tuple) and isinstance(args[1], int)):
            func_args = self.__get_node_from_db(args)
        else:
            assert(isinstance(args, (tuple, list)))
            func_args = []
            for name_desc in args:
                func_args.append(self.__get_node_from_db(name_desc))
        internals = node.cc if conf is None else node.c[conf]
        internals.set_generator_func_arg(generator_node_arg=func_args)

    def _complete_generator_from_desc(self, node, args, conf):
        node_args = self._create_graph_from_desc(args, None)
        internals = node.cc if conf is None else node.c[conf]
        internals.set_generator_func_arg(generator_node_arg=node_args)

    def _set_env(self, node, args):
        env = Env()
        env.delayed_jobs_enabled = self.delayed_jobs
        node.set_env(env)

    def __get_node_from_db(self, name_desc):
        ref = self._handle_name(name_desc)
        if ref not in self.node_dico:
            raise ValueError("arguments refer to an inexistent node ({:s}, {!s})!".format(ref[0], ref[1]))

        node = self.node_dico[ref]
        if isinstance(node.cc, NodeInternals_Empty):
            raise ValueError("Node ({:s}, {!s}) is Empty!".format(ref[0], ref[1]))

        return node


class State(object):
    """
    Represent states at the lower level
    """

    def __init__(self, machine):
        """
        Args:
            machine (StateMachine): state machine where it lives (local context)
        """
        self.machine = machine
        self.init_specific()

    def init_specific(self):
        """
        Can be overridden to express additional initializations
        """
        pass

    def _run(self, context):
        raise NotImplementedError

    def run(self, context):
        """
        Do some actions on the current character.
        Args:
            context (StateMachine): root state machine (global context)
        """
        if context.input is not None and \
                ((context.charset == MH.Charset.ASCII and ord(context.input) > 0x7F) or
                     (context.charset == MH.Charset.ASCII_EXT and ord(context.input) > 0xFF)):
            raise CharsetError()
        self._run(context)
        context.inputs.pop(0)

    def advance(self, context):
        """
        Check transitions using the first non-run character.
        Args:
            context (StateMachine): root state machine (global context)

        Returns:
            Class of the next state de run (None if we are in a final state)
        """
        raise NotImplementedError


class StateMachine(State):
    """
    Represent states that contain other states.
    """

    def __init__(self, machine=None):
        self.states = {}
        self.inputs = None

        for name, cls in inspect.getmembers(self.__class__):
            if inspect.isclass(cls) and issubclass(cls, State) and hasattr(cls, 'INITIAL'):
                self.states[cls] = cls(self)

        State.__init__(self, self if machine is None else machine)

    @property
    def input(self):
        return None if self.inputs is None or len(self.inputs) == 0 else self.inputs[0]

    def _run(self, context):
        while self.state is not None:
            self.state.run(context)
            next_state = self.state.advance(context)
            self.state = self.states[next_state] if next_state is not None else None

    def run(self, context):
        for state in self.states:
            if state.INITIAL:
                self.state = self.states[state]
                break
        else:
            raise InitialStateNotFoundError()

        self._run(context)


def register(cls):
    cls.INITIAL = False
    return cls


def initial(cls):
    cls.INITIAL = True
    return cls


class RegexParser(StateMachine):

    @initial
    class Initial(State):

        def _run(self, ctx):
            pass

        def advance(self, ctx):
            if ctx.input in ('?', '*', '+', '{'):
                raise QuantificationError()
            elif ctx.input in ('}', ')', ']'):
                raise StructureError(ctx.input)
            else:
                ctx.append_to_contents("")

                if ctx.input == '[':
                    return self.machine.SquareBrackets
                elif ctx.input == '(':
                    return self.machine.Parenthesis
                elif ctx.input == '.':
                    return self.machine.Dot
                elif ctx.input == '\\':
                    return self.machine.Escape
                elif ctx.input == '|':
                    return self.machine.Choice
                elif ctx.input is None:
                    return self.machine.Final
                else:
                    return self.machine.Main

    @register
    class Choice(Initial):

        def _run(self, ctx):
            ctx.start_new_shape()

    @register
    class Final(State):

        def _run(self, ctx):
            ctx.flush()

        def advance(self, ctx):
            return None

    @register
    class Main(State):

        def _run(self, ctx):
            ctx.append_to_buffer(ctx.input)

        def advance(self, ctx):

            if ctx.input == '.':
                return self.machine.Dot
            elif ctx.input == '\\':
                return self.machine.Escape
            elif ctx.input == '|':

                if len(ctx.current_shape) > 0:
                    ctx.flush()

                return self.machine.Choice

            elif ctx.input == '(':
                return self.machine.Parenthesis
            elif ctx.input == '[':
                return self.machine.SquareBrackets

            elif ctx.input in ('?', '*', '+', '{'):

                ctx.start_new_shape_from_buffer()

                if len(ctx.buffer) > 1:
                    char = ctx.buffer[-1]
                    ctx.buffer = ctx.buffer[:-1]
                    ctx.flush()
                    ctx.append_to_buffer(char)

                if ctx.input == '{':
                    return self.machine.Brackets
                else:
                    return self.machine.QtyState

            elif ctx.input in ('}', ')', ']'):
                raise StructureError(ctx.input)
            elif ctx.input is None:
                return self.machine.Final

            return self.machine.Main

    @register
    class QtyState(State):

        def _run(self, ctx):
            ctx.min = 1 if ctx.input == '+' else 0
            ctx.max = 1 if ctx.input == '?' else None

            ctx.flush()

        def advance(self, ctx):
            if ctx.input in ('?', '*', '+', '{'):
                raise QuantificationError()
            elif ctx.input in ('}', ')', ']'):
                raise StructureError(ctx.input)
            elif ctx.input == '|':
                return self.machine.Choice
            elif ctx.input is None:
                return self.machine.Final

            ctx.append_to_contents("")

            if ctx.input == '(':
                return self.machine.Parenthesis
            elif ctx.input == '[':
                return self.machine.SquareBrackets
            elif ctx.input == '.':
                return self.machine.Dot
            elif ctx.input == '\\':
                return self.machine.Escape
            else:
                return self.machine.Main

    @register
    class Brackets(StateMachine, QtyState):

        @initial
        class Initial(State):

            def _run(self, ctx):
                ctx.min = ""

            def advance(self, ctx):
                if ctx.input.isdigit():
                    return self.machine.Min
                else:
                    raise QuantificationError()

        @register
        class Min(State):

            def _run(self, ctx):
                ctx.min += ctx.input

            def advance(self, context):
                if context.input.isdigit():
                    return self.machine.Min
                elif context.input == ',':
                    return self.machine.Comma
                elif context.input == '}':
                    return self.machine.Final
                else:
                    raise QuantificationError()

        @register
        class Max(State):

            def _run(self, ctx):
                ctx.max += ctx.input

            def advance(self, context):
                if context.input.isdigit():
                    return self.machine.Max
                elif context.input == '}':
                    return self.machine.Final
                else:
                    raise QuantificationError()

        @register
        class Comma(Max):

            def _run(self, ctx):
                ctx.max = ""

        @register
        class Final(State):
            def _run(self, ctx):
                ctx.min = int(ctx.min)

                if ctx.max is None:
                    ctx.max = ctx.min
                elif len(ctx.max) == 0:
                    ctx.max = None
                else:
                    ctx.max = int(ctx.max)

                if ctx.max is not None and ctx.min > ctx.max:
                    raise QuantificationError(u"{X,Y}: X \u2264 Y constraint not respected.")

                ctx.flush()

            def advance(self, context):
                return None

        def advance(self, ctx):
            return self.machine.QtyState.advance(self, ctx)

    class Group(State):

        def advance(self, ctx):
            if ctx.input in (')', '}', ']'):
                raise StructureError(ctx.input)

            elif ctx.input in ('*', '+', '?'):
                return self.machine.QtyState
            elif ctx.input == '{':
                return self.machine.Brackets
            else:
                ctx.flush()

            if ctx.input == '|':
                return self.machine.Choice
            elif ctx.input is None:
                return self.machine.Final

            ctx.append_to_contents("")

            if ctx.input == '(':
                return self.machine.Parenthesis
            elif ctx.input == '[':
                return self.machine.SquareBrackets
            elif ctx.input == '.':
                return self.machine.Dot
            elif ctx.input == '\\':
                return self.machine.Escape
            else:
                return self.machine.Main

    @register
    class Parenthesis(StateMachine, Group):

        @initial
        class Initial(State):

            def _run(self, ctx):
                ctx.start_new_shape_from_buffer()
                if len(ctx.buffer) > 0:
                    ctx.flush()
                    ctx.append_to_contents("")

            def advance(self, ctx):
                if ctx.input in ('?', '*', '+', '{'):
                    raise QuantificationError()
                elif ctx.input in ('}', ']', None):
                    raise StructureError(ctx.input)
                elif ctx.input in ('(', '[', '.'):
                    raise InconvertibilityError()
                elif ctx.input == '\\':
                    return self.machine.Escape
                elif ctx.input == ')':
                    return self.machine.Final
                elif ctx.input == '|':
                    return self.machine.Choice
                else:
                    return self.machine.Main

        @register
        class Final(State):

            def _run(self, context):
                pass

            def advance(self, context):
                return None

        @register
        class Main(Initial):
            def _run(self, ctx):
                ctx.append_to_buffer(ctx.input)

            def advance(self, ctx):
                if ctx.input in ('?', '*', '+', '{'):
                    raise InconvertibilityError()

                return self.machine.Initial.advance(self, ctx)

        @register
        class Choice(Initial):

            def _run(self, ctx):
                ctx.append_to_contents("")

            def advance(self, ctx):
                if ctx.input in ('?', '*', '+', '{'):
                    raise QuantificationError()

                return self.machine.Initial.advance(self, ctx)

        @register
        class Escape(State):

            def _run(self, ctx):
                pass

            def advance(self, ctx):
                if ctx.input in ctx.META_SEQUENCES:
                    raise InconvertibilityError()
                elif ctx.input in ctx.SPECIAL_CHARS:
                    return self.machine.Main
                else:
                    raise EscapeError(ctx.input)

    @register
    class SquareBrackets(StateMachine, Group):

        @initial
        class Initial(State):

            def _run(self, ctx):
                ctx.start_new_shape_from_buffer()
                if len(ctx.buffer) > 0:
                    ctx.flush()
                else:
                    ctx.values = None

                ctx.append_to_alphabet("")

            def advance(self, ctx):
                if ctx.input in ('?', '*', '+', '{'):
                    raise QuantificationError()
                elif ctx.input in ('}', ')', None):
                    raise StructureError(ctx.input)
                elif ctx.input in ('(', '['):
                    raise InconvertibilityError()
                elif ctx.input == '-':
                    raise InvalidRangeError()
                elif ctx.input == ']':
                    raise EmptyAlphabetError()
                elif ctx.input == '\\':
                    return self.machine.EscapeBeforeRange
                else:
                    return self.machine.BeforeRange

        @register
        class Final(State):

            def _run(self, ctx):
                pass

            def advance(self, ctx):
                return None

        @register
        class BeforeRange(Initial):
            def _run(self, ctx):
                ctx.append_to_alphabet(ctx.input)

            def advance(self, ctx):
                if ctx.input == ']':
                    return self.machine.Final
                elif ctx.input == '-':
                    return self.machine.Range
                else:
                    return self.machine.Initial.advance(self, ctx)

        @register
        class Range(State):
            def _run(self, ctx):
                pass

            def advance(self, ctx):
                if ctx.input in ('?', '*', '+', '{', '}', '(', ')', '[', ']', '|', '-', None):
                    raise InvalidRangeError()
                elif ctx.input == '\\':
                    return self.machine.EscapeAfterRange
                else:
                    return self.machine.AfterRange

        @register
        class AfterRange(Initial):
            def _run(self, ctx):
                if ctx.alphabet[-1] > ctx.input:
                    raise InvalidRangeError()
                elif ctx.input == ctx.alphabet[-1]:
                    pass
                else:
                    for i in range(ord(ctx.alphabet[-1]) + 1, ord(ctx.input) + 1):
                        ctx.append_to_alphabet(ctx.int_to_string(i))

            def advance(self, ctx):
                if ctx.input == ']':
                    return self.machine.Final
                else:
                    return self.machine.Initial.advance(self, ctx)

        @register
        class EscapeBeforeRange(State):

            def _run(self, ctx):
                pass

            def advance(self, ctx):
                if ctx.input in ctx.META_SEQUENCES:
                    return self.machine.EscapeMetaSequence
                elif ctx.input in ctx.SPECIAL_CHARS:
                    return self.machine.BeforeRange
                else:
                    raise EscapeError(ctx.input)

        @register
        class EscapeMetaSequence(BeforeRange):

            def _run(self, ctx):
                ctx.append_to_alphabet(ctx.META_SEQUENCES[ctx.input])

        @register
        class EscapeAfterRange(State):

            def _run(self, ctx):
                pass

            def advance(self, ctx):
                if ctx.input in ctx.META_SEQUENCES:
                    raise InvalidRangeError()
                elif ctx.input in ctx.SPECIAL_CHARS:
                    return self.machine.AfterRange
                else:
                    raise EscapeError(ctx.input)

    @register
    class Escape(State):

        def _run(self, ctx):
            pass

        def advance(self, ctx):
            if ctx.input in ctx.META_SEQUENCES:
                return self.machine.EscapeMetaSequence
            elif ctx.input in ctx.SPECIAL_CHARS:
                return self.machine.Main
            else:
                raise EscapeError(ctx.input)

    @register
    class EscapeMetaSequence(Group):

        def _run(self, ctx):

            ctx.start_new_shape_from_buffer()
            if len(ctx.buffer) > 0:
                ctx.flush()
            else:
                ctx.values = None

            ctx.append_to_alphabet(ctx.META_SEQUENCES[ctx.input])

    @register
    class Dot(Group):

        def _run(self, ctx):

            ctx.start_new_shape_from_buffer()
            if len(ctx.buffer) > 0:
                ctx.flush()
            else:
                ctx.values = None

            ctx.append_to_alphabet(ctx.get_complement(""))


    def init_specific(self):
        self._name = None
        self.charset = None

        self.values = None
        self.alphabet = None

        self.min = None
        self.max = None

        self.shapes = [[]]
        self.current_shape = self.shapes[0]


    def start_new_shape_from_buffer(self):
        if self.values is not None and len(self.values) > 1:
            buffer = self.buffer
            self.values = self.values[:-1]
            self.flush()

            self.start_new_shape()
            self.append_to_buffer(buffer)

    def start_new_shape(self):
        if len(self.current_shape) > 0:
            self.shapes.append([])
            self.current_shape = self.shapes[-1]

    def append_to_contents(self, content):
        if self.values is None:
            self.values = []
        self.values.append(content)

    def append_to_buffer(self, str):
        if self.values is None:
            self.values = [""]
        if self.values[-1] is None:
            self.values[-1] = ""
        self.values[-1] += str

    def append_to_alphabet(self, alphabet):
        if self.alphabet is None:
            self.alphabet = ""
        self.alphabet += alphabet

    @property
    def buffer(self):
        return None if self.values is None else self.values[-1]

    @buffer.setter
    def buffer(self, buffer):
        if self.values is None:
            self.values = [""]
        self.values[-1] = buffer

    def flush(self):

        if self.values is None and self.alphabet is None:
            return

        # set default values for min & max if none was provided
        if self.min is None and self.max is None:
            self.min = self.max = 1

        # guess the type of the terminal node to create
        if self.values is not None and all(val.isdigit() for val in self.values):
            self.values = [int(i) for i in self.values]
            type = fvt.INT_str
        else:
            type = fvt.String

        node_nb = 0
        for nodes in self.shapes:
            node_nb += len(nodes)

        name = self._name + '_' + str(node_nb + 1)
        self.current_shape.append(self._create_terminal_node(name, type,
                                                             values=self.values,
                                                             alphabet=self.alphabet,
                                                             qty=(self.min, self.max)))
        self.reset()

    def reset(self):
        self.values = None
        self.alphabet = None
        self.min = None
        self.max = None

    def parse(self, inputs, name, charset=MH.Charset.ASCII_EXT):
        self._name = name
        self.charset = charset
        self.int_to_string = chr if sys.version_info[0] == 2 and self.charset != MH.Charset.UNICODE else six.unichr

        if self.charset == MH.Charset.ASCII:
            max = 0x7F
            self.codec = 'ascii'
        elif self.charset == MH.Charset.UNICODE:
            max = 0xFFFF
            self.codec = 'utf8'
        else:
            max = 0xFF
            self.codec = 'latin-1'

        def get_complement(chars):
            return ''.join([self.int_to_string(i) for i in range(0, max + 1) if self.int_to_string(i) not in chars])
        self.get_complement = get_complement

        self.META_SEQUENCES = {'s': string.whitespace,
                               'S': get_complement(string.whitespace),
                               'd': string.digits,
                               'D': get_complement(string.digits),
                               'w': string.ascii_letters + string.digits + '_',
                               'W': get_complement(string.ascii_letters + string.digits + '_')}

        self.SPECIAL_CHARS = list('\\()[]{}*+?|-.')

        # None indicates the beginning and the end of the regex
        self.inputs = [None] + list(inputs) + [None]
        self.run(self)

        return self._create_non_terminal_node()

    def _create_terminal_node(self, name, type, values=None, alphabet=None, qty=None):

        assert (values is not None or alphabet is not None)

        if alphabet is not None:
            return [Node(name=name,
                         vt=fvt.String(alphabet=alphabet, min_sz=qty[0], max_sz=qty[1],
                                       codec=self.codec)), 1, 1]
        else:
            if type == fvt.String:
                node = Node(name=name, vt=fvt.String(values=values, codec=self.codec))
            else:
                node = Node(name=name, vt=fvt.INT_str(values=values))

            return [node, qty[0], -1 if qty[1] is None else qty[1]]

    def _create_non_terminal_node(self):

        if len(self.shapes) == 1:
            non_terminal = [1, [MH.Copy + MH.Ordered] + self.shapes[0]]
        elif all(len(nodes) == 1 for nodes in self.shapes):
            non_terminal = [1, [MH.Copy + MH.Pick] + [nodes[0] for nodes in self.shapes]]
        else:
            non_terminal = []
            for nodes in self.shapes:
                non_terminal += [1, [MH.Copy + MH.Ordered] + nodes]

        return non_terminal