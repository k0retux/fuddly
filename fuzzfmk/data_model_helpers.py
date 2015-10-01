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

from fuzzfmk.data_model import *
import fuzzfmk.value_types as fvt
from fuzzfmk.value_types import VT

from libs.external_modules import *

import traceback
import datetime
import types

################################
# ModelWalker Helper Functions #
################################

GENERIC_ARGS = {
    'init': ('make the model walker ignore all the steps until the provided one', 1, int),
    'max_steps': ('maximum number of steps (-1 means until the end)', -1, int),
    'runs_per_node': ('maximum number of test cases for a single node (-1 means until the end)', -1, int),
    'clone_node': ('if True the dmaker will always return a copy ' \
                   'of the node. (for stateless diruptors dealing with ' \
                   'big data it can be usefull to it to False)', True, bool)
}

def modelwalker_inputs_handling_helper(dmaker, user_generic_input):

    assert(dmaker.runs_per_node > 0 or dmaker.runs_per_node == -1)

    if dmaker.runs_per_node == -1:
        dmaker.max_runs_per_node = -1
        dmaker.min_runs_per_node = -1
    else:
        dmaker.max_runs_per_node = dmaker.runs_per_node + 3
        dmaker.min_runs_per_node = max(dmaker.runs_per_node - 2, 1)


#####################
# Data Model Helper #
#####################

class MH:
    # node type attribute
    NonTerminal = 1
    Generator = 2
    Leaf = 3

    # shape_type & section_type attribute
    Ordered = '>'
    Random = '=..'
    FullyRandom = '=.'
    Pick = '=+'

    # duplicate_mode attribute
    Copy = 'u'
    ZeroCopy = 's'

    # Function node (leaf) mode
    FrozenArgs = 1
    RawArgs = 2

    # NonTerminal node mode
    NotMutableClone = 1
    MutableClone = 2

    ###########################
    ### Generator Templates ###
    ###########################

    @staticmethod
    def LEN(vt=fvt.INT_str):
        '''
        Return a *generator* that returns the length of a node parameter.

        Args:
          vt (type): value type used for node generation (refer to :mod:`fuzzfmk.value_types`)
        '''
        def length(vt, node):
            n = Node('cts', value_type=vt(int_list=[len(node.to_bytes())]))
            n.set_semantics(NodeSemantics(['len']))
            return n

        vt = MH._validate_int_vt(vt)
        return functools.partial(length, vt)

    @staticmethod
    def QTY(node_name, vt=fvt.INT_str):
        '''Return a *generator* that returns the quantity of child node instances (referenced
        by name) of the node parameter provided to the *generator*.

        Args:
          vt (type): value type used for node generation (refer to :mod:`fuzzfmk.value_types`)
          node_name (str): name of the child node whose instance amount will be returned
            by the generator
        '''
        def qty(node_name, vt, node):
            nb = node.cc.get_drawn_node_qty(node_name)
            n = Node('cts', value_type=vt(int_list=[nb]))
            n.set_semantics(NodeSemantics(['qty']))
            return n

        vt = MH._validate_int_vt(vt)
        return functools.partial(qty, node_name, vt)

    @staticmethod
    def TIMESTAMP(time_format="%H%M%S", utc=False):
        '''
        Return a *generator* that returns the current time (in a String-type node).

        Args:
          time_format (str): time format to be used by the generator.
        '''
        def timestamp(time_format, utc):
            if utc:
                now = datetime.datetime.utcnow()
            else:
                now = datetime.datetime.now()
            ts = now.strftime(time_format)
            n = Node('cts', value_type=fvt.String(val_list=[ts], size=len(ts)))
            n.set_semantics(NodeSemantics(['timestamp']))
            return n
        
        return functools.partial(timestamp, time_format, utc)

    @staticmethod
    def CRC(vt=fvt.INT_str, poly=0x104c11db7, init_crc=0, xor_out=0xFFFFFFFF, rev=True):
        '''Return a *generator* that returns the CRC (in the chosen type) of
        all the node parameters. (Default CRC is PKZIP CRC32)

        Args:
          vt (type): value type used for node generation (refer to :mod:`fuzzfmk.value_types`)
          poly (int): CRC polynom
          init_crc (int): initial value used to start the CRC calculation.
          xor_out (int): final value to XOR with the calculated CRC value.
          rev (bool): bit reversed algorithm when `True`.
        '''
        def crc(vt, poly, init_crc, xor_out, rev, nodes):
            crc_func = crcmod.mkCrcFun(poly, initCrc=init_crc, xorOut=xor_out, rev=rev)
            if isinstance(nodes, Node):
                s = nodes.to_bytes()
            else:
                if issubclass(nodes.__class__, NodeAbstraction):
                    nodes = nodes.get_concrete_nodes()
                elif not isinstance(nodes, tuple) and not isinstance(nodes, list):
                    raise TypeError("Contents of 'nodes' parameter is incorrect!")
                s = b''
                for n in nodes:
                    s += n.to_bytes()

            result = crc_func(s)

            n = Node('cts', value_type=vt(int_list=[result]))
            n.set_semantics(NodeSemantics(['crc']))
            return n

        if not crcmod_module:
            raise NotImplementedError('the CRC template has been disabled because python-crcmod module is not installed!')

        vt = MH._validate_int_vt(vt)
        return functools.partial(crc, vt, poly, init_crc, xor_out, rev)


    @staticmethod
    def _validate_int_vt(vt):
        if not issubclass(vt, fvt.INT):
            print("*** WARNING: the value type of typed node requested is not supported!" \
                  " Use of 'INT_str' instead.")
            vt = fvt.INT_str             
        return vt



class ModelHelper(object):

    HIGH_PRIO = 1
    MEDIUM_PRIO = 2
    LOW_PRIO = 3
    VERYLOW_PRIO = 4

    valid_keys = [
        # generic description keys
        'name', 'contents', 'qty', 'clone', 'type', 'alt', 'conf', 'mode',
        # NonTerminal description keys
        'weight', 'shape_type', 'section_type', 'duplicate_mode', 'weights',
        'separator', 'prefix', 'suffix', 'unique',
        # Generator/Function description keys
        'node_args', 'other_args', 'provide_helpers',
        # Export description keys
        'export_from', 'data_id',        
        # node properties description keys
        'determinist', 'random', 'clear_attrs', 'set_attrs',
        'absorb_csts', 'absorb_helper',
        'semantics', 'fuzz_weight',
        'sync_qty_with', 'exists_if', 'exists_if_not',
        'post_freeze'
    ]

    def __init__(self, dm=None):
        self.dm = dm

    def _verify_keys_conformity(self, desc):
        for k in desc.keys():
            if k not in self.valid_keys:
                raise KeyError("The description key '{:s}' is not recognized!".format(k))


    def create_graph_from_desc(self, desc):
        self.sorted_todo = {}
        self.node_dico = {}
        self.empty_node = Node('EMPTY')
        
        n = self._create_graph_from_desc(desc, None)

        self._register_todo(n, self._set_env, prio=self.LOW_PRIO)
        self._create_todo_list()

        for node, func, args, unpack_args in self.todo:
            if isinstance(args, tuple) and unpack_args:
                func(node, *args)
            else:
                func(node, args)

        return n

    def _handle_name(self, name_desc):
        if isinstance(name_desc, tuple) or isinstance(name_desc, list):
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
            elif hasattr(contents, '__call__') and pre_ntype in [None, MH.Generator]:
                ntype = MH.Generator
            else:
                ntype = MH.Leaf
            return ntype

        self._verify_keys_conformity(desc)

        contents = desc.get('contents', None)
        dispatcher = {MH.NonTerminal: self._create_non_terminal_node,
                      MH.Generator:  self._create_generator_node,
                      MH.Leaf:  self._create_leaf_node}

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
        name, ident = self._handle_name(desc['name'])

        exp = desc.get('export_from', None)
        if exp is not None:
            assert self.dm is not None, "ModelHelper should be initialized with the current data model!"
            data_id = desc.get('data_id', None)
            assert data_id is not None, "Missing field: 'data_id' (to be used with 'export_from' field)"
            nd = self.dm.get_external_node(dm_name=exp, data_id=data_id, name=name)
            assert nd is not None, "The requested data ID '{:s}' does not exist!".format(data_id)
            self.node_dico[(name, ident)] = nd
            return nd

        nd = Node(name)
        clone_ref = desc.get('clone', None)
        if clone_ref is not None:
            ref = self._handle_name(clone_ref)
            self._register_todo(nd, self._clone_from_dict, args=ref, unpack_args=False,
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
        else:
            conf = None
            ref = self._handle_name(desc['name'])
            if ref in self.node_dico:
                raise ValueError("name {!r} is already used!".format(ref))
            n = Node(ref[0])

        return n, conf

    def __post_handling(self, desc, node):
        if not isinstance(node.cc, NodeInternals_Empty):
            ref = self._handle_name(desc['name'])
            self.node_dico[ref] = node


    def _create_generator_node(self, desc, node=None):

        n, conf = self.__pre_handling(desc, node)

        contents = desc.get('contents')

        if hasattr(contents, '__call__'):
            other_args = desc.get('other_args', None)
            provide_helpers = desc.get('provide_helpers', False)
            node_args = desc.get('node_args', None)
            n.set_generator_func(contents, func_arg=other_args,
                                 provide_helpers=provide_helpers, conf=conf)
            if node_args is not None:
                # node_args interpretation is postponed after all nodes has been created
                self._register_todo(n, self._complete_generator, args=(node_args, conf), unpack_args=True,
                                    prio=self.HIGH_PRIO)
        else:
            raise ValueError("*** ERROR: {:s} is an invalid contents!".format(repr(contents)))

        self._handle_common_attr(n, desc, conf)

        return n


    def _create_non_terminal_node(self, desc, node=None):

        n, conf = self.__pre_handling(desc, node)

        shapes = []
        cts = desc.get('contents')
        if not cts:
            raise ValueError

        if isinstance(cts[0], list):
            # thus contains at least something that is not a
            # node_desc, that is directly a node. Thus, only one
            # shape!
            w = None
        else:
            w = cts[0].get('weight')

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

        mode = desc.get('mode', MH.MutableClone)
        internals = n.cc if conf is None else n.c[conf]
        internals.set_mode(mode)

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
                if isinstance(n, list) and (len(n) == 2 or len(n) == 3):
                    sh.append(n)
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

        # Note that sections are not always materialised in the description
        for section_desc in shapes:

            # check if it is directly a node
            if isinstance(section_desc, list):
                sh.append(dup_mode + shape_type)
                _handle_section([section_desc], sh)

            # check if it is a section description
            elif section_desc.get('name') is None:
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
                sh.append(dup_mode + shape_type)
                _handle_section([section_desc], sh)

        return sh


    def _create_leaf_node(self, desc, node=None):

        n, conf = self.__pre_handling(desc, node)

        contents = desc.get('contents')

        if issubclass(contents.__class__, VT):
            if hasattr(contents, 'usable') and contents.usable == False:
                raise ValueError("ERROR: {:s} is not usable! (use a subclass of it)".format(repr(contents)))
            n.set_values(value_type=contents, conf=conf)
        elif hasattr(contents, '__call__'):
            other_args = desc.get('other_args', None)
            provide_helpers = desc.get('provide_helpers', False)
            node_args = desc.get('node_args', None)
            n.set_func(contents, func_arg=other_args,
                       provide_helpers=provide_helpers, conf=conf)

            mode = desc.get('mode', 1)
            internals = n.cc if conf is None else n.c[conf]
            internals.set_mode(mode)

            # node_args interpretation is postponed after all nodes has been created
            self._register_todo(n, self._complete_func, args=(node_args, conf), unpack_args=True,
                                prio=self.HIGH_PRIO)

        else:
            raise ValueError("ERROR: {:s} is an invalid contents!".format(repr(contents)))

        self._handle_common_attr(n, desc, conf)

        return n

    def _handle_common_attr(self, node, desc, conf):
        param = desc.get('determinist', None)
        if param is not None:
            node.make_determinist(conf=conf)
        param = desc.get('random', None)
        if param is not None:
            node.make_random(conf=conf)     
        param = desc.get('clear_attrs', None)
        if param is not None:
            for a in param:
                node.clear_attr(a, conf=conf)
        param = desc.get('set_attrs', None)
        if param is not None:
           for a in param:
                node.set_attr(a, conf=conf)
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
                                args=(ref, SyncScope.Qty, conf),
                                unpack_args=True)
        condition = desc.get('exists_if', None)
        if condition is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(condition, SyncScope.Existence, conf),
                                unpack_args=True)
        condition = desc.get('exists_if_not', None)
        if condition is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(condition, SyncScope.Inexistence, conf),
                                unpack_args=True)
        fw = desc.get('fuzz_weight', None)
        if fw is not None:
            node.set_fuzz_weight(fw)
        pfh = desc.get('post_freeze', None)
        if pfh is not None:
            node.register_post_freeze_handler(pfh)


    def _register_todo(self, node, func, args=None, unpack_args=True, prio=VERYLOW_PRIO):
        if self.sorted_todo.get(prio, None) is None:
            self.sorted_todo[prio] = []
        self.sorted_todo[prio].insert(0, (node, func, args, unpack_args))

    def _create_todo_list(self):
        self.todo = []
        tdl = sorted(self.sorted_todo.items(), key=lambda x: x[0])
        for prio, sub_tdl in tdl:
            self.todo += sub_tdl

    # Should be called at the last time to avoid side effects (e.g.,
    # when creating generator/function nodes, the node arguments are
    # provided at a later time. If set_contents()---which copy nodes---is called
    # in-between, node arguments risk to not be copied)
    def _clone_from_dict(self, node, ref):
        if ref not in self.node_dico:
            raise ValueError("arguments refer to an inexistent node ({:s}, {!s})!".format(ref[0], ref[1]))
        node.set_contents(self.node_dico[ref])

    def _get_from_dict(self, node, ref, parent_node):
        if ref not in self.node_dico:
            raise ValueError("arguments refer to an inexistent node ({:s}, {!s})!".format(ref[0], ref[1]))
        parent_node.replace_subnode(node, self.node_dico[ref])

    def _set_sync_node(self, node, arg, scope, conf):
        if isinstance(arg, tuple) and issubclass(arg[0].__class__, NodeCondition):
            param = arg[0]
            sync_with = self.__get_node_from_db(arg[1])
        else:
            param = None
            sync_with = self.__get_node_from_db(arg)

        node.make_synchronized_with(sync_with, scope=scope, param=param, conf=conf)

    def _complete_func(self, node, args, conf):
        if isinstance(args, str):
            func_args = self.__get_node_from_db(args)
        else:
            assert(isinstance(args, list) or isinstance(args, tuple))
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
            assert(isinstance(args, list) or isinstance(args, tuple))
            func_args = []
            for name_desc in args:
                func_args.append(self.__get_node_from_db(name_desc))
        internals = node.cc if conf is None else node.c[conf]
        internals.set_generator_func_arg(generator_node_arg=func_args)

    def _set_env(self, node, args):
        node.set_env(Env())

    def __get_node_from_db(self, name_desc):
        ref = self._handle_name(name_desc)
        if ref not in self.node_dico:
            raise ValueError("arguments refer to an inexistent node ({:s}, {!s})!".format(ref[0], ref[1]))

        node = self.node_dico[ref]
        assert(not isinstance(node.cc, NodeInternals_Empty))
               
        return node



#### Data Model Abstraction

class DataModel(object):
    ''' The abstraction of a data model.
    '''

    file_extension = 'bin'
    name = None

    def __init__(self):
        self.__dm_hashtable = {}
        self.__built = False
        self.__confs = set()

    def pre_build(self):
        '''
        This method is called when a data model is loaded.
        It is executed before build_data_model().
        To be implemented by the user.
        '''
        pass


    def build_data_model(self):
        '''
        This method is called when a data model is loaded.
        It is called only the first time the data model is loaded.
        To be implemented by the user.
        '''
        pass

    def load_data_model(self, dm_db):
        self.pre_build()
        if not self.__built:
            self.__dm_db = dm_db
            self.build_data_model()
            self.__built = True

    def unload_data_model(self):
        pass


    def absorb(self, data, idx):
        '''
        If your data model is able to absorb raw data, do it here.  This
        function is called for each files (with the right extension)
        present in imported_data/<data_model_name>.
        '''
        return data

    def get_external_node(self, dm_name, data_id, name=None):
        dm = self.__dm_db[dm_name]
        dm.load_data_model(self.__dm_db)
        try:
            node = dm.get_data(data_id, name=name)
        except ValueError:
            return None

        return node


    def show(self):
        print(colorize(FontStyle.BOLD + '\n-=[ Data Types ]=-\n', rgb=Color.INFO))
        idx = 0
        for data_key in self.__dm_hashtable:
            print(colorize('[%d] ' % idx + data_key, rgb=Color.SUBINFO))
            idx += 1

    def get_data(self, hash_key, name=None):
        if hash_key in self.__dm_hashtable:
            nm = hash_key if name is None else name
            node = Node(nm, base_node=self.__dm_hashtable[hash_key], ignore_frozen_state=False)
            return node
        else:
            raise ValueError('Requested data does not exist!')


    def data_identifiers(self):
        hkeys = sorted(self.__dm_hashtable.keys())
        for k in hkeys:
            yield k


    def get_available_confs(self):
        return sorted(self.__confs)

    def register(self, *node_or_desc_list):
        for n in node_or_desc_list:
            if isinstance(n, Node):
                self.register_nodes(n)
            else:
                self.register_descriptors(n)


    def register_nodes(self, *node_list):
        '''Enable to registers the nodes that will be part of the data
        model. At least one node should be registered within
        :func:`DataModel.build_data_model()` to represent the data
        format. But several nodes can be registered in order, for instance, to
        represent the various component of a protocol/standard/...
        '''
        if not node_list:
            msg = "\n*** WARNING: nothing to register for " \
                  "the data model '{nm:s}'!"\
                  "\n   [probable reason: ./imported_data/{nm:s}/ not " \
                  "populated with sample files]".format(nm=self.name)
            raise UserWarning(msg)

        for e in node_list:
            if e is None:
                continue
            if e.env is None:
                env = Env()
                env.set_data_model(self)
                e.set_env(env)
            else:
                e.env.set_data_model(self)

            self.__dm_hashtable[e.name] = e

            self.__confs = self.__confs.union(e.gather_alt_confs())


    def register_descriptors(self, *desc_list):
        for desc in desc_list:
            mh = ModelHelper(dm=self)
            desc_name = 'Unreadable Name'
            try:
                desc_name = desc['name']
                node = mh.create_graph_from_desc(desc)
            except:
                print('-'*60)
                traceback.print_exc(file=sys.stdout)
                print('-'*60)
                msg = "*** ERROR: problem encountered with the '{desc:s}' descriptor!".format(desc=desc_name)
                raise UserWarning(msg)

            self.register_nodes(node)

    def set_new_env(self, node):
        env = Env()
        env.set_data_model(self)
        node.set_env(env)


    def import_file_contents(self, extension=None, absorber=None,
                             subdir=None, path=None, filename=None):

        if absorber is None:
            absorber = self.absorb

        if extension is None:
            extension = self.file_extension
        if path is None:
            path = self.get_import_directory_path(subdir=subdir)

        r_file = re.compile(".*\." + extension + "$")
        def is_good_file_by_ext(fname):
            return bool(r_file.match(fname))

        def is_good_file_by_fname(fname):
            return filename == fname

        files = []
        for (dirpath, dirnames, filenames) in os.walk(path):
            files.extend(filenames)
            break

        if filename is None:
            files = list(filter(is_good_file_by_ext, files))
        else:
            files = list(filter(is_good_file_by_fname, files))
        msgs = {}
        idx = 0

        for name in files:
            with open(os.path.join(path, name), 'rb') as f:
                buff = f.read()
                d_abs = absorber(buff, idx)
                if d_abs is not None:
                    msgs[name] = d_abs
            idx +=1

        return msgs

    def get_import_directory_path(self, subdir=None):
        if subdir is None:
            subdir = self.name
        if subdir is None:
            path = os.path.join(app_folder, 'imported_data')
        else:
            path = os.path.join(app_folder, 'imported_data', subdir)

        if not os.path.exists(path):
            os.makedirs(path)

        return path
