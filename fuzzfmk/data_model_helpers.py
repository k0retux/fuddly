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
from fuzzfmk.value_types import VT

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

    # section_type attribute
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

class ModelHelper(object):

    HIGH_PRIO = 1
    MEDIUM_PRIO = 2
    LOW_PRIO = 3
    VERYLOW_PRIO = 4

    valid_keys = [
        # generic description keys
        'name', 'contents', 'qty', 'clone', 'type', 'alt', 'conf', 'mode',
        # NonTerminal description keys
        'weight', 'section_type', 'duplicate_mode', 'weights',
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
            raise ValueError("Name is not recognized: '%s'!"%name_desc)

        return name, ident


    def _create_graph_from_desc(self, desc, parent_node):

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
            if isinstance(contents, list):
                ntype = MH.NonTerminal
            else:
                ntype = desc.get('type', MH.Leaf)

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
                if isinstance(cts, list):
                    ntype = MH.NonTerminal
                else:
                    ntype = alt.get('type', MH.Leaf)

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
            # node_args interpretation is postponed after all nodes has been created
            self._register_todo(n, self._complete_generator, args=(node_args, conf), unpack_args=True,
                                prio=self.HIGH_PRIO)
        else:
            raise ValueError("Error[invalid contents]: {:s}".format(repr(contents)))

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
            shape = self._create_nodes_from_shape(cts, n)
            shapes.append(1)
            shapes.append(shape)

        n.set_subnodes_with_csts(shapes, conf=conf)

        mode = desc.get('mode', MH.MutableClone)
        internals = n.cc if conf is None else n.c[conf]
        internals.set_mode(mode)

        self._handle_common_attr(n, desc, conf)

        return n


    def _create_nodes_from_shape(self, shapes, parent_node):
        
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
                    raise ValueError

        if isinstance(shapes[0], list):
            # This is a node and not a node_desc. Thus, no section!
            ref = 'NotNone'
        else:
            ref = shapes[0].get('name')

        sh = []

        if ref is None:
            # in this case, sections are materialised in the description
            for section_desc in shapes:
                self._verify_keys_conformity(section_desc)
                sec_type = section_desc.get('section_type', '>')
                dupmode = section_desc.get('duplicate_mode', 'u')
                # TODO: revamp weights
                weights = ''.join(str(section_desc.get('weights', '')).split(' '))
                sh.append(dupmode+sec_type+weights)
                _handle_section(section_desc.get('contents', []), sh)
        else:
            # if 'name' attr is present, there is no section in the
            # shape, thus we adopt a default sequencing of nodes (that
            # is 'u>')
            sh.append('u>')
            _handle_section(shapes, sh)

        return sh


    def _create_leaf_node(self, desc, node=None):

        n, conf = self.__pre_handling(desc, node)

        contents = desc.get('contents')

        if issubclass(contents.__class__, VT):
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
            raise ValueError("Error[invalid contents]: {:s}".format(repr(contents)))

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
        ref = desc.get('exists_if', None)
        if ref is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(ref, SyncScope.Existence, conf),
                                unpack_args=True)
        ref = desc.get('exists_if_not', None)
        if ref is not None:
            self._register_todo(node, self._set_sync_node,
                                args=(ref, SyncScope.Inexistence, conf),
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

    def _set_sync_node(self, node, sync_with_ref, scope, conf):
        sync_with = self.__get_node_from_db(sync_with_ref)
        node.make_synchronized_with(sync_with, scope=scope, conf=conf)

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
                msg = "*** ERROR: problem encountered with the '{desc:s}' descriptor!".format(desc=desc_name)
                raise UserWarning(msg)

            self.register_nodes(node)

    def set_new_env(self, node):
        env = Env()
        env.set_data_model(self)
        node.set_env(env)


    def import_file_contents(self, extension=None, dissector=lambda x, y: x,
                             subdir=None, path=None, filename=None):

        if hasattr(self, 'dissect'):
            dissector = self.dissect

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
                msgs[name] = dissector(buff, idx)
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
