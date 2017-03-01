from framework.data_model import *

import datetime

#####################
# Data Model Helper #
#####################

class MH(object):
    """
    Define constants and generator templates for data
    model description.
    """

    #################
    ### Node Type ###
    #################

    NonTerminal = 1
    Generator = 2
    Leaf = 3
    Regex = 5

    RawNode = 4  # if a Node() is provided

    ##################################
    ### Non-Terminal Node Specific ###
    ##################################

    # shape_type & section_type attribute
    Ordered = '>'
    Random = '=..'
    FullyRandom = '=.'
    Pick = '=+'

    # duplicate_mode attribute
    Copy = 'u'
    ZeroCopy = 's'


    ##############################
    ### Regex Parser Specific ####
    ##############################

    class Charset:
        ASCII = 1
        ASCII_EXT = 2
        UNICODE = 3

    ##########################
    ### Node Customization ###
    ##########################

    class Custo:
        # NonTerminal node custo
        class NTerm:
            MutableClone = NonTermCusto.MutableClone
            FrozenCopy = NonTermCusto.FrozenCopy
            CollapsePadding = NonTermCusto.CollapsePadding

        # Generator node (leaf) custo
        class Gen:
            ForwardConfChange = GenFuncCusto.ForwardConfChange
            CloneExtNodeArgs = GenFuncCusto.CloneExtNodeArgs
            ResetOnUnfreeze = GenFuncCusto.ResetOnUnfreeze
            TriggerLast = GenFuncCusto.TriggerLast

        # Function node (leaf) custo
        class Func:
            FrozenArgs = FuncCusto.FrozenArgs
            CloneExtNodeArgs = FuncCusto.CloneExtNodeArgs


    #######################
    ### Node Attributes ###
    #######################

    class Attr:
        Freezable = NodeInternals.Freezable
        Mutable = NodeInternals.Mutable
        Determinist = NodeInternals.Determinist
        Finite = NodeInternals.Finite
        Abs_Postpone = NodeInternals.Abs_Postpone

        Separator = NodeInternals.Separator

        LOCKED = NodeInternals.LOCKED
        DEBUG = NodeInternals.DEBUG


    ############################################
    ### Helpers for Generator Node Templates ###
    ############################################

    @staticmethod
    def _validate_int_vt(vt):
        if not issubclass(vt, fvt.INT):
            raise DataModelDefinitionError("The value type requested is not supported! (expect a subclass of INT)")
        return vt

    @staticmethod
    def _validate_vt(vt):
        if not issubclass(vt, fvt.INT) and not issubclass(vt, fvt.String):
            raise DataModelDefinitionError("The value type requested is not supported!")
        return vt

    @staticmethod
    def _handle_attrs(n, set_attrs, clear_attrs):
        if set_attrs is not None:
            for sa in set_attrs:
                n.set_attr(sa)
        if clear_attrs is not None:
            for ca in clear_attrs:
                n.clear_attr(ca)


################################
### Generator Node Templates ###
################################


def LEN(vt=fvt.INT_str, base_len=0,
        set_attrs=None, clear_attrs=None, after_encoding=True, freezable=False):
    """
    Return a *generator* that returns the length of a node parameter.

    Args:
      vt (type): value type used for node generation (refer to :mod:`framework.value_types`).
      base_len (int): this base length will be added to the computed length.
      set_attrs (list): attributes that will be set on the generated node.
      clear_attrs (list): attributes that will be cleared on the generated node.
      after_encoding (bool): if False compute the length before any encoding. Can be
        set to False only if node arguments support encoding.
      freezable (bool): If ``False`` make the generator unfreezable in order to always provide
        the right value. (Note that tTYPE will still be able to corrupt the generator.)
    """
    class Length(object):
        unfreezable = not freezable

        def __init__(self, vt, set_attrs, clear_attrs):
            self.vt = vt
            self.set_attrs = set_attrs
            self.clear_attrs = clear_attrs

        def __call__(self, node):
            blob = node.to_bytes() if after_encoding else node.get_raw_value()
            n = Node('cts', value_type=self.vt(values=[len(blob)+base_len], force_mode=True))
            n.set_semantics(NodeSemantics(['len']))
            MH._handle_attrs(n, self.set_attrs, self.clear_attrs)
            return n

    vt = MH._validate_int_vt(vt)
    return Length(vt, set_attrs, clear_attrs)


def QTY(node_name, vt=fvt.INT_str,
        set_attrs=None, clear_attrs=None, freezable=False):
    """
    Return a *generator* that returns the quantity of child node instances (referenced
    by name) of the node parameter provided to the *generator*.

    Args:
      vt (type): value type used for node generation (refer to :mod:`framework.value_types`)
      node_name (str): name of the child node whose instance amount will be returned
        by the generator
      set_attrs (list): attributes that will be set on the generated node.
      clear_attrs (list): attributes that will be cleared on the generated node.
      freezable (bool): If ``False`` make the generator unfreezable in order to always provide
        the right value. (Note that tTYPE will still be able to corrupt the generator.)
    """
    class Qty(object):
        unfreezable = not freezable

        def __init__(self, node_name, vt, set_attrs, clear_attrs):
            self.node_name = node_name
            self.vt = vt
            self.set_attrs = set_attrs
            self.clear_attrs = clear_attrs

        def __call__(self, node):
            nb = node.cc.get_drawn_node_qty(self.node_name)
            n = Node('cts', value_type=self.vt(values=[nb], force_mode=True))
            n.set_semantics(NodeSemantics(['qty']))
            MH._handle_attrs(n, self.set_attrs, self.clear_attrs)
            return n

    vt = MH._validate_int_vt(vt)
    return Qty(node_name, vt, set_attrs, clear_attrs)


def TIMESTAMP(time_format="%H%M%S", utc=False,
              set_attrs=None, clear_attrs=None):
    """
    Return a *generator* that returns the current time (in a String node).

    Args:
      time_format (str): time format to be used by the generator.
      set_attrs (list): attributes that will be set on the generated node.
      clear_attrs (list): attributes that will be cleared on the generated node.
    """
    def timestamp(time_format, utc, set_attrs, clear_attrs):
        if utc:
            now = datetime.datetime.utcnow()
        else:
            now = datetime.datetime.now()
        ts = now.strftime(time_format)
        n = Node('cts', value_type=fvt.String(values=[ts], size=len(ts)))
        n.set_semantics(NodeSemantics(['timestamp']))
        MH._handle_attrs(n, set_attrs, clear_attrs)
        return n

    return functools.partial(timestamp, time_format, utc, set_attrs, clear_attrs)


def CRC(vt=fvt.INT_str, poly=0x104c11db7, init_crc=0, xor_out=0xFFFFFFFF, rev=True,
        set_attrs=None, clear_attrs=None, after_encoding=True, freezable=False):
    """
    Return a *generator* that returns the CRC (in the chosen type) of
    all the node parameters. (Default CRC is PKZIP CRC32)

    Args:
      vt (type): value type used for node generation (refer to :mod:`framework.value_types`)
      poly (int): CRC polynom
      init_crc (int): initial value used to start the CRC calculation.
      xor_out (int): final value to XOR with the calculated CRC value.
      rev (bool): bit reversed algorithm when `True`.
      set_attrs (list): attributes that will be set on the generated node.
      clear_attrs (list): attributes that will be cleared on the generated node.
      after_encoding (bool): if False compute the CRC before any encoding. Can be
        set to False only if node arguments support encoding.
      freezable (bool): if ``False`` make the generator unfreezable in order to always provide
        the right value. (Note that tTYPE will still be able to corrupt the generator.)
    """
    class Crc(object):
        unfreezable = not freezable

        def __init__(self, vt, poly, init_crc, xor_out, rev, set_attrs, clear_attrs):
            self.vt = vt
            self.poly = poly
            self.init_crc = init_crc
            self.xor_out = xor_out
            self.rev = rev
            self.set_attrs = set_attrs
            self.clear_attrs = clear_attrs

        def __call__(self, nodes):
            crc_func = crcmod.mkCrcFun(self.poly, initCrc=self.init_crc,
                                       xorOut=self.xor_out, rev=self.rev)
            if isinstance(nodes, Node):
                s = nodes.to_bytes() if after_encoding else nodes.get_raw_value()
            else:
                if issubclass(nodes.__class__, NodeAbstraction):
                    nodes = nodes.get_concrete_nodes()
                elif not isinstance(nodes, (tuple, list)):
                    raise TypeError("Contents of 'nodes' parameter is incorrect!")
                s = b''
                for n in nodes:
                    blob = n.to_bytes() if after_encoding else n.get_raw_value()
                    s += blob

            result = crc_func(s)

            n = Node('cts', value_type=self.vt(values=[result], force_mode=True))
            n.set_semantics(NodeSemantics(['crc']))
            MH._handle_attrs(n, self.set_attrs, self.clear_attrs)
            return n

    if not crcmod_module:
        raise NotImplementedError('the CRC template has been disabled because python-crcmod module is not installed!')

    vt = MH._validate_int_vt(vt)
    return Crc(vt, poly, init_crc, xor_out, rev, set_attrs, clear_attrs)



def WRAP(func, vt=fvt.String,
         set_attrs=None, clear_attrs=None, after_encoding=True, freezable=False):
    """
    Return a *generator* that returns the result (in the chosen type)
    of the provided function applied on the concatenation of all
    the node parameters.

    Args:
      func (function): function applied on the concatenation
      vt (type): value type used for node generation (refer to :mod:`framework.value_types`)
      set_attrs (list): attributes that will be set on the generated node.
      clear_attrs (list): attributes that will be cleared on the generated node.
      after_encoding (bool): if False, execute `func` on node arguments before any encoding.
        Can be set to False only if node arguments support encoding.
      freezable (bool): If ``False`` make the generator unfreezable in order to always provide
        the right value. (Note that tTYPE will still be able to corrupt the generator.)
    """
    class WrapFunc(object):
        unfreezable = not freezable

        def __init__(self, vt, func, set_attrs, clear_attrs):
            self.vt = vt
            self.func = func
            self.set_attrs = set_attrs
            self.clear_attrs = clear_attrs

        def __call__(self, nodes):
            if isinstance(nodes, Node):
                s = nodes.to_bytes() if after_encoding else nodes.get_raw_value()
            else:
                if issubclass(nodes.__class__, NodeAbstraction):
                    nodes = nodes.get_concrete_nodes()
                elif not isinstance(nodes, (tuple, list)):
                    raise TypeError("Contents of 'nodes' parameter is incorrect!")
                s = b''
                for n in nodes:
                    blob = n.to_bytes() if after_encoding else n.get_raw_value()
                    s += blob

            result = self.func(s)

            if issubclass(self.vt, fvt.String):
                result = convert_to_internal_repr(result)
            else:
                assert isinstance(result, int)

            if issubclass(vt, fvt.INT):
                vt_obj = self.vt(values=[result], force_mode=True)
            else:
                vt_obj = self.vt(values=[result])
            n = Node('cts', value_type=vt_obj)
            MH._handle_attrs(n, self.set_attrs, self.clear_attrs)
            return n

    vt = MH._validate_vt(vt)
    return WrapFunc(vt, func, set_attrs, clear_attrs)


def CYCLE(vals, depth=1, vt=fvt.String,
          set_attrs=None, clear_attrs=None):
    """
    Return a *generator* that iterates other the provided value list
    and returns at each step a `vt` node corresponding to the
    current value.

    Args:
      vals (list): the value list to iterate on.
      depth (int): depth of our nth-ancestor used as a reference to iterate. By default,
        it is the parent node. Thus, in this case, depending on the drawn quantity
        of parent nodes, the position within the grand-parent determines the index
        of the value to use in the provided list, modulo the quantity.
      vt (type): value type used for node generation (refer to :mod:`framework.value_types`).
      set_attrs (list): attributes that will be set on the generated node.
      clear_attrs (list): attributes that will be cleared on the generated node.
    """
    class Cycle(object):
        provide_helpers = True

        def __init__(self, vals, depth, vt, set_attrs, clear_attrs):
            self.vals = vals
            self.vals_sz = len(vals)
            self.vt = vt
            self.depth = depth
            self.set_attrs = set_attrs
            self.clear_attrs = clear_attrs

        def __call__(self, helper):
            info = helper.graph_info
            # print('INFO: ', info)
            try:
                clone_info, name = info[self.depth]
                idx, total = clone_info
            except:
                idx = 0
            idx = idx % self.vals_sz
            if issubclass(self.vt, fvt.INT):
                vtype = self.vt(values=[self.vals[idx]])
            elif issubclass(self.vt, fvt.String):
                vtype = self.vt(values=[self.vals[idx]])
            else:
                raise NotImplementedError('Value type not supported')

            n = Node('cts', value_type=vtype)
            MH._handle_attrs(n, set_attrs, clear_attrs)
            return n

    assert(not issubclass(vt, fvt.BitField))
    return Cycle(vals, depth, vt, set_attrs, clear_attrs)


def OFFSET(use_current_position=True, depth=1, vt=fvt.INT_str,
           set_attrs=None, clear_attrs=None, after_encoding=True, freezable=False):
    """
    Return a *generator* that computes the offset of a child node
    within its parent node.

    If `use_current_position` is `True`, the child node is
    selected automatically, based on our current index within our
    own parent node (or the nth-ancestor, depending on the
    parameter `depth`). Otherwise, the child node has to be
    provided in the node parameters just before its parent node.

    Besides, if there are N node parameters, the first N-1 (or N-2
    if `use_current_position` is False) nodes are used for adding
    a fixed amount (the length of their concatenated values) to
    the offset (determined thanks to the node in the last position
    of the node parameters).

    The generator returns the result wrapped in a `vt` node.

    Args:
      use_current_position (bool): automate the computation of the child node position
      depth (int): depth of our nth-ancestor used as a reference to compute automatically
        the targeted child node position. Only relevant if `use_current_position` is True.
      vt (type): value type used for node generation (refer to :mod:`framework.value_types`).
      set_attrs (list): attributes that will be set on the generated node.
      clear_attrs (list): attributes that will be cleared on the generated node.
      after_encoding (bool): if False compute the fixed amount part of the offset before
        any encoding. Can be set to False only if node arguments support encoding.
      freezable (bool): If ``False`` make the generator unfreezable in order to always provide
        the right value. (Note that tTYPE will still be able to corrupt the generator.)
    """
    class Offset(object):
        provide_helpers = True
        unfreezable = not freezable

        def __init__(self, use_current_position, depth, vt, set_attrs, clear_attrs):
            self.vt = vt
            self.use_current_position = use_current_position
            self.depth = depth
            self.set_attrs = set_attrs
            self.clear_attrs = clear_attrs

        def __call__(self, nodes, helper):
            if self.use_current_position:
                info = helper.graph_info
                try:
                    clone_info, name = info[self.depth]
                    idx, total = clone_info
                except:
                    idx = 0

            if isinstance(nodes, Node):
                assert(self.use_current_position)
                base = 0
                off = nodes.get_subnode_off(idx)
            else:
                if issubclass(nodes.__class__, NodeAbstraction):
                    nodes = nodes.get_concrete_nodes()
                elif not isinstance(nodes, (tuple, list)):
                    raise TypeError("Contents of 'nodes' parameter is incorrect!")

                if not self.use_current_position:
                    child = nodes[-2]
                    parent = nodes[-1]
                    parent.get_value()
                    idx = parent.get_subnode_idx(child)

                s = b''
                end = -1 if self.use_current_position else -2
                for n in nodes[:end]:
                    blob = n.to_bytes() if after_encoding else n.get_raw_value()
                    s += blob
                base = len(s)
                off = nodes[-1].get_subnode_off(idx)

            n = Node('cts_off', value_type=self.vt(values=[base+off], force_mode=True))
            MH._handle_attrs(n, set_attrs, clear_attrs)
            return n

    vt = MH._validate_int_vt(vt)
    return Offset(use_current_position, depth, vt, set_attrs, clear_attrs)


def COPY_VALUE(path, depth=None, vt=None,
               set_attrs=None, clear_attrs=None, after_encoding=True):
    """
    Return a *generator* that retrieves the value of another node, and
    then return a `vt` node with this value. The other node is
    selected:

    - either directly by following the provided relative `path` from
      the given generator-parameter node.

    - or indirectly (if `depth` is provided) where a *base* node is
      first selected automatically, based on our current index
      within our own parent node (or the nth-ancestor, depending
      on the parameter `depth`), and then the targeted node is selected
      by following the provided relative `path` from the *base* node.

    Args:
      path (str): relative path to the node whose value will be picked.
      depth (int): depth of our nth-ancestor used as a reference to compute automatically
        the targeted base node position.
      vt (type): value type used for node generation (refer to :mod:`framework.value_types`).
      set_attrs (list): attributes that will be set on the generated node.
      clear_attrs (list): attributes that will be cleared on the generated node.
      after_encoding (bool): if False, copy the raw value, otherwise the encoded one. Can be
        set to False only if node arguments support encoding.
    """
    class CopyValue(object):
        provide_helpers = True

        def __init__(self, path, depth, vt, set_attrs, clear_attrs):
            self.vt = vt
            self.path = path
            self.depth = depth
            self.set_attrs = set_attrs
            self.clear_attrs = clear_attrs

        def __call__(self, node, helper):
            if self.depth is not None:
                info = helper.graph_info
                # print('INFO: ', info)
                try:
                    clone_info, name = info[self.depth]
                    idx, total = clone_info
                except:
                    # print('\n*** WARNING[Pick Generator]: incorrect depth ({:d})!\n' \
                    #       '  (Normal behavior if used during absorption.)'.format(self.depth))
                    idx = 0
                base_node = node.get_subnode(idx)
            else:
                base_node = node

            tg_node = base_node[self.path]

            if tg_node.is_nonterm():
                n = Node('cts', base_node=tg_node, ignore_frozen_state=False)
            else:
                blob = tg_node.to_bytes() if after_encoding else tg_node.get_raw_value()

                if self.vt is None:
                    assert(tg_node.is_typed_value() and not tg_node.is_typed_value(subkind=fvt.BitField))
                    self.vt = tg_node.get_current_subkind()

                if issubclass(self.vt, fvt.INT):
                    vtype = self.vt(values=[tg_node.get_raw_value()])
                elif issubclass(self.vt, fvt.String):
                    vtype = self.vt(values=[blob])
                else:
                    raise NotImplementedError('Value type not supported')
                n = Node('cts', value_type=vtype)

            n.set_semantics(NodeSemantics(['clone']))
            MH._handle_attrs(n, set_attrs, clear_attrs)
            return n


    assert(vt is None or not issubclass(vt, fvt.BitField))
    return CopyValue(path, depth, vt, set_attrs, clear_attrs)

