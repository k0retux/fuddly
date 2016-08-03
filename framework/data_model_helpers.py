
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

from framework.data_model import *
import framework.value_types as fvt
from framework.value_types import VT
import framework.global_resources as gr

from libs.external_modules import *

import traceback
import datetime
import six

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

class MH(object):
    '''Define constants and generator templates for data
    model description.
    '''

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

    ###########################
    ### Generator Templates ###
    ###########################

    @staticmethod
    def LEN(vt=fvt.INT_str, base_len=0,
            set_attrs=[], clear_attrs=[], after_encoding=True):
        '''
        Return a *generator* that returns the length of a node parameter.

        Args:
          vt (type): value type used for node generation (refer to :mod:`framework.value_types`).
          base_len (int): this base length will be added to the computed length.
          set_attrs (list): attributes that will be set on the generated node.
          clear_attrs (list): attributes that will be cleared on the generated node.
          after_encoding (bool): if False compute the length before any encoding. Can be
            set to False only if node arguments support encoding.
        '''
        def length(vt, set_attrs, clear_attrs, node):
            blob = node.to_bytes() if after_encoding else node.get_raw_value()
            n = Node('cts', value_type=vt(int_list=[len(blob)+base_len]))
            n.set_semantics(NodeSemantics(['len']))
            MH._handle_attrs(n, set_attrs, clear_attrs)
            return n

        vt = MH._validate_int_vt(vt)
        return functools.partial(length, vt, set_attrs, clear_attrs)

    @staticmethod
    def QTY(node_name, vt=fvt.INT_str,
            set_attrs=[], clear_attrs=[]):
        '''Return a *generator* that returns the quantity of child node instances (referenced
        by name) of the node parameter provided to the *generator*.

        Args:
          vt (type): value type used for node generation (refer to :mod:`framework.value_types`)
          node_name (str): name of the child node whose instance amount will be returned
            by the generator
          set_attrs (list): attributes that will be set on the generated node.
          clear_attrs (list): attributes that will be cleared on the generated node.
        '''
        def qty(node_name, vt, set_attrs, clear_attrs, node):
            nb = node.cc.get_drawn_node_qty(node_name)
            n = Node('cts', value_type=vt(int_list=[nb]))
            n.set_semantics(NodeSemantics(['qty']))
            MH._handle_attrs(n, set_attrs, clear_attrs)
            return n

        vt = MH._validate_int_vt(vt)
        return functools.partial(qty, node_name, vt, set_attrs, clear_attrs)

    @staticmethod
    def TIMESTAMP(time_format="%H%M%S", utc=False,
                  set_attrs=[], clear_attrs=[]):
        '''
        Return a *generator* that returns the current time (in a BYTES node).

        Args:
          time_format (str): time format to be used by the generator.
          set_attrs (list): attributes that will be set on the generated node.
          clear_attrs (list): attributes that will be cleared on the generated node.
        '''
        def timestamp(time_format, utc, set_attrs, clear_attrs):
            if utc:
                now = datetime.datetime.utcnow()
            else:
                now = datetime.datetime.now()
            ts = now.strftime(time_format)
            n = Node('cts', value_type=fvt.BYTES(val_list=[ts], size=len(ts)))
            n.set_semantics(NodeSemantics(['timestamp']))
            MH._handle_attrs(n, set_attrs, clear_attrs)
            return n
        
        return functools.partial(timestamp, time_format, utc, set_attrs, clear_attrs)

    @staticmethod
    def CRC(vt=fvt.INT_str, poly=0x104c11db7, init_crc=0, xor_out=0xFFFFFFFF, rev=True,
            set_attrs=[], clear_attrs=[], after_encoding=True):
        '''Return a *generator* that returns the CRC (in the chosen type) of
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
        '''
        def crc(vt, poly, init_crc, xor_out, rev, set_attrs, clear_attrs, nodes):
            crc_func = crcmod.mkCrcFun(poly, initCrc=init_crc, xorOut=xor_out, rev=rev)
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

            n = Node('cts', value_type=vt(int_list=[result]))
            n.set_semantics(NodeSemantics(['crc']))
            MH._handle_attrs(n, set_attrs, clear_attrs)
            return n

        if not crcmod_module:
            raise NotImplementedError('the CRC template has been disabled because python-crcmod module is not installed!')

        vt = MH._validate_int_vt(vt)
        return functools.partial(crc, vt, poly, init_crc, xor_out, rev, set_attrs, clear_attrs)


    @staticmethod
    def WRAP(func, vt=fvt.INT_str,
             set_attrs=[], clear_attrs=[], after_encoding=True):
        '''Return a *generator* that returns the result (in the chosen type)
        of the provided function applied on the concatenation of all
        the node parameters.

        Args:
          func (function): function applied on the concatenation
          vt (type): value type used for node generation (refer to :mod:`framework.value_types`)
          set_attrs (list): attributes that will be set on the generated node.
          clear_attrs (list): attributes that will be cleared on the generated node.
          after_encoding (bool): if False, execute `func` on node arguments before any encoding.
            Can be set to False only if node arguments support encoding.
        '''
        def map_func(vt, func, set_attrs, clear_attrs, nodes):
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

            result = func(s)

            n = Node('cts', value_type=vt(int_list=[result]))
            MH._handle_attrs(n, set_attrs, clear_attrs)
            return n

        vt = MH._validate_int_vt(vt)
        return functools.partial(map_func, vt, func, set_attrs, clear_attrs)

    @staticmethod
    def CYCLE(vals, depth=1, vt=fvt.BYTES,
              set_attrs=[], clear_attrs=[]):
        '''Return a *generator* that iterates other the provided value list
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
        '''
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
                    vtype = self.vt(int_list=[self.vals[idx]])
                elif issubclass(self.vt, fvt.String):
                    vtype = self.vt(val_list=[self.vals[idx]])
                else:
                    raise NotImplementedError('Value type not supported')

                n = Node('cts', value_type=vtype)
                MH._handle_attrs(n, set_attrs, clear_attrs)
                return n

        assert(not issubclass(vt, fvt.BitField))
        return Cycle(vals, depth, vt, set_attrs, clear_attrs)


    @staticmethod
    def OFFSET(use_current_position=True, depth=1, vt=fvt.INT_str,
               set_attrs=[], clear_attrs=[], after_encoding=True):
        '''Return a *generator* that computes the offset of a child node
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
        '''
        class Offset(object):
            provide_helpers = True
            
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

                n = Node('cts_off', value_type=self.vt(int_list=[base+off]))
                MH._handle_attrs(n, set_attrs, clear_attrs)
                return n

        vt = MH._validate_int_vt(vt)
        return Offset(use_current_position, depth, vt, set_attrs, clear_attrs)


    @staticmethod
    def COPY_VALUE(path, depth=None, vt=None,
                   set_attrs=[], clear_attrs=[], after_encoding=True):
        '''Return a *generator* that retrieves the value of another node, and
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
        '''
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
                        vtype = self.vt(int_list=[tg_node.get_raw_value()])
                    elif issubclass(self.vt, fvt.String):
                        vtype = self.vt(val_list=[blob])
                    else:
                        raise NotImplementedError('Value type not supported')
                    n = Node('cts', value_type=vtype)

                n.set_semantics(NodeSemantics(['clone']))
                MH._handle_attrs(n, set_attrs, clear_attrs)
                return n


        assert(vt is None or not issubclass(vt, fvt.BitField))
        return CopyValue(path, depth, vt, set_attrs, clear_attrs)


    @staticmethod
    def _validate_int_vt(vt):
        if not issubclass(vt, fvt.INT):
            print("*** WARNING: the value type of typed node requested is not supported!" \
                  " Use of 'INT_str' instead.")
            vt = fvt.INT_str             
        return vt

    @staticmethod
    def _handle_attrs(n, set_attrs, clear_attrs):
        for sa in set_attrs:
            n.set_attr(sa)
        for ca in clear_attrs:
            n.clear_attr(ca)


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

            elif ctx.input == '[':
                return self.machine.SquareBrackets
            elif ctx.input == '(':
                return self.machine.Parenthesis
            elif ctx.input == '\\':
                return self.machine.Escape
            else:
                ctx.append_to_contents("")

                if ctx.input == '|':
                    return self.machine.Choice
                elif ctx.input is None:
                    return self.machine.Final
                else:
                    return self.machine.Main


    @register
    class Choice(Initial):

        def _run(self, ctx):
            if not ctx.choice:
                # if it is still possible to build a NT with multiple shapes
                if len(ctx.nodes) == 0 or (len(ctx.nodes) == 1 and ctx.buffer is None):
                    ctx.choice = True
                else:
                    raise InconvertibilityError()
            else:
                pass


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
            if ctx.input == '(':
                return self.machine.Parenthesis
            elif ctx.input == '[':
                return self.machine.SquareBrackets
            elif ctx.input == '\\':
                return self.machine.Escape
            elif ctx.input == '|':
                return self.machine.Choice
            elif ctx.input in ('?', '*', '+', '{'):

                if ctx.choice and len(ctx.values) > 1 and len(ctx.buffer) > 1:
                    raise InconvertibilityError()

                if len(ctx.buffer) == 1:
                    if len(ctx.values) > 1:
                        content = ctx.buffer
                        ctx.values = ctx.values[:-1]
                        ctx.flush()
                        ctx.append_to_buffer(content)

                else:
                    content = ctx.buffer[-1]
                    ctx.buffer = ctx.buffer[:-1]
                    ctx.flush()
                    ctx.append_to_buffer(content)

                if ctx.input == '{':
                    return self.machine.Brackets
                else:
                    return self.machine.QtyState

            elif ctx.input in ('}',')',']'):
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

            if ctx.choice:
                raise InconvertibilityError()

            if ctx.input == '(':
                return self.machine.Parenthesis
            elif ctx.input == '[':
                return self.machine.SquareBrackets
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
            elif ctx.choice:
                raise InconvertibilityError()

            if ctx.input == '(':
                return self.machine.Parenthesis
            elif ctx.input == '[':
                return self.machine.SquareBrackets
            elif ctx.input == '\\':
                return self.machine.Escape
            else:
                return self.machine.Main


    @register
    class Parenthesis(StateMachine, Group):

        @initial
        class Initial(State):

            def _run(self, ctx):
                ctx.flush()
                ctx.append_to_buffer("")

            def advance(self, ctx):
                if ctx.input in ('?', '*', '+', '{'):
                    raise QuantificationError()
                elif ctx.input in ('}', ']', None):
                    raise StructureError(ctx.input)
                elif ctx.input in ('(', '['):
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
                ctx.flush()
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
            if ctx.choice and len(ctx.values) > 1 and len(ctx.buffer) > 1:
                raise InconvertibilityError()

            if ctx.buffer is not None:

                if len(ctx.buffer) == 0:

                    if len(ctx.values[:-1]) > 0:
                        ctx.values = ctx.values[:-1]
                        ctx.flush()
                else:
                    ctx.flush()

            ctx.append_to_alphabet(ctx.META_SEQUENCES[ctx.input])


    def init_specific(self):
        self._name = None
        self.charset = None

        self.values = None
        self.alphabet = None

        self.choice = False

        self.min = None
        self.max = None

        self.nodes = []


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

        name = self._name + '_' + str(len(self.nodes) + 1)
        self.nodes.append(self._create_terminal_node(name, type, values=self.values,
                                                     alphabet=self.alphabet, qty=(self.min, self.max)))
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
        elif self.charset == MH.Charset.UNICODE:
            max = 0xFFFF
        else:
            max = 0xFF

        def get_complement(chars):
            return ''.join([self.int_to_string(i) for i in range(0, max + 1) if self.int_to_string(i) not in chars])

        self.META_SEQUENCES = {'s': string.whitespace,
                               'S': get_complement(string.whitespace),
                               'd': string.digits,
                               'D': get_complement(string.digits),
                               'w': string.ascii_letters + string.digits + '_',
                               'W': get_complement(string.ascii_letters + string.digits + '_')}

        self.SPECIAL_CHARS = list('\\()[]{}*+?|-')

        # None indicates the beginning and the end of the regex
        self.inputs = [None] + list(inputs) + [None]
        self.run(self)

        return self._create_non_terminal_node()


    def _create_terminal_node(self, name, type, values=None, alphabet=None, qty=None):

        assert(values is not None or alphabet is not None)

        if alphabet is not None:
            return [Node(name=name, vt=fvt.String(alphabet=alphabet, min_sz=qty[0], max_sz=qty[1])), 1, 1]
        else:
            if type == fvt.String:
                node = Node(name=name, vt=fvt.String(val_list=values))
            else:
                node = Node(name=name, vt=fvt.INT_str(int_list=values))

            return [node, qty[0], -1 if qty[1] is None else qty[1]]

    def _create_non_terminal_node(self):
        non_terminal = [1, [MH.Copy + MH.Ordered]]
        formatted_terminal = non_terminal[1]

        for terminal in self.nodes:
            formatted_terminal.append(terminal)
            if self.choice and len(self.nodes) > 1:
                non_terminal.append(1)
                formatted_terminal = [MH.Copy + MH.Ordered]
                non_terminal.append(formatted_terminal)

        return non_terminal



class ModelHelper(object):

    HIGH_PRIO = 1
    MEDIUM_PRIO = 2
    LOW_PRIO = 3
    VERYLOW_PRIO = 4

    valid_keys = [
        # generic description keys
        'name', 'contents', 'qty', 'clone', 'type', 'alt', 'conf',
        'custo_set', 'custo_clear',
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
        'post_freeze', 'charset'
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
            assert self.dm is not None, "ModelHelper should be initialized with the current data model!"
            data_id = desc.get('data_id', None)
            assert data_id is not None, "Missing field: 'data_id' (to be used with 'import_from' field)"
            nd = self.dm.get_external_node(dm_name=exp, data_id=data_id, name=name)
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
            if node_args is not None:
                # node_args interpretation is postponed after all nodes has been created
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


        custo_set = desc.get('custo_set', None)
        custo_clear = desc.get('custo_clear', None)

        if custo_set or custo_clear:
            custo = NonTermCusto(items_to_set=custo_set, items_to_clear=custo_clear)
            internals = n.cc if conf is None else n.c[conf]
            internals.customize(custo)

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

        if custo_set or custo_clear:
            custo = Custo(items_to_set=custo_set, items_to_clear=custo_clear)
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
        node.set_contents(self.node_dico[ref])
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


    def merge_with(self, data_model):
        for k, v in data_model.__dm_hashtable.items():
            if k in self.__dm_hashtable:
                raise ValueError("the data ID {:s} exists already".format(k))
            else:
                self.__dm_hashtable[k] = v

        self.__confs = self.__confs.union(data_model.__confs)

        
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

    def cleanup(self):
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
            node = Node(nm, base_node=self.__dm_hashtable[hash_key], ignore_frozen_state=False,
                        new_env=True)
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
                  "\n   [probable reason: {fdata:s}/imported_data/{nm:s}/ not " \
                  "populated with sample files]".format(nm=self.name, fdata=gr.fuddly_data_folder)
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
            path = gr.imported_data_folder
        else:
            path = os.path.join(gr.imported_data_folder, subdir)

        if not os.path.exists(path):
            os.makedirs(path)

        return path
