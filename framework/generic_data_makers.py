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

import types
import subprocess
import uuid

from copy import *

from framework.node import *
from framework.data import *
from framework.tactics_helpers import *
from framework.fuzzing_primitives import *
from framework.basic_primitives import *
from framework.value_types import *
from framework.data_model import DataModel
from framework.dmhelpers.generic import MH
from framework.node import NodeSemanticsCriteria as NSC, NodeInternalsCriteria as NIC

# from framework.plumbing import *
from framework.evolutionary_helpers import Population
from framework.global_resources import *

tactics = Tactics()


#######################
#     GENERATORS      #
#######################

@generator(tactics, gtype="GENP", weight=4,
           args={'pattern': ('Pattern to be used for generating data', b'1234567890', bytes),
                 'prefix': ('Prefix added to the pattern', b'', bytes),
                 'suffix': ('Suffix replacing the end of the pattern', b'', bytes),
                 'size': ('Size of the generated data.', None, int),
                 'eval': ('The pattern will be evaluated before being used. Note that the evaluation '
                          'shall result in a byte string.', False, bool)
                 })
class g_generic_pattern(Generator):
    """
    Generate basic data based on a pattern and different parameters.
    """
    def setup(self, dm, user_input):
        if not self.pattern:
            return False
        return True

    def generate_data(self, dm, monitor, target):
        if self.eval:
            try:
                pattern = eval(self.pattern)
            except:
                data = Data()
                # data.make_unusable()
                data.add_info('Invalid expression provided in @pattern. It will be used without evaluation.')
                return data
        else:
            pattern = self.pattern

        if self.size is not None:
            psize = len(pattern)
            pattern = pattern * (self.size // psize) + pattern[:(self.size%psize)]
            if self.prefix:
                pattern = self.prefix + pattern[:-(len(self.prefix))]

        else:
            pattern = self.prefix+pattern

        if self.suffix:
            pattern = pattern[:-len(self.suffix)] + self.suffix
        if self.size is not None and self.size < len(pattern):
            pattern = pattern[:self.size]

        return Data(pattern)


@generator(tactics, gtype='POPULATION', weight=1,
           args={'population': ('The population to iterate over.', None, Population),
                 'track': ('Keep trace of the changes that occurred on data, generation after generation',
                           False, bool)}
           )
class g_population(Generator):
    """ Walk through the given population """
    def setup(self, dm, user_input):
        assert self.population is not None
        self.population.reset()
        self._pop_sz = self.population.size()
        self._curr_generation = self.population.generation
        return True

    def generate_data(self, dm, monitor, target):
        reset = False

        try:
            data = self.population.next().data
        except StopIteration:
            # all individuals of the current population have been sent

            if self.population.is_final():
                reset = True
            else:
                try:
                    self.population.evolve()
                    self._pop_sz = self.population.size()
                    self._curr_generation = self.population.generation
                except ExtinctPopulationError:
                    reset = True
                else:
                    return self.generate_data(dm, monitor, target)

        if reset:
            data = Data()
            data.make_unusable()
            self.need_reset()

        data.add_info('Generation: {}, Population size: {}'.format(self._curr_generation, self._pop_sz))
        data.add_info('Data index in the population: {}'.format(self.population.index))
        data.take_info_ownership(keep_previous_info=self.track)

        return data


#######################
# STATEFUL DISRUPTORS #
#######################

def truncate_info(info, max_size=60):
    if len(info) > max_size:
        info = info[:max_size] + b' ...'
    return repr(info)


@disruptor(tactics, dtype="tWALK", weight=1, modelwalker_user=True,
           args={'path': ('Graph path regexp to select nodes on which' \
                          ' the disruptor should apply.', None, str),
                 'sem': ('Semantics to select nodes on which' \
                         ' the disruptor should apply.', None, (str, list)),
                 'full_combinatory': ('When set to True, enable full-combinatory mode for '
                                      'non-terminal nodes. It means that the non-terminal nodes '
                                      'will be customized in "FullCombinatory" mode', False, bool),
                 'leaf_determinism': ("If set to 'True', all the typed nodes of the model will be "
                                       "set to determinist mode prior to any fuzzing. If set "
                                       "to 'False', they will be set to random mode. "
                                       "Otherwise, if set to 'None', nothing will be done.", None, bool),
                 'order': ('When set to True, the walking order is strictly guided ' \
                           'by the data structure. Otherwise, fuzz weight (if specified ' \
                           'in the data model) is used for ordering.', True, bool),
                 'nt_only': ('Walk through non-terminal nodes only.', False, bool),
                 'deep': ('When set to True, if a node structure has changed, the modelwalker ' \
                          'will reset its walk through the children nodes.', True, bool),
                 'consider_sibbling_change':
                     ('While walking through terminal nodes, if sibbling nodes are '
                      'no more the same because of existence condition for instance, walk through '
                      'the new nodes.', True, bool),
                 'ign_mutable_attr': ('Walk through all the nodes even if their Mutable attribute '
                                      'is cleared.', True, bool),
                 'fix_all': ('For each produced data, reevaluate the constraints on the whole graph.',
                             True, bool)})
class sd_walk_data_model(StatefulDisruptor):
    """
    Walk through the provided data and for each visited node, iterates
    over the allowed values (with respect to the data model).
    Note: *no alteration* is performed by this disruptor.
    """
    def setup(self, dm, user_input):
        return True

    def set_seed(self, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('DONT_PROCESS_THIS_KIND_OF_DATA')
            return prev_data

        prev_content.make_finite(all_conf=True, recursive=True)

        if self.full_combinatory:
            nic = NodeInternalsCriteria(node_kinds=[NodeInternals_NonTerm])
            nl = prev_content.get_reachable_nodes(internals_criteria=nic, path_regexp=self.path,
                                                  ignore_fstate=True)
            for n in nl:
                n.cc.custo.full_combinatory_mode = True

        if self.leaf_determinism is not None:
            nic = NodeInternalsCriteria(node_kinds=[NodeInternals_TypedValue])
            nl = prev_content.get_reachable_nodes(internals_criteria=nic, path_regexp=self.path,
                                                  ignore_fstate=True)
            for n in nl:
                if self.leaf_determinism:
                    n.make_determinist()
                else:
                    n.make_random()

        if self.nt_only:
            consumer = NonTermVisitor(respect_order=self.order, ignore_mutable_attr=self.ign_mutable_attr,
                                      consider_side_effects_on_sibbling=self.consider_sibbling_change,
                                      reset_when_change=self.deep, fix_constraints=self.fix_all)
        else:
            consumer = BasicVisitor(respect_order=self.order, ignore_mutable_attr=self.ign_mutable_attr,
                                    consider_side_effects_on_sibbling=self.consider_sibbling_change,
                                    reset_when_change=self.deep, fix_constraints=self.fix_all)
        sem_crit = NSC(optionalbut1_criteria=self.sem)
        consumer.set_node_interest(path_regexp=self.path, semantics_criteria=sem_crit)
        self.modelwalker = ModelWalker(prev_content, consumer, max_steps=self.max_steps, initial_step=self.init)
        self.walker = iter(self.modelwalker)


    def disrupt_data(self, dm, target, data):
        try:
            rnode, consumed_node, orig_node_val, idx = next(self.walker)
        except StopIteration:
            data.make_unusable()
            self.handover()
            return data

        data.add_info('model walking index: {:d}'.format(idx))
        data.add_info('current node:     {!s}'.format(self.modelwalker.consumed_node_path))

        if self.clone_node:
            exported_node = Node(rnode.name, base_node=rnode, new_env=True)
        else:
            exported_node = rnode

        if self.fix_all:
            exported_node.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
            exported_node.freeze()
            data.add_info('reevaluate all the constraints (if any)')

        data.update_from(exported_node)

        return data



@disruptor(tactics, dtype="tTYPE", weight=1, modelwalker_user=True,
           args={'path': ('Graph path regexp to select nodes on which' \
                          ' the disruptor should apply.', None, str),
                 'sem': ('Semantics to select nodes on which' \
                         ' the disruptor should apply.', None, (str, list)),
                 'order': ('When set to True, the fuzzing order is strictly guided ' \
                           'by the data structure. Otherwise, fuzz weight (if specified ' \
                           'in the data model) is used for ordering.', True, bool),
                 'deep': ('When set to True, if a node structure has changed, the modelwalker ' \
                          'will reset its walk through the children nodes.', True, bool),
                 'full_combinatory': ('When set to True, enable full-combinatory mode for non-terminal nodes. It '
                                      'means that the non-terminal nodes will be customized in "FullCombinatory" mode',
                                      False,bool),
                 'ign_sep': ('When set to True, separators will be ignored ' \
                          'if any are defined.', False, bool),
                 'fix_all': ('For each produced data, reevaluate the constraints on the whole graph.',
                             False, bool),
                 'fix': ("Limit constraints fixing to the nodes related to the currently fuzzed one"
                         " (only implemented for 'sync_size_with' and 'sync_enc_size_with').", True, bool),
                 'fuzz_mag': ('Order of magnitude for maximum size of some fuzzing test cases.',
                              1.0, float),
                 'make_determinist': ("If set to 'True', the whole model will be set in determinist mode."
                                      "Otherwise it will be guided by the data model determinism.", False, bool),
                 'leaf_fuzz_determinism': ("If set to 'True', each typed node will be fuzzed in "
                                      "a deterministic way. If set to 'False' each typed node "
                                      "will be fuzzed in a random way. Otherwise, if it is set to "
                                      "'None', it will be guided by the "
                                      "data model determinism. Note: this option is complementary to "
                                      "'determinism' as it acts on the typed node substitutions "
                                      "that occur through this disruptor", True, bool),
                 'leaf_determinism': ("If set to 'True', all the typed nodes of the model will be "
                                       "set to determinist mode prior to any fuzzing. If set "
                                       "to 'False', they will be set to random mode. "
                                       "Otherwise, if set to 'None', nothing will be done.", None, bool),
                 'ign_mutable_attr': ('Walk through all the nodes even if their Mutable attribute '
                                      'is cleared.', False, bool),
                 'consider_sibbling_change':
                     ('[EXPERIMENTAL] While walking through terminal nodes, if sibbling nodes are '
                      'no more the same because of existence condition for instance, walk through '
                      'the new nodes. (Currently, work only with some specific data model construction.)',
                      False, bool),
                 })
class sd_fuzz_typed_nodes(StatefulDisruptor):
    """
    Perform alterations on typed nodes (one at a time) according to:
    - their type (e.g., INT, Strings, ...)
    - their attributes (e.g., allowed values, minimum size, ...)
    - knowledge retrieved from the data (e.g., if the input data uses separators, their symbols
    are leveraged in the fuzzing)
    - knowledge on the target retrieved from the project file or dynamically from feedback inspection
    (e.g., C language, GNU/Linux OS, ...)

    If the input has different shapes (described in non-terminal nodes), this will be taken into
    account by fuzzing every shape combinations.

    Note: this disruptor includes what tSEP does and goes beyond with respect to separators.
    """
    def setup(self, dm, user_input):
        return True

    def set_seed(self, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('DONT_PROCESS_THIS_KIND_OF_DATA')
            return prev_data

        if self.full_combinatory:
            nic = NodeInternalsCriteria(node_kinds=[NodeInternals_NonTerm])
            nl = prev_content.get_reachable_nodes(internals_criteria=nic, path_regexp=self.path,
                                                  ignore_fstate=True)
            for n in nl:
                n.cc.custo.full_combinatory_mode = True

        if self.leaf_determinism is not None:
            nic = NodeInternalsCriteria(node_kinds=[NodeInternals_TypedValue])
            nl = prev_content.get_reachable_nodes(internals_criteria=nic, path_regexp=self.path,
                                                  ignore_fstate=True)
            for n in nl:
                if self.leaf_determinism:
                    n.make_determinist()
                else:
                    n.make_random()

        self.consumer = TypedNodeDisruption(max_runs_per_node=self.max_runs_per_node,
                                            min_runs_per_node=self.min_runs_per_node,
                                            fuzz_magnitude=self.fuzz_mag,
                                            fix_constraints=self.fix,
                                            respect_order=self.order,
                                            ignore_mutable_attr=self.ign_mutable_attr,
                                            consider_side_effects_on_sibbling=self.consider_sibbling_change,
                                            ignore_separator=self.ign_sep,
                                            determinist=self.leaf_fuzz_determinism)
        self.consumer.need_reset_when_structure_change = self.deep
        sem_crit = NSC(optionalbut1_criteria=self.sem)
        self.consumer.set_node_interest(path_regexp=self.path, semantics_criteria=sem_crit)
        self.modelwalker = ModelWalker(prev_content, self.consumer, max_steps=self.max_steps,
                                       initial_step=self.init, make_determinist=self.make_determinist)

        # After ModelWalker init, 'prev_content' is frozen. We can now check if 'self.path' exists in the
        # node, because if it does not exist (e.g., user mistype) the ModelWalker will walk until the end of
        # all the possible paths, and will finally yield nothing. This walk could take a lot of time depending on
        # the model. Thus, in this situation we inform the user right away.
        if self.path:
            d = prev_content.get_nodes_by_paths(path_list=[self.path])
            if not d[self.path]:
                raise ValueError(f'The provided path "{self.path}" does not exist.')

        self.walker = iter(self.modelwalker)

        self.max_runs = None
        self.current_node = None
        self.run_num = None

    def disrupt_data(self, dm, target, data):
        try:
            rnode, consumed_node, orig_node_val, idx = next(self.walker)
        except StopIteration:
            data.make_unusable()
            self.handover()
            return data

        new_max_runs = self.consumer.max_nb_runs_for(consumed_node)
        if self.max_runs != new_max_runs or self.current_node != consumed_node:
            self.current_node = consumed_node
            self.max_runs = new_max_runs
            self.run_num = 1
        else:
            self.run_num +=1

        corrupt_node_bytes = consumed_node.to_bytes()

        data.add_info('model walking index: {:d}'.format(idx))
        data.add_info(' |_ run: {:d} / {:d} (max)'.format(self.run_num, self.max_runs))
        data.add_info('current fuzzed node:     {!s}'.format(self.modelwalker.consumed_node_path))
        data.add_info(' |_ value type:          {!s}'.format(consumed_node.cc.get_value_type()))
        data.add_info(' |_ original node value (hex): {!s}'.format(truncate_info(binascii.b2a_hex(orig_node_val))))
        data.add_info(' |                    (ascii): {!s}'.format(truncate_info(orig_node_val)))
        data.add_info(' |_ corrupt node value  (hex): {!s}'.format(truncate_info(binascii.b2a_hex(corrupt_node_bytes))))
        data.add_info('                      (ascii): {!s}'.format(truncate_info(corrupt_node_bytes)))

        if self.clone_node:
            exported_node = Node(rnode.name, base_node=rnode, new_env=True)
        else:
            exported_node = rnode

        if self.fix_all:
            exported_node.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
            exported_node.freeze()
            data.add_info('reevaluate all the constraints (if any)')

        data.update_from(exported_node)
        data.altered = True

        return data



@disruptor(tactics, dtype="tALT", weight=1, modelwalker_user=True,
           args={'conf': ("Change the configuration, with the one provided (by name), of " \
                          "all nodes reachable from the root, one-by-one. [default value is set " \
                          "dynamically with the first-found existing alternate configuration]",
                          None, (str,list,tuple))})
class sd_switch_to_alternate_conf(StatefulDisruptor):
    '''
    Switch the configuration of each node, one by one, with the
    provided alternate configuration.
    '''
    def setup(self, dm, user_input):
        if not isinstance(dm, DataModel):
            return False

        available_confs = dm.node_backend.get_all_confs()

        all_alternate_confs = copy.copy(available_confs)
        if not all_alternate_confs:
            return False

        self.confs_list = None

        if self.conf is None:
            self.confs_list = all_alternate_confs
        else:
            if isinstance(self.conf, (tuple, list)):
                for c in self.conf:
                    if c in all_alternate_confs:
                        ok = True
                        break
                else:
                    ok = False
                if ok:
                    self.confs_list = self.conf
                else:
                    return False
            elif self.conf not in all_alternate_confs:
                return False
            else:
                self.confs_list = [self.conf]
            
        return True

    def set_seed(self, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('DONT_PROCESS_THIS_KIND_OF_DATA')
            return prev_data

        self.consumer = AltConfConsumer(max_runs_per_node=self.max_runs_per_node,
                                        min_runs_per_node=self.min_runs_per_node,
                                        respect_order=False)
        self.consumer.set_node_interest(owned_confs=self.confs_list)
        self.modelwalker = ModelWalker(prev_content, self.consumer, max_steps=self.max_steps, initial_step=self.init)
        self.walker = iter(self.modelwalker)

        self.max_runs = None
        self.current_node = None
        self.run_num = None


    def disrupt_data(self, dm, target, data):

        try:
            rnode, consumed_node, orig_node_val, idx = next(self.walker)
        except StopIteration:
            data.make_unusable()
            self.handover()
            return data

        new_max_runs = self.consumer.max_nb_runs_for(consumed_node)
        if self.max_runs != new_max_runs or self.current_node != consumed_node:
            self.current_node = consumed_node
            self.max_runs = new_max_runs
            self.run_num = 1
        else:
            self.run_num +=1

        data.add_info('model walking index: {:d}'.format(idx))        
        data.add_info(' |_ run: {:d} / {:d} (max)'.format(self.run_num, self.max_runs))
        data.add_info('current node with alternate conf: {!s}'.format(self.modelwalker.consumed_node_path))
        data.add_info(' |_ associated value: {!s}'.format(truncate_info(consumed_node.to_bytes())))
        data.add_info(' |_ original node value: {!s}'.format(truncate_info(orig_node_val)))

        if self.clone_node:
            exported_node = Node(rnode.name, base_node=rnode, new_env=True)
            data.update_from(exported_node)
        else:
            data.update_from(rnode)

        return data


@disruptor(tactics, dtype="tSEP", weight=1, modelwalker_user=True,
           args={'path': ('Graph path regexp to select nodes on which' \
                          ' the disruptor should apply.', None, str),
                 'sem': ('Semantics to select nodes on which' \
                         ' the disruptor should apply.', None, (str, list)),
                 'order': ('When set to True, the fuzzing order is strictly guided ' \
                           'by the data structure. Otherwise, fuzz weight (if specified ' \
                           'in the data model) is used for ordering.', True, bool),
                 'deep': ('When set to True, if a node structure has changed, the modelwalker ' \
                          'will reset its walk through the children nodes.', True, bool)})
class sd_fuzz_separator_nodes(StatefulDisruptor):
    '''
    Perform alterations on separators (one at a time). Each time a
    separator is encountered in the provided data, it will be replaced
    by another separator picked from the ones existing within the
    provided data.
    '''
    def setup(self, dm, user_input):
        return True

    def set_seed(self, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('DONT_PROCESS_THIS_KIND_OF_DATA')
            return prev_data

        prev_content.get_value()

        ic = dm.NodeInternalsCriteria(mandatory_attrs=[dm.NodeInternals.Separator])
        sep_list = set(map(lambda x: x.to_bytes(), prev_content.get_reachable_nodes(internals_criteria=ic)))
        sep_list = list(sep_list)
        prev_data.add_info('separators found: {!r}'.format(sep_list))

        prev_content.make_finite(all_conf=True, recursive=True)

        self.consumer = SeparatorDisruption(max_runs_per_node=self.max_runs_per_node,
                                            min_runs_per_node=self.min_runs_per_node,
                                            respect_order=self.order,
                                            separators=sep_list)
        self.consumer.need_reset_when_structure_change = self.deep
        sem_crit = NSC(optionalbut1_criteria=self.sem)
        self.consumer.set_node_interest(path_regexp=self.path, semantics_criteria=sem_crit)
        self.modelwalker = ModelWalker(prev_content, self.consumer, max_steps=self.max_steps, initial_step=self.init)
        self.walker = iter(self.modelwalker)

        self.max_runs = None
        self.current_node = None
        self.run_num = None

    def disrupt_data(self, dm, target, data):
        try:
            rnode, consumed_node, orig_node_val, idx = next(self.walker)
        except StopIteration:
            data.make_unusable()
            self.handover()
            return data

        new_max_runs = self.consumer.max_nb_runs_for(consumed_node)
        if self.max_runs != new_max_runs or self.current_node != consumed_node:
            self.current_node = consumed_node
            self.max_runs = new_max_runs
            self.run_num = 1
        else:
            self.run_num +=1

        corrupt_node_bytes = consumed_node.to_bytes()

        data.add_info('model walking index: {:d}'.format(idx))        
        data.add_info(' |_ run: {:d} / {:d} (max)'.format(self.run_num, self.max_runs))
        data.add_info('current fuzzed separator:     {!s}'.format(self.modelwalker.consumed_node_path))
        data.add_info(' |_ value type:         {!s}'.format(consumed_node.cc.get_value_type()))
        data.add_info(' |_ original separator (hex): {!s}'.format(truncate_info(binascii.b2a_hex(orig_node_val))))
        data.add_info(' |                   (ascii): {!s}'.format(truncate_info(orig_node_val)))
        data.add_info(' |_ replaced by        (hex): {!s}'.format(truncate_info(binascii.b2a_hex(corrupt_node_bytes))))
        data.add_info('                     (ascii): {!s}'.format(truncate_info(corrupt_node_bytes)))

        if self.clone_node:
            exported_node = Node(rnode.name, base_node=rnode, new_env=True)
            data.update_from(exported_node)
        else:
            data.update_from(rnode)

        data.altered = True
        return data



@disruptor(tactics, dtype="tSTRUCT", weight=1,
           args={'init': ('Make the model walker ignore all the steps until the provided one.', 1, int),
                 'max_steps': ('Maximum number of steps (-1 means until the end).', -1, int),
                 'path': ('Graph path regexp to select nodes on which' \
                          ' the disruptor should apply.', None, str),
                 'sem': ('Semantics to select nodes on which' \
                         ' the disruptor should apply.', None, (str, list)),
                 'deep': ('If True, enable corruption of non-terminal node internals',
                          False, bool) })
class sd_struct_constraints(StatefulDisruptor):
    """
    Perform constraints alteration (one at a time) on each node that depends on another one
    regarding its existence, its quantity, its size, ...

    If `deep` is set, enable more corruption cases on the data structure, based on the internals of
    each non-terminal node:
    - the minimum and maximum amount of the subnodes of each non-terminal nodes
    - ...
    """
    def setup(self, dm, user_input):
        return True

    def set_seed(self, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('CANNOT PROCESS THIS KIND OF DATA')
            return prev_data

        self.seed = prev_content
        self.seed.make_finite(all_conf=True, recursive=True)
        # self.seed.make_determinist(all_conf=True, recursive=True)
        self.seed.freeze()

        # self.seed.unfreeze(recursive=True)
        # self.seed.freeze()

        # print('\n*** original data:\n',self.seed.to_bytes())

        self.idx = 0

        ic_exist_cst = NodeInternalsCriteria(required_csts=[SyncScope.Existence])
        ic_qty_cst = NodeInternalsCriteria(required_csts=[SyncScope.Qty])
        ic_size_cst = NodeInternalsCriteria(required_csts=[SyncScope.Size])
        ic_minmax_cst = NodeInternalsCriteria(node_kinds=[NodeInternals_NonTerm])

        sem_crit = None if self.sem is None else NSC(optionalbut1_criteria=self.sem)

        self.exist_cst_nodelist = self.seed.get_reachable_nodes(internals_criteria=ic_exist_cst, path_regexp=self.path,
                                                                semantics_criteria=sem_crit,
                                                                ignore_fstate=True)
        # print('\n*** NOT FILTERED nodes')
        # for n in self.exist_cst_nodelist:
        #     print(' |_ ' + n.name)
        # self.exist_cst_nodelist = self.seed.filter_out_entangled_nodes(self.exist_cst_nodelist)
        # print('\n*** FILTERED nodes')
        # for n in self.exist_cst_nodelist:
        #     print(' |_ ' + n.name)

        # print('\n***before:')
        # for n in self.exist_cst_nodelist:
        #     print(' |_ ' + n.name)

        nodelist = copy.copy(self.exist_cst_nodelist)
        for n in nodelist:
            if n.get_path_from(self.seed) is None:
                self.exist_cst_nodelist.remove(n)
        # print('\n***after:')
        # for n in self.exist_cst_nodelist:
        #     print(' |_ ' + n.name)

        self.qty_cst_nodelist_1 = self.seed.get_reachable_nodes(internals_criteria=ic_qty_cst, path_regexp=self.path,
                                                                semantics_criteria=sem_crit,
                                                                ignore_fstate=True)
        # self.qty_cst_nodelist_1 = self.seed.filter_out_entangled_nodes(self.qty_cst_nodelist_1)
        nodelist = copy.copy(self.qty_cst_nodelist_1)
        for n in nodelist:
            if n.get_path_from(self.seed) is None:
                self.qty_cst_nodelist_1.remove(n)

        self.qty_cst_nodelist_2 = copy.copy(self.qty_cst_nodelist_1)

        self.size_cst_nodelist_1 = self.seed.get_reachable_nodes(internals_criteria=ic_size_cst, path_regexp=self.path,
                                                                 semantics_criteria=sem_crit,
                                                                 ignore_fstate=True)
        nodelist = copy.copy(self.size_cst_nodelist_1)
        for n in nodelist:
            if n.get_path_from(self.seed) is None:
                self.size_cst_nodelist_1.remove(n)
        self.size_cst_nodelist_2 = copy.copy(self.size_cst_nodelist_1)

        if self.deep:
            minmax_cst_nodelist = self.seed.get_reachable_nodes(internals_criteria=ic_minmax_cst, path_regexp=self.path,
                                                                semantics_criteria=sem_crit,
                                                                ignore_fstate=True)
            self.minmax_cst_nodelist_1 = set()

            for n in minmax_cst_nodelist:
                for sn in n.subnodes_set:
                    minmax = n.get_subnode_minmax(sn)
                    if minmax is not None:
                        mini, maxi = minmax
                        self.minmax_cst_nodelist_1.add((sn, mini, maxi))

            nodedesclist = copy.copy(self.minmax_cst_nodelist_1)
            for n_desc in nodedesclist:
                n, mini, maxi = n_desc
                if n.get_path_from(self.seed) is None:
                    self.minmax_cst_nodelist_1.remove((n, mini, maxi))

            self.minmax_cst_nodelist_2 = copy.copy(self.minmax_cst_nodelist_1)
            self.minmax_cst_nodelist_3 = copy.copy(self.minmax_cst_nodelist_1)

        else:
            self.minmax_cst_nodelist_1 = self.minmax_cst_nodelist_2 = self.minmax_cst_nodelist_3 = []

        self.max_runs = len(self.exist_cst_nodelist) + 2*len(self.size_cst_nodelist_1) + \
                        2*len(self.qty_cst_nodelist_1) + 3*len(self.minmax_cst_nodelist_1)

        # print('\n*** final setup:\n',self.seed.to_bytes())

    def disrupt_data(self, dm, target, data):

        stop = False
        if self.idx == 0:
            step_idx = self.init-1
        else:
            step_idx = self.idx

        while self.idx <= step_idx:
            if self.exist_cst_nodelist:
                consumed_node = self.exist_cst_nodelist.pop()
                if self.idx == step_idx:
                    self.seed.env.add_node_to_corrupt(consumed_node, corrupt_type=Node.CORRUPT_EXIST_COND)
                    op_performed = 'existence condition switched'
            elif self.qty_cst_nodelist_1:
                consumed_node = self.qty_cst_nodelist_1.pop()
                if self.idx == step_idx:
                    self.seed.env.add_node_to_corrupt(consumed_node, corrupt_type=Node.CORRUPT_QTY_SYNC,
                                                      corrupt_op=lambda x: x+1)
                    op_performed = 'increase quantity constraint by 1'
            elif self.qty_cst_nodelist_2:
                consumed_node = self.qty_cst_nodelist_2.pop()
                if self.idx == step_idx:
                    self.seed.env.add_node_to_corrupt(consumed_node, corrupt_type=Node.CORRUPT_QTY_SYNC,
                                                      corrupt_op=lambda x: max(x-1, 0))
                    op_performed = 'decrease quantity constraint by 1'
            elif self.size_cst_nodelist_1:
                consumed_node = self.size_cst_nodelist_1.pop()
                if self.idx == step_idx:
                    self.seed.env.add_node_to_corrupt(consumed_node, corrupt_type=Node.CORRUPT_SIZE_SYNC,
                                                      corrupt_op=lambda x: x+1)
                    op_performed = 'increase size constraint by 1'
            elif self.size_cst_nodelist_2:
                consumed_node = self.size_cst_nodelist_2.pop()
                if self.idx == step_idx:
                    self.seed.env.add_node_to_corrupt(consumed_node, corrupt_type=Node.CORRUPT_SIZE_SYNC,
                                                      corrupt_op=lambda x: max(x-1, 0))
                    op_performed = 'decrease size constraint by 1'
            elif self.deep and self.minmax_cst_nodelist_1:
                consumed_node, mini, maxi = self.minmax_cst_nodelist_1.pop()
                if self.idx == step_idx:
                    new_mini = max(0, mini-1)
                    self.seed.env.add_node_to_corrupt(consumed_node, corrupt_type=Node.CORRUPT_NODE_QTY,
                                                      corrupt_op=lambda x, y: (new_mini, new_mini))
                    op_performed = f"set node amount to its minimum minus one ({new_mini})"
            elif self.deep and self.minmax_cst_nodelist_2:
                consumed_node, mini, maxi = self.minmax_cst_nodelist_2.pop()
                if self.idx == step_idx:
                    new_maxi = (maxi+1)
                    self.seed.env.add_node_to_corrupt(consumed_node, corrupt_type=Node.CORRUPT_NODE_QTY,
                                                      corrupt_op=lambda x, y: (new_maxi, new_maxi))
                    op_performed = f"set node amount to its maximum plus one ({new_maxi})"
            elif self.deep and self.minmax_cst_nodelist_3:
                consumed_node, mini, maxi = self.minmax_cst_nodelist_3.pop()
                if self.idx == step_idx:
                    new_maxi = (maxi*10)
                    self.seed.env.add_node_to_corrupt(consumed_node, corrupt_type=Node.CORRUPT_NODE_QTY,
                                                      corrupt_op=lambda x, y: (new_maxi, new_maxi))
                    op_performed = f"set node amount to a value way beyond its maximum ({new_maxi})"
            else:
                stop = True
                break

            self.idx += 1

        if stop or (self.idx > self.max_steps and self.max_steps != -1):
            data.make_unusable()
            self.handover()
            return data

        # print('\n***disrupt before:\n',self.seed.to_bytes())
        corrupted_seed = Node(self.seed.name, base_node=self.seed, ignore_frozen_state=False, new_env=True)
        corrupted_seed = self.seed.get_clone(ignore_frozen_state=False, new_env=True)
        self.seed.env.remove_node_to_corrupt(consumed_node)

        # print('\n***disrupt source:\n',self.seed.to_bytes())
        # print('\n***disrupt clone 1:\n',corrupted_seed.to_bytes())
        # nt_nodes_crit = NodeInternalsCriteria(node_kinds=[NodeInternals_NonTerm])
        # ntlist = corrupted_seed.get_reachable_nodes(internals_criteria=nt_nodes_crit, ignore_fstate=False)
        # for nd in ntlist:
        #     # print(nd.is_attr_set(NodeInternals.Finite))
        #     nd.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)

        corrupted_seed.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
        corrupted_seed.freeze()

        # print('\n***disrupt after:\n',corrupted_seed.to_bytes())

        data.add_info('sample index: {:d}'.format(self.idx))
        data.add_info(' |_ run: {:d} / {:d}'.format(self.idx, self.max_runs))
        data.add_info('current fuzzed node:    {:s}'.format(consumed_node.get_path_from(self.seed)))
        data.add_info(' |_ {:s}'.format(op_performed))

        data.update_from(corrupted_seed)
        data.altered = True

        return data


########################
# STATELESS DISRUPTORS #
########################


@disruptor(tactics, dtype="EXT", weight=1,
           args={'cmd': ('The external command the execute.', None, (list,tuple,str)),
                 'file_mode': ('If True the data will be provided through ' \
                               'a file to the external program, otherwise it ' \
                               'will be provided on the command line directly.', True, bool),
                 'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str)})
class d_call_external_program(Disruptor):
    '''
    Call an external program to deal with the data.
    '''
    def setup(self, dm, user_input):
        if self._get_cmd() is None:
            if self.cmd is None:
                print("\n*** ERROR: A command should be provided!")
                return False

        return True

    def _get_cmd(self):
        return self.cmd

    def disrupt_data(self, dm, target, prev_data):
        prev_content = prev_data.content
        if self.path and isinstance(prev_content, Node):
            node = prev_content.get_first_node_by_path(path_regexp=self.path)
            if node is None:
                prev_data.add_info('INVALID INPUT')
                return prev_data
            raw_data = node.to_bytes()
        else:
            node = None
            raw_data = prev_data.to_bytes()

        cmd = self._get_cmd()

        if isinstance(cmd, list):
            cmd_repr = ' '.join(cmd)
        else:
            cmd_repr = cmd

        # provide prev_data through a file
        if self.file_mode:
            dm = prev_data.get_data_model()
            if dm:
                file_extension = dm.file_extension
            else:
                file_extension = 'bin'

            filename = os.path.join(workspace_folder, 'EXT_file.' + file_extension)
            with open(filename, 'wb') as f:
                f.write(raw_data)

            prev_data.add_info("Execute command: {:s}".format(cmd_repr + ' ' + filename))
            arg = filename

        # provide prev_data on the command line
        else:
            prev_data.add_info("Execute command: {:s}".format(cmd_repr + ' ' + str(prev_data)[:20] + '...'))
            arg = raw_data

        if isinstance(cmd, list):
            cmd = list(cmd)
            cmd.append(arg)
        else:
            cmd = cmd + ' ' + arg
            cmd = cmd.split()

        try:
            out_val = subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            prev_data.add_info("/!\\ Error encountered while executing external command!")
            return prev_data

        if node is None:
            prev_data.update_from(out_val)
        else:
            node.set_values(values=[out_val])
            node.get_value()

        return prev_data


@disruptor(tactics, dtype="STRUCT", weight=1,
           args={'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str)})
class d_fuzz_model_structure(Disruptor):
    '''
    Disrupt the data model structure (replace ordered sections by
    unordered ones).
    '''
    def setup(self, dm, user_input):
        return True

    def disrupt_data(self, dm, target, prev_data):
        prev_content = prev_data.content
        if isinstance(prev_content, Node):
            fuzz_data_tree(prev_content, self.path)
            prev_data.altered = True
        else:
            prev_data.add_info('DONT_PROCESS_THIS_KIND_OF_DATA')

        return prev_data


@disruptor(tactics, dtype="ALT", weight=1,
           args={'conf': ("Change the configuration, with the one provided (by name), of " \
                          "all subnodes fetched by @path, one-by-one. [default value is set " \
                          "dynamically with the first-found existing alternate configuration]",
                          None, str),
                 'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str),
                 'recursive': ('Does the reachable nodes from the selected ' \
                               'ones need also to be changed?', True, bool)})
class d_switch_to_alternate_conf(Disruptor):
    '''
    Switch to an alternate configuration.
    '''
    def setup(self, dm, user_input):
        self.available_confs = dm.node_backend.get_all_confs()

        if self.available_confs:
            self.conf_fallback = self.available_confs[0]
        else:
            self.conf_fallback = None

        if self.conf is None:
            self.conf = self.conf_fallback
            self.provided_alt = False
        else:
            self.provided_alt = True

        if self.conf in self.available_confs:
            self.existing_conf = True
        else:
            self.existing_conf = False

        return True


    def disrupt_data(self, dm, target, prev_data):
        prev_content = prev_data.content
        if isinstance(prev_content, Node):
            # try to get more specific default conf
            if not self.provided_alt and self.available_confs:
                confs = prev_content.gather_alt_confs()
                if confs:
                    self.conf_fallback = confs.pop()
                    self.conf = self.conf_fallback
                    self.provided_alt = True
                    self.existing_conf = True

            if self.provided_alt and not self.existing_conf:
                prev_data.add_info("NO ALTERNATE CONF '{!s}' AVAILABLE".format(self.conf))
                return prev_data

            if self.conf_fallback is None:
                prev_data.add_info("NO ALTERNATE CONF AVAILABLE")
                return prev_data

            prev_data.add_info("ALTERNATE CONF '{!s}' USED".format(self.conf))

            prev_content.set_current_conf(self.conf, recursive=self.recursive, root_regexp=self.path)
            prev_content.unfreeze(recursive=True, reevaluate_constraints=True)
            prev_content.freeze()

        else:
            prev_data.add_info('DONT_PROCESS_THIS_KIND_OF_DATA')

        return prev_data


@disruptor(tactics, dtype="SIZE", weight=4,
           args={'sz': ("Truncate the data (or part of the data) to the provided size.", 10, int),
                 'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str)})
class d_max_size(Disruptor):
    '''
    Truncate the data (or part of the data) to the provided size.
    '''

    def setup(self, dm, user_input):
        return True


    def disrupt_data(self, dm, target, prev_data):

        prev_content = prev_data.content
        if isinstance(prev_content, Node):
            if self.path is not None:
                node = prev_content.get_first_node_by_path(self.path)
                if node is None:
                    node = prev_content
            else:
                node = prev_content

            val = node.to_bytes()
            orig_len = len(val)
            prev_data.add_info('orig node length: {:d}'.format(orig_len))
            
            if self.sz >= 0:
                node.set_values([val[:min(self.sz, orig_len)]])
                prev_data.add_info('right truncation')
            else:
                self.sz = - self.sz
                node.set_values([val[orig_len - min(self.sz, orig_len):]])
                prev_data.add_info('left truncation')

            prev_data.add_info('new node length: {:d}'.format(min(self.sz, orig_len)))

            ret = prev_data

        else:
            val = prev_data.to_bytes()
            orig_len = len(val)
            prev_data.add_info('orig data length: {:d}'.format(orig_len))

            if self.sz >= 0:
                new_val = val[:min(self.sz, orig_len)]
                prev_data.add_info('right truncation')
            else:
                self.sz = - self.sz
                new_val = val[orig_len - min(self.sz, orig_len):]
                prev_data.add_info('left truncation')

            prev_data.add_info('new data length: {:d}'.format(len(new_val)))

            prev_data.update_from(new_val)
            ret = prev_data

        ret.altered = True
        return ret



@disruptor(tactics, dtype="C", weight=4,
           args={'nb': ('Apply corruption on @nb Nodes fetched randomly within the data model.', 2, int),
                 'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str),
                 'new_val': ('If provided change the selected byte with the new one.', None, str),
                 'ascii': ('Enforce all outputs to be ascii 7bits.', False, bool)})
class d_corrupt_node_bits(Disruptor):
    '''
    Corrupt bits on some nodes of the data model.
    '''
    def setup(self, dm, user_input):
        return True


    def disrupt_data(self, dm, target, prev_data):

        prev_content = prev_data.content
        if isinstance(prev_content, Node):
            prev_content.get_value()

            c = NodeInternalsCriteria(mandatory_attrs=[NodeInternals.Mutable],
                                      node_kinds=[NodeInternals_TypedValue])
            l = prev_content.get_reachable_nodes(path_regexp=self.path,
                                                   internals_criteria=c)
            if not l:
                prev_data.add_info('INVALID INPUT')
                return prev_data

            if self.nb > 0:
                try:
                    l = random.sample(l, self.nb)
                except ValueError:
                    prev_data.add_info('Only one Node (Terminal) has been found!')
                    l = random.sample(l, 1)

            for i in l:
                val = i.to_bytes()
                prev_data.add_info('current fuzzed node: {!s}'.format(i.get_path_from(prev_content)))
                prev_data.add_info('orig data: {!s}'.format(truncate_info(val)))

                if self.new_val is None:
                    if val != b'':
                        val = corrupt_bits(val, n=1, ascii=self.ascii)
                        prev_data.add_info('corrupted data: {!s}'.format(truncate_info(val)))
                    else:
                        prev_data.add_info('Nothing to corrupt!')
                else:
                    val = self.new_val
                    prev_data.add_info('corrupted data: {!s}'.format(truncate_info(val)))

                status, _, _, _ = i.absorb(val, constraints=AbsNoCsts())
                if status != AbsorbStatus.FullyAbsorbed:
                    prev_data.add_info('data absorption failure, fallback to node replacement')
                    i.set_values(values=[val])
                i.freeze()

            ret = prev_data

        else:
            new_val = corrupt_bits(prev_data.to_bytes(), ascii=self.ascii)
            prev_data.update_from(new_val)
            prev_data.add_info('Corruption performed on a byte string as no Node is available')
            ret = prev_data

        ret.altered = True
        return ret


@disruptor(tactics, dtype="Cp", weight=4,
           args={'idx': ('Byte index to be corrupted (from 1 to data length).', 1, int),
                 'new_val': ('If provided change the selected byte with the new one.', None, bytes),
                 'ascii': ('Enforce all outputs to be ascii 7bits.', False, bool)})
class d_corrupt_bits_by_position(Disruptor):
    '''
    Corrupt bit at a specific byte.
    '''
    def setup(self, dm, user_input):
        return True


    def disrupt_data(self, dm, target, prev_data):

        val = prev_data.to_bytes()

        prev_data.add_info('corrupted bit index: {:d}'.format(self.idx))

        new_value = self.new_val if self.new_val is not None \
                    else corrupt_bits(val[self.idx-1:self.idx], n=1, ascii=self.ascii)
        msg = val[:self.idx-1]+new_value+val[self.idx:]

        prev_data.update_from(msg)
        prev_data.altered = True

        return prev_data


@disruptor(tactics, dtype="FIX", weight=4,
           args={'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str),
                 'clone_node': ('If True the dmaker will always return a copy ' \
                                'of the node. (For stateless disruptors dealing with ' \
                                'big data it can be useful to it to False.)', False, bool)})
class d_fix_constraints(Disruptor):
    '''
    Fix data constraints.

    Release constraints from input data or from only a piece of it (if
    the parameter `path` is provided), then recompute them. By
    constraints we mean every generator (or function) nodes that may
    embeds constraints between nodes, and every node *existence
    conditions*.
    '''
    def setup(self, dm, user_input):
        return True

    def disrupt_data(self, dm, target, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('UNSUPPORTED INPUT')
            return prev_data

        if self.path:
            c = NodeInternalsCriteria(mandatory_attrs=[NodeInternals.Mutable])
            l = prev_content.get_reachable_nodes(path_regexp=self.path,
                                                   internals_criteria=c)
            if not l:
                prev_data.add_info('INVALID INPUT')
                return prev_data

            for n in l:
                n.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
                prev_data.add_info("reevaluate constraints from the node '{!s}'".format(n.name))
                n.freeze()

        else:
            prev_content.unfreeze(recursive=True, reevaluate_constraints=True, ignore_entanglement=True)
            prev_data.add_info('reevaluate constraints from the root')

        prev_content.freeze()

        if self.clone_node:
            exported_node = Node(prev_content.name, base_node=prev_content, new_env=True)
            prev_data.update_from(exported_node)

        return prev_data


@disruptor(tactics, dtype="NEXT", weight=4,
           args={'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str),
                 'recursive': ('Apply the disruptor recursively.', True, str),
                 'clone_node': ('If True the dmaker will always return a copy ' \
                                'of the node. (for stateless disruptors dealing with ' \
                                'big data it can be useful to it to False).', False, bool)})
class d_next_node_content(Disruptor):
    '''
    Move to the next content of the nodes from input data or from only
    a piece of it (if the parameter `path` is provided). Basically,
    unfreeze the nodes then freeze them again, which will consequently
    produce a new data.
    '''
    def setup(self, dm, user_input):
        return True

    def disrupt_data(self, dm, target, prev_data):

        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('UNSUPPORTED INPUT')
            return prev_data

        prev_content.freeze()

        if self.path:
            l = prev_content.get_reachable_nodes(path_regexp=self.path)
            if not l:
                prev_data.add_info('INVALID INPUT')
                return prev_data

            for n in l:
                n.unfreeze(recursive=self.recursive)
                n.freeze()
                prev_data.add_info("unfreeze the node {!s}".format(n.get_path_from(prev_content)))
                prev_data.add_info("new value:        {!s}".format(n.to_bytes()))

        else:
            prev_content.unfreeze(recursive=self.recursive)
            prev_data.add_info('unfreeze from the root node')

        prev_content.freeze()

        if self.clone_node:
            exported_node = Node(prev_content.name, base_node=prev_content, new_env=True)
            prev_data.update_from(exported_node)

        return prev_data

@disruptor(tactics, dtype="OP", weight=4,
           args={'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str),
                 'sem': ('Semantics to select nodes on which' \
                         ' the disruptor should apply.', None, (str, list)),
                 'op': ('The operation to perform on the selected nodes.', Node.clear_attr,
                        (types.MethodType, types.FunctionType)), # python3, python2
                 'op_ref': ("Predefined operation that can be referenced by name. The current "
                            "predefined function are: 'unfreeze', 'freeze', 'walk', 'set_qty'. Take "
                            "precedence over @op if not None." , None, str),
                 'params': ('Tuple of parameters that will be provided to the operation.',
                            (),
                            tuple),
                 'clone_node': ('If True the dmaker will always return a copy ' \
                                'of the node. (For stateless disruptors dealing with ' \
                                'big data it can be useful to set it to False.)', False, bool)})
class d_operate_on_nodes(Disruptor):
    '''
    Perform an operation on the nodes specified by the regexp path. @op is an operation that
    applies to a node and @params are a tuple containing the parameters that will be provided to
    @op. If no path is provided, the root node will be used.
    '''
    def setup(self, dm, user_input):
        return True

    def disrupt_data(self, dm, target, prev_data):
        ok = False
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('UNSUPPORTED INPUT')
            return prev_data

        if self.op_ref is not None:
            if self.op_ref == 'unfreeze':
                self.op = Node.unfreeze
            elif self.op_ref == 'freeze':
                self.op = Node.freeze
            elif self.op_ref == 'walk':
                self.op = Node.walk
            elif self.op_ref == 'set_qty':
                self.op = NodeInternals_NonTerm.set_subnode_default_qty
                n = prev_content.get_first_node_by_path(path_regexp=self.path)
                self.path = self.path[:self.path.rfind('/')] + '$'
                self.params = (n, *self.params)
            else:
                prev_data.add_info('Unsupported operation')
                return prev_data

        sem_crit = None if self.sem is None else NSC(optionalbut1_criteria=self.sem)
        if self.path or sem_crit:
            l = prev_content.get_reachable_nodes(path_regexp=self.path, semantics_criteria=sem_crit)
            if not l:
                prev_data.add_info('INVALID INPUT')
                return prev_data

            for n in l:
                try:
                    self.op(n, *self.params)
                except:
                    prev_data.add_info("An error occurred while performing the operation on the "
                                       "node '{:s}'".format(n.name))
                else:
                    ok = True
                    self._add_info(prev_data, n)
        else:
            try:
                self.op(prev_content, *self.params)
            except:
                prev_data.add_info("An error occurred while performing the operation on the "
                                   "node '{:s}'".format(prev_content.name))
            else:
                ok = True
                self._add_info(prev_data, prev_content)

        if ok:
            prev_data.add_info("performed operation: {!r}".format(self.op))
            prev_data.add_info("parameters provided: {:s}"
                               .format(', '.join((str(x) for x in self.params))))

        prev_content.freeze()

        if self.clone_node:
            exported_node = Node(prev_content.name, base_node=prev_content, new_env=True)
            prev_data.update_from(exported_node)

        prev_data.altered = True
        return prev_data

    def _add_info(self, prev_data, n):
        prev_data.add_info("changed node:        {!s}".format(n.get_path_from(prev_data.content)))

@disruptor(tactics, dtype="MOD", weight=4,
           args={'path': ('Graph path regexp to select nodes on which ' \
                          'the disruptor should apply.', None, str),
                 'sem': ('Semantics to select nodes on which' \
                         ' the disruptor should apply.', None, (str, list)),
                 'value': ('The new value to inject within the data.', b'', bytes),
                 'constraints': ('Constraints for the absorption of the new value.', AbsNoCsts(), AbsCsts),
                 'multi_mod': ('Dictionary of <path>:<item> pairs or '
                               '<NodeSemanticsCriteria>:<item> pairs or '
                               '<NodeInternalsCriteria>:<item> pairs to change multiple nodes with '
                               'different values. <item> can be either only the new <value> or a '
                               'tuple (<value>,<abscsts>) if new constraint for absorption is '
                               'needed', None, dict),
                 'unfold': ('Resolve all the generator nodes within the input before performing '
                            'the @path/@sem research', False, bool),
                 'clone_node': ('If True the dmaker will always return a copy ' \
                                'of the node. (For stateless disruptors dealing with ' \
                                'big data it can be useful to set it to False.)', False, bool)})
class d_modify_nodes(Disruptor):
    """
    Perform modifications on the provided data. Two ways are possible:

    - Either the change is performed on the content of the nodes specified by the `path`
      parameter with the new `value` provided, and the optional constraints for the
      absorption (use *node absorption* infrastructure);

    - Or the changed is performed based on a dictionary provided through the parameter `multi_mod`

    """
    def setup(self, dm, user_input):
        return True

    def disrupt_data(self, dm, target, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('UNSUPPORTED INPUT')
            return prev_data

        if self.multi_mod:
            change_dict = self.multi_mod
        else:
            sem = None if self.sem is None else NSC(optionalbut1_criteria=self.sem)
            change_dict = {self.path if sem is None else sem: (self.value, self.constraints)}

        for selector, item in change_dict.items():
            if isinstance(item, (tuple, list)):
                assert len(item) == 2
                new_value, new_csts = item
            else:
                new_value = item
                new_csts = AbsNoCsts()

            if selector:
                if isinstance(selector, str):
                    l = prev_content.get_reachable_nodes(path_regexp=selector,
                                                         resolve_generator=self.unfold)
                elif isinstance(selector, NSC):
                    l = prev_content.get_reachable_nodes(semantics_criteria=selector,
                                                         resolve_generator=self.unfold)
                elif isinstance(selector, NIC):
                    l = prev_content.get_reachable_nodes(internals_criteria=selector,
                                                         resolve_generator=self.unfold)
                else:
                    raise ValueError('Unsupported selector')

                if not l:
                    prev_data.add_info('No node found with current criteria')
                    return prev_data

                for n in l:
                    status, off, size, name = n.absorb(new_value, constraints=new_csts)
                    self._add_info(prev_data, n, new_value, status, size)
            else:
                status, off, size, name = prev_content.absorb(new_value, constraints=new_csts)
                self._add_info(prev_data, prev_content, new_value, status, size)

        prev_content.freeze()

        if self.clone_node:
            exported_node = Node(prev_content.name, base_node=prev_content, new_env=True)
            prev_data.update_from(exported_node)

        prev_data.altered = True
        return prev_data

    def _add_info(self, prev_data, n, new_value, status, size):
        val_len = len(new_value)
        prev_data.add_info("changed node:     {!s}".format(n.name))
        prev_data.add_info("absorption status: {!s}".format(status))
        prev_data.add_info("value provided:   {!s}".format(truncate_info(new_value)))
        prev_data.add_info("__ length:         {:d}".format(val_len))
        if status != AbsorbStatus.FullyAbsorbed:
            prev_data.add_info("absorbed size:     {:d}".format(size))
            if val_len - size > 100:
                remaining = self.value[size:size+100] + ' ...'
            else:
                remaining = self.value[size:]
            prev_data.add_info("remaining:      '{!s}'".format(remaining))


@disruptor(tactics, dtype="CALL", weight=4,
           args={'func': ('The function that will be called with a node as its first parameter, '
                          'and provided optionnaly with addtionnal parameters if @params is set.',
                          lambda x:x,
                          (types.MethodType, types.FunctionType)), # python3, python2
                 'params': ('Tuple of parameters that will be provided to the function.',
                            None, tuple) })
class d_call_function(Disruptor):
    """
    Call the function provided with the first parameter being the Data() object received as
    input of this disruptor, and optionally with additional parameters if @params is set. The
    function should return a Data() object.

    The signature of the function should be compatible with:

    `func(data, *args) --> Data()`

    """

    def disrupt_data(self, dm, target, prev_data):
        try:
            if self.params:
                new_data = self.func(prev_data, *self.params)
            else:
                new_data = self.func(prev_data)
        except:
            new_data = prev_data
            new_data.add_info("An error occurred while executing the user function '{!r}':".format(self.func))
            new_data.add_info(traceback.format_exc())
        else:
            new_data.add_info("called function: {!r}".format(self.func))
            if self.params:
                new_data.add_info("additional parameters provided: {:s}"
                                  .format(', '.join((str(x) for x in self.params))))

        return new_data


@disruptor(tactics, dtype="COPY", weight=4,
           args=None)
class d_shallow_copy(Disruptor):
    '''
    Shallow copy of the input data, which means: ignore its frozen
    state during the copy.
    '''
    def setup(self, dm, user_input):
        return True

    def disrupt_data(self, dm, target, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('UNSUPPORTED INPUT')
            return prev_data

        prev_data.add_info('shallow copy of input data has been done')
        exported_node = Node(prev_content.name, base_node=prev_content, new_env=True,
                             ignore_frozen_state=True)
        prev_data.update_from(exported_node)

        return prev_data

@disruptor(tactics, dtype="ADD", weight=4,
           args={'path': ('Graph path to select the node on which ' \
                          'the disruptor should apply.', None, str),
                 'after': ('If True, the addition will be done after the selected node. Otherwise, '
                           'it will be done before.',
                          True, bool),
                 'atom': ('Name of the atom to add within the retrieved input. It is mutually '
                         'exclusive with @raw',
                          None, str),
                 'raw': ('Raw value to add within the retrieved input. It is mutually '
                         'exclusive with @atom.',
                         b'', (bytes,str)),
                 'name': ('If provided, the added node will have this name.',
                          None, str)
                 })
class d_add_data(Disruptor):
    """
    Add some data within the retrieved input.
    """
    def setup(self, dm, user_input):
        if self.atom and self.raw:
            return False
        return True

    def disrupt_data(self, dm, target, prev_data):
        prev_content = prev_data.content
        if isinstance(prev_content, bytes):
            prev_content = Node('wrapper', subnodes=[Node('raw', values=[prev_content])])
            prev_content.set_env(Env())
            prev_content.freeze()
        elif isinstance(prev_content, Node) and prev_content.is_term():
            prev_content = Node('wrapper', subnodes=[prev_content])
            prev_content.set_env(Env())
            prev_content.freeze()

        assert isinstance(prev_content, Node)

        if self.atom is not None:
            try:
                obj = dm.get_atom(self.atom)
            except:
                prev_data.add_info("An error occurred while retrieving the atom named '{:s}'".format(self.atom))
                return prev_data
        else:
            obj = Node('raw{}'.format(uuid.uuid1()), values=[self.raw])

        if self.name is not None:
            obj.name = self.name

        if self.path:
            nt_node_path = self.path[:self.path.rfind('/')]
            try:
                nt_node = prev_content[nt_node_path][0]
                pivot = prev_content[self.path][0]
            except:
                prev_data.add_info('An error occurred while handling @path')
                return prev_data

            if self.after:
                nt_node.add(obj, after=pivot)
            else:
                nt_node.add(obj, before=pivot)
        else:
            prev_content.add(obj)
            prev_data.update_from(prev_content)
            # prev_content.show()

        return prev_data


@disruptor(tactics, dtype="tWALKcsp", weight=1, modelwalker_user=False,
           args={'init': ('Make the operator ignore all the steps until the provided one', 1, int),
                 'clone_node': ('If True, this operator will always return a copy '
                                'of the node. (for stateless diruptors dealing with '
                                'big data it can be usefull to set it to False)', True, bool),
                 'notify_exhaustion': ('When all the solutions of the CSP have been walked '
                                       'through, the disruptor will notify it if this parameter '
                                       'is set to True.', True, bool),
                 })
class sd_walk_csp_solutions(StatefulDisruptor):
    """

    When the CSP (Constraint Satisfiability Problem) backend are used in the data description.
    This operator walk through the solutions of the CSP.

    """

    def setup(self, dm, user_input):
        self._first_call_performed = False
        self._count = 1
        self._step_size = self.init-1 if self.init > 1 else 1
        return True

    def set_seed(self, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('UNSUPPORTED INPUT')
            return prev_data

        self.csp = prev_content.get_csp()
        if not self.csp:
            prev_data.add_info('CSP BACKEND NOT USED BY THIS ATOM')
            return prev_data

        self.seed = prev_content
        self.seed.freeze(resolve_csp=True)

    def disrupt_data(self, dm, target, data):

        if self._first_call_performed or self.init > 1:
            self.seed.unfreeze(recursive=False, dont_change_state=True, walk_csp=True,
                               walk_csp_step_size=self._step_size)

        self._step_size = 1

        if self.seed.no_more_solution_for_csp and self.notify_exhaustion:
            data.make_unusable()
            self.handover()

        else:
            if self._first_call_performed or self.init > 1:
                self.seed.freeze(resolve_csp=True)
                self._count += 1
            else:
                self._first_call_performed = True

            data.add_info('csp solution index: {:d}'.format(self._count))
            data.add_info(' |_ variables assignment:')
            solution = self.csp.get_solution()
            for var, value in solution.items():
                data.add_info(f'     --> {var}: {value}')

            if self.clone_node:
                exported_node = Node(self.seed.name, base_node=self.seed, new_env=True)
                data.update_from(exported_node)
            else:
                data.update_from(self.seed)

        return data


@disruptor(tactics, dtype="tCONST", weight=1, modelwalker_user=False,
           args={'const_idx': ('Index of the constraint to begin with (first index is 1)', 1, int),
                 'sample_idx': ('Index of the sample for the selected constraint to begin with ('
                                'first index is 1)', 1, int),
                 'clone_node': ('If True, this operator will always return a copy '
                                'of the node. (for stateless diruptors dealing with '
                                'big data it can be usefull to set it to False)', True, bool),
                 'samples_per_cst': ('Maximum number of samples to output for each negated '
                                     'constraint (-1 means until the end)',
                                     -1, int),
                 })
class sd_constraint_fuzz(StatefulDisruptor):
    """

    When the CSP (Constraint Satisfiability Problem) backend are used in the node description.
    This operator negates the constraint one-by-one and output 1 or more samples for each negated
    constraint.

    """

    def setup(self, dm, user_input):

        assert self.const_idx > 0
        assert self.sample_idx > 0

        self._first_call = True
        self._count = 0
        self._constraint_negated = False
        self._current_constraint_idx = self.const_idx-1
        self._sample_count = 0
        self._step_size = self.sample_idx

        return True

    def set_seed(self, prev_data):
        prev_content = prev_data.content
        if not isinstance(prev_content, Node):
            prev_data.add_info('UNSUPPORTED INPUT')
            return prev_data

        self.csp = prev_content.get_csp()
        if not self.csp:
            prev_data.add_info('CSP BACKEND NOT USED BY THIS ATOM')
            return prev_data

        self.seed = prev_content

        self.seed.freeze(resolve_csp=True)
        self.valid_solution = self.csp.get_solution()
        self.csp_constraints = self.csp.get_all_constraints()
        self.csp_variables = {v for c in self.csp_constraints for v in c.vars}

    def _update_csp(self):
        current_constraint = self.csp.get_constraint(self._current_constraint_idx)
        variables = self.csp_variables - set(current_constraint.vars)
        for v in variables:
            self.csp.set_var_domain(v, [self.valid_solution[v]])

    def _process_next_constraint(self):
        self.csp.restore_var_domains()
        self.csp.reset_constraint(self._current_constraint_idx)
        self._constraint_negated = False
        if self._current_constraint_idx < self.csp.nb_constraints - 1:
            self._current_constraint_idx += 1
            self.csp.negate_constraint(self._current_constraint_idx)
            self._constraint_negated = True
            self._update_csp()
            self._sample_count = 1
            return True

        else:
            return False

    def disrupt_data(self, dm, target, data):

        if not self._constraint_negated:
            self.csp.negate_constraint(self._current_constraint_idx)
            self._constraint_negated = True
            self._update_csp()
            self.seed.freeze(resolve_csp=True)

        if self._sample_count < self.samples_per_cst or self.samples_per_cst == -1:
            if self._first_call:
                self._sample_count = self._step_size
            else:
                self._sample_count += 1
        else:
            if not self._process_next_constraint(): # no more constraint to deal with
                data.make_unusable()
                self.handover()
                return data

        if self._first_call:
            self.seed.unfreeze(recursive=False, dont_change_state=True, walk_csp=True,
                               walk_csp_step_size=self._step_size)
            self._first_call = False
        else:
            self.seed.unfreeze(recursive=False, dont_change_state=True, walk_csp=True,
                               walk_csp_step_size=1)

        if self.seed.no_more_solution_for_csp: # Node.unfreeze() will trigger it if no new solution
            if not self._process_next_constraint():
                data.make_unusable()
                self.handover()
                return data

        self.seed.freeze(resolve_csp=True)
        self._count += 1

        data.add_info(f'constraint fuzzing test case index: {self._count}')
        data.add_info(f' |_ constraint number: {self._current_constraint_idx+1}/{self.csp.nb_constraints}')
        data.add_info(f' |_ sample index: {self._sample_count}/{self.samples_per_cst}')
        data.add_info(' |_ variables assignment:')
        solution = self.csp.get_solution()
        for var, value in solution.items():
            data.add_info(f'     --> {var}: {value}')

        if self.clone_node:
            exported_node = Node(self.seed.name, base_node=self.seed, new_env=True)
            data.update_from(exported_node)
        else:
            data.update_from(self.seed)

        data.altered = True

        return data
