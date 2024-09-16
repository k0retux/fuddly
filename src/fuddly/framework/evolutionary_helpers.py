################################################################################
#
#  Copyright 2016 Julien Baladier
#  Copyright 2016-2017 Eric Lacombe <eric.lacombe@security-labs.org>
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

import math
import re
import functools
import uuid
from operator import attrgetter

from fuddly.framework.tactics_helpers import *
from fuddly.framework.global_resources import UI
from fuddly.framework.scenario import *
from fuddly.framework.error_handling import ExtinctPopulationError, PopulationError, CrossOverError
from fuddly.framework.data import DataProcess

class Population(object):
    """ Population to be used within an evolutionary scenario """
    def __init__(self, fmk, *args, **kwargs):
        self._fmk = fmk
        self._individuals = None
        self.index = None
        self._initialize(*args, **kwargs)

    def _initialize(self, *args, **kwargs):
        """
            Initialize the population
            Only called once during the creating of the Population instance
        """
        pass

    def reset(self):
        """
            Reset the population
            Called before each evolutionary process
        """
        self._individuals = []
        self.index = 0

    def evolve(self):
        """ Describe the evolutionary process """
        raise NotImplementedError

    def is_final(self):
        """ Check if the population can still evolve or not """
        raise NotImplementedError

    def size(self):
        return len(self._individuals)

    def __len__(self):
        return len(self._individuals)

    def __delitem__(self, key):
        del self._individuals[key]

    def __getitem__(self, key):
        return self._individuals[key]

    def __setitem__(self, key, value):
        self._individuals[key] = value

    def __iter__(self):
        return self

    def __next__(self):
        if self.index == len(self._individuals):
            raise StopIteration
        else:
            self.index += 1
            return self._individuals[self.index-1]

    next = __next__

    def __repr__(self):
        return self.__class__.__name__


class Individual(object):
    """ Represents a population member """
    def __init__(self, fmk, data):
        self._fmk = fmk
        self.data = data
        self.feedback = None

    def mutate(self):
        raise NotImplementedError

class CrossoverHelper(object):

    class Operand(object):

        def __init__(self, node):
            self.node = node
            self.leafs = []

            for path, node in self.node.iter_paths():
                if node.is_term() and path not in self.leafs:
                    self.leafs.append(path)

            self.shared = None

        def compute_sub_graphs(self, percentage):
            random.shuffle(self.leafs)
            self.shared = self.leafs[:int(round(len(self.leafs) * percentage))]
            self.shared.sort()

            change = True
            while change:

                change = False
                index = 0
                length = len(self.shared)

                while index < length:

                    current_path = self.shared[index]

                    slash_index = current_path[::-1].find('/')
                    # check if we are dealing with the root node
                    if slash_index == -1:
                        index += 1
                        continue

                    parent_path = current_path[:-current_path[::-1].find('/') - 1]
                    children_nb = self._count_brothers(index, parent_path)
                    if children_nb == self.node.get_first_node_by_path(parent_path).cc.get_subnode_qty():
                        self._merge_brothers(index, parent_path, children_nb)
                        change = True
                        index += 1
                        length = len(self.shared)
                    else:
                        index += children_nb

        def _count_brothers(self, index, pattern):
            count = 1
            p = re.compile(u'^' + pattern + '($|/*)')
            for i in range(index + 1, len(self.shared)):
                if re.match(p, self.shared[i]) is not None:
                    count += 1
            return count

        def _merge_brothers(self, index, pattern, length):
            for _ in range(0, length, 1):
                del self.shared[index]
            self.shared.insert(index, pattern)

    @staticmethod
    def _swap_nodes(node_1, node_2):
        node_2_copy = node_2.get_clone()
        node_1_copy = node_1.get_clone()
        node_2.set_contents(node_1_copy)
        node_1.set_contents(node_2_copy)

    @staticmethod
    def _get_nodes(node):
        while True:
            nodes = [node] if node.is_term() else node.cc.frozen_node_list
            if len(nodes) == 1 and not nodes[0].is_term():
                node = nodes[0]
            else:
                break
        return nodes

    @staticmethod
    def _add_default_crossover_info(ind_1, ind_2, crossover_desc=''):
        crossover_desc = "[" + crossover_desc + "]" if crossover_desc else ''

        crossover_desc = 'Crossover between data ID {} and {} {}'\
            .format(ind_1._data_id, ind_2._data_id, crossover_desc)

        ind_1.altered = True
        ind_1.add_info(crossover_desc)
        ind_2.altered = True
        ind_2.add_info(crossover_desc)


    @classmethod
    def crossover_algo1(cls, ind_1, ind_2):
        ind_1_nodes = cls._get_nodes(ind_1.content)
        ind_2_nodes = cls._get_nodes(ind_2.content)

        if len(ind_1_nodes) == 0 or len(ind_2_nodes) == 0:
            raise CrossOverError

        swap_nb = len(ind_1_nodes) if len(ind_1_nodes) < len(ind_2_nodes) else len(ind_2_nodes)
        swap_nb = int(math.ceil(swap_nb / 2.0))

        random.shuffle(ind_1_nodes)
        random.shuffle(ind_2_nodes)

        for i in range(swap_nb):
            cls._swap_nodes(ind_1_nodes[i], ind_2_nodes[i])

        cls._add_default_crossover_info(ind_1, ind_2, crossover_desc='algo1')
        return ind_1, ind_2

    @classmethod
    def _crossover_algo2(cls, ind_1, ind_2, percentage_to_share):
        ind_1_operand = cls.Operand(ind_1.content)
        ind_1_operand.compute_sub_graphs(percentage_to_share)
        random.shuffle(ind_1_operand.shared)

        ind_2_operand = cls.Operand(ind_2.content)
        ind_2_operand.compute_sub_graphs(1.0 - percentage_to_share)
        random.shuffle(ind_2_operand.shared)

        swap_nb = len(ind_1_operand.shared) if len(ind_1_operand.shared) < len(ind_2_operand.shared) else len(ind_2_operand.shared)

        for i in range(swap_nb):
            node_1 = ind_1_operand.node.get_first_node_by_path(ind_1_operand.shared[i])
            node_2 = ind_2_operand.node.get_first_node_by_path(ind_2_operand.shared[i])
            cls._swap_nodes(node_1, node_2)

        cls._add_default_crossover_info(ind_1, ind_2,
                                        crossover_desc='algo2, sharing%:{}'.format(percentage_to_share))
        return ind_1, ind_2

    @classmethod
    def get_configured_crossover_algo2(cls, percentage_to_share=None):
        """
        Args:
            percentage_to_share: Percentage of the nodes to share.

        Returns: func
        """
        if percentage_to_share is None:
            percentage_to_share = float(random.randint(3, 7)) / 10.0
        elif not (0 < percentage_to_share < 1):
            print("Invalid percentage, a float between 0 and 1 need to be provided")
            return None

        return functools.partial(cls._crossover_algo2, percentage_to_share=percentage_to_share)

class DefaultIndividual(Individual):
    """ Provide a default implementation of the Individual class """

    def __init__(self, fmk, data, mutation_order=1):
        Individual.__init__(self, fmk, data)

        self.score = None
        self.probability_of_survival = None  # between 0 and 1
        self.mutation_order = mutation_order

    def mutate(self):
        assert isinstance(self.data.content, Node)
        data = self._fmk.process_data([('C', UI(nb=self.mutation_order))], seed=self.data)
        if data is None:
            raise PopulationError
        data.add_info('Mutation applied on data {}'.format(data._data_id))
        self.data = data


class DefaultPopulation(Population):
    """ Provide a default implementation of the Population base class """

    def _initialize(self, init_process, max_size=100, max_generation_nb=50,
                    crossover_algo=CrossoverHelper.crossover_algo1):
        """
            Configure the population

            Args:
                init_process (string): individuals that compose this population will be built using
                  the provided :class:`framework.data.DataProcess`
                max_size (integer): maximum size of the population to manipulate
                max_generation_nb (integer): criteria used to stop the evolution process
                crossover_algo (func): Crossover algorithm to use
        """
        Population._initialize(self)

        self.DATA_PROCESS = init_process
        self.MAX_SIZE = max_size
        self.MAX_GENERATION_NB = max_generation_nb
        self.generation = None
        self.crossover_algo = crossover_algo

    def reset(self):
        """ Generate the first generation of individuals in a random way """
        Population.reset(self)

        self.generation = 1

        # individuals initialization
        cpt = 0
        while cpt < self.MAX_SIZE or self.MAX_SIZE == -1:
            cpt += 1
            data = self._fmk.handle_data_desc(self.DATA_PROCESS, resolve_dataprocess=True,
                                              save_generator_seed=False)
            if data is None:
                break
            data.add_info('Data generated from the DataProcess provided for the population initialization:')
            data.add_info(' |_ {!s}'.format(self.DATA_PROCESS))
            self._individuals.append(DefaultIndividual(self._fmk, data))

    def _compute_scores(self):
        """ Compute the scores of each individuals """
        for individual in self._individuals:
            individual.score = random.uniform(0, 100)

    def _compute_probability_of_survival(self):
        """ Normalize fitness scores between 0 and 1 """

        min_score = min(self._individuals, key=attrgetter('score')).score
        max_score = max(self._individuals, key=attrgetter('score')).score

        for ind in self._individuals:
            if min_score != max_score:
                ind.probability_of_survival = (ind.score - min_score) / (max_score - min_score) + 0.3
            else:
                ind.probability_of_survival = 0.50

    def _kill(self):
        """ Simply rolls the dice """
        for i in range(len(self._individuals))[::-1]:
            if random.randrange(100) > self._individuals[i].probability_of_survival*100:
                del self._individuals[i]

    def _mutate(self):
        """ Operates three bit flips on each individual """
        for individual in self._individuals:
            individual.mutate()

    def _crossover(self):
        """ Compensates the kills through the usage of the COMB disruptor """
        random.shuffle(self._individuals)

        current_size = len(self._individuals)

        i = 0
        while len(self._individuals) < self.MAX_SIZE and i < int(current_size / 2):
            ind_1 = self._individuals[i].data
            ind_2 = copy.copy(self._individuals[i+1].data)

            try:
                ind_1, ind_2 = self.crossover_algo(ind_1, ind_2)
            except CrossOverError:
                continue
            else:
                self._individuals.append(DefaultIndividual(self._fmk, ind_1))
                self._individuals.append(DefaultIndividual(self._fmk, ind_2))
            finally:
                i += 2

    def evolve(self):
        """ Describe the evolutionary process """

        if len(self) < 2:
            raise ExtinctPopulationError()

        self._compute_scores()
        self._compute_probability_of_survival()
        self._kill()
        self._mutate()
        self._crossover()

        self.generation += 1
        self.index = 0

    def is_final(self):
        return self.generation == self.MAX_GENERATION_NB

    def __repr__(self):
        return self.__class__.__name__ + '[max_sz={}, max_gen={}]'.format(self.MAX_SIZE, self.MAX_GENERATION_NB)



class EvolutionaryScenariosFactory(object):

    @staticmethod
    def build(fmk, name, population_cls, args):
        """
        Create a scenario that takes advantage of an evolutionary approach
        Args:
            fmk (FmkPlumbing): reference to FmkPlumbing
            name (string): name of the scenario to create
            population_cls (classobj): population class to instantiate
            args (dict of str: object): arguments that will be used to instantiate a population

        Returns:
            Scenario : evolutionary scenario
        """

        population = population_cls(fmk, **args)

        def cbk_after(env, current_step, next_step, fbk_gate):
            # set the feedback of the last played individual
            population[population.index - 1].feedback = list(fbk_gate)

            return True

        generator_name = 'POPULATION#{!s}'.format(random.randint(1,100000))
        step = Step(data_desc=DataProcess(process=[(generator_name,
                                                    UI(population=population))]))
        step.connect_to(step, cbk_after_fbk=cbk_after)

        return Scenario(name, anchor=step)
