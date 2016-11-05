import re
from operator import attrgetter

from framework.tactics_helpers import *
from framework.scenario import *
from framework.error_handling import ExtinctPopulationError


def feature(coefficient):
    def features_decorator(func):
        def func_wrapper(*args, **kwargs):
            return coefficient * func(*args, **kwargs)
        return func_wrapper
    return features_decorator


class FitnessScore(object):

    def __init__(self):
        pass

    @feature(1)
    def string_distance(self):
        return 0

    @feature(1)
    def specific_words(self, output, words):
        result = 0
        for word in words:
            result += len(re.findall(word, output))
        return result

    @feature(1)
    def size_variation(self, input, output):
        return len(input) / len(output)

    def compute(self, input, output):
        return self.specific_words(output, ['error', 'failure']) + \
               self.string_distance() + \
               self.size_variation(input, output)


class Individual(object):
    """ Represents a population member """

    def __init__(self, fmk, node):
        self.fmk = fmk

        self.node = node
        self.feedback = None
        self.score = None
        self.probability_of_survival = None  # between 0 and 1

    def mutate(self, nb):
        self.node = self.fmk.get_data(['C', None, UI(nb=nb)], data_orig=Data(self.node)).node


class Population(object):

    def __init__(self, model, size, max_generation_nb, fitness_score):
        """
            Configure the population
            Args:
                model (string): individuals that compose this population will be built using this model
                size (integer): size of the population to manipulate
                max_generation_nb (integer): criteria used to stop the evolution process
                fitness_score (FitnessScore): used to compute fitness scores
        """
        self.MODEL = model
        self.SIZE = size
        self.MAX_GENERATION_NB = max_generation_nb

        self._individuals = []
        self.generation = 0
        self.index = 0

        self.fmk = None  # initialized by the framework itself

        self.fitness_score = fitness_score

    def setup(self):
        """
            Generate the first generation of individuals
            The default implementation creates them in a random way
        """
        for _ in range(0, self.SIZE + 1):
            node = self.fmk.get_data([self.MODEL]).node
            node.make_random(recursive=True)
            node.freeze()
            self._individuals.append(Individual(self.fmk, node))

    def _compute_scores(self):
        """ Compute the scores of each individuals using a FitnessScore object """
        for individual in self._individuals:
            individual.score = self.fitness_score.compute(individual.node, individual.feedback)

    def _compute_probability_of_survival(self):
        """ The default implementation simply normalize the score between 0 and 1 """

        min_score = min(self._individuals, key=attrgetter('score')).score
        max_score = max(self._individuals, key=attrgetter('score')).score

        for ind in self._individuals:
            if min_score != max_score:
                ind.probability_of_survival = (ind.probability_of_survival - min_score) / (max_score - min_score)
            else:
                ind.probability_of_survival = 0.50

    def _kill(self):
        """ The default implementation simply rolls the dice """
        for i in range(len(self._individuals))[::-1]:
            if random.randrange(100) < self._individuals[i].probability_of_survival*100:
                del self._individuals[i]

    def _mutate(self):
        """ The default implementation operates three bit flips on each individual """
        for individual in self._individuals:
            individual.mutate(3)

    def _crossover(self):
        """ The default implementation compensates the kills through the usage of the tCROSS disruptor """
        random.shuffle(self._individuals)

        current_size = len(self._individuals)

        i = 0
        while len(self._individuals) < self.SIZE and i <= int(current_size / 2):
            individual_1 = self._individuals[i].node
            individual_2 = self._individuals[i+1].node.get_clone()

            self._individuals.extend([self.fmk.get_data(['tCOMB', None, UI(node=individual_2.node)],
                                                        data_orig=Data(individual_1.node)).node,
                                      self.fmk.get_data(['tCOMB'],
                                                        data_orig=Data(individual_1.node)).node])
            i += 2

    def evolve(self):
        """ Describe the evolutionary process """
        self._compute_scores()
        self._compute_probability_of_survival()
        self._kill()
        self._mutate()
        self._crossover()

        self.generation += 1

        if len(self._individuals) < 2:
            raise ExtinctPopulationError()

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

    def next(self):
        if self.index == len(self._individuals):
            raise StopIteration
        else:
            self.index += 1
            return self._individuals[self.index-1]


class EvolutionaryScenariosBuilder(object):

    @staticmethod
    def build(name, population):
        """
        Create a scenario that takes advantage of an evolutionary approach
        Args:
            name (string): name of the scenario to create
            population (Population): population to use

        Returns:
            Scenario : evolutionary scenario
        """

        def cbk_before(env, current_step, next_step):
            print("Callback before")
            return True

        def cbk_after(env, current_step, next_step, fbk):
            print("Callback after")

            # set the feedback of the last played individual
            env.population[env.population.index].feedback = fbk

            if env.population.index == len(env.population) - 1:
                if env.population.generation == env.population.MAX_GENERATION_NB:
                    return False
                else:
                    env.population.evolve()

            return True

        step = Step(data_desc=DataProcess(process=[('POPULATION', None, UI(population=population))]))
        step.connect_to(step, cbk_before_sending=cbk_before, cbk_after_fbk=cbk_after)

        sc = Scenario(name, anchor=step)
        sc._env.population = population
        return sc
