import re
from operator import attrgetter

from framework.tactics_helpers import *
from framework.scenario import *
from framework.error_handling import ExtinctPopulationError


class FitnessScore(object):

    def compute(self, input, output):
        raise NotImplementedError


class Population(object):

    def __init__(self):
        self._individuals = []
        self.index = 0

    def setup(self):
        """ Generate the first generation of individuals """
        self._individuals = []
        self.index = 0

    def evolve(self):
        """ Describe the evolutionary process """
        raise NotImplementedError

    def stop_criteria(self):
        """ Check the stop criteria """
        raise NotImplementedError

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


def feature(coefficient):
    def features_decorator(func):
        def func_wrapper(*args, **kwargs):
            return coefficient * func(*args, **kwargs)
        return func_wrapper
    return features_decorator


class DefaultFitnessScore(FitnessScore):

    @feature(1)
    def string_distance(self):
        return 0

    @feature(1)
    def specific_words(self, output, words):
        result = 0
        for word in words:
            result += len(re.findall(word, output.to_bytes()))
        return result

    @feature(1)
    def size_variation(self, input, output):
        return len(input) / len(output)

    def compute(self, input, output):
        return random.uniform(1, 100)


class Individual(object):
    """ Represents a population member """

    def __init__(self, fmk, node):
        self.fmk = fmk

        self.node = node
        self.feedback = None
        self.score = None
        self.probability_of_survival = None  # between 0 and 1

    def mutate(self, nb):
        self.node = self.fmk.get_data([('C', None, UI(nb=nb))], data_orig=Data(self.node)).node


class DefaultPopulation(Population):

    def __init__(self, model, size, max_generation_nb, fitness_score):
        """
            Configure the population
            Args:
                model (string): individuals that compose this population will be built using this model
                size (integer): size of the population to manipulate
                max_generation_nb (integer): criteria used to stop the evolution process
                fitness_score (FitnessScore): used to compute fitness scores
        """
        Population.__init__(self)
        self.MODEL = model
        self.SIZE = size
        self.MAX_GENERATION_NB = max_generation_nb

        self.generation = 1

        self.fmk = None  # initialized by the framework itself

        self.fitness_score = fitness_score

    def setup(self):
        """
            Generate the first generation of individuals
            The default implementation creates them in a random way
        """
        Population.setup(self)

        self.generation = 1

        for _ in range(0, self.SIZE):
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
                ind.probability_of_survival = (ind.score - min_score) / (max_score - min_score)
            else:
                ind.probability_of_survival = 0.50

    def _kill(self):
        """ The default implementation simply rolls the dice """
        for i in range(len(self._individuals))[::-1]:
            if random.randrange(100) > self._individuals[i].probability_of_survival*100:
                del self._individuals[i]

        if len(self._individuals) < 2:
            raise ExtinctPopulationError()

    def _mutate(self):
        """ The default implementation operates three bit flips on each individual """
        for individual in self._individuals:
            individual.mutate(3)

    def _crossover(self):
        """ The default implementation compensates the kills through the usage of the tCROSS disruptor """
        random.shuffle(self._individuals)

        current_size = len(self._individuals)

        i = 0
        while len(self._individuals) < self.SIZE and i < int(current_size / 2):
            ind_1 = self._individuals[i].node
            ind_2 = self._individuals[i+1].node.get_clone()

            self._individuals.extend([
                Individual(self.fmk, self.fmk.get_data([('tCOMB', None, UI(node=ind_2))], data_orig=Data(ind_1)).node),
                Individual(self.fmk, self.fmk.get_data(['tCOMB'], data_orig=Data(ind_1)).node)])

            i += 2

    def evolve(self):
        """ Describe the evolutionary process """
        self._compute_scores()
        self._compute_probability_of_survival()
        self._kill()
        self._mutate()
        self._crossover()

        self.generation += 1



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
            env.population[env.population.index - 1].feedback = fbk

            if env.population.index == len(env.population):

                if env.population.generation == env.population.MAX_GENERATION_NB:
                    return False
                else:
                    env.population.index = 0
                    try:
                        env.population.evolve()
                    except ExtinctPopulationError:
                        return False

            return True

        step = Step(data_desc=DataProcess(process=[('POPULATION', None, UI(population=population))]))
        step.connect_to(step, cbk_before_sending=cbk_before, cbk_after_fbk=cbk_after)
        step.connect_to(FinalStep())

        sc = Scenario(name, anchor=step)
        sc._env.population = population
        return sc
