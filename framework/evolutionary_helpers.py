from operator import attrgetter

from framework.tactics_helpers import *
from framework.scenario import *
from framework.error_handling import ExtinctPopulationError, PopulationError


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


class Individual(object):
    """ Represents a population member """
    def __init__(self, fmk, node):
        self._fmk = fmk
        self.node = node
        self.feedback = None


class DefaultIndividual(Individual):
    """ Provide a default implementation of the Individual class """

    def __init__(self, fmk, node):
        Individual.__init__(self, fmk, node)

        self.score = None
        self.probability_of_survival = None  # between 0 and 1

    def mutate(self, nb):
        data = self._fmk.get_data([('C', None, UI(nb=nb))], data_orig=Data(self.node))
        if data is None:
            raise PopulationError
        self.node = data.node


class DefaultPopulation(Population):
    """ Provide a default implementation of the Population base class """

    def _initialize(self, model, size=100, max_generation_nb=50):
        """
            Configure the population

            Args:
                model (string): individuals that compose this population will be built using this model
                size (integer): size of the population to manipulate
                max_generation_nb (integer): criteria used to stop the evolution process
        """
        Population._initialize(self)

        self.MODEL = model
        self.SIZE = size
        self.MAX_GENERATION_NB = max_generation_nb

        self.generation = None

    def reset(self):
        """ Generate the first generation of individuals in a random way """
        Population.reset(self)

        self.generation = 1

        # individuals initialization
        for _ in range(0, self.SIZE):
            data = self._fmk.get_data([self.MODEL])
            if data is None:
                raise PopulationError
            node = data.node
            node.make_random(recursive=True)
            node.freeze()
            self._individuals.append(DefaultIndividual(self._fmk, node))

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
            individual.mutate(3)
            print(str(individual) + "mutated !!")

    def _crossover(self):
        """ Compensates the kills through the usage of the tCOMB disruptor """
        random.shuffle(self._individuals)

        current_size = len(self._individuals)

        i = 0
        while len(self._individuals) < self.SIZE and i < int(current_size / 2):
            ind_1 = self._individuals[i].node
            ind_2 = self._individuals[i+1].node.get_clone()


            while True:
                data = self._fmk.get_data([('tCOMB', None, UI(node=ind_2))], data_orig=Data(ind_1))
                if data is None or data.is_unusable():
                    break
                else:
                    self._individuals.append(DefaultIndividual(self._fmk, data.node))

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

        def cbk_after(env, current_step, next_step, fbk):
            print("Callback after")

            # set the feedback of the last played individual
            population[population.index - 1].feedback = fbk

            return True

        step = Step(data_desc=DataProcess(process=[('POPULATION', None, UI(population=population))]))
        step.connect_to(step, cbk_after_fbk=cbk_after)

        return Scenario(name, anchor=step)
