from matplotlib.axes import Axes

from abc import ABCMeta, abstractmethod


class APlottyGeometry:

    __metaclass__ = ABCMeta

    def __init__(self):
        self._area = None


    @property
    def area(self):
        return self._area


    @area.setter
    def area(self, value: 'PlottyFigureArea'):
        self._area = value

    
    @property
    @abstractmethod
    def points(self):
        pass


    @abstractmethod
    def plot(self, axes: Axes):
        pass


    @abstractmethod
    def plot_additionals(self, axes: Axes):
        pass
    