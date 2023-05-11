
from tools.plotty.globals import PlottyGlobals, PlottyOptions
from tools.plotty.plot.PlottyFigure import PlottyFigure
from tools.plotty.plot.APlottyGeometry import APlottyGeometry

from matplotlib.axes import Axes


class PlottyFigureArea:

    def __init__(
            self,
            main_geometry: APlottyGeometry,
            index: int
    ):
        self.__figure: PlottyFigure = None
        self.__main_geometry = main_geometry
        self.__additional_geometries = []
        self.__index = index
    

    @property
    def main_geometry(self) -> APlottyGeometry:
        return self.__main_geometry

    @property
    def figure(self) -> PlottyFigure:
        return self.__figure

    @figure.setter
    def figure(self, figure: PlottyFigure):
        self.__figure = figure

    @property
    def alignement_index(self) -> int:
        return self.__index


    def add_geometry(self, geometry: APlottyGeometry):
        self.__additional_geometries.append(geometry)
        geometry.area = self


    def plot_aligned(self, reference_area: 'PlottyFigureArea', axes: Axes):
        """
        In the scope of the Plotty tool, we always assume that the first point
        of a geometry is the smallest in term of x-value as well as y-value,
        and the last one in the highest.
        """
        if len(self.__main_geometry.points) == 0:
            return

        reference_first = reference_area.main_geometry.points[0]
        first = self.__main_geometry.points[0]
        last = self.__main_geometry.points[-1]
        curve_height = abs(last.y - first.y)
        shift_x = reference_first.x - first.x
        shift_y = reference_first.y - first.y + \
            self.__index * curve_height * \
            PlottyOptions.vertical_shift

        for geometry in [self.__main_geometry, *self.__additional_geometries]:
            for point in geometry.points:
                point.x += shift_x
                point.y += shift_y

        self.plot(axes)


    def plot(self, axes: Axes):
        color = PlottyGlobals.colors[self.__index]
        points = self.__main_geometry.plot(axes, color)
        self.__figure.add_plotted_points(points)
        additionals = self.__main_geometry.plot_additionals(axes)
        self.__figure.add_plotted_additionals(additionals)
        for geometry in self.__additional_geometries:
            points = geometry.plot(axes, color)
            self.__figure.add_plotted_points(points)
