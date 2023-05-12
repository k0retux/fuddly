
from typing import Optional
from datetime import datetime

from matplotlib import pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure
from matplotlib.dates import DateFormatter

from tools.plotty.globals import GridMatch, PlottyOptions
from tools.plotty.plot.PlottyPoint import PlottyPoint


class PlottyFigure:

    def __init__(self, main_area: 'PlottyFigureArea'):
        self.__figure: Figure = plt.figure()
        self.__axes: Axes = self.__figure.add_subplot(111)
        self.__x_type: Optional[type] = None
        self.__y_type: Optional[type] = None
        self.__plotted_points: list[PlottyPoint] = []
        self.__plotted_additionals: list[PlottyPoint] = []
        self.__main_area = main_area
        self.__main_area.figure = self
        self.__additional_areas: list['PlottyFigureArea'] = []
        self.__is_plotted: bool = False


    @property
    def x_type(self) -> Optional[type]:
        return self.__x_type
    
    @x_type.setter
    def x_type(self, value: type):
        self.__x_type = value

    @property
    def y_type(self) -> Optional[type]:
        return self.__y_type
    
    @y_type.setter
    def y_type(self, value: type):
        self.__y_type = value


    def add_area(self, area: 'PlottyFigureArea'):
        self.__additional_areas.append(area)
        area.figure = self


    def add_plotted_points(self, points: list[PlottyPoint]):
        self.__plotted_points.extend(points)


    def add_plotted_additionals(self, additionals: list[PlottyPoint]):
        self.__plotted_additionals.extend(additionals)


    def plot_point(self, point: PlottyPoint):
        self.__axes.plot(point.x, point.y, point.marker, point.color)
        if point.label is not None:
            PlottyFigure.add_annotation(self.__axes, point.x, point.y, point.label)


    @staticmethod
    def add_annotation(axes: Axes, x: float, y: float, label: str):
        text_height = label.count('\n') + 1
        axes.annotate(
            f"{label}",
            xy=(x, y), xycoords='data',
            xytext=(-10, 20 * text_height), textcoords='offset pixels',
            horizontalalignment='right', verticalalignment='top'
        )


    def plot_areas(self):
        self.__main_area.figure
        self.__main_area.plot(self.__axes)
        for area in self.__additional_areas:
            area.plot_aligned(self.__main_area, self.__axes)
        self.__post_process()
        self.__is_plotted = True


    def show(self):
        plt.show()


    def __post_process(self):
        self.__setup_axes()
        self.__setup_grid()
        self.__setup_legend()


    def __setup_grid(self):
        if PlottyOptions.grid_match == GridMatch.AUTO:
            pass

        elif PlottyOptions.grid_match == GridMatch.POI:
            new_xticks = list(map(lambda point: point.x, self.__plotted_additionals))
            new_yticks = list(map(lambda point: point.y, self.__plotted_additionals))
            self.__axes.xaxis.set_ticks(new_xticks)
            self.__axes.yaxis.set_ticks(new_yticks)

        elif PlottyOptions.grid_match == GridMatch.ALL:
            new_xticks = list(map(lambda point: point.x, self.__plotted_points))
            new_yticks = list(map(lambda point: point.y, self.__plotted_points))
            self.__axes.xaxis.set_ticks(new_xticks)
            self.__axes.yaxis.set_ticks(new_yticks)

        self.__axes.grid(True)


    def __setup_axes(self):
        if self.__x_type == datetime:
            formatter = DateFormatter(PlottyOptions.date_format)
            self.__axes.xaxis.set_major_formatter(formatter)
            self.__axes.tick_params(axis='x', which='major', labelrotation=30)

        if self.__y_type == datetime:
            formatter = DateFormatter(PlottyOptions.date_format)
            self.__axes.yaxis.set_major_formatter(formatter)
            self.__axes.tick_params(axis='y', which='major', reset=True)


    def __setup_legend(self):
        self.__axes.set_title(PlottyOptions.formula)
        self.__axes.set_xlabel(PlottyOptions.formula.x_expression)
        self.__axes.set_ylabel(PlottyOptions.formula.y_expression)
