
from matplotlib.axes import Axes

from tools.plotty.plot.PlottyFigure import PlottyFigure
from tools.plotty.plot.APlottyGeometry import APlottyGeometry
from tools.plotty.plot.PlottyPoint import PlottyPoint
from tools.plotty.globals import PlottyOptions


class PlottyPointCloud(APlottyGeometry):
    
    def __init__(self, points: list[PlottyPoint]):
        super().__init__()
        self.__points = points


    @property
    def points(self) -> list[PlottyPoint]:
        return self.__points


    def plot(self, axes: Axes, color: str) -> list[PlottyPoint]:

        if len(self.__points) == 0:
            return

        x_data = list(map(lambda point: point.x, self.__points))
        y_data = list(map(lambda point: point.y, self.__points))
        colors = list(map(lambda point: point.color, self.__points))
        markers = list(map(lambda point: point.marker, self.__points))
        for marker in markers:
            axes.scatter(x_data, y_data, color=colors, marker=marker)

        for point in self.__points:
            if point.label is not None:
                PlottyFigure.add_annotation(
                    axes,
                    point.x,
                    point.y,
                    point.label
                )

        return self.__points