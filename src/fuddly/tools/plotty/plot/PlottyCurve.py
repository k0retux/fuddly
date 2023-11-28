
from matplotlib.axes import Axes

from tools.plotty.plot.PlottyFigure import PlottyFigure
from tools.plotty.plot.APlottyGeometry import APlottyGeometry
from tools.plotty.plot.PlottyPoint import PlottyPoint
from tools.plotty.globals import PlottyGlobals, PlottyOptions


class PlottyCurve(APlottyGeometry):
    
    def __init__(self, points: list[PlottyPoint]):
        super().__init__()
        self.__points = points
        self.__draw_line = True


    @property
    def points(self) -> list[PlottyPoint]:
        return self.__points

    @property
    def draw_line(self) -> bool:
        return self.__draw_line
    

    @draw_line.setter
    def draw_line(self, value: bool):
        self.__draw_line = value


    def plot(self, axes: Axes, color: str) -> list[PlottyPoint]:

        if len(self.__points) == 0:
            return

        x_data = list(map(lambda point: point.x, self.__points))
        y_data = list(map(lambda point: point.y, self.__points))
        if self.__draw_line:
            axes.plot(x_data, y_data, color=color)

        if not PlottyOptions.hide_points:
            for point in self.__points:
                axes.plot(
                    point.x,
                    point.y,
                    color=point.color,
                    marker=point.marker
                )

        for point in self.__points:
            if point.label is not None:
                PlottyFigure.add_annotation(
                    axes,
                    point.x,
                    point.y,
                    point.label
                )

        return self.__points


    def plot_additionals(self, axes: Axes) -> list[PlottyPoint]:
        if PlottyOptions.poi <= 0:
            return []
        
        poi = self.compute_poi(PlottyOptions.poi)
        for point in poi:
            axes.plot(
                point.x,
                point.y,
                color=point.color,
                marker=point.marker
            )

        return poi
    

    def compute_poi(self, n: int) -> list[PlottyPoint]:
        scores = PlottyCurve.backward_difference(self.__points)
        prefered_poi = sorted(
            enumerate(scores),
            key=lambda enumerated: enumerated[1],
            reverse=True
        )

        result = []
        for index, _ in prefered_poi[:n]:
            point = self.__points[index]
            poi = PlottyPoint(
                (point.x, point.y),
                PlottyGlobals.poi_color,
                PlottyGlobals.poi_marker
            )
            result.append(poi)
        return result


    @staticmethod
    def backward_difference(target_list: list[PlottyPoint]) -> list[float]:
        scores = [0]
        for i in range(1, len(target_list)):
            scores.append(target_list[i].y - target_list[i-1].y)
        return scores