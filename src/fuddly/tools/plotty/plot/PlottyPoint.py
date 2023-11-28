
from typing import Optional


class PlottyPoint:

    def __init__(
        self,
        coords: tuple[float, float],
        color: str,
        marker: str,
        label: Optional[str] = None
    ):
        self.__x = coords[0]
        self.__y = coords[1]
        self.__color = color
        self.__marker = marker
        self.__label = label

    @property
    def x(self) -> float:
        return self.__x

    @x.setter
    def x(self, value: float):
        self.__x = value

    @property
    def y(self) -> float:
        return self.__y

    @y.setter
    def y(self, value):
        self.__y = value

    @property
    def color(self) -> str:
        return self.__color
    
    @color.setter
    def color(self, value):
        self.__color = value

    @property
    def marker(self) -> str:
        return self.__marker
    
    @marker.setter
    def marker(self, value):
        self.__marker = value

    @property
    def label(self) -> Optional[str]:
        return self.__label
