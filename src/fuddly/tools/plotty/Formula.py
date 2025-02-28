from matplotlib.dates import date2num
from fuddly.tools.plotty.cli.parse.formula import parse_formula

from datetime import datetime
from typing import Any, Optional


class Formula:
    def __init__(self, x_variable_name: str, y_variable_name: str):
        self.__x_variable_name = x_variable_name
        self.__y_variable_name = y_variable_name


    @classmethod
    def from_string(cls, formula: str) -> Optional['Formula']:
        exprs = parse_formula(formula)
        if exprs is None:
            return None
        lhs, rhs = exprs
        return cls(rhs, lhs)

    @property
    def x_variable_name(self) -> str:
        return self.__x_variable_name

    @property
    def y_variable_name(self) -> str:
        return self.__y_variable_name
    
    @property
    def variable_names(self) -> list[str]:
        return [self.__x_variable_name, self.__y_variable_name]

    @staticmethod
    def __convert_non_operable_types(instanciation: dict[str, Any]):
        for name, value in instanciation.items():
            if isinstance(value, datetime):
                instanciation[name] = date2num(value)

    def evaluate(self, instanciation: dict[str, Any]) -> tuple[float, float]:
        Formula.__convert_non_operable_types(instanciation)
        return (
            instanciation[self.__x_variable_name],
            instanciation[self.__y_variable_name]
        )

    def __str__(self) -> str:
        return f"{self.__y_variable_name} ~ {self.__x_variable_name}"
