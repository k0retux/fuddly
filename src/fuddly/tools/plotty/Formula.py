from matplotlib.dates import date2num
import tools.plotty.cli.parse.formula as parse_formula

import cexprtk

from datetime import datetime
from typing import Any, Optional


class MathExpression:

    def __init__(self, expression: str):
        self.expression = expression

        variable_names, function_names = self.__collect_names()
        self.__variable_names = variable_names
        self.__function_names = function_names

    @property
    def variable_names(self) -> list[str]:
        return self.__variable_names

    @property
    def function_names(self) -> list[str]:
        return self.__function_names

    def __collect_names(self) -> tuple[list[str], list[str]]:
        variable_names = []
        function_names = []
        on_build_name = ""
        for char in self.expression:
            if char.isalpha() or char == '_':
                on_build_name += char
                continue

            if on_build_name != "":
                if char == '(':
                    function_names.append(on_build_name)
                else:
                    variable_names.append(on_build_name)
                on_build_name = ""

        if on_build_name != "":
            variable_names.append(on_build_name)

        return (variable_names, function_names)


    def evaluate(self, instanciation: dict[str, Any]) -> float:
        return cexprtk.evaluate_expression(self.expression, instanciation)


    def __str__(self) -> str:
        return self.expression


class Formula:
    def __init__(self, x_expression: str, y_expression: str):
        self.__x_expression = MathExpression(x_expression)
        self.__y_expression = MathExpression(y_expression)
        self.__variable_names = self.__x_expression.variable_names + \
            self.__y_expression.variable_names
        self.__function_names = self.__x_expression.function_names + \
            self.__y_expression.function_names


    @classmethod
    def from_string(cls, formula: str) -> Optional['Formula']:
        exprs = parse_formula.parse_formula(formula)
        if exprs is None:
            return None
        lhs, rhs = exprs
        return cls(rhs, lhs)

    @property
    def x_expression(self) -> MathExpression:
        return self.__x_expression

    @property
    def y_expression(self) -> MathExpression:
        return self.__y_expression

    @property
    def variable_names(self) -> list[str]:
        return self.__variable_names

    @property
    def function_names(self) -> list[str]:
        return self.__function_names

    @staticmethod
    def __convert_non_operable_types(instanciation: dict[str, Any]):
        for name, value in instanciation.items():
            if isinstance(value, datetime):
                instanciation[name] = date2num(value)

    def evaluate(self, instanciation: dict[str, Any]) -> tuple[float, float]:
        Formula.__convert_non_operable_types(instanciation)
        return (
            self.x_expression.evaluate(instanciation),
            self.y_expression.evaluate(instanciation)
        )

    def __str__(self) -> str:
        return f"{self.__y_expression} ~ {self.__x_expression}"
