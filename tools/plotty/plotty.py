
import argparse
from datetime import datetime
import inspect
import os
from statistics import mean
import sys
from typing import Any, Optional
from enum import Enum

import cexprtk
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

ARG_INVALID_FMDBK = -1
ARG_INVALID_ID = -2
ARG_INVALID_FORMULA = -3
ARG_INVALID_DATE_UNIT = -4
ARG_INVALID_VAR_NAMES = -5
ARG_INVALID_POI = -6

UNION_DELIMITER = ','
INTERVAL_OPERATOR = '..'

class DateUnit(Enum):
    SECOND = 1
    MILLISECOND = 2

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
rootdir = os.path.dirname(os.path.dirname(currentdir))
sys.path.insert(0, rootdir)

from framework.database import Database
from libs.external_modules import *

#region Argparse
parser = argparse.ArgumentParser(description='Argument for FmkDB toolkit script')

group = parser.add_argument_group('Main parameters')

group.add_argument(
    '-id', 
    '--id_interval', 
    type=str, 
    help='The ID interval to take into account x..y',
    required=True
)

group.add_argument(
    '-f', 
    '--formula', 
    type=str, 
    help='The formula to plot, in the form "y ~ x"',
    required=True
)

group.add_argument(
    '-d',
    '--date_unit',
    type=str,
    help='Unit used for datetime conversion. Can be "s" or "ms"',
    choices=['s', 'ms'],
    required=True
)

group = parser.add_argument_group('Options')

group.add_argument(
    '-db', 
    '--fmkdb', 
    metavar='PATH', 
    help='Path to an alternative fmkDB.db', 
    nargs='?',
    required=False
)

group.add_argument(
    '-poi',
    '--points_of_interest',
    type=int,
    default=0,
    help='How many point of interest the plot should show. Works only if -poi is set to true',
    required=False
)

#endregion


#region Plot

def add_points_of_interest(axes, x_data: list[float], y_data: list[float], points_of_interest: int):

    backward_difference = [0]
    for i in range(1, len(y_data)):
        backward_difference.append(y_data[i] - y_data[i-1])
    backdiff_mean = mean(backward_difference)

    points = []
    for i in range(len(y_data)):
        if backward_difference[i] > 2*backdiff_mean:
            points.append((x_data[i], y_data[i]))

    points = sorted(points, key=lambda p: p[1], reverse=True)
    for i in range(points_of_interest):
        if i >= len(points):
            break
        x, y = points[i]
        plt.plot(x, y, 'o', color='red')
        axes.annotate(
            f"{int(x)}",
            xy=(x, y), xycoords='data',
            xytext=(-10, 20), textcoords='offset pixels',
            horizontalalignment='right', verticalalignment='top'
        )

def display_line(
    x_data: list[float], 
    x_true_type: Optional[type], 
    y_data: list[float], 
    y_true_type: Optional[type], 
    date_unit: DateUnit,
    points_of_interest: int
):
    axes = plt.figure().add_subplot(111)

    plt.plot(x_data, y_data, '-')

    if points_of_interest != 0:
        add_points_of_interest(axes, x_data, y_data, points_of_interest)
    
    # Avoid userwarning and fix location of ticks
    ticks_loc = axes.get_yticks().tolist()
    axes.yaxis.set_major_locator(mticker.FixedLocator(ticks_loc))

    if x_true_type is not None and x_true_type == datetime:
        actual_labels = axes.get_xticklabels()
        new_labels = map(lambda label: float_to_datetime(label.get_position()[1], date_unit), actual_labels)
        axes.set_xticklabels(list(new_labels))
    if y_true_type is not None and y_true_type == datetime:
        actual_labels = axes.get_yticklabels()
        new_labels = map(lambda label: float_to_datetime(label.get_position()[1], date_unit), actual_labels)
        axes.set_yticklabels(list(new_labels))

    plt.grid()
    plt.show()

#endregion


#region Formula
def collect_names(expression: str) -> tuple[set[str], set[str]]:
    variable_names = set()
    function_names = set()
    on_build_name = ""
    for char in expression:
        if char.isalpha() or char == '_':
            on_build_name += char
        else:
            if on_build_name != "":
                if char == '(':
                    function_names.add(on_build_name)
                else:
                    variable_names.add(on_build_name)
                on_build_name = ""
    
    if on_build_name != "":
        variable_names.add(on_build_name)
    return (variable_names, function_names)


def split_formula(formula: str) -> tuple[str, str, bool]:
    parts = formula.split('~')
    if len(parts) != 2:
        return ("", "", False)
    
    parts = list(map(lambda s: "".join(s.split(' ')), parts))

    return (parts[0], parts[1], True)
#endregion


#region Interval
def try_parse_int(s: str) -> Optional[int]:
    try:
        int_value = int(s)
        return int_value
    except ValueError:
        print(colorize(f"*** ERROR: Value '{s}' is not a valid integer*** ", rgb=Color.ERROR))
        return None


def parse_interval(interval: str) -> set[int]:

    bounds = interval.split(INTERVAL_OPERATOR)
    if len(bounds) == 1:
        value = try_parse_int(bounds[0])
        if value is not None:
            return set(value)
        
        print(colorize(f"*** WARNING: Ignoring interval '{interval}' *** ", rgb=Color.WARNING))
        return set()

    if len(bounds) == 2:
        lower_bound = try_parse_int(bounds[0])
        upper_bound = try_parse_int(bounds[1])
        if lower_bound is None or upper_bound is None:
            print(colorize(f"*** WARNING: Ignoring interval '{interval}' *** ", rgb=Color.WARNING))
            return set()

        if lower_bound >= upper_bound:
            print(colorize(f"*** WARNING: Ignoring interval '{interval}' *** ", rgb=Color.WARNING))
            return set()

        result = set()
        for value in range(lower_bound, upper_bound):
            result.add(value)
        return result
            
    print(colorize(f"*** WARNING: Invalid interval found: '{interval}' *** ", rgb=Color.ERROR))
    return set()


def parse_interval_union(interval_union: str) -> set[int]:
    result = set()
    parts = interval_union.split(UNION_DELIMITER)
    for part in parts:
        interval_values = parse_interval(part)
        result = result.union(interval_values)
    return result
#endregion


def datetime_to_float(date_time: datetime, date_unit: DateUnit):
    res = date_time.timestamp()
    return res if date_unit == DateUnit.SECOND else res * 1000


def float_to_datetime(timestamp: float, date_unit: DateUnit):
    if date_unit == DateUnit.MILLISECOND:
        timestamp /= 1000
    return datetime.fromtimestamp(timestamp)


def convert_non_operable_types(variables_values: list[dict[str, Any]]):
    for instanciation in variables_values:
        for key, value in instanciation.items():
            if isinstance(value, datetime):
                instanciation[key] = datetime_to_float(value, date_unit)


def solve_expression(expression: str, variables_values: list[dict[str, Any]]) -> list[float]:
    results = []
    for variables_value in variables_values:
        result = cexprtk.evaluate_expression(expression, variables_value)
        results.append(result)
    return results


def request_from_database(
    id_interval: set[int], 
    column_names: list[str]
) -> Optional[list[dict[str, Any]]]:
    
    fmkdb = Database()
    ok = fmkdb.start()
    if not ok:
        print(colorize("*** ERROR: The database {:s} is invalid! ***".format(fmkdb.fmk_db_path),
                       rgb=Color.ERROR))
        sys.exit(-1)

    id_interval_str = list(map(str, id_interval))

    statement = f"SELECT {', '.join(column_names)} FROM DATA " \
                f"WHERE ID IN ({', '.join(id_interval_str)})"

    matching_data = fmkdb.execute_sql_statement(statement)

    fmkdb.stop()

    if matching_data is None or matching_data == []:
        return None

    result = []
    for line in matching_data:
        line_values = dict()
        for index, value in enumerate(line):
            line_values[column_names[index]] = value
        result.append(line_values)

    return result


if __name__ == "__main__": 

    args = parser.parse_args()

    fmkdb = args.fmkdb
    if fmkdb is not None and not os.path.isfile(fmkdb):
        print(colorize(f"*** ERROR: '{fmkdb}' does not exist ***", rgb=Color.ERROR))
        sys.exit(ARG_INVALID_FMDBK)

    id_interval = args.id_interval
    if id_interval is None:
        print(colorize(f"*** ERROR: Please provide a valid ID interval*** ", rgb=Color.ERROR))
        print(colorize(f"*** INFO: ID interval can be provided in the form '1..5,9..10,7..8'*** ", rgb=Color.INFO))
        sys.exit(ARG_INVALID_ID)

    formula = args.formula
    if formula is None:
        print(colorize(f"*** ERROR: Please provide a valid formula***", rgb=Color.ERROR))
        print(colorize(f"*** INFO: Formula can be provided on the form 'a+b~c*d'*** ", rgb=Color.INFO))
        print(colorize(f"*** INFO: for a plot of a+b in function of c*d'*** ", rgb=Color.INFO))
        sys.exit(ARG_INVALID_FORMULA)

    date_unit_str = args.date_unit
    if date_unit_str is None:
        print(colorize(f"*** ERROR: Please provide a unit for date values***", rgb=Color.ERROR))
        sys.exit(ARG_INVALID_DATE_UNIT)

    poi = args.points_of_interest
    if poi < 0:
        print(colorize(f"*** ERROR: Please provide a positive or zero number of point of interest***", rgb=Color.ERROR))
        sys.exit(ARG_INVALID_POI)

    date_unit = DateUnit.MILLISECOND
    if date_unit_str == 's':
        date_unit = DateUnit.SECOND

    id_interval = parse_interval_union(id_interval)

    y_expression, x_expression, valid_formula = split_formula(formula)

    x_variable_names, x_function_names = collect_names(x_expression)
    y_variable_names, y_function_names = collect_names(y_expression)

    if not valid_formula:
        sys.exit(ARG_INVALID_FORMULA)

    variable_names = x_variable_names.union(y_variable_names)
    variables_values = request_from_database(id_interval, list(variable_names))
    if variables_values is None:
        sys.exit(ARG_INVALID_VAR_NAMES)
    variables_true_types = {}
    for variable, value in variables_values[0].items():
        variables_true_types[variable] = type(value)
    convert_non_operable_types(variables_values)

    x_values = solve_expression(x_expression, variables_values)
    y_values = solve_expression(y_expression, variables_values)

    x_conversion_type = None
    if len(x_variable_names) == 1:
        elmt = next(iter(x_variable_names))
        x_conversion_type = variables_true_types[elmt]
    y_conversion_type = None
    if len(y_variable_names) == 1:
        elmt = next(iter(y_variable_names))
        y_conversion_type = variables_true_types[elmt]

    display_line(x_values, x_conversion_type, y_values, y_conversion_type, date_unit, poi)
    
    sys.exit(0)