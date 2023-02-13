
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
STEP_OPERATOR = '|'

class DateUnit(Enum):
    SECOND = 1
    MILLISECOND = 2

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
rootdir = os.path.dirname(os.path.dirname(currentdir))
sys.path.insert(0, rootdir)

from framework.database import Database
from libs.external_modules import *

def print_info(msg: str):
    print(colorize(f"*** INFO: {msg} *** ", reg=Color.INFO))

def print_warning(msg: str):
    print(colorize(f"*** WARNING: {msg} *** ", rgb=Color.WARNING))

def print_error(msg: str):
    print(colorize(f"*** ERROR: {msg} *** ", rgb=Color.ERROR))

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

def sort_points_by_interest(x_data: list[float], y_data: list[float]) -> list[tuple[float, float]]:
    backward_difference = [0]
    for i in range(1, len(y_data)):
        backward_difference.append(y_data[i] - y_data[i-1])

    result = zip(x_data, y_data, backward_difference)
    result = sorted(result, key=lambda tup: tup[2], reverse=True)
    result = list(map(lambda tup: (tup[0], tup[1]), result))

    return result


def add_points_of_interest(axes, x_data: list[float], y_data: list[float], points_of_interest: int):

    points = sort_points_by_interest(x_data, y_data)
    
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
        print_error(f"Value '{s}' is not a valid integer")
        return None


def parse_int_range(int_range: str) -> Optional[range]:

    step = 1
    bounds_and_step = int_range.split(STEP_OPERATOR)
    if len(bounds_and_step) == 2:
        parsed_step = try_parse_int(bounds_and_step[1])
        if parsed_step is None:
            print_warning(f"Ignoring interval '{int_range}': invalid step '{bounds_and_step[1]}'")
            return None
        step = parsed_step

    bounds = bounds_and_step[0].split(INTERVAL_OPERATOR)
    if len(bounds) == 1:
        value = try_parse_int(bounds[0])
        if value is not None:
            return range(value, value+1)
        
        print_warning(f"Ignoring interval '{int_range}' : invalid integer '{bounds[0]}'")
        return None

    if len(bounds) == 2:
        lower_bound = try_parse_int(bounds[0])
        upper_bound = try_parse_int(bounds[1])
        if lower_bound is None:
            print_warning(f"Ignoring interval '{int_range}' : invalid integer '{bounds[0]}'")
            return None

        if upper_bound is None:
            print_warning(f"Ignoring interval '{int_range}' : invalid integer '{bounds[1]}'")
            return None

        if lower_bound >= upper_bound:
            print_warning(f"Ignoring interval '{int_range}'")
            return None

        return range(lower_bound, upper_bound, step)
            
    print_warning(f"Invalid interval found: '{int_range}'")
    return None


def parse_int_range_union(int_range_union: str) -> list[range]:
    result = []
    parts = int_range_union.split(UNION_DELIMITER)
    for part in parts:
        int_range = parse_int_range(part)
        if int_range is not None:
            result.append(int_range)
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


def belongs_condition_sql_string(column_label: str, int_ranges: list[range]):
    result = "false"
    for int_range in int_ranges:
        sub_condition = ""
        if int_range.start == int_range.stop:
            sub_condition = f" OR {column_label} = {list(int_range)}"
        else:
            if int_range.step == 1:
                sub_condition = f" OR {column_label} >= {int_range.start} AND {column_label} < {int_range.stop}"
                
            else:
                sql_range = ','.join(list(map(str, list(int_range))))
                sub_condition = f" OR {column_label} IN ({sql_range})"
        result += sub_condition
    return result


def request_from_database(
    fmkdb_path: str,
    int_ranges: list[range], 
    column_names: list[str]
) -> Optional[list[dict[str, Any]]]:
    
    fmkdb = Database(fmkdb_path)
    ok = fmkdb.start()
    if not ok:
        print_error(f"The database {fmkdb_path} is invalid!")
        sys.exit(ARG_INVALID_FMDBK)

    id_ranges_check_str = belongs_condition_sql_string("ID", int_ranges)

    statement = f"SELECT {', '.join(column_names)} FROM DATA " \
                f"WHERE {id_ranges_check_str}"

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
        print_error(f"'{fmkdb}' does not exist")
        sys.exit(ARG_INVALID_FMDBK)

    id_interval = args.id_interval
    if id_interval is None:
        print_error(f"Please provide a valid ID interval")
        print_info(f"ID interval can be provided in the form '1..5,9..10,7..8'")
        sys.exit(ARG_INVALID_ID)

    formula = args.formula
    if formula is None:
        print_error(f"Please provide a valid formula")
        print_info(f"Formula can be provided on the form 'a+b~c*d'")
        print_info(f"for a plot of a+b in function of c*d'")
        sys.exit(ARG_INVALID_FORMULA)

    date_unit_str = args.date_unit
    if date_unit_str is None:
        print_error(f"Please provide a unit for date values")
        sys.exit(ARG_INVALID_DATE_UNIT)

    poi = args.points_of_interest
    if poi < 0:
        print_error(f"Please provide a positive or zero number of point of interest")
        sys.exit(ARG_INVALID_POI)

    date_unit = DateUnit.MILLISECOND
    if date_unit_str == 's':
        date_unit = DateUnit.SECOND

    id_interval = parse_int_range_union(id_interval)

    y_expression, x_expression, valid_formula = split_formula(formula)

    x_variable_names, x_function_names = collect_names(x_expression)
    y_variable_names, y_function_names = collect_names(y_expression)

    if not valid_formula:
        sys.exit(ARG_INVALID_FORMULA)

    variable_names = x_variable_names.union(y_variable_names)
    variables_values = request_from_database(fmkdb, id_interval, list(variable_names))
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