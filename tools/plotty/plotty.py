
import argparse
from datetime import datetime
import inspect
import os
import sys
from typing import Any, Optional
from enum import Enum

import cexprtk
import matplotlib.pyplot as plt


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

#endregion

def display_line(x_data: list[float], y_data: list[float]):
    plt.plot(x_data, y_data)
    plt.show()

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


def solve_expression(expression: str, variables_values: list[dict[str, Any]]) -> list[float]:
    results = []
    for variables_value in variables_values:
        result = cexprtk.evaluate_expression(expression, variables_value)
        results.append(result)
    return results


def request_from_database(id_interval: set[int], column_names: list[str], date_unit: DateUnit) -> Optional[list[dict[str, Any]]]:
    
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

    if matching_data is None:
        return None

    result = []
    for line in matching_data:
        line_values = dict()
        for index, value in enumerate(line):
            if isinstance(value, datetime):
                value = value.timestamp()
                if date_unit == DateUnit.MILLISECOND:
                    value *= 1000
            line_values[column_names[index]] = value
        result.append(line_values)

    return result


if __name__ == "__main__": 

    args = parser.parse_args()

    fmkdb = args.fmkdb
    if fmkdb is not None and not os.path.isfile(fmkdb):
        print(colorize(f"*** ERROR: '{fmkdb}' does not exist ***", rgb=Color.ERROR))
        sys.exit(-1)

    id_interval = args.id_interval
    if id_interval is None:
        print(colorize(f"*** ERROR: Please provide a valid ID interval*** ", rgb=Color.ERROR))
        print(colorize(f"*** INFO: ID interval can be provided in the form '1..5,9..10,7..8'*** ", rgb=Color.INFO))
        sys.exit(-2)

    formula = args.formula
    if formula is None:
        print(colorize(f"*** ERROR: Please provide a valid formula***", rgb=Color.ERROR))
        print(colorize(f"*** INFO: Formula can be provided on the form 'a+b~c*d'*** ", rgb=Color.INFO))
        print(colorize(f"*** INFO: for a plot of a+b in function of c*d'*** ", rgb=Color.INFO))
        sys.exit(-3)

    date_unit_str = args.date_unit
    if date_unit_str is None:
        print(colorize(f"*** ERROR: Please provide a unit for date values***", rgb=Color.ERROR))
        sys.exit(-4)
    
    date_unit = DateUnit.MILLISECOND
    if date_unit_str == 's':
        date_unit = DateUnit.SECOND

    id_interval = parse_interval_union(id_interval)

    y_expression, x_expression, valid_formula = split_formula(formula)

    variable_names, function_names = collect_names(formula)

    if not valid_formula:
        sys.exit(-3)

    variables_values = request_from_database(id_interval, list(variable_names), date_unit)

    x_values = solve_expression(x_expression, variables_values)
    y_values = solve_expression(y_expression, variables_values)

    display_line(x_values, y_values)
    
    sys.exit(0)