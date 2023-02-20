#!/usr/bin/env python

import argparse
from datetime import datetime
import inspect
import os
import sys
from typing import Any, Optional
from enum import Enum

import cexprtk
from matplotlib.axes import Axes
from matplotlib.figure import Figure
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

class GridMatch(Enum):
    DEFAULT = 1
    POI = 2
    ALL = 3

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
    '--id_range', 
    type=str, 
    help='The ID range to take into account x..y',
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
    help='How many point of interest the plot should show. Default is none',
    required=False
)

group.add_argument(
    '-gm',
    '--grid_match',
    type=str,
    help='Should the plot grid specifically match some element. Possible options are "all" and "poi". Default is an arbitrary grid',
    choices=['all', 'poi'],
    required=False
)

group.add_argument(
    '-pts',
    '--display_points',
    action='store_true',
    help='Should the graph display every point above the line, or just he line. Default is just the line',
    required=False
)

group.add_argument(
    '-a',
    '--annotations',
    action='append',
    default=['TYPE'],
    help='Which values to show above the points. Must be used with -pts. Default is TYPE',
    required=False
)

group.add_argument(
    '-async_a',
    '--async_annotations',
    action='append',
    default=['ID'],
    help='Which values to show above the aync points. Must be used with -pts. Default is ID',
    required=False
)

group.add_argument(
    '-o',
    '--other_id_range',
    action='append',
    help='Other ranges of IDs to plot against the main one. All other options apply to it',
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


def add_point(axes: Axes, x: float, y: float, color: str):
    axes.plot(x, y, 'o', color=color)


def add_annotation(axes: Axes, x: float, y: float, value: str):
    axes.annotate(
        f"{value}",
        xy=(x, y), xycoords='data',
        xytext=(-10, 20), textcoords='offset pixels',
        horizontalalignment='right', verticalalignment='top'
    )


def add_points_of_interest(
    axes: Axes, 
    x_data: list[float], 
    y_data: list[float], 
    points_of_interest: int
) -> set[tuple[float, float]]:

    points = sort_points_by_interest(x_data, y_data)
    plotted_points = set()

    for i in range(points_of_interest):
        if i >= len(points):
            break
        x, y = points[i]
        add_point(axes, x, y, 'red')
        add_annotation(axes, x, y)
        plotted_points.add((x,y))

    return plotted_points


def plot_line(
    axes: Axes,
    x_data: list[float],
    y_data: list[float],
    annotations: list[str],
    args: dict[Any]
) -> set[tuple[float, float]]:

    axes.plot(x_data, y_data, '-')
    
    if args['display_points']:
        for (x, y) in zip(x_data, y_data):
            add_point(axes, x, y, 'b')

    if len(args['annotations']) != 0:
        for i, (x, y) in enumerate(zip(x_data, y_data)):
            add_annotation(axes, x, y, annotations[i])

    if args['poi'] == 0:
        return set()
    
    return add_points_of_interest(axes, x_data, y_data, args['poi'])


def plot_async_data(
    axes: Axes, 
    x_data: list[float],
    y_data: list[float],
    annotations: list[str],
    args: dict[Any]
):
    for (x,y) in zip(x_data, y_data):
        axes.plot(x, y, 'g^')

    if args['async_annotations']:
        for i, (x, y) in enumerate(zip(x_data, y_data)):
            add_annotation(axes, x, y, annotations[i])


def set_grid(
    axes: Axes, 
    grid_match: GridMatch, 
    plotted_poi: set[tuple[float, float]],
    plotted_points: set[tuple[float, float]]
):
    
    if grid_match == GridMatch.DEFAULT:
        return 
    
    if grid_match == GridMatch.POI:
        new_xticks, new_yticks = zip(*plotted_poi)
        axes.xaxis.set_ticks(new_xticks)
        axes.yaxis.set_ticks(new_yticks)
        return

    if grid_match == GridMatch.ALL:
        new_xticks, new_yticks = zip(*plotted_points)
        axes.xaxis.set_ticks(new_xticks)
        axes.yaxis.set_ticks(new_yticks)


def post_process_plot(
    figure: Figure, 
    x_true_type: Optional[type], 
    y_true_type: Optional[type], 
    plotted_poi: set[tuple[float, float]],
    plotted_points: set[tuple[float, float]],
    args: dict[Any]
):
    axes: Axes = figure.get_axes()[0]

    set_grid(axes, args['grid_match'], plotted_poi, plotted_points)

    if x_true_type is not None and x_true_type == datetime:
        formatter = mticker.FuncFormatter(lambda value, _: float_to_datetime(value, args['date_unit']))
        axes.xaxis.set_major_formatter(formatter)
        axes.tick_params(axis='x', which='major', labelrotation=30)
        
    if y_true_type is not None and y_true_type == datetime:
        axes.tick_params(axis='y', which='major', reset=True)
        formatter = mticker.FuncFormatter(lambda value, _: float_to_datetime(value, args['date_unit']))
        axes.yaxis.set_major_formatter(formatter)


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
    if date_unit == DateUnit.MILLISECOND:
        res *= 1000
    return res

def float_to_datetime(timestamp: float, date_unit: DateUnit):
    if date_unit == DateUnit.MILLISECOND:
        timestamp /= 1000
    return datetime.fromtimestamp(timestamp)


def convert_non_operable_types(variables_values: list[dict[str, Any]], date_unit: DateUnit):
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
    column_names: list[str],
    annotation_column_names: list[str],
    async_annotation_column_names: list[str],
) -> tuple[Optional[list[dict[str, Any]]], Optional[list[dict[str,Any]]], list[dict[str, Any]], list[dict[str, Any]]]:
    
    if len(column_names) == 0:
        return (None, [])

    fmkdb = Database(fmkdb_path)
    ok = fmkdb.start()
    if not ok:
        print_error(f"The database {fmkdb_path} is invalid!")
        sys.exit(ARG_INVALID_FMDBK)

    id_ranges_check_str = belongs_condition_sql_string("ID", int_ranges)
    async_id_ranges_check_str = id_ranges_check_str.replace("ID", "CURRENT_DATA_ID")

    requested_data_columns_str = ', '.join(column_names)
    data_statement = f"SELECT {requested_data_columns_str} FROM DATA " \
                     f"WHERE {id_ranges_check_str}"

    requested_data_annotations_columns_str = ', '.join(annotation_column_names)
    data_annotation_statement = f"SELECT {requested_data_annotations_columns_str} FROM DATA " \
                     f"WHERE {id_ranges_check_str}"

    # async data 'CURRENT_DATA_ID' is considered to be their ID for plotting
    requested_async_data_columns_str = ', '.join(column_names).replace('ID', 'CURRENT_DATA_ID')
    async_data_statement = f"SELECT {requested_async_data_columns_str} FROM ASYNC_DATA " \
                           f"WHERE {async_id_ranges_check_str}"

    requested_async_data_annotations_columns_str = ', '.join(async_annotation_column_names)
    async_data_annotation_statement = f"SELECT {requested_async_data_annotations_columns_str} FROM ASYNC_DATA " \
                           f"WHERE {async_id_ranges_check_str}"

    matching_data = fmkdb.execute_sql_statement(data_statement)
    matching_data_annotations = fmkdb.execute_sql_statement(data_annotation_statement)
    matching_async_data = fmkdb.execute_sql_statement(async_data_statement)
    matching_async_data_annotations = fmkdb.execute_sql_statement(async_data_annotation_statement)

    fmkdb.stop()

    if matching_data is None or matching_data == []:
        return (None, None)

    data = []
    for line in matching_data:
        line_values = dict()
        for index, value in enumerate(line):
            line_values[column_names[index]] = value
        data.append(line_values)

    if matching_async_data is None:
        return (data, [])

    async_data = []
    for line in matching_async_data:
        line_values = dict()
        for index, value in enumerate(line):
            # CURRENT_DATA_ID is matched to ID variable name
            line_values[column_names[index]] = value
        async_data.append(line_values)

    return (data, matching_data_annotations, async_data, matching_async_data_annotations)


def parse_arguments() -> dict[Any]:
    result = dict()

    args = parser.parse_args()

    fmkdb = args.fmkdb
    if fmkdb is not None and not os.path.isfile(fmkdb):
        print_error(f"'{fmkdb}' does not exist")
        sys.exit(ARG_INVALID_FMDBK)
    result['fmkdb'] = fmkdb

    id_range = args.id_range
    if id_range is None:
        print_error("Please provide a valid ID interval")
        print_info("ID interval can be provided in the form '1..5,9..10,7..8'")
        sys.exit(ARG_INVALID_ID)
    result['id_range'] = id_range

    formula = args.formula
    if formula is None:
        print_error("Please provide a valid formula")
        print_info("Formula can be provided on the form 'a+b~c*d'")
        print_info("for a plot of a+b in function of c*d'")
        sys.exit(ARG_INVALID_FORMULA)
    result['formula'] = formula

    date_unit_str = args.date_unit
    if date_unit_str is None:
        print_error("Please provide a unit for date values")
        sys.exit(ARG_INVALID_DATE_UNIT)
    date_unit = DateUnit.MILLISECOND
    if date_unit_str == 's':
        date_unit = DateUnit.SECOND
    result['date_unit'] = date_unit

    poi = args.points_of_interest
    if poi < 0:
        print_error("Please provide a positive or zero number of point of interest")
        sys.exit(ARG_INVALID_POI)
    result['poi'] = poi

    grid_match_str = args.grid_match
    grid_match = GridMatch.ALL
    if grid_match_str is None:
        grid_match = GridMatch.DEFAULT
    elif grid_match_str == 'poi':
        grid_match = GridMatch.POI
        if poi == 0:
            parser.error("--points_of_interest must be set to use --grid_match 'poi' option")
    result['grid_match'] = grid_match

    display_points = args.display_points
    annotations = args.annotations
    if len(annotations) != 0 and not display_points:
        parser.error("--points option is required for --annotations option")
    async_annotations = args.async_annotations
    if len(async_annotations) != 0 and not display_points:
        parser.error("--points option is required for --async_annotations option")
    result['display_points'] = display_points
    result['annotations'] = annotations
    result['async_annotations'] = async_annotations

    result['other_id_range'] = args.other_id_range

    return result


def plot_formula(
    axes: Axes, 
    formula: str, 
    id_range: list[range], 
    args: dict[Any]
) -> Optional[tuple[str, str, Optional[type], Optional[type], set[tuple[float,float]], list[tuple[float,float]]]]:

    y_expression, x_expression, valid_formula = split_formula(formula)

    x_variable_names, x_function_names = collect_names(x_expression)
    y_variable_names, y_function_names = collect_names(y_expression)

    if not valid_formula:
        sys.exit(ARG_INVALID_FORMULA)

    variable_names = x_variable_names.union(y_variable_names)
    variables_values, annotations_values, async_variables_values, async_annotations_values = \
        request_from_database(args['fmkdb'], id_range, list(variable_names), args['annotations'], args['async_annotations'])
    if variables_values is None:
        return None

    variables_true_types = {}
    for variable, value in variables_values[0].items():
        variables_true_types[variable] = type(value)
    convert_non_operable_types(variables_values, args['date_unit'])
    convert_non_operable_types(async_variables_values, args['date_unit'])

    x_values = solve_expression(x_expression, variables_values)
    y_values = solve_expression(y_expression, variables_values)
    annotations = []
    for annotation_values in annotations_values:
        annotation_str = f"{', '.join([str(value) for value in annotation_values])}"
        annotations.append(annotation_str)

    x_async_values = solve_expression(x_expression, async_variables_values)
    y_async_values = solve_expression(y_expression, async_variables_values)
    async_annotations = []
    for async_annotation_values in async_annotations_values:
        annotation_str = f"{', '.join([str(value) for value in async_annotation_values])}"
        async_annotations.append(annotation_str)

    plotted_poi = plot_line(axes, x_values, y_values, annotations, args)
    plot_async_data(axes, x_async_values, y_async_values, async_annotations, args)

    x_conversion_type = None
    if len(x_variable_names) == 1:
        elmt = next(iter(x_variable_names))
        x_conversion_type = variables_true_types[elmt]
    y_conversion_type = None
    if len(y_variable_names) == 1:
        elmt = next(iter(y_variable_names))
        y_conversion_type = variables_true_types[elmt]

    all_plotted_points = set(zip(x_values, y_values)).union(set(zip(x_async_values, y_async_values)))

    return x_expression, y_expression, x_conversion_type, y_conversion_type, plotted_poi, all_plotted_points


def main():
    args = parse_arguments()
    
    figure = plt.figure()
    axes: Axes = figure.add_subplot(111)

    all_plotted_poi: set[tuple[float,float]] = set()
    all_plotted_points: set[tuple[float,float]] = set()
            
    id_range = parse_int_range_union(args['id_range'])
    plot_result = plot_formula(axes, args['formula'], id_range, args)
    if plot_result is None:
        print_error("Given formula or variables names are invalid")
        sys.exit(ARG_INVALID_VAR_NAMES)
    
    x_expression, y_expression, x_conversion_type, y_conversion_type, plotted_poi, plotted_points = plot_result

    all_plotted_poi = all_plotted_poi.union(plotted_poi)
    all_plotted_points = all_plotted_points.union(plotted_points)

    if args['other_id_range'] is not None:
        for other_id_range in args['other_id_range']:
            id_range = parse_int_range_union(other_id_range)
            plot_result = plot_formula(axes, args['formula'], id_range, args)
            if plot_result is None:
                print_error(f"Cannot gather database information for range '{other_id_range}', skipping it")
                continue
            _, _, _, _, plotted_poi, plotted_points = plot_result
            all_plotted_poi = all_plotted_poi.union(plotted_poi)
            all_plotted_points = all_plotted_points.union(plotted_points)

    post_process_plot(figure, x_conversion_type, y_conversion_type, all_plotted_poi, all_plotted_points, args)

    axes.set_title(f"{args['formula']}")
    axes.set_xlabel(x_expression)
    axes.set_ylabel(y_expression)
    axes.grid()
    plt.show()
    
    sys.exit(0)


if __name__ == "__main__": 
    main()
    