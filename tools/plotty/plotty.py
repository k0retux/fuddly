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
from matplotlib.dates import DateFormatter, date2num
import matplotlib.pyplot as plt


ARG_INVALID_FMDBK = -1
ARG_INVALID_ID = -2
ARG_INVALID_FORMULA = -3
ARG_INVALID_VAR_NAMES = -5
ARG_INVALID_POI = -6

UNION_DELIMITER = ','
INTERVAL_OPERATOR = '..'
STEP_OPERATOR = '|'

class GridMatch(Enum):
    AUTO = 1
    POI = 2
    ALL = 3

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
rootdir = os.path.dirname(os.path.dirname(currentdir))
sys.path.insert(0, rootdir)

from framework.database import Database
from libs.external_modules import *

def print_info(msg: str):
    print(colorize(f"*** INFO: {msg} *** ", rgb=Color.INFO))

def print_warning(msg: str):
    print(colorize(f"*** WARNING: {msg} *** ", rgb=Color.WARNING))

def print_error(msg: str):
    print(colorize(f"*** ERROR: {msg} *** ", rgb=Color.ERROR))


#region Argparse

parser = argparse.ArgumentParser(description='Arguments for Plotty')

group = parser.add_argument_group('Main parameters')

group.add_argument(
    '-ids',
    '--id-range',
    type=str, 
    help='The ID range to take into account should be: '
         'either <id_start>..<id_stop>[|<step>], '
         'or <id_start_1>..<id_stop_1>[|<step_1>], ..., <id_start_n>..<id_stop_n>[|<step_n>]',
    required=True
)

group.add_argument(
    '-df',
    '--date-format',
    type=str,
    default='%H:%M:%S.%f',
    help='Wanted date format, in a strftime format (1989 C standard). Default is %%H:%%M:%%S.%%f',
    required=False
)

group.add_argument(
    '-db',
    '--fmkdb',
    metavar='PATH',
    default=[],
    action='extend',
    nargs="+",
    help='Path to any fmkDB.db files. There can be many if using the --other_id_range option.'
         ' Default is fuddly/data/directory/fmkDB.db',
    required=False
)

group = parser.add_argument_group('Display Options')

group.add_argument(
    '-f', 
    '--formula', 
    default='SENT_DATE~ID',
    type=str, 
    help='The formula to plot, in the form "y ~ x"',
    required=False
)

group.add_argument(
    '-poi',
    '--points-of-interest',
    type=int,
    default=0,
    help='How many point of interest the plot should show. Default is none',
    required=False
)

group.add_argument(
    '-gm',
    '--grid-match',
    type=str,
    default='all',
    help="Should the plot grid specifically match some element. Possible options are 'all', "
         "'poi' and 'auto'. Default is 'all'",
    choices=['all', 'poi', 'auto'],
    required=False
)

group.add_argument(
    '-hp',
    '--hide-points',
    action='store_true',
    help='Should the graph display every point above the line, or just the line. Default is to display the points',
    required=False
)

group = parser.add_argument_group('Labels Configuration')

group.add_argument(
    '-l',
    '--labels',
    dest='annotations',
    action='extend',
    nargs='+',
    help='''
    Display the specified labels for each Data ID represented in the curve.
    ('t' for TYPE, 'g' for TARGET, 's' for SIZE, 'a' for ACK_DATE)
    ''',
    required=False
)

group.add_argument(
    '-al',
    '--async-labels',
    dest='async_annotations',
    action='extend',
    nargs='+',
    help='''
    Display the specified labels for each Async Data ID represented in the curve.
    ('i' for 'ID', 't' for TYPE, 'g' for TARGET, 's' for SIZE)
    ''',
    required=False
)

group = parser.add_argument_group('Multiple Curves Options')

group.add_argument(
    '-o',
    '--other-id-range',
    type=str,
    action='append',
    help='Other ranges of IDs to plot against the main one. All other options apply to it',
    required=False
)

group.add_argument(
    '-s',
    '--vertical-shift',
    type=float,
    default=1,
    help='When --other-id-range is used, specify the spacing between the curves. The shift is '
         'computed as the multiplication between the original curve height and this value',
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
    text_height = value.count('\n') + 1
    axes.annotate(
        f"{value}",
        xy=(x, y), xycoords='data',
        xytext=(-10, 20 * text_height), textcoords='offset pixels',
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
    
    if not args['hide_points']:
        for (x, y) in zip(x_data, y_data):
            add_point(axes, x, y, 'b')

    if args['annotations'] is not None:
        for i, (x, y) in enumerate(zip(x_data, y_data)):
            add_annotation(axes, x, y, annotations[i])

    if args['poi'] != 0:
        return add_points_of_interest(axes, x_data, y_data, args['poi'])
    
    return set()


def plot_async_data(
    axes: Axes, 
    x_data: list[float],
    y_data: list[float],
    annotations: list[str],
    args: dict[Any]
):
        
    for (x,y) in zip(x_data, y_data):
        axes.plot(x, y, 'g^')

    if args['async_annotations'] is not None:
        for i, (x, y) in enumerate(zip(x_data, y_data)):
            add_annotation(axes, x, y, annotations[i])


def set_grid(
    axes: Axes, 
    grid_match: GridMatch, 
    plotted_poi: set[tuple[float, float]],
    plotted_points: set[tuple[float, float]]
):
    
    if grid_match == GridMatch.AUTO:
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
        formatter = DateFormatter(args['date_format'])
        axes.xaxis.set_major_formatter(formatter)
        axes.tick_params(axis='x', which='major', labelrotation=30)
        
    if y_true_type is not None and y_true_type == datetime:
        formatter = DateFormatter(args['date_format'])
        axes.yaxis.set_major_formatter(formatter)
        axes.tick_params(axis='y', which='major', reset=True)


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


def convert_non_operable_types(variables_values: list[dict[str, Any]]):
    for instanciation in variables_values:
        for key, value in instanciation.items():
            if isinstance(value, datetime):
                instanciation[key] = date2num(value)


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
        return (None, None, [], [])

    fmkdb = Database(fmkdb_path)
    ok = fmkdb.start()
    if not ok:
        print_error(f"The database {fmkdb_path} is invalid!")
        sys.exit(ARG_INVALID_FMDBK)

    async_data_column_names = fmkdb.column_names_from('ASYNC_DATA')
    for c in column_names:
        if c not in async_data_column_names:
            compatible_async = False
            break
    else:
        compatible_async = True

    id_ranges_check_str = belongs_condition_sql_string("ID", int_ranges)
    async_id_ranges_check_str = id_ranges_check_str.replace("ID", "CURRENT_DATA_ID")

    requested_data_columns_str = ', '.join(column_names)
    data_statement = f"SELECT {requested_data_columns_str} FROM DATA " \
                     f"WHERE {id_ranges_check_str}"
    matching_data = fmkdb.execute_sql_statement(data_statement)

    matching_data_annotations = []
    if annotation_column_names is not None:
        requested_data_annotations_columns_str = ', '.join(annotation_column_names)
        data_annotation_statement = f"SELECT {requested_data_annotations_columns_str} FROM DATA " \
                         f"WHERE {id_ranges_check_str}"
        matching_data_annotations = fmkdb.execute_sql_statement(data_annotation_statement)


    matching_async_data_annotations = []
    matching_async_data = None
    if compatible_async:
        # async data 'CURRENT_DATA_ID' is considered to be their ID for plotting
        requested_async_data_columns_str = ', '.join(column_names).replace('ID', 'CURRENT_DATA_ID')
        async_data_statement = f"SELECT {requested_async_data_columns_str} FROM ASYNC_DATA " \
                               f"WHERE {async_id_ranges_check_str}"
        matching_async_data = fmkdb.execute_sql_statement(async_data_statement)

        if async_annotation_column_names is not None:
            requested_async_data_annotations_columns_str = ', '.join(async_annotation_column_names)
            async_data_annotation_statement = f"SELECT {requested_async_data_annotations_columns_str} FROM ASYNC_DATA " \
                                   f"WHERE {async_id_ranges_check_str}"
            matching_async_data_annotations = fmkdb.execute_sql_statement(async_data_annotation_statement)

    fmkdb.stop()

    if matching_data is None or matching_data == []:
        return (None, None, [], [])

    data = []
    for line in matching_data:
        if None in line:
            continue
        line_values = dict()
        for index, value in enumerate(line):
            line_values[column_names[index]] = value
        data.append(line_values)

    if matching_async_data is None:
        return (data, matching_data_annotations, [], [])

    async_data = []
    for line in matching_async_data:
        if None in line:
            continue
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
    if not fmkdb:
        fmkdb = [Database.get_default_db_path()]
    for db in fmkdb:
        if db is not None and not os.path.isfile(os.path.expanduser(db)):
            print_error(f"'{db}' does not exist")
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

    poi = args.points_of_interest
    if poi < 0:
        print_error("Please provide a positive or zero number of point of interest")
        sys.exit(ARG_INVALID_POI)
    result['poi'] = poi

    grid_match_str = args.grid_match
    if grid_match_str is None or grid_match_str == 'all':
        grid_match = GridMatch.ALL
    elif grid_match_str == 'auto':
        grid_match = GridMatch.AUTO
    elif grid_match_str == 'poi':
        grid_match = GridMatch.POI
        if poi == 0:
            parser.error("--points-of-interest must be set to use --grid-match 'poi' option")
    else:
        parser.error(f"Unknown Grid Match value '{grid_match_str}'")

    result['grid_match'] = grid_match

    result['hide_points'] = args.hide_points

    if args.annotations is not None:
        labels = []
        for l in args.annotations:
            labels.append(
                {'t': 'TYPE',
                 'g': 'TARGET',
                 's': 'SIZE',
                 'a': 'ACK_DATE'}.get(l, None)
            )
        if None in labels:
            print_warning('Unknown labels have been discarded')
        labels = list(filter(lambda x: x is not None, labels))
        result['annotations'] = labels
    else:
        result['annotations'] = None

    if args.async_annotations is not None:
        async_labels = []
        for l in args.async_annotations:
            async_labels.append(
                {'i': 'ID',
                 't': 'TYPE',
                 'g': 'TARGET',
                 's': 'SIZE'}.get(l, None)
            )
        if None in async_labels:
            print_warning('Unknown async labels have been discarded')
        async_labels = list(filter(lambda x: x is not None, async_labels))
        result['async_annotations'] = async_labels
    else:
        result['async_annotations'] = None

    result['other_id_range'] = args.other_id_range
    max_fmkdb = len(args.other_id_range) if args.other_id_range else 0
    if len(result['fmkdb']) not in {1, max_fmkdb + 1}:
        parser.error('Number of given fmkdbs must be one, or match the total number of given ranges')

    result['vertical_shift'] = args.vertical_shift
    
    result['date_format'] = args.date_format

    return result


def plot_formula(
    axes: Axes, 
    formula: str, 
    id_range: list[range], 
    align_to: Optional[tuple[Any, Any]],
    index: int,
    args: dict[Any]
) -> Optional[tuple[str, str, Optional[type], Optional[type], set[tuple[float,float]], set[tuple[float,float]]]]:

    y_expression, x_expression, valid_formula = split_formula(formula)

    x_variable_names, x_function_names = collect_names(x_expression)
    y_variable_names, y_function_names = collect_names(y_expression)

    if not valid_formula:
        print_error("Given formula or variables names are invalid")
        return None

    db = args['fmkdb'][index % len(args['fmkdb'])]
    variable_names = x_variable_names.union(y_variable_names)
    variables_values, annotations_values, async_variables_values, async_annotations_values = \
        request_from_database(db, id_range, list(variable_names), args['annotations'], args['async_annotations'])
    if variables_values is None:
        print_error(f"Cannot gather database information for range '{id_range}', skipping it")
        return None

    variables_true_types = {}
    if not variables_values:
        print_error(f"No valid values to display given the formula")
        return None

    for variable, value in variables_values[0].items():
        variables_true_types[variable] = type(value)
    convert_non_operable_types(variables_values)
    convert_non_operable_types(async_variables_values)

    x_values = solve_expression(x_expression, variables_values)
    y_values = solve_expression(y_expression, variables_values)
    annotations = []
    if annotations_values is not None:
        for annotation_values in annotations_values:
            annotation_str = '\n'.join([str(value) for value in annotation_values])
            annotations.append(annotation_str)

    x_async_values = solve_expression(x_expression, async_variables_values)
    y_async_values = solve_expression(y_expression, async_variables_values)
    async_annotations = []
    for async_annotation_values in async_annotations_values:
        annotation_str = '\n'.join([str(value) for value in async_annotation_values])
        async_annotations.append(annotation_str)
    
    if align_to is not None:
        sorted_points = sorted(zip(x_values, y_values), key=lambda p: p[0])
        first = sorted_points[0]
        last = sorted_points[-1]
        curve_height = abs(last[1] - first[1])
        shift_x = align_to[0] - first[0]
        shift_y = align_to[1] - first[1] + index * curve_height * args['vertical_shift']
        x_values = list(map(lambda x: x + shift_x, x_values))
        y_values = list(map(lambda y: y + shift_y, y_values)) 
        x_async_values = list(map(lambda x: x + shift_x, x_async_values))
        y_async_values = list(map(lambda y: y + shift_y, y_async_values)) 

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
    plot_result = plot_formula(axes, args['formula'], id_range, None, 0, args)
    if plot_result is None:
        sys.exit(ARG_INVALID_VAR_NAMES)
    
    x_expression, y_expression, x_conversion_type, y_conversion_type, plotted_poi, plotted_points = plot_result
    origin = sorted(list(plotted_points), key=lambda p: p[0])[0]
    all_plotted_poi = all_plotted_poi.union(plotted_poi)
    all_plotted_points = all_plotted_points.union(plotted_points)

    if args['other_id_range'] is not None:
        for index, other_id_range in enumerate(args['other_id_range']):
            
            id_range = parse_int_range_union(other_id_range)
            plot_result = plot_formula(axes, args['formula'], id_range, origin, index+1, args)
            if plot_result is None:
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
    