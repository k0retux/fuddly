#!/usr/bin/env python

import os
import sys
import inspect


currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
rootdir = os.path.dirname(os.path.dirname(currentdir))
sys.path.insert(0, rootdir)

from typing import Optional

from tools.plotty.globals import PlottyGlobals, PlottyOptions

from tools.plotty.cli import arguments
from tools.plotty.plot.PlottyCurve import PlottyCurve
from tools.plotty.plot.PlottyPointCloud import PlottyPointCloud
from tools.plotty.PlottyDatabase import PlottyDatabase
from tools.plotty.plot.PlottyFigure import PlottyFigure
from tools.plotty.plot.PlottyFigureArea import PlottyFigureArea
from tools.plotty.plot.PlottyPoint import PlottyPoint
from tools.plotty.utils import print_error, print_warning

x_type = None
y_type = None

def get_points(
        database: PlottyDatabase,
        table_name: str,
        data_ids: list[range],
        ids_column_name: str,
        column_names: str,
        annotation_column_names: list[str],
        is_typing_reference: bool
) -> Optional[list[PlottyPoint]]:

    data = database.request(
        table_name,
        data_ids,
        ids_column_name,
        column_names
    )

    if is_typing_reference:
        global x_type
        if len(PlottyOptions.formula.x_expression.variable_names) == 1:
            column_name = tuple(PlottyOptions.formula.x_expression.variable_names)[0]
            column_index = column_names.index(column_name)
            x_type = type(data[0][column_index])
        global y_type
        y_type = None
        if len(PlottyOptions.formula.y_expression.variable_names) == 1:
            column_name = tuple(PlottyOptions.formula.y_expression.variable_names)[0]
            column_index = column_names.index(column_name)
            y_type = type(data[0][column_index])

    if data is None:
        return None
    
    points_coordinates = []
    for entry in data:
        instanciation = \
        {
            (column_names[i] if column_names[i] != PlottyGlobals.async_data_id_column_name else PlottyGlobals.data_id_column_name)
            : entry[i] for i in range(len(column_names))
        }
        points_coordinates.append(PlottyOptions.formula.evaluate(instanciation))

    annotations = None
    if annotation_column_names is not None:
        all_annotations = database.request(
            table_name,
            data_ids,
            ids_column_name,
            annotation_column_names
        )
        annotations = []
        for raw_annotation in all_annotations:
            annotations.append('\n'.join([str(value) for value in raw_annotation]))
    
    points = []
    for i, coord in enumerate(points_coordinates):
        point = PlottyPoint(
            coord,
            PlottyGlobals.main_color,
            PlottyGlobals.main_marker,
            annotations[i] if annotations is not None else None
        )
        points.append(point)

    return points



def create_figure_area(
        database: PlottyDatabase,
        data_ids: list[range],
        area_index: int,
        is_typing_reference: bool
) -> tuple[PlottyFigureArea, PlottyFigureArea]:
    
    column_names = PlottyOptions.formula.variable_names.copy()
    data_points = get_points(
        database, 
        PlottyGlobals.data_table_name, 
        data_ids, 
        PlottyGlobals.data_id_column_name,
        column_names,
        PlottyOptions.annotations,
        is_typing_reference
    )
    
    if data_points is None:
        print_error('Given formula contains unknown variable names')
        sys.exit(PlottyGlobals.ERR_INVALID_VAR_NAMES)

    data_geometry = PlottyCurve(data_points)
    area = PlottyFigureArea(data_geometry, area_index)

    compatible_async = database.has_columns(
        PlottyGlobals.async_data_table_name, 
        PlottyOptions.formula.variable_names
    )

    if compatible_async:
        for i in range(len(column_names)):
            if column_names[i] == PlottyGlobals.data_id_column_name:
                column_names[i] = PlottyGlobals.async_data_id_column_name

        async_data_points = get_points(
            database,
            PlottyGlobals.async_data_table_name,
            data_ids,
            PlottyGlobals.async_data_id_column_name,
            column_names,
            PlottyOptions.async_annotations,
            False
        )

        for point in async_data_points:
            point.color = PlottyGlobals.async_color
            point.marker = PlottyGlobals.async_marker

        async_data_geometry = PlottyPointCloud(async_data_points)
        area.add_geometry(async_data_geometry)
    else:
        print_warning(
            'Given formula does not allow to display ASYNC_DATA information'
        )

    return area


def main():

    main_area = create_figure_area(
        PlottyOptions.fmkdb[0],
        PlottyOptions.data_ids,
        0,
        True
    )
    figure = PlottyFigure(main_area)
    figure.x_type = x_type
    figure.y_type = y_type

    for i, data_ids in enumerate(PlottyOptions.other_data_ids):
        area = create_figure_area(
            PlottyOptions.fmkdb[i % len(PlottyOptions.fmkdb)],
            data_ids,
            i+1,
            False
        )
        figure.add_area(area)

    figure.plot_areas()
    figure.show()

    sys.exit(PlottyGlobals.EXIT_SUCCESS)


if __name__ == "__main__":
    arguments.setup_parser()
    arguments.parse_arguments()
    main()
