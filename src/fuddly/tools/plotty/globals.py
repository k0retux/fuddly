from typing import Any, TypeAlias
from enum import Enum


DBResult: TypeAlias = list[tuple[Any]]


class GridMatch(Enum):
    AUTO = 1
    POI = 2
    ALL = 3


class PlottyOptions:
    fmkdb: list['PlottyDatase']
    data_ids: list[range]
    formula: 'Formula'
    poi: int
    grid_match: GridMatch
    hide_points: bool
    annotations: list[str]
    async_annotations: list[str]
    other_data_ids: list[list[range]]
    vertical_shift: float
    date_format: str


class PlottyGlobals:
    EXIT_SUCCESS = 0
    ERR_INVALID_VAR_NAMES = -1
    ERR_INVALID_FMDBK = -2
    colors: list[str] = ['b', 'r', 'g']
    main_marker: str = 'o'
    poi_color: str = 'r'
    poi_marker: str = 'o'
    async_color: str = 'g'
    async_marker: str = '^'
    data_table_name: str = 'DATA'
    data_id_column_name: str = 'ID'
    async_data_table_name: str = 'ASYNC_DATA'
    async_data_id_column_name: str = 'CURRENT_DATA_ID'

