
from framework.database import Database

from typing import Optional
from tools.plotty.globals import DBResult

from tools.plotty.utils import print_error


class CachedDatabaseTable:

    def __init__(
            self,
            name: str,
            column_names: list[str],
            values: DBResult
    ):
        self.name = name
        self.column_names = column_names
        self.values = values
        self.__column_names_lookup_table = \
            {column: i for i, column in enumerate(column_names)}

    def get(self, data_ids: list[range], data_ids_column_name: str, column_names: list[str]) -> DBResult:
        column_indexes = [self.__column_names_lookup_table[column] for column in column_names]
        id_column_index = self.__column_names_lookup_table[data_ids_column_name]
        filter_condition = lambda line: any(line[id_column_index] in interval for interval in data_ids)
        right_id_lines = list(filter(filter_condition, self.values))
        return [tuple(line[i] for i in column_indexes) for line in right_id_lines]


class PlottyDatabase(object):

    __cached_databases: dict[str, 'PlottyDatabase'] = {}


    def __new__(cls, path: str) -> 'PlottyDatabase':
        if path in cls.__cached_databases.keys():
            return cls.__cached_databases[path]

        new_instance = super(PlottyDatabase, cls).__new__(cls)
        new_instance.__cached = False
        return new_instance


    def __init__(self, path: str):
        """Given path is always considered to be valid"""
        if not self.__cached:
            self.path = path
            self.__database = Database(path)
            self.__cached_tables: dict[str, CachedDatabaseTable] = dict()

            self.__cached_databases[path] = self
            self.__cached = True


    def __database_request(
            self,
            table_name: str
    ) -> Optional[tuple[list[str], DBResult]]:
        start_ok = self.__database.start()
        if not start_ok:
            print_error(f"The database '{self.path}' could not start")
            return None

        column_names = Database.column_names_from(self.__database, table_name)

        database_answer = self.__database.execute_sql_statement(
            f"SELECT * FROM {table_name};",
        )
        if database_answer is None:
            return None

        self.__database.stop()

        return column_names, database_answer


    def __pull_table(self, table_name: str) -> bool:
        database_answer = self.__database_request(table_name)
        if database_answer is None:
            return False
        column_names, values = database_answer

        new_table = CachedDatabaseTable(table_name, column_names, values)
        self.__cached_tables[table_name] = new_table

        return True


    def has_columns(self, table_name: str, column_names: list[str]) -> bool:
        existing_columns = self.__database.column_names_from(table_name)
        return all(column in existing_columns for column in column_names)


    def request(
        self,
        table_name: str,
        data_ids: list[range],
        data_ids_column_name: str,
        column_names: list[str]
    ) -> Optional[DBResult]:

        if len(data_ids) == 0 or len(column_names) == 0:
            return None

        if table_name not in self.__cached_tables.keys():
            pull_ok = self.__pull_table(table_name)
            if not pull_ok:
                print_error(f"The table {table_name} could not be retrieved")
                return None

        return self.__cached_tables[table_name].get(data_ids, data_ids_column_name, column_names)

