from tools.plotty.utils import print_error, try_parse_int, print_warning

from typing import Optional


UNION_DELIMITER = ','
INTERVAL_OPERATOR = '..'
STEP_OPERATOR = '|'


def parse_int_range(int_range: str) -> Optional[range]:

    step = 1
    bounds_and_step = int_range.split(STEP_OPERATOR)
    if len(bounds_and_step) == 2:
        parsed_step = try_parse_int(bounds_and_step[1])
        if parsed_step is None:
            print_error(f"Value '{parsed_step}' is not a valid integer")
            print_warning(
                f"Ignoring interval '{int_range}': invalid step '{bounds_and_step[1]}'"
            )
            return None
        step = parsed_step

    bounds = bounds_and_step[0].split(INTERVAL_OPERATOR)
    if len(bounds) == 1:
        value = try_parse_int(bounds[0])
        if value is None:
            print_error(f"Value '{value}' is not a valid integer")
            print_warning(
                f"Ignoring interval '{int_range}' : invalid integer '{bounds[0]}'"
            )
            return None
        return range(value, value+1)

    if len(bounds) == 2:
        lower_bound = try_parse_int(bounds[0])
        upper_bound = try_parse_int(bounds[1])
        if lower_bound is None:
            print_error(f"Value '{lower_bound}' is not a valid integer")
            print_warning(
                f"Ignoring interval '{int_range}' : invalid integer '{bounds[0]}'"
            )
            return None

        if upper_bound is None:
            print_error(f"Value '{upper_bound}' is not a valid integer")
            print_warning(
                f"Ignoring interval '{int_range}' : invalid integer '{bounds[1]}'"
            )
            return None

        if lower_bound >= upper_bound:
            print_warning(f"Ignoring interval '{int_range}'")
            return None

        return range(lower_bound, upper_bound, step)

    print_warning(f"Invalid interval found: '{int_range}'")
    return None


def parse_int_range_union(int_range_union: str) -> list[range]:
    result = []
    int_range_list = int_range_union.split(UNION_DELIMITER)
    for int_range in int_range_list:
        parsed_range = parse_int_range(int_range)
        if parsed_range is not None:
            result.append(parsed_range)
    return result
