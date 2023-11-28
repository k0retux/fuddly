from tools.fmkdb import colorize

from libs.external_modules import Color

from typing import Optional


def print_info(msg: str):
    print(colorize(f"*** INFO: {msg} *** ", rgb=Color.INFO))


def print_warning(msg: str):
    print(colorize(f"*** WARNING: {msg} *** ", rgb=Color.WARNING))


def print_error(msg: str):
    print(colorize(f"*** ERROR: {msg} *** ", rgb=Color.ERROR))


def try_parse_int(s: str) -> Optional[int]:
    try:
        int_value = int(s)
        return int_value
    except ValueError:
        return None

