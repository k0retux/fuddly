import argparse
# This wildcard import makes this module contains everything from the original
# argpars making it a drop-in replacement
from argparse import *
import os


def contextualize(obj):

    def ctx_manager_enter(self):
        return self

    def ctx_manager_exit(self, ex_type, ex_value, ex_traceback):
        pass

    obj.__enter__ = ctx_manager_enter
    obj.__exit__ = ctx_manager_exit


# Hack to make argparse work in "with" context
# This is only syntactic sugar, the underlying behavior does not change
contextualize(argparse._MutuallyExclusiveGroup)
contextualize(argparse._ArgumentGroup)
contextualize(argparse.ArgumentParser)


# Taken from https://mail.python.org/pipermail/stdlib-sig/2015-July/000990.html
# Replaced string interpolation with f-strings and syntax tweak
class PathType(object):
    def __init__(self, exists=True, type='file'):
        '''exists:
                True: a path that does exist
                False: a path that does not exist, in a valid parent directory
                None: don't care
           type: file, dir, symlink, None, or a function returning True for valid paths
                None: don't care
        '''

        assert exists in (True, False, None)
        assert type in ('file', 'dir', 'symlink', None) or hasattr(type, '__call__')

        self._exists = exists
        self._type = type

    def __call__(self, string):
        e = os.path.exists(string)
        if self._exists is True:
            if not e:
                raise ArgumentTypeError(f"path does not exist: '{string}'")
            if self._type is None:
                pass
            elif self._type == 'file':
                if not os.path.isfile(string):
                    raise ArgumentTypeError(f"path is not a file: '{string}'")
            elif self._type == 'symlink':
                if not os.path.islink(string):
                    raise ArgumentTypeError(f"path is not a symlink: '{string}'")
            elif self._type == 'dir':
                if not os.path.isdir(string):
                    raise ArgumentTypeError(f"path is not a directory: '{string}'")
            elif not self._type(string):
                raise ArgumentTypeError(f"path not valid: '{string}'")
        else:
            if self._exists is False and e:
                raise ArgumentTypeError(f"path exists: '{string}'")

            p = os.path.dirname(os.path.normpath(string)) or '.'
            if not os.path.isdir(p):
                raise ArgumentTypeError(f"parent path is not a directory: '{p}'")
            elif not os.path.exists(p):
                raise ArgumentTypeError(f"parent directory does not exist: '{p}'")

        return string
