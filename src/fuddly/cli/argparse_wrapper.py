import argparse
from argparse import *
import os

class ContextArgumentParser(argparse.ArgumentParser):
    def __enter__(self):
        return self
    def __exit__(self, ex_type, ex_value, ex_traceback):
        pass

def contextualize(obj):
    def ctx_manager_enter(self):
        return self
    def ctx_manager_exit(self, ex_type, ex_value, ex_traceback):
        pass
    obj.__enter__ = ctx_manager_enter
    obj.__exit__ = ctx_manager_exit

# Hack to make groups work in "with" context
contextualize(argparse._MutuallyExclusiveGroup)
contextualize(argparse._ArgumentGroup)
contextualize(argparse.ArgumentParser)

# Taken from https://mail.python.org/pipermail/stdlib-sig/2015-July/000990.html
# Replaced string interpolation with f-strings
class PathType(object):
    def __init__(self, exists=True, type='file', dash_ok=True):
        '''exists:
                True: a path that does exist
                False: a path that does not exist, in a valid parent directory
                None: don't care
           type: file, dir, symlink, None, or a function returning True for valid paths
                None: don't care
           dash_ok: whether to allow "-" as stdin/stdout'''

        assert exists in (True, False, None)
        assert type in ('file','dir','symlink',None) or hasattr(type,'__call__')

        self._exists = exists
        self._type = type
        self._dash_ok = dash_ok

    def __call__(self, string):
        if string=='-':
            # the special argument "-" means sys.std{in,out}
            if self._type == 'dir':
                raise ArgumentTypeError('standard input/output (-) not allowed as directory path')
            elif self._type == 'symlink':
                raise ArgumentTypeError('standard input/output (-) not allowed as symlink path')
            elif not self._dash_ok:
                raise ArgumentTypeError('standard input/output (-) not allowed')
        else:
            e = os.path.exists(string)
            if self._exists==True:
                if not e:
                    raise ArgumentTypeError(f"path does not exist: '{string}'")

                if self._type is None:
                    pass
                elif self._type=='file':
                    if not os.path.isfile(string):
                        raise ArgumentTypeError(f"path is not a file: '{string}'")
                elif self._type=='symlink':
                    if not os.path.symlink(string):
                        raise ArgumentTypeError(f"path is not a symlink: '{string}'")
                elif self._type=='dir':
                    if not os.path.isdir(string):
                        raise ArgumentTypeError(f"path is not a directory: '{string}'")
                elif not self._type(string):
                    raise ArgumentTypeError(f"path not valid: '{string}'")
            else:
                if self._exists==False and e:
                    raise ArgumentTypeError(f"path exists: '{string}'")

                p = os.path.dirname(os.path.normpath(string)) or '.'
                if not os.path.isdir(p):
                    raise ArgumentTypeError(f"parent path is not a directory: '{p}'")
                elif not os.path.exists(p):
                    raise ArgumentTypeError(f"parent directory does not exist: '{p}'")

        return string

