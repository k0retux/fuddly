# -*- coding: utf-8 -*-

##
# framework.knowledge
#
#  Copyright 2017 by Matthieu Daumas <matthieu@daumas.me> and other authors.
#
# This file is a part of fuddly, as part of the knowledge component.
#
#  Licensed under GNU General Public License 3.0 or later.
#  Some rights reserved. See COPYING, AUTHORS.
#
# @license GPL-3.0+ <http://spdx.org/licenses/GPL-3.0+>
##

from __future__ import (absolute_import, division, print_function,
                        unicode_literals, with_statement)

import sys


assert sys.version_info >= (2, 7)


def handle_unicode(_input):
    if sys.version_info < (3, ) and isinstance(_input, str):
        return unicode(_input)
    else:
        return _input


def is_string(_input):
    _input = handle_unicode(_input)
    if sys.version_info < (3, ):
        return isinstance(_input, unicode)
    else:
        return isinstance(_input, str)


def listify(target):
    if target is None:
        return []
    if isinstance(target, tuple):
        return list(target)
    if isinstance(target, list):
        return target
    return [target]


def to_str(target, strlify_class=None.__class__):
    if is_string(target):
        return str(target)
    elif isinstance(target, dict):
        return ('{' + ','.join([
            str(k) + ':' + str(v)
            for k, v in (sorted(target.items(), key=lambda x: x[0]))
        ]) + '}')
    elif isinstance(target, tuple):
        return '(' + ','.join([str(t) for t in target]) + ')'
    elif issubclass(target.__class__, strlify_class):
        return str(target)
    elif sys.version_info < (3, ) and isinstance(target, unicode):
        return str(target)

    try:
        return target.__name__
    except AttributeError:
        return target.__class__.__name__
