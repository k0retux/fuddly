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
import traceback
import warnings

import numpy as np
import framework.knowledge as kn

assert sys.version_info >= (2, 7)

# Stable Residual (used when numeric instability can't be avoided)
_stable_residual = 1e-12

# Warnings text
_stable_warntext = ('Numerically unstable calculus suppressed ' +
                    '(obtained values may not be meaningful).')
_unrecov_failure = (
    'Unrecoverable failure during numerical instability ' + 'handling ' +
    '(likely to be caused by NaN values, see `framework.knowledge.error.state`).')

last_warning = None


class _state:
    inverse_suppress = True
    inverse_inf = True
    inverse_nan = True
    verbose = True
    quiet = False


state = _state()


def warn(text):
    global last_warning
    last_warning = text
    if state.quiet:
        return

    if not state.verbose:
        warnings.warn(text, RuntimeWarning)
        return

    try:
        last = ''
        infos = traceback.extract_stack()[-2][0:3]
        prefix = ''
        for infos in traceback.extract_stack():
            s = ('\n' + 'From file "{}", line {}, in {}:').format(*infos)
            if not s == last:
                prefix = prefix + s
                last = s

        prefix = '\n'
        stack = traceback.format_stack()[:-2]
        for line in stack:
            if '[Previous line repeated' in line:
                continue
            if not line.replace('\n', ' ') in prefix.replace('\n', ' '):
                prefix += line

        prefix += '    '
        try:
            prefix += ' ' * prefix.split('\n')[-2].strip().find('(')
        except BaseException:
            pass
        prefix += ' ^ '

        warnings.warn(prefix + text + '\n', RuntimeWarning, 2)
    except BaseException:
        warnings.warn(text, RuntimeWarning)


def _try_inverse_details(vector):
    _vector = None
    if issubclass(vector.dtype.type, np.float):
        _vector = vector.copy()
    else:
        _vector = vector.astype(np.float64)

    if state.inverse_nan:
        _nans = np.isnan(_vector)
        _vector[_nans] = _stable_residual

    _invalids = (np.abs(_vector) < _stable_residual)
    if any(_invalids):
        _vector[_invalids] = _stable_residual

    result = 1.0 / _vector
    if state.inverse_nan:
        result[_nans] = vector[_nans]

    if state.inverse_inf:
        result[_invalids] = (np.sign(_vector[_invalids]) * float('inf'))
    return result


def try_inverse(vector):
    assert isinstance(vector, np.ndarray)
    global last_warning, state
    last_warning = None

    try:
        with np.errstate(divide='raise', invalid='raise'):
            return 1.0 / vector
    except FloatingPointError as e:
        if not state.inverse_suppress:
            raise e
        else:
            warn(_stable_warntext)

        try:
            with np.errstate(divide='raise', invalid='raise'):
                return _try_inverse_details(vector)
        except FloatingPointError as f:
            warn(_unrecov_failure)

        raise e  # Unable to recover from/suppress numerical instability
    assert False  # Unreachable
