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

import inspect
import random
import sys
import traceback
import unittest
import warnings

import numpy as np
import framework.knowledge as kn
import framework.knowledge.error
import framework.knowledge.logic

assert sys.version_info >= (2, 7)

test_types = kn.logic.types
test_ops = [
    '__invert__', 'probability', 'alpha', 'beta', 'weight', '__iadd__',
    'trust', '__imul__', '__idiv__', '__iand__', '__ior__', 'c', 'true',
    'false', 'uncertain'
]


# test near-equality with a relative/absolute tolerance
def _similar(a, b):
    return np.allclose(
        a,
        b,
        rtol=kn.logic.eq_rtol,
        atol=kn.logic.eq_atol,
        equal_nan=kn.logic.eq_nan)


# TOFIX: restructure tests code in a unittest-friendly fashion
class test_logic(unittest.TestCase):

    # run tests
    def test_logic(self):

        # test without infinity-semantics (cause NaNs)
        kn.error.state.inverse_inf = False

        # test basic constructor
        for vtype in test_types:
            vtype(size=5)

        # test from-instance constructor
        for vtype in test_types:
            x = vtype(size=3)
            y = vtype(x)

            self.assertTrue(x.value is not y.value)
            for vx, vy in zip(x.value, y.value):
                self.assertTrue(_similar(vx, vy))
                self.assertTrue(vx is not vy)

        # test islogic
        for vtype in test_types:
            x = vtype(size=5)
            self.assertTrue(kn.logic.islogic(x))
            self.assertTrue(not kn.logic.islogic(x.value))

        # test by-name getters and setters of internal value
        for vtype in test_types:
            x = vtype(size=7)
            for i, name in enumerate(vtype.value_names):
                self.assertTrue(getattr(x, name) is x.value[i])

                n = np.ones(7)
                setattr(x, name, n)
                self.assertTrue(n is x.value[i])

        # test by-tuple constructor
        for vtype in test_types:
            n = [np.ones(4) for _ in range(0, len(vtype.value_names))]
            x = vtype(tuple(n))
            for a, b in zip(x.value, n):
                self.assertTrue(a is b)

        # test by-value constructor
        for vtype in test_types:
            n = [np.random.rand() for _ in range(0, len(vtype.value_names))]
            x = vtype(tuple(n))
            for a, b in zip(x.value, n):
                self.assertTrue(len(a) == 1)
                self.assertTrue(a[0] == b)

        # test back-forth cast consistency (« AtoB(BtoA(b)) == b »)
        for stype in test_types:
            x = stype.uniform(6)
            for dtype in test_types:
                n = x.cast_to(dtype)
                v = n.cast_to(stype)
                self.assertTrue(isinstance(v, stype) and isinstance(n, dtype))
                self.assertTrue((x == v) and (x.equals(n)))

        # test double-invert consistency
        for vtype in test_types:
            x = vtype.uniform(3)
            self.assertTrue((x == (~x).invert()) and (~x == ~(~x).invert()))

        # test getitem & setitem
        for vtype in test_types:
            x = vtype(vtype.true(size=5))

            x[2:4] = ~x[2:4]
            x[::2] = ~x[::2]

            self.assertTrue(x[0] == vtype(vtype.false()))
            self.assertTrue(x[1] == vtype(vtype.true()))
            self.assertTrue(x[2] == vtype(vtype.true()))
            self.assertTrue(x[3] == vtype(vtype.false()))
            self.assertTrue(x[4] == vtype(vtype.false()))

            y = vtype(vtype.false(size=5))
            x[1:3] = y[0:2]

            self.assertTrue(x == y)

        # test if « p(A) + p(!A) == 1 »
        for vtype in test_types:
            x = vtype.uniform(11)
            y = ~x
            self.assertTrue(_similar(x.p() + y.p(), np.ones_like(x.p())))

        # test if trust factor is linear uppon consensus
        for vtype in test_types:
            x = vtype.uniform(47)
            y = vtype.uniform(47)
            self.assertTrue(_similar(x.trust + y.trust, (x + y).trust))

        # test various properties of and & or
        for vtype in test_types:
            x = vtype.uniform(101)
            y = vtype.uniform(101)
            self.assertTrue(~(~x | ~y) == x & y)
            self.assertTrue(~(~x & ~y) == x | y)

            minxp = np.minimum(x.p(), (~x).p())
            maxxp = np.maximum(x.p(), (~x).p())
            self.assertTrue((minxp > (x & ~x).p()).all())
            self.assertTrue((maxxp < (x | ~x).p()).all())

    # test numerically unstable assertions
    def test_logic_unstable(self):

        # try until success, fails if no warning raised at the right time
        _success = False
        failures = []
        for j in range(0, 24):
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter('always')

                try:
                    _unstable_tests()
                    _success = True
                except AssertionError as e:
                    e.exc_info = sys.exc_info()
                    failures.append(e)

                    _warns = []
                    for i in range(0, len(w)):
                        _wi = None
                        if sys.version_info < (3, ):
                            _wi = str(w[i].message)
                        else:
                            _wi = str(w[i])

                        if kn.error._stable_warntext in _wi.replace(
                                '\n', ' '):
                            _warns.append(w[i])

                    if len(_warns) < 1:
                        traceback.print_exception(*e.exc_info)
                        self.fail('No warning raised when ' +
                                  'assertion failed: {}, {} '.format(
                                      str(w), e))
            if _success:
                break

        # raise an AssertionError if we fail to converge
        if not _success:
            for e in failures:
                traceback.print_exception(*e.exc_info)
            self.fail('Numerically unstable operations failed ' +
                      '{} times in a row'.format(j + 1))

    # test operators equivalence between representations
    def test_logic_operators(self):

        # (further details printed within)
        for op in test_ops:
            self.assertTrue(_check_op(op))


def _unstable_tests():
    # test basic discounting
    for vtype in test_types:
        x, y = kn.logic.uniform(599, 2, vtype)
        assert x * y.trust == x * y
        assert not x * y.trust == y * x
        assert not x * y == y * x

    # test left/right-distributivity of discounting upon consensus
    for vtype in test_types:
        x, y, z = kn.logic.uniform(607, 3, vtype)
        assert (x * z) + (y * z) == (x + y) * z
        assert (z * x) + (z * y) == z * (x + y)

    # test weak commutativity and associativity
    for vtype in test_types:
        x, y, z = kn.logic.uniform(601, 3, vtype)
        assert (x * y * z) == (x * z * y)
        assert not (x * y * z) == (y * x * z)
        assert x * (y * z) == (x * y) * z

    # test if scalar product « by n » == « x + x + … + x » (n times)
    for vtype in test_types:
        x = vtype.uniform(541)
        assert 2 * x == x + x
        assert x * 3 == x + x + x
        assert 2 * x * 2 == x + x + x + x

    # test various calculus upon product & trust
    for vtype in test_types:
        x, y, z = kn.logic.uniform(463, 3, vtype)
        assert x / 2 == (x * 2) / 4
        assert (x * y) / y == x
        assert (((x * 2) / y) / 2) * y == x
        assert (x * y * z * z) / (y * z) == x * z
        assert _similar(x.trust * 2, (x * 2).trust)
        assert _similar(x.trust**3, (x * x * x).trust)
        assert _similar(x.trust * y.trust, (x * y).trust)
        assert _similar((x.trust + y.trust) * z.trust, (x * z + y * z).trust)


def _get_op_from_name(vtype, op_name):
    op = getattr(vtype, op_name)
    if isinstance(op, property):
        return op.fget
    return op


def _evaluate_op_with_vtype(op_name, vtype, values):
    op = _get_op_from_name(vtype, op_name)
    _values = [vtype(value) for value in values]

    result = op(*_values)
    if isinstance(result, tuple) and isinstance(result[0], np.ndarray):
        result = vtype(result)
    return result, (op_name, vtype, values)


def _evaluate_op_forall(op_name, values):
    results = []
    reports = []
    for vtype in test_types:
        result, report = _evaluate_op_with_vtype(op_name, vtype, values)
        results.append(result)
        reports.append(report)
    return results, reports


def _check_op_forall(op_name, values):
    results = []
    reports = []
    for vtype in test_types:
        resu, repo = _evaluate_op_forall(op_name, [vtype(v) for v in values])
        results += resu
        reports += repo

    for j, result in enumerate(results):
        if isinstance(result, np.ndarray):
            checks = [_similar(result, other) for other in results]
        else:
            checks = [(result == other) for other in results]

        if isinstance(checks[0], np.ndarray):
            checks = [c.all() for c in checks]

        for i, c in enumerate(checks):
            error = None
            if not isinstance(c, (bool, np.bool_)):
                error = "Equality '==' doesn't return a proper boolean !"
            elif not c:
                error = 'Incoherent results !'

            if error is not None:
                expected = (_evaluate_op_with_vtype(*reports[j]), reports[j])
                obtained = (_evaluate_op_with_vtype(*reports[i]), reports[i])

                try:
                    obt = obtained[0][0]
                    exp = expected[0][0]
                    if exp.__class__ in test_types:
                        obt = obt.cast_to(exp.__class__).value
                        exp = exp.value

                        differ = [abs(o - e) for o, e in zip(obt, exp)]
                        rerror = [
                            kn.logic.eq_atol + kn.logic.eq_rtol * abs(e)
                            for e in exp
                        ]
                    else:
                        differ = abs(obt - exp)
                        rerror = kn.logic.eq_atol + kn.logic.eq_rtol * abs(
                            exp)

                except BaseException as e:
                    differ = 'Unavailable: {}'.format(e)
                    rerror = 'Unavailable: <see above exception>'

                raise AssertionError(
                    error + '\n\n >> Here is the failing test case:' +
                    '\n\t{}'.format(str(obtained)) +
                    '\n\n >> Here is the expected result:' +
                    '\n\t{}'.format(str(expected)) +
                    '\n\n >> Here is the error vs tolerance:' +
                    '\n\t{}'.format(differ) + '\n\t{}'.format(rerror) + '\n')
    return True


def _get_parameter_count(op):
    if sys.version_info < (3, ):
        spec = inspect.getargspec(op)
        _len = len(spec.args)
        if spec.defaults is not None:
            _len -= len(spec.defaults)
        return _len

    spec = inspect.signature(op).parameters
    args = [p for p in spec if spec[p].default is inspect._empty]
    args = [p for p in args if spec[p].kind not in {2, 4}]
    return len(args)


def _check_op(op_name):
    vtypes = list(test_types)
    random.shuffle(vtypes)

    width = random.randint(2, 10)
    for vtype in vtypes:
        op = _get_op_from_name(vtype, op_name)
        nargs = _get_parameter_count(op)
        args = kn.logic.uniform(width, nargs, vtype)
        assert _check_op_forall(op_name, args)

    return True


if __name__ == '__main__':
    unittest.main()
