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

import numpy as np
import framework.knowledge as kn
import framework.knowledge.error

assert sys.version_info >= (2, 7)

# Non-informative prior weight
ebsl_prior = 2  # (ensure uniform Beta-distribution when « apriori == 0.5 »)

# Minimal uncertainty considered during discounting
min_uncertainty = 1.0 / \
    33.  # defaulted at 33:1 to fix « inert_weight(2) == 64 »

# Belief required for full-trust during discounting
trust_threshold = 1.0 / 2.0  # defaulted at 2:1 for positive against negative

# Operator __eq__ constants
eq_rtol = 1e-5  # relative tolerance
eq_atol = 1e-8  # absolute tolerance
eq_nan = False  # is NaN equal to NaN ?


def islogic(item):
    try:
        return issubclass(item.__class__, _base)
    except AttributeError:
        return False


class _base(object):
    '''Base class for logic types

    '''
    aliases = (('__eq__', 'equals'), ('__iadd__', 'merge_with'), )
    properties = (('probability', 'p'), ('weight', 'w'), ('trust', 't'),
                  ('common_belief', 'c'), )
    bycopy_ops = (('invert', '__invert__'), ('__iadd__', '__add__'),
                  ('__imul__', '__mul__'), ('__imul__', '__rmul__'),
                  ('__idiv__', '__div__'), ('__idiv__', '__truediv__'),
                  ('__iand__', '__and__'), ('__ior__', '__or__'), )

    def __init__(self, other=None, size=None):
        if isinstance(other, tuple):
            if not len(other) == len(self.value_names):
                raise AssertionError('Expected a tuple of lenght {}'.format(
                    len(self.value_names)))

            s = None
            if isinstance(other[0], (float, int)):
                s = 1
            else:
                s = len(other[0])

            new_values = []
            for v in other:
                if isinstance(v, (float, int)):
                    v = np.array([
                        float(v),
                    ])

                if not isinstance(v, np.ndarray):
                    raise AssertionError(
                        'Expecting numpy.ndarray: {} in {}'.format(v, other))

                if not s == len(v):
                    raise AssertionError(
                        'Expecting uniform lenght: {}'.format(other))

                new_values.append(v)

            if size is not None:
                kn.error.warn('Size given but ignored')

            self.size = s
            self.value = tuple(new_values)
        elif other is not None:
            assert other.__class__ in types
            if size is not None:
                kn.error.warn('Size given but ignored')

            self.size = len(other)
            self.value = other.cast_to(self.__class__).value
        else:
            assert size is not None
            assert isinstance(size, int) and size > 0

            self.size = size
            self.reset()

    def __str__(self, crop_to=None):
        if crop_to is None:
            crop_to = len(self)

        values = []
        for a in self.value:
            s = ['{:0.4}'.format(float(v)) for v in a[:crop_to]]
            if len(s) != len(a):
                s.append('...')
            values.append('[' + ', '.join(s) + ']')
        s = '{}'.format(self.__class__.__name__)
        return s + '(' + ', '.join(values) + ', size={})'.format(len(self))

    def __repr__(self):
        return '{}@{}'.format(self.__str__(crop_to=1), hex(id(self)))

    @staticmethod
    def true(size=1, apriori=0.5, prior=None, mu=None):
        raise NotImplementedError

    @staticmethod
    def false(size=1, apriori=0.5, prior=None, mu=None):
        raise NotImplementedError

    @staticmethod
    def uncertain(size=1, apriori=0.5):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError

    @staticmethod
    def uniform(size, _min=0, _max=None, prior=None, mu=None):
        raise NotImplementedError

    @staticmethod
    def inert_weight(prior=None, mu=None):
        if prior is None:
            prior = ebsl_prior
        if mu is None:
            mu = min_uncertainty
        return prior * (1 - mu) / mu

    def cast_to(self, other):
        assert other in types

        if isinstance(self, other):
            return self.copy()

        return other(size=self.size)

    def copy(self):
        n = tuple([np.array(a, copy=True) for a in self.value])
        return self.__class__(n)

    def __len__(self):
        return self.size

    def __eq__(self, other, rtol=None, atol=None, equal_nan=None):
        assert other.__class__ in types
        if rtol is None:
            rtol = eq_rtol
        if atol is None:
            atol = eq_atol
        if equal_nan is None:
            equal_nan = eq_nan

        if not isinstance(other, self.__class__):
            other = other.cast_to(self.__class__)

        return all([
            np.allclose(a, b, rtol, atol, equal_nan)
            for a, b in zip(self.value, other.value)
        ])

    def invert(self):
        raise NotImplementedError

    @property
    def probability(self):
        raise NotImplementedError

    def alpha(self, prior=None):
        if prior is None:
            prior = ebsl_prior
        return self.cast_to(ebsl, prior=prior).alpha(prior=prior)

    def beta(self, prior=None):
        if prior is None:
            prior = ebsl_prior
        return self.cast_to(ebsl, prior=prior).beta(prior=prior)

    @property
    def weight(self, prior=None):
        raise NotImplementedError

    def __iadd__(self, other, prior=None):
        raise NotImplementedError

    @property
    def trust(self, prior=None, mu=None, tt=None):
        raise NotImplementedError

    def __imul__(self, other):
        if other.__class__ in types:
            return self.__imul__(other.trust)
        elif isinstance(other, (int, float)):
            return self.__imul__(np.ones_like(self.value[0]) * float(other))

        raise AssertionError('Expecting scalar, numpy.ndarray or *bsl')

    def __idiv__(self, other):
        _trust = None
        if other.__class__ in types:
            _trust = other.trust
        elif isinstance(other, (int, float)):
            _trust = np.ones_like(self.value[0]) * float(other)
        elif isinstance(other, np.ndarray):
            _trust = other
        else:
            raise AssertionError('Expecting scalar, numpy.ndarray' +
                                 ' or *bsl')

        return self.__imul__(kn.error.try_inverse(_trust))

    def set_value(self, new_value, _slice=slice(None)):
        if islogic(new_value):
            new_value = new_value.cast_to(self.__class__).value
        for idx, (l, r) in enumerate(zip(self.value, new_value)):
            if l is r:
                continue
            l[_slice] = r[:]

    def __setitem__(self, slice_or_index, value):
        _value = self.__class__(value).value
        self.set_value(_value, slice_or_index)

    def __getitem__(self, slice_or_index):
        _value = [v[slice_or_index] for v in self.value]
        return self.__class__(tuple(_value))

    def __iand__(self, other):
        raise NotImplementedError

    def __ior__(self, other):
        raise NotImplementedError


class obsl(_base):
    '''Opinion-Based Subjective Logic (as found in the litterature)

    '''
    value_names = ['belief', 'disbelief', 'uncertainty', 'apriori']

    @staticmethod
    def true(size=1, apriori=0.5, mu=None):
        if mu is None:
            mu = min_uncertainty

        _uncertain = obsl.uncertain(size=size, apriori=apriori)

        _belief, _disbelief, _uncertainty, _apriori = _uncertain
        _belief, _uncertainty = (_uncertainty - mu), (_belief + mu)

        return (_belief, _disbelief, _uncertainty, _apriori)

    @staticmethod
    def false(size=1, apriori=0.5, mu=None):
        if mu is None:
            mu = min_uncertainty

        _uncertain = obsl.uncertain(size=size, apriori=apriori)

        _belief, _disbelief, _uncertainty, _apriori = _uncertain
        _disbelief, _uncertainty = (_uncertainty - mu), (_disbelief + mu)

        return (_belief, _disbelief, _uncertainty, _apriori)

    @staticmethod
    def uncertain(size=1, apriori=0.5):
        _belief = np.zeros(size)
        _disbelief = np.zeros(size)
        _uncertainty = np.ones(size)
        _apriori = np.ones(size) * apriori

        return (_belief, _disbelief, _uncertainty, _apriori)

    def reset(self, apriori=0.5):
        self.value = self.uncertain(self.size, apriori=apriori)

    @staticmethod
    def uniform(size, _min=0, _max=None, prior=None, mu=None):
        if prior is None:
            prior = ebsl_prior
        if mu is None:
            mu = min_uncertainty

        if _max is None:
            _max = 1.0 - mu
        low, high = (1. - _max, 1. - _min)

        _uncertainty = np.random.uniform(low=low, high=high, size=size)
        snd = np.random.uniform(high=(1.0 - _uncertainty), size=size)
        trd = 1.0 - snd - _uncertainty

        snd, trd = np.random.permutation((snd, trd))

        _belief = snd
        _disbelief = trd
        _apriori = np.random.uniform(size=size)

        return obsl((_belief, _disbelief, _uncertainty, _apriori))

    def cast_to(self, other, prior=None):
        if prior is None:
            prior = ebsl_prior

        n = _base.cast_to(self, other)
        if isinstance(n, obsl):
            pass
        elif isinstance(n, tbsl):
            _truth = self.belief - self.disbelief
            _confidence = 1.0 - self.uncertainty
            _apriori = 2 * self.apriori - 1.0

            n.value = (_truth, _confidence, _apriori)
        elif isinstance(n, ebsl):
            _positive = self.w(prior) * self.belief
            _negative = self.w(prior) * self.disbelief

            n.value = (_positive, _negative, self.apriori)
        return n

    def invert(self):
        self.value = (self.disbelief, self.belief, self.uncertainty,
                      1.0 - self.apriori)
        return self

    @property
    def probability(self):
        return self.belief + self.apriori * self.uncertainty

    @property
    def weight(self, prior=None):
        if prior is None:
            prior = ebsl_prior

        norm = kn.error.try_inverse(self.uncertainty)
        return prior * norm

    def __iadd__(self, other, prior=None):
        if prior is None:
            prior = ebsl_prior

        assert other.__class__ in types
        if not isinstance(other, self.__class__):
            other = other.cast_to(self.__class__)

        norm = kn.error.try_inverse(
            0. +
            self.uncertainty +
            other.uncertainty -
            self.uncertainty *
            other.uncertainty)

        _belief = (
            self.belief * other.uncertainty + other.belief * self.uncertainty
        ) * norm
        _disbelief = (self.disbelief * other.uncertainty +
                      other.disbelief * self.uncertainty) * norm
        _uncertainty = 1 - _belief - _disbelief

        s_weight = self.w(prior) - prior
        o_weight = other.w(prior) - prior

        _apriori = None
        norm = kn.error.try_inverse(s_weight + o_weight)
        if kn.error.last_warning is None:
            _apriori = self.apriori * s_weight + other.apriori * o_weight
            _apriori *= norm
        else:
            _apriori = (self.apriori + other.apriori) / 2.

        self.value = (_belief, _disbelief, _uncertainty, _apriori)
        return self

    @property
    def trust(self, prior=None, mu=None, tt=None):
        if prior is None:
            prior = ebsl_prior
        if mu is None:
            mu = min_uncertainty
        if tt is None:
            tt = trust_threshold
        iw = self.inert_weight(prior, mu)

        scale = tt * mu
        scale = (scale - tt) / (scale - mu)
        scale = iw / scale

        brate = (self.belief * scale - self.disbelief) * self.w(prior)
        arate = (self.apriori - 1. / 2.) * (self.w(prior) - prior)

        result = (brate + arate) / iw
        return result

    @property
    def common_belief(self, prior=None):
        return self.belief

    def __imul__(self, other):
        if not isinstance(other, np.ndarray):
            return _base.__imul__(self, other)

        _belief = other * self.belief
        _disbelief = other * self.disbelief

        norm = kn.error.try_inverse(_belief + _disbelief + self.uncertainty)
        _belief *= norm
        _disbelief *= norm
        _uncertainty = self.uncertainty * norm

        self.value = (_belief, _disbelief, _uncertainty, self.apriori)
        return self

    def __iand__(self, other):
        assert other.__class__ in types
        if not isinstance(other, self.__class__):
            other = other.cast_to(self.__class__)

        _disbelief = (1. - self.disbelief) * (other.disbelief - 1.) + 1.
        _apriori = self.apriori * other.apriori

        norm = kn.error.try_inverse(1. - _apriori)
        spare_lrate = (1. - self.apriori) * norm
        spare_rrate = (1. - other.apriori) * norm

        _uncertainty = self.uncertainty * other.uncertainty
        _uncertainty += other.belief * self.uncertainty * spare_lrate
        _uncertainty += self.belief * other.uncertainty * spare_rrate

        _belief = 1. - _uncertainty - _disbelief
        self.value = (_belief, _disbelief, _uncertainty, _apriori)
        return self

    def __ior__(self, other):
        assert other.__class__ in types
        if not isinstance(other, self.__class__):
            other = other.cast_to(self.__class__)

        _belief = (1. - self.belief) * (other.belief - 1.) + 1.
        _apriori = (1. - self.apriori) * (other.apriori - 1.) + 1.

        norm = kn.error.try_inverse(_apriori)
        spare_lrate = self.apriori * norm
        spare_rrate = other.apriori * norm

        _uncertainty = self.uncertainty * other.uncertainty
        _uncertainty += other.disbelief * self.uncertainty * spare_lrate
        _uncertainty += self.disbelief * other.uncertainty * spare_rrate

        _disbelief = 1. - _uncertainty - _belief
        self.value = (_belief, _disbelief, _uncertainty, _apriori)
        return self


class tbsl(_base):
    '''Three-Value-Based Subjective Logic

    '''
    value_names = ['truth', 'confidence', 'apriori']

    @staticmethod
    def uniform(size, _min=0, _max=None, prior=None, mu=None):
        if prior is None:
            prior = ebsl_prior
        if mu is None:
            mu = min_uncertainty

        if _max is None:
            _max = 1.0 - mu

        _confi = np.random.uniform(low=_min, high=_max, size=size)
        _truth = np.random.uniform(low=-_confi, high=_confi, size=size)
        _apriori = np.random.uniform(low=-1.0, high=1.0, size=size)

        return tbsl((_truth, _confi, _apriori))

    @staticmethod
    def true(size=1, apriori=0, mu=None):
        if mu is None:
            mu = min_uncertainty

        _truth = np.ones(size) - mu
        _confidence = np.ones(size) * (1 - mu)
        _apriori = np.ones(size) * apriori

        return (_truth, _confidence, _apriori)

    @staticmethod
    def false(size=1, apriori=0, mu=None):
        if mu is None:
            mu = min_uncertainty

        _truth = -(np.ones(size) - mu)
        _confidence = np.ones(size) * (1 - mu)
        _apriori = np.ones(size) * apriori

        return (_truth, _confidence, _apriori)

    @staticmethod
    def uncertain(size=1, apriori=0):
        _truth = np.zeros(size)
        _confidence = np.zeros(size)
        _apriori = np.ones(size) * apriori

        return (_truth, _confidence, _apriori)

    def reset(self, apriori=0.0):
        self.value = self.uncertain(self.size, apriori=apriori)

    def cast_to(self, other, prior=None):
        if prior is None:
            prior = ebsl_prior

        n = _base.cast_to(self, other)
        if isinstance(n, tbsl):
            pass
        elif isinstance(n, ebsl):
            _positive = (1.0 + self.truth) * self.w(prior)
            _negative = (1.0 - self.truth) * self.w(prior)
            _apriori = 1.0 + self.apriori

            half = 1.0 / 2.0
            _apriori *= half
            _positive = (_positive - prior) * half
            _negative = (_negative - prior) * half

            n.value = (_positive, _negative, _apriori)
        elif isinstance(n, obsl):
            _belief = self.confidence + self.truth
            _disbelief = self.confidence - self.truth
            _uncertainty = 1.0 - self.confidence
            _apriori = 1.0 + self.apriori

            half = 1.0 / 2.0
            _belief *= half
            _apriori *= half
            _disbelief *= half

            n.value = (_belief, _disbelief, _uncertainty, _apriori)
        return n

    def invert(self):
        self.value = (-self.truth, self.confidence, -self.apriori)
        return self

    @property
    def probability(self):
        return (
            1.0 + self.truth + self.apriori - self.apriori * self.confidence
        ) / 2.0

    @property
    def weight(self, prior=None):
        if prior is None:
            prior = ebsl_prior

        norm = kn.error.try_inverse(1. - self.confidence)
        return prior * norm

    def __iadd__(self, other, prior=None):
        if prior is None:
            prior = ebsl_prior

        n = self.cast_to(ebsl)
        n += other

        self.value = n.cast_to(tbsl).value
        return self

    @property
    def trust(self, prior=None, mu=None, tt=None):
        if prior is None:
            prior = ebsl_prior
        if mu is None:
            mu = min_uncertainty
        if tt is None:
            tt = trust_threshold
        iw = self.inert_weight(prior, mu)

        scale = tt * mu
        scale = (scale - tt) / (scale - mu)
        scale = iw / scale

        brate = ((1. + self.truth) * scale + self.truth - 1.) * self.w(prior)
        arate = self.apriori * (self.w(prior) - prior) / 2.

        brate -= prior * (scale - 1.)
        brate /= 2.0

        result = (brate + arate) / iw
        return result

    @property
    def common_belief(self, prior=None):
        if prior is None:
            prior = ebsl_prior

        return (self.truth + self.confidence) / 2.0

    def __imul__(self, other):
        if not isinstance(other, np.ndarray):
            return _base.__imul__(self, other)

        _truth = self.truth * other
        _confidence = self.confidence * other

        norm = kn.error.try_inverse(1.0 + self.confidence * (other - 1))
        _truth *= norm
        _confidence *= norm

        self.value = (_truth, _confidence, self.apriori)
        return self

    def __iand__(self, other):
        assert other.__class__ in types
        if not isinstance(other, self.__class__):
            other = other.cast_to(self.__class__)
        _apriori = (1. + self.apriori) * (1. + other.apriori) / 2. - 1.

        norm = kn.error.try_inverse(1. - _apriori)
        spare_lrate = (1. - self.apriori) * norm
        spare_rrate = (1. - other.apriori) * norm

        sc = 1. - self.confidence
        oc = 1. - other.confidence

        _confidence = 1. - sc * oc
        _confidence -= (other.confidence + other.truth) * sc * spare_lrate / 2.
        _confidence -= (self.confidence + self.truth) * oc * spare_rrate / 2.

        _truth = self.truth + other.truth
        _truth += _confidence - self.confidence - other.confidence
        _truth += (sc + self.truth - 1.) * (oc + other.truth - 1.) / 2.

        self.value = (_truth, _confidence, _apriori)
        return self

    def __ior__(self, other):
        assert other.__class__ in types
        if not isinstance(other, self.__class__):
            other = other.cast_to(self.__class__)

        _apriori = (1. - self.apriori) * (other.apriori - 1.) / 2. + 1.

        norm = kn.error.try_inverse(1. + _apriori)
        spare_lrate = (1 + self.apriori) * norm
        spare_rrate = (1 + other.apriori) * norm

        sc = 1. - self.confidence
        oc = 1. - other.confidence

        _confidence = 1. - sc * oc
        _confidence -= (other.confidence - other.truth) * sc * spare_lrate / 2.
        _confidence -= (self.confidence - self.truth) * oc * spare_rrate / 2.

        _truth = self.truth + other.truth
        _truth -= _confidence - self.confidence - other.confidence
        _truth -= (self.truth - sc + 1.) * (other.truth - oc + 1.) / 2.

        self.value = (_truth, _confidence, _apriori)
        return self


class ebsl(_base):
    '''Evidence-Based Subjective Logic

    '''
    value_names = ['positive', 'negative', 'apriori']

    @staticmethod
    def true(size=1, apriori=0.5, prior=None, mu=None):
        if prior is None:
            prior = ebsl_prior
        if mu is None:
            mu = min_uncertainty

        _positive = np.ones(size) * _base.inert_weight(prior, mu)
        _negative = np.zeros(size)
        _apriori = np.ones(size) * apriori

        return (_positive, _negative, _apriori)

    @staticmethod
    def false(size=1, apriori=0.5, prior=None, mu=None):
        if prior is None:
            prior = ebsl_prior
        if mu is None:
            mu = min_uncertainty

        _positive = np.zeros(size)
        _negative = np.ones(size) * _base.inert_weight(prior, mu)
        _apriori = np.ones(size) * apriori

        return (_positive, _negative, _apriori)

    @staticmethod
    def uncertain(size=1, apriori=0.5):
        _positive = np.zeros(size)
        _negative = np.zeros(size)
        _apriori = np.ones(size) * apriori

        return (_positive, _negative, _apriori)

    def reset(self, apriori=0.5):
        self.value = self.uncertain(self.size, apriori=apriori)

    @staticmethod
    def uniform(size, _min=0, _max=None, prior=None, mu=None):
        if prior is None:
            prior = ebsl_prior

        if _max is None:
            _max = _base.inert_weight(prior, mu) / 2.0

        _positive = np.random.randint(_min, _max, size=size)
        _negative = np.random.randint(_min, _max, size=size)
        _apriori = np.random.uniform(size=size)

        return ebsl((_positive, _negative, _apriori))

    def cast_to(self, other, prior=None):
        if prior is None:
            prior = ebsl_prior

        n = _base.cast_to(self, other)
        if isinstance(n, ebsl):
            pass
        if isinstance(n, tbsl):
            norm = 1.0 / self.w(prior)
            _truth = (self.positive - self.negative) * norm
            _confidence = 1.0 - prior * norm
            _apriori = 2 * self.apriori - 1

            n.value = (_truth, _confidence, _apriori)
        elif isinstance(n, obsl):
            norm = 1.0 / self.w(prior)
            _belief = self.positive * norm
            _disbelief = self.negative * norm
            _uncertainty = prior * norm

            n.value = (_belief, _disbelief, _uncertainty, self.apriori)
        return n

    def invert(self):
        self.value = (self.negative, self.positive, 1.0 - self.apriori)
        return self

    @property
    def probability(self, prior=None):
        if prior is None:
            prior = ebsl_prior

        return (self.positive + self.apriori * prior) / self.w(prior)

    def alpha(self, prior=None):
        if prior is None:
            prior = ebsl_prior

        return self.positive + prior * self.apriori

    def beta(self, prior=None):
        if prior is None:
            prior = ebsl_prior

        return self.negative + prior * (1.0 - self.apriori)

    @property
    def weight(self, prior=None):
        if prior is None:
            prior = ebsl_prior

        return self.negative + self.positive + prior

    def __iadd__(self, other, prior=None):
        if prior is None:
            prior = ebsl_prior

        assert other.__class__ in types
        if not isinstance(other, self.__class__):
            other = other.cast_to(self.__class__)

        _positive = self.positive + other.positive
        _negative = self.negative + other.negative

        s_weight = self.w(prior) - prior
        o_weight = other.w(prior) - prior

        _apriori = None
        norm = kn.error.try_inverse(s_weight + o_weight)
        if kn.error.last_warning is None:
            _apriori = self.apriori * s_weight + other.apriori * o_weight
            _apriori *= norm
        else:
            _apriori = (self.apriori + other.apriori) / 2.

        self.value = (_positive, _negative, _apriori)
        return self

    @property
    def trust(self, prior=None, mu=None, tt=None):
        if prior is None:
            prior = ebsl_prior
        if mu is None:
            mu = min_uncertainty
        if tt is None:
            tt = trust_threshold
        iw = self.inert_weight(prior, mu)

        scale = tt * mu
        scale = (scale - tt) / (scale - mu)
        scale = iw / scale

        brate = self.positive * scale - self.negative
        arate = (self.apriori - 1. / 2.) * (self.w(prior) - prior)

        result = (brate + arate) / iw
        return result

    @property
    def common_belief(self, prior=None):
        if prior is None:
            prior = ebsl_prior

        return self.positive / self.w(prior)

    def __imul__(self, other):
        if not isinstance(other, np.ndarray):
            return _base.__imul__(self, other)

        _positive = other * self.positive
        _negative = other * self.negative

        self.value = (_positive, _negative, self.apriori)
        return self

    def __iand__(self, other, prior=None):
        if prior is None:
            prior = ebsl_prior

        n = self.cast_to(obsl, prior=prior)
        n &= other

        self.value = n.cast_to(ebsl, prior=prior).value
        return self

    def __ior__(self, other, prior=None):
        if prior is None:
            prior = ebsl_prior

        n = self.cast_to(obsl, prior=prior)
        n |= other

        self.value = n.cast_to(ebsl, prior=prior).value
        return self


def describe_likelihood(scalar):
    if isinstance(scalar, types):
        assert len(scalar) == 1
        scalar = scalar.probability[0]
    if isinstance(scalar, np.ndarray):
        assert len(scalar) == 1
        scalar = scalar[0]
    assert isinstance(scalar, (float, int))

    if False:
        pass
    elif scalar > 95. / 100.:
        return 'Absolutely'
    elif scalar > 85. / 100.:
        return 'Highly Likely'
    elif scalar > 75. / 100.:
        return 'Likely'
    elif scalar > 65. / 100.:
        return 'Somewhat Likely'
    elif scalar > 55. / 100.:
        return 'Better than even'
    elif scalar > 45. / 100.:
        return 'Chances about even'
    elif scalar > 35. / 100.:
        return 'Lesser than even'
    elif scalar > 25. / 100.:
        return 'Somewhat Unlikely'
    elif scalar > 15. / 100.:
        return 'Unlikely'
    elif scalar > 5. / 100.:
        return 'Highly Unlikely'
    else:
        return 'Absolutely Not'


def describe_uncertainty(scalar):
    if isinstance(scalar, types):
        assert len(scalar) == 1
        scalar = 1. - scalar.obsl.uncertainty[0]
    if isinstance(scalar, np.ndarray):
        assert len(scalar) == 1
        scalar = scalar[0]
    assert isinstance(scalar, (float, int))

    if False:
        pass
    elif scalar > 95. / 100.:
        return 'Completely Certain'
    elif scalar > 85. / 100.:
        return 'Almost Certain'
    elif scalar > 70. / 100.:
        return 'Somewhat Certain'
    elif scalar > 55. / 100.:
        return 'Somewhat Uncertain'
    elif scalar > 45. / 100.:
        return 'Uncertain'
    elif scalar > 35. / 100.:
        return 'Very Uncertain'
    elif scalar > 15. / 100.:
        return 'Highly Uncertain'
    elif scalar > 5. / 100.:
        return 'Almost Fully Uncertain'
    else:
        return 'Completely Uncertain'


def describe(_this):
    _begin = describe_likelihood(_this)
    _end = describe_uncertainty(_this)
    if 'Uncertain' in _end:
        return _begin + ", but it's " + _end
    return _begin + ", and it's " + _end


def uniform(size, count=1, vtype=obsl):
    if count == 1:
        return [vtype.uniform(size)]
    else:
        return [vtype.uniform(size) for _ in range(0, count)]


types = (obsl, tbsl, ebsl)
for vtype in types:
    for dtype in types:

        def _fcast(self, target=dtype):
            return self.cast_to(target)

        if sys.version_info < (3, ):
            _fcast.__name__ = str('_cast_to_{}'.format(dtype.__name__))
        else:
            _fcast.__name__ = '_cast_to_{}'.format(dtype.__name__)
        setattr(vtype, dtype.__name__, property(_fcast))

    for i, name in enumerate(vtype.value_names):

        def _fget(self, idx=i):
            return self.value[idx]

        def _fset(self, array, idx=i):
            assert isinstance(array, np.ndarray)
            assert len(self) == len(array)

            self.value = (tuple() + self.value[:idx] +
                          (array, ) + self.value[idx + 1:])

        if sys.version_info < (3, ):
            _fget.__name__ = str('_fget_{}'.format(name))
            _fset.__name__ = str('_fset_{}'.format(name))
        else:
            _fget.__name__ = '_fget_{}'.format(name)
            _fset.__name__ = '_fset_{}'.format(name)
        setattr(vtype, name, property(_fget, _fset))

for name, alias in _base.aliases:
    for vtype in types:
        op = getattr(vtype, name)
        setattr(vtype, alias, op)

for name, alias in _base.properties:
    for vtype in types:
        op = getattr(vtype, name)
        setattr(vtype, alias, op.fget)

for name, alias in _base.bycopy_ops:
    for vtype in types:
        op = getattr(vtype, name)

        def _bycopy_factory(_name=name, _op=op):
            def _bycopy(self, *kargs):
                return _op(self.copy(), *kargs)

            if sys.version_info < (3, ):
                _bycopy.__name__ = str('_bycopy_{}'.format(_name))
            else:
                _bycopy.__name__ = '_bycopy_{}'.format(_name)

            return _bycopy

        setattr(vtype, alias, _bycopy_factory())
