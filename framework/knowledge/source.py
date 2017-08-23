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

import collections
import sys

import framework.knowledge as kn
import framework.knowledge.tools

assert sys.version_info >= (2, 7)


def issource(item):
    try:
        return issubclass(item.__class__, _base_source)
    except AttributeError:
        return False


class _base_source(object):
    name = '_base'
    prop = 'genericity'

    def __init__(self, **attributes):
        _dict = dict(**attributes)
        self._attributes = collections.OrderedDict(
            sorted(_dict.items(), key=lambda x: x[0]))
        if self.prop is not None and self.prop in attributes:
            self._genericity = attributes[self.prop]
            del self._attributes[self.prop]
        else:
            self._genericity = None

        if self.prop is not None:

            def _fget(self):
                return self._genericity

            def _fset(self, value):
                self._genericity = value

            setattr(self.__class__, self.prop, property(_fget, _fset))

        for p in self._attributes:
            assert p[0] != '_'

            def _fget_p(self, _key=p):
                return self._attributes[_key]

            def _fset_p(self, value, _key=p):
                self._attributes[_key] = value

            setattr(self.__class__, p, property(_fget_p, _fset_p))

    def __str__(self):
        s = self.name
        if self._genericity is not None:
            s += '<{}>'.format(
                kn.tools.to_str(self._genericity, _base_source))

        if len(self._attributes) < 1:
            s += '()'
        else:
            _attr = []
            for key, value in self._attributes.items():
                _attr.append(key + '=' + kn.tools.to_str(value, _base_source))
            s += '({})'.format(','.join(_attr))
        return s

    def __repr__(self):
        return self.__str__()

    def dict(self):
        _dict = {str('name'): str(self.name)}
        if self._genericity is not None:
            _dict[str(self.prop)] = self._genericity
        for k, v in self._attributes.items():
            _dict[str(k)] = v

        return _dict

    def __eq__(self, other):
        return str(self) == str(other)


class default_source(_base_source):
    name = 'default'
    prop = None


default = default_source()


class named_source(_base_source):
    prop = None

    def __init__(self, name, **attributes):
        _base_source.__init__(self, **attributes)
        self.name = name


class oracle_source(_base_source):
    name = 'oracle'
    prop = 'name'


class merge_source(_base_source):
    name = 'merge'
    prop = 'op'


class label_source(_base_source):
    name = 'label'
    prop = 'tag'
