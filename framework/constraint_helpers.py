################################################################################
#
#  Copyright 2022 Eric Lacombe <eric.lacombe@security-labs.org>
#
################################################################################
#
#  This file is part of fuddly.
#
#  fuddly is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  fuddly is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with fuddly. If not, see <http://www.gnu.org/licenses/>
#
################################################################################

import copy
from libs.external_modules import *
if csp_module:
    from constraint import *

class ConstraintError(Exception): pass

class Constraint(object):

    _vars = None
    _relations = None
    _var_to_varns = None
    _var_node_mapping = None
    _var_domain = None
    _problem = None
    _solutions = None
    _model = None
    _solution_to_be_processed = False

    def __init__(self, vars, relations, var_to_varns: dict = None):
        assert csp_module, "the CSP backend is disabled because python-constraint module is not installed!"

        self._vars = copy.copy(vars)
        self._var_to_varns = copy.copy(var_to_varns)
        if isinstance(relations, (list, tuple)):
            self._relations = relations
        else:
            self._relations = [relations]

        self._var_node_mapping = {}
        self._var_domain = {}

    @property
    def relations(self):
        return self._relations

    def reset(self):
        self._problem = Problem()
        self._solutions = None
        self._model = None
        self._solution_to_be_processed = False

    def iter_vars(self):
        for v in self._vars:
            yield v

    def from_var_to_varns(self, var):
        return var if self._var_to_varns is None else self._var_to_varns[var]

    def set_var_domain(self, var, domain):
        self._var_domain[var] = copy.copy(domain)

    def map_var_to_node(self, var, node):
        self._var_node_mapping[var] = node

    @property
    def var_mapping(self):
        return self._var_node_mapping

    def get_solution(self):
        if not self._model:
            self.next_solution()

        self._solution_to_be_processed = True

        return self._model

    def _solve_constraints(self):
        for v in self._vars:
            self._problem.addVariable(v, self._var_domain[v])
        for r in self._relations:
            self._problem.addConstraint(r, tuple(self._vars))

        self._solutions = self._problem.getSolutionIter()

    def next_solution(self):
        if self._solutions is None:
            self.reset()
            self._solve_constraints()
            try:
                mdl = next(self._solutions)
            except StopIteration:
                mdl = None
                raise ConstraintError(f'no solution found with the provided constraint {id(self)}')
        else:
            try:
                mdl = next(self._solutions)
            except StopIteration:
                self.reset()
                self._solve_constraints()
                mdl = self._solutions.next()

        self._model = mdl
        self._solution_to_be_processed = False

    @property
    def is_current_solution_processed(self):
        return self._solution_to_be_processed


    def __copy__(self):
        new_cst = type(self)(self._vars, self._relations)
        new_cst.__dict__.update(self.__dict__)
        new_cst._var_domain = copy.copy(self._var_domain)
        new_cst._var_node_mapping = copy.copy(self._var_node_mapping)
        new_cst._solutions = self._problem.getSolutionIter() if self._problem else None
        new_cst._model = copy.copy(self._model)

        return new_cst
