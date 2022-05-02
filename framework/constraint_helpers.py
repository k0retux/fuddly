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
from typing import Tuple, List
from libs.external_modules import *
if csp_module:
    from constraint import *

class ConstraintError(Exception): pass

class Constraint(object):

    relation = None
    vars = None

    def __init__(self, relation, vars: Tuple, var_to_varns: dict = None):
        self.relation = relation
        self.vars = vars
        self.var_to_varns = var_to_varns

class CSP(object):

    _constraints = None
    _vars = None
    _var_to_varns = None
    _var_node_mapping = None
    _var_domain = None
    _problem = None
    _solutions = None
    _model = None
    _exhausted_solutions = None
    _solution_to_be_processed = False

    def __init__(self, constraints: Constraint or List[Constraint] = None):
        assert csp_module, "the CSP backend is disabled because python-constraint module is not installed!"

        if isinstance(constraints, Constraint):
            c_copy = copy.copy(constraints)
            self._vars = c_copy.vars
            self._constraints = [c_copy]
            self._var_to_varns = copy.copy(c_copy.var_to_varns)
        else:
            self._constraints = []
            self._vars = ()
            for r in constraints:
                r_copy = copy.copy(r)
                self._constraints.append(r_copy)
                self._vars += r_copy.vars
                if r_copy.var_to_varns:
                    if self._var_to_varns is None:
                        self._var_to_varns = {}
                    self._var_to_varns.update(r_copy.var_to_varns)
                    for v in r_copy.vars:
                        if v not in r_copy.var_to_varns:
                            self._var_to_varns[v] = v

        self._var_node_mapping = {}
        self._var_domain = {}

    def reset(self):
        self._problem = Problem()
        self._solutions = None
        self._model = None
        self._exhausted_solutions = False
        self._solution_to_be_processed = False

    def iter_vars(self):
        for v in self._vars:
            yield v

    def from_var_to_varns(self, var):
        return var if self._var_to_varns is None else self._var_to_varns[var]

    def set_var_domain(self, var, domain):
        assert bool(domain)
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
        for c in self._constraints:
            for v in c.vars:
                try:
                    self._problem.addVariable(v, self._var_domain[v])
                except ValueError:
                    # most probable cause: duplicated variable is attempted to be inserted
                    # (other cause is empty domain which is checked at init)
                    pass
            self._problem.addConstraint(c.relation, c.vars)

        self._solutions = self._problem.getSolutionIter()

    def next_solution(self):
        if self._solutions is None or self.exhausted_solution:
            self.reset()
            self._solve_constraints()
            try:
                mdl = next(self._solutions)
            except StopIteration:
                raise ConstraintError(f'no solution found with the provided constraint {id(self)}')
            else:
                self._model = mdl
        else:
            try:
                mdl = next(self._solutions)
            except StopIteration:
                self._exhausted_solutions = True
            else:
                self._model = mdl

        self._solution_to_be_processed = False

    @property
    def is_current_solution_processed(self):
        return self._solution_to_be_processed

    @property
    def exhausted_solution(self):
        return self._exhausted_solutions

    def __copy__(self):
        new_cst = type(self)(constraints=self._constraints)
        new_cst.__dict__.update(self.__dict__)
        new_cst._var_domain = copy.copy(self._var_domain)
        new_cst._var_node_mapping = copy.copy(self._var_node_mapping)
        new_cst._solutions = None # the generator cannot be copied
        new_cst._model = copy.copy(self._model)

        return new_cst
