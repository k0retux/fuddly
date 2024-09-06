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

import z3

from libs.external_modules import *
if z3_module:
    from z3 import *

import framework.global_resources as gr

_Z3_MODEL_NOT_COMPUTED = 1

class ConstraintError(Exception): pass
class CSPDefinitionError(Exception): pass
class CSPUnsat(Exception): pass

class Constraint(object):

    relation = None
    vars = None
    _var_domain = None
    _orig_relation = None

    def __init__(self, relation, vars: Tuple, var_to_varns: dict = None):
        """

        Args:
            relation: boolean function that define the constraints between variables
            vars (list): list of the names of the nodes used in the boolean function in `relation`
              (in the same order as the parameters of the function).
            var_to_varns (dict): dictionary that associates for each name in `vars`, the comprehensive
              reference to the related node, which is a tuple of its name and its namespace.
        """

        self.relation = self._orig_relation = relation
        self.vars = vars
        self.var_to_varns = var_to_varns

    @property
    def var_domain(self):
        return self._var_domain

    @var_domain.setter
    def var_domain(self, var_domain):
        self._var_domain = var_domain

    def negate(self):
        self.relation = self._negated_relation

    def reset_to_original(self):
        self.relation = self._orig_relation

    def _negated_relation(self, *args):
        return not self._orig_relation(*args)

    def __copy__(self):
        new_cst = type(self)(self._orig_relation, self.vars, self.var_to_varns)
        new_cst.__dict__.update(self.__dict__)
        return new_cst

class Z3Constraint(object):

    relation = None
    vars = None
    z3vars = None
    _var_domain = None
    _orig_relation = None
    _is_relation_translated = None

    def __init__(self, relation, vars: Tuple, var_to_varns: dict = None):
        """

        Args:
            relation: expression that define the constraints between variables
            vars (list): list of the names of the nodes used in the boolean function in `relation`
              (in the same order as the parameters of the function).
            var_to_varns (dict): dictionary that associates for each name in `vars`, the comprehensive
              reference to the related node, which is a tuple of its name and its namespace.
        """

        self.vars = vars
        self.var_to_varns = var_to_varns
        self._is_relation_translated = False
        self.relation = self._orig_relation = relation

    def provide_translated_relation(self, relation):
        self.relation = self._orig_relation = relation
        self._is_relation_translated = True

    @property
    def is_relation_translated(self):
        return self._is_relation_translated

    @property
    def var_domain(self):
        return self._var_domain

    @var_domain.setter
    def var_domain(self, var_domain):
        self._var_domain = var_domain

    def negate(self):
        self.relation = 'Not(' + self._orig_relation + ')'

    def reset_to_original(self):
        self.relation = self._orig_relation

    def __copy__(self):
        new_cst = type(self)(self._orig_relation, self.vars, self.var_to_varns)
        new_cst.__dict__.update(self.__dict__)
        return new_cst


class CSP(object):

    _constraints = None
    _vars = None
    _z3vars = None
    _var_types = None
    _var_to_varns = None
    _var_node_mapping = None
    _var_domain = None
    _var_domain_updated = False
    _orig_var_domain = None
    _var_default_value = None
    _orig_var_default_value = None
    _checked_with_default_values = None
    _default_value_constraints_added = None
    _problem = None
    _solver = None
    _solutions = None
    _model = None
    _default_model = None  # used in the context of python-constraint
    _exhausted_solutions = None
    _is_solution_queried = False
    highlight_variables = None

    z3_problem = None

    def __init__(self, constraints: Constraint or Z3Constraint or List[Constraint or Z3Constraint],
                 highlight_variables=False):
        assert csp_module or z3_module, "the CSP backbone is disabled because of missing CSP backends!"

        self.z3_problem = False

        if isinstance(constraints, (Constraint, Z3Constraint)):
            if isinstance(constraints, Z3Constraint):
                self.z3_problem = True
            c_copy = copy.copy(constraints)
            self._vars = c_copy.vars
            self._constraints = [c_copy]
            self._var_to_varns = copy.copy(c_copy.var_to_varns)
        else:
            self._constraints = []
            self._vars = ()
            self._z3vars = {}
            self._var_types = {}
            self.z3_problem = isinstance(constraints[0], Z3Constraint)
            for r in constraints:
                if self.z3_problem:
                    assert isinstance(r, Z3Constraint), \
                        "Mix of Z3Constraint and Constraint objects are not allowed"
                else:
                    assert isinstance(r, Constraint), \
                        "Mix of Z3Constraint and Constraint objects are not allowed"

                r_copy = copy.copy(r)
                self._constraints.append(r_copy)
                self._vars += r_copy.vars
                if self._var_to_varns is None:
                    self._var_to_varns = {}
                if r_copy.var_to_varns:
                    self._var_to_varns.update(r_copy.var_to_varns)
                for v in r_copy.vars:
                    if not r_copy.var_to_varns or v not in r_copy.var_to_varns:
                        self._var_to_varns[v] = v

        self._var_node_mapping = {}
        self._var_domain = {}
        self._var_default_value = {}
        self._var_domain_updated = False

        self.highlight_variables = highlight_variables

    def freeze(self):
        if self.z3_problem:
            for r in self._constraints:
                for var in r.vars:
                    dom = self._var_domain[var]
                    # print(f'\n*** DEBUG: var:{var}, type:{type(dom[0])}')
                    if isinstance(dom[0], int):
                        self._var_types[var] = z3.Int
                    elif isinstance(dom[0], bytes):
                        self._var_types[var] = z3.String
                    else:
                        raise NotImplementedError

                    self._z3vars[var] = self._var_types[var](var)

        self.save_current_var_domains()

    def reset(self):
        # print(f'\n*** DBG RESET - info:'
        #       f'\n --> variables: {self._vars}'
        #       f'\n --> Z3 variables: {list(map(type, self._z3vars.values()))}'
        #       f'\n --> variable types: {self._var_types}'
        #       f'\n --> domains: {self._var_domain}')

        if self.z3_problem:
            self._solver = Solver()
        else:
            self._problem = cst.Problem()

        self._checked_with_default_values = False
        self._default_value_constraints_added = False
        self._solutions = None
        self._model = None
        self._default_model = None
        self._exhausted_solutions = False
        self._is_solution_queried = False

    def iter_vars(self):
        for v in self._vars:
            yield v

    def from_var_to_varns(self, var):
        return var if self._var_to_varns is None else self._var_to_varns[var]

    @property
    def var_domain_updated(self):
        return self._var_domain_updated

    def set_var_domain(self, var, domain, min=None, max=None, default=None):
        if min is None:
            self._var_domain[var] = copy.copy(domain)
            if self.z3_problem:
                v_type = self._var_types.get(var)
                if isinstance(domain[0], bytes) and (v_type is None or v_type == z3.Int):
                    # This inconsistency can happen when a disruptor play with the domain of a node
                    # which is normally a vt.INT and replace it temporarily for the generated
                    # fuzzing cases by a vt.String.
                    self._z3vars[var] = z3.String(var)
                    self._var_types[var] = z3.String
                elif isinstance(domain[0], int) and v_type == z3.String:
                    # the domain has been restored we go back to the original domain
                    self._z3vars[var] = z3.Int(var)
                    self._var_types[var] = z3.Int
                else:
                    pass
        else:
            self._var_domain[var] = (min, max)

        self._var_default_value[var] = default

        self._var_domain_updated = True

    def save_current_var_domains(self):
        self._orig_var_domain = copy.deepcopy(self._var_domain)
        self._orig_var_default_value = copy.copy(self._var_default_value)
        if self.z3_problem:
            self._orig_var_types = copy.copy(self._var_types)
            self._orig_z3vars = copy.deepcopy(self._z3vars)
        self._var_domain_updated = False

    def restore_var_domains(self):
        self._var_domain = copy.deepcopy(self._orig_var_domain)
        self._var_default_value = copy.copy(self._orig_var_default_value)
        if self.z3_problem:
            self._var_types = copy.copy(self._orig_var_types)
            self._z3vars = copy.deepcopy(self._orig_z3vars)
        self._var_domain_updated = False

    def map_var_to_node(self, var, node):
        self._var_node_mapping[var] = node

    @property
    def var_mapping(self):
        return self._var_node_mapping

    @property
    def var_types(self):
        return self._var_types

    def get_solution(self):
        try:
            if not self._model:
                self.next_solution()
        except:
            # We propagate the exception to the caller. It generally signifies that
            # no solution have been found.
            raise
        finally:
            self._is_solution_queried = True

        return self._model

    def _solve_constraints(self):
        default_value_constraints = []
        for c in self._constraints:
            if isinstance(c, Z3Constraint):
                relation = c.relation
                for v in c.vars:
                    z3var = self._z3vars[v]
                    dom = self._var_domain[v]
                    default = self._var_default_value.get(v)
                    v_type = self._var_types.get(v)
                    if v_type is None or v_type is z3.Int:
                        if not self._checked_with_default_values and default is not None:
                            default_value_constraints.append(z3var == default)

                        if isinstance(dom, tuple) and len(dom) == 2:
                            min, max = dom
                            self._solver.add(And([min <= z3var, z3var <= max]))
                        else:
                            self._solver.add(Or([z3var == value for value in dom]))

                    elif v_type is z3.String:
                        if not self._checked_with_default_values and default is not None:
                            default_value_constraints.append(z3var == gr.unconvert_from_internal_repr(default))
                        self._solver.add(Or([z3var == gr.unconvert_from_internal_repr(value) for value in dom]))

                    else:
                        raise NotImplementedError

                if not c.is_relation_translated:
                    tmp_vars = []
                    for v in c.vars:
                        tmp_vars.append('!?'+v)
                    for v, tmp_v in zip(c.vars, tmp_vars):
                        relation = relation.replace(v, tmp_v)
                    for v, tmp_v in zip(c.vars, tmp_vars):
                        relation = relation.replace(tmp_v, 'self._z3vars["'+ v +'"]')

                if not c.is_relation_translated:
                    c.provide_translated_relation(relation)

                try:
                    z3formula = eval(c.relation)
                except z3types.Z3Exception:
                    # this case can happen if some variable types have been changed by a disruptor
                    # to generate specific test cases. (For instance tTYPE will change a vt.INT into
                    # a vt.String to add specific cases mixing integers and separators.)
                    # In such cases, it does not make sense to add a constraint anyway.
                    self._checked_with_default_values = True
                    raise CSPDefinitionError(f'\nVariable types in the constraint formula are not consistent'
                                             f' (root cause: incorrect data model or some fuzzing is'
                                             f' performed?)'
                                             f'\n --> Z3 formula: {c.relation}'
                                             f'\n --> variables: {self._vars}'
                                             f'\n --> variable types: {self._var_types}'
                                             f'\n --> domains: {self._var_domain}')
                else:
                    self._solver.add(z3formula)

                if not self._checked_with_default_values and default_value_constraints:
                    self._solver.push()
                    for z3_cst in default_value_constraints:
                        self._solver.add(z3_cst)
                    self._default_value_constraints_added = True

            else:
                for v in c.vars:
                    dom = self._var_domain[v]
                    default = self._var_default_value.get(v)
                    if not self._checked_with_default_values and default is not None:
                        dom = [default]
                        self._default_value_constraints_added = True
                    elif isinstance(dom, tuple) and len(dom) == 2:
                        dom = range(dom[0], dom[1] + 1)

                    try:
                        self._problem.addVariable(v, dom)
                    except ValueError:
                        # most probable cause: duplicated variable is attempted to be inserted
                        # (other cause is empty domain which is checked at init)
                        pass
                self._problem.addConstraint(c.relation, c.vars)


        if self.z3_problem:
            self._solutions = _Z3_MODEL_NOT_COMPUTED
            self._checked_with_default_values = True

        else:
            try:
                self._solutions = self._problem.getSolutionIter()
            except TypeError:
                self._solutions = None
                raise CSPDefinitionError(f'\nVariable types in the constraint formula are not consistent'
                                         f' (root cause: incorrect data model or some fuzzing is'
                                         f' performed?)'
                                         f'\n --> variables: {self._vars}'
                                         f'\n --> domains: {self._var_domain}')
            finally:
                self._checked_with_default_values = True


    def _next_solution(self):
        z3mdl = self._solutions
        if z3mdl is _Z3_MODEL_NOT_COMPUTED:
            r = self._solver.check()
            if r == sat:
                self._solutions = self._solver.model()
                return self._next_solution()
            else:
                raise CSPUnsat()

        else:
            self._solutions = _Z3_MODEL_NOT_COMPUTED
            if self._checked_with_default_values and self._default_value_constraints_added:
                self._solver.pop()
                self._default_value_constraints_added = False
            self._solver.add(Or([z3v != z3mdl[z3v] for z3v in self._z3vars.values()]))
            mdl = {}
            for var in z3mdl:
                var_str = str(var)
                v_type = self._var_types.get(var_str)
                if v_type is None or v_type is z3.Int:
                    mdl[var_str] = z3mdl[var].as_long()
                elif v_type is z3.String:
                    mdl[var_str] = z3mdl[var].as_string()
                else:
                    raise NotImplementedError
            return mdl


    def next_solution(self):
        if self._solutions is None or self._exhausted_solutions:
            self.reset()
            try:
                self._solve_constraints()
            except CSPDefinitionError as err:
                self._exhausted_solutions = True
                print(err)
            else:
                if self.z3_problem:
                    try:
                        self._model = self._next_solution()
                    except CSPUnsat:
                        self._exhausted_solutions = True
                        raise ConstraintError(
                            f'No solution found for this CSP by keeping any default values within '
                            f'the DM definition.\n --> variables: {self._vars}')
                else:
                    try:
                        mdl = next(self._solutions)
                    except StopIteration:
                        self._exhausted_solutions = True
                        raise ConstraintError(
                            f'No solution found for this CSP by keeping any default values within '
                            f'the DM definition.\n --> variables: {self._vars}')
                    except TypeError:
                        self._exhausted_solutions = True
                        print(f'\nVariable types in the constraint formula are not consistent'
                              f' (root cause: incorrect data model or some fuzzing is'
                              f' performed?)'
                              f'\n --> variables: {self._vars}'
                              f'\n --> domains: {self._var_domain}')
                    else:
                        self._model = mdl
                        if self._default_value_constraints_added:
                            self._default_model = mdl
        else:
            if self.z3_problem:
                try:
                    mdl = self._next_solution()
                except CSPUnsat:
                    self._exhausted_solutions = True
                else:
                    self._model = mdl
            else:
                if self._default_value_constraints_added and self._checked_with_default_values:
                    self._problem.reset()
                    try:
                        self._solve_constraints()
                    except CSPDefinitionError as err:
                        self._exhausted_solutions = True
                        print(err)
                    finally:
                        self._default_value_constraints_added = False
                try:
                    mdl = next(self._solutions)
                    if self._default_model is not None:
                        if mdl == self._default_model:
                            self._default_model = None
                            mdl = next(self._solutions)
                except StopIteration:
                    self._exhausted_solutions = True
                else:
                    self._model = mdl

        self._is_solution_queried = False

    def negate_constraint(self, idx):
        assert 0 <= idx < self.nb_constraints
        c = self._constraints[idx]
        c.negate()
        self.reset()

    def reset_constraint(self, idx):
        assert 0 <= idx < self.nb_constraints
        c = self._constraints[idx]
        c.reset_to_original()
        self.reset()

    def get_all_constraints(self):
        return self._constraints

    def get_constraint(self, idx):
        assert 0 <= idx < self.nb_constraints
        return self._constraints[idx]

    @property
    def nb_constraints(self):
        return len(self._constraints)

    @property
    def is_current_solution_queried(self):
        return self._is_solution_queried

    @property
    def exhausted_solutions(self):
        return self._exhausted_solutions

    @property
    def no_solution_exists(self):
        return self._exhausted_solutions

    def __copy__(self):
        new_csp = type(self)(constraints=self._constraints)
        new_csp.__dict__.update(self.__dict__)
        new_csp._var_domain = copy.deepcopy(self._var_domain)
        new_csp._var_default_value = copy.copy(self._var_default_value)
        new_csp._var_to_varns = copy.deepcopy(self._var_to_varns)
        new_csp._var_types = copy.copy(self._var_types)
        new_csp._z3vars = copy.deepcopy(self._z3vars)
        # print(f'\n*** DBG RESET - info:'
        #       f'\n --> variables: {self._vars}'
        #       f'\n --> Z3 variables: {list(map(type, self._z3vars.values()))}'
        #       f'\n --> variable types: {self._var_types}'
        #       f'\n --> domains: {self._var_domain}')
        new_csp._var_node_mapping = copy.copy(self._var_node_mapping)
        new_csp._solutions = None # the generator cannot be copied
        new_csp._model = copy.copy(self._model)
        new_csp._default_model = copy.copy(self._default_model)
        new_csp._constraints = []
        for c in self._constraints:
            new_csp._constraints.append(copy.copy(c))

        return new_csp
