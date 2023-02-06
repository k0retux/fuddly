
import tools.plotty.plotty as sut 
import unittest
import ddt


@ddt.ddt
class PlottyTest(unittest.TestCase):

#region Formula
    
    @ddt.data(
        {'expression': "a", 'variables': set(["a"])},
        {'expression': "a + b", 'variables': set(["a", "b"])},
        {'expression': "exp((a + b) / c)", 'variables': set(["a", "b", "c"]), 'functions': set(["exp"])},
        {
            'expression': "sqrt((1-a*exp(2t) + w^pi) / (sin(2x / pi) + cos(pi/y)))", 
            'variables': set(["a", "t", "w", "pi", "x", "y"]),
            'functions': set(["sqrt", "exp", "sin", "cos"])
        }
    )
    @ddt.unpack
    def test_should_find_all_variables_when_given_well_formed_expression(self, expression, variables=set(), functions=set()):
        found_variables, found_functions = sut.collect_names(expression)

        self.assertSetEqual(found_variables, variables)
        self.assertSetEqual(found_functions, functions)


    @ddt.data(
        {'formula': "a ~ b"},
        {'formula': "a + b ~ c"},
        {'formula': "exp((a + b) / c) ~ cos(a + sin(b))"},
        {'formula': "sqrt((1-a*exp(2t) + w^pi) ~ (sin(2x / pi) + cos(pi/y) ))  "}
    )
    @ddt.unpack
    def test_should_return_true_when_given_valid_formula(self, formula):
        _, _, valid_formula = sut.split_formula(formula)

        self.assertTrue(valid_formula)


    @ddt.data(
        {'formula': "a = b"},
        {'formula': "f(a) = b"},
        {'formula': "exp((a + b) / c) cos(a + sin(b))"},
        {'formula': "a ~ b ~ c"},
    )
    @ddt.unpack
    def test_should_return_false_when_given_invalid_formula(self, formula):
        _, _, valid_formula = sut.split_formula(formula)

        self.assertFalse(valid_formula)


    @ddt.data(
        {'formula': "a ~ b", 'left_expr': "a", 'right_expr': "b"},
        {'formula': "a + b ~ c", 'left_expr': "a+b", 'right_expr': "c"},
        {
            'formula': "exp((a + b) / c) ~ cos(a + sin(b))",
            'left_expr': "exp((a+b)/c)", 
            'right_expr': "cos(a+sin(b))"
        },
        {
            'formula': "sqrt ((1  -a *exp(2t) + w^ pi) ~ (  sin(2x / pi) + cos(pi/y) ))  ",
            'left_expr': "sqrt((1-a*exp(2t)+w^pi)", 
            'right_expr': "(sin(2x/pi)+cos(pi/y)))"
        }
    )
    @ddt.unpack
    def test_should_properly_split_and_trim_when_given_valid_formula(self, formula, left_expr, right_expr):
        left, right, _ = sut.split_formula(formula)

        self.assertEqual(left, left_expr)
        self.assertEqual(right, right_expr)
    
#endregion
    
#region Interval
    @ddt.data(
        {'interval': "1..4", 'expected_set': set(range(1,4))},
        {'interval': "0..1", 'expected_set': set(range(1))},
        {'interval': "547..960", 'expected_set': set(range(547,960))},
    )
    @ddt.unpack
    def test_should_retrieve_all_integers_given_well_formed_interval(self, interval, expected_set):
        result = sut.parse_interval(interval)

        self.assertSetEqual(result, expected_set)


    @ddt.data(
        {'interval': ""},
        {'interval': "not..an_interval"},
        {'interval': "definitely..not..an_interval"},
        {'interval': "10..1"},
        {'interval': "100..1i0"},
        {'interval': "10.."},
        {'interval': "..10"},
    )
    @ddt.unpack
    def test_should_output_empty_set_on_invalid_intervals(self, interval):
        result = sut.parse_interval(interval)

        self.assertSetEqual(result, set())


    @ddt.data(
        {'interval_union': "1..4", 'expected_set': set(range(1,4))},
        {'interval_union': "0..5, 5..10", 'expected_set': set(range(0,10))},
        {'interval_union': "0..120, 100..120", 'expected_set': set(range(120))},
        {
            'interval_union': "0..120, 130..140, 150..200", 
            'expected_set': set(range(120)).union(set(range(130,140))).union(set(range(150,200)))
        },
    )
    @ddt.unpack
    def test_should_properly_merge_intervals_of_intervals_union(self, interval_union, expected_set):
        result = sut.parse_interval_union(interval_union)
        self.assertSetEqual(result, expected_set)

#endregion

    def dummy_test():
        pass