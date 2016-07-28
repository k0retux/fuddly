from framework.data_model_helpers import *
import framework.value_types as vt
import unittest
import ddt
from test import mock


@ddt.ddt
class RegexParserTest(unittest.TestCase):
    """Test case used to test the 'RegexParser' class."""

    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        self._parser = RegexParser()
        self._parser._create_terminal_node = mock.Mock()

    def tearDown(self):
        pass

    @ddt.data(r"(sa(lu))(les)(louloux)", r"(salut)(les(louloux)", r"(salut))les(louloux)",
              r"(sal*ut)oo", r"(sal?ut)oo", r"sal{utoo", r"(sal+ut)oo", r"(sal{u)too",
              r"(sal{2}u)too", r"sal{2,1}utoo", r"sal(u[t]o)o",
              r"whatever|toto?ff", r"whate?ver|toto", r"(toto)*ohoho|haha", r"(toto)ohoho|haha",
              'salut[abcd]{,15}rr', r"[]whatever", r"t{,15}")
    def test_invalid_regexes(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data(
        {'regex': r"[abcd]?", 'nodes': [{"alphabet": "abcd", "qty": (0, 1)}]},
        {'regex': r"[abcd]*", 'nodes': [{"alphabet": "abcd", "qty": (0, None)}]},
        {'regex': r"[abcd]+", 'nodes': [{"alphabet": "abcd", "qty": (1, None)}]},
        {'regex': r"[abcd]{7}", 'nodes': [{"alphabet": "abcd", "qty": (7, 7)}]},
        {'regex': r"[abcd]{2,7}", 'nodes': [{"alphabet": "abcd", "qty": (2, 7)}]},
        {'regex': r"[abcd]{0}", 'nodes': [{"alphabet": "abcd", "qty": (0, 0)}]},
        {'regex': r"[abcd]{0,0}", 'nodes': [{"alphabet": "abcd", "qty": (0, 0)}]},
        {'regex': r"[abcd]{3,}", 'nodes': [{"alphabet": "abcd", "qty": (3, None)}]},
    )
    def test_quantifiers(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': r"salut(l\(es)(lou\\lous)cmoi",
         'nodes': [
             {"values": ["salut"]},
             {"values": ["l(es"]},
             {"values": ["lou\lous"]},
             {"values": ["cmoi"]},
         ]},
        {'regex': r"hi\x58", 'nodes': [{"values": ["hi\x58"]}]},
        {'regex': r"hi\x00hola", 'nodes': [{"values": ["hi\x00hola"]}]},
        {'regex': r"\xFFdom", 'nodes': [{"values": ["\xFFdom"]}]},
        {'regex': r"\ddom", 'nodes': [{"alphabet": "0123456789"}, {"values": ["dom"]}]},
        {'regex': r"dom[abcd\d]", 'nodes': [{"values": ["dom"]}, {"alphabet": "abcd0123456789"}]},
        {'regex': r"[abcd]\x43", 'nodes': [{"alphabet": "abcd"}, {"values": ["\x43"]}]},
        {'regex': r"(abcd)\x53", 'nodes': [{"values": ["abcd"]}, {"values": ["\x53"]}]},
        {'regex': r"\x43[abcd]", 'nodes': [{"values": ["\x43"]}, {"alphabet": "abcd"}]},
        {'regex': r"\x43(abcd)", 'nodes': [{"values": ["\x43"]}, {"values": ["abcd"]}]},
    )
    def test_escape(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(r"?", r"*", r"+", r"{1,2}", r"what{,}ever", r"bj{}er"
              r"what{1, 2}", r"what{,3}ever", r"ee{l1, 2}ever", r"whddddat{\13, 2}eyyyver",
              r"wat{3,2d}eyyyver", r"w**r", r"w+*r", r"w*?r")
    def test_quantifier_raise(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data(r"salut(", r"dd[", r"(", r"[", r"{0")
    def test_wrong_end_raise(self, regex):
        self.assert_regex_is_invalid(regex)


    @ddt.data(
        {'regex': r"[abcd]*toto(|\(ab\)|cd)+what?ever",
         'nodes': [
             {"alphabet": "abcd", "qty": (0, None)},
             {"values": ["toto"]},
             {"values": ["", "(ab)", "cd"], "qty": (1, None)},
             {"values": ["wha"]},
             {"values": ["t"], "qty": (0, 1)},
             {"values": ["ever"]}
         ]},
    )
    def test_complete(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': r"()", 'nodes': [{"values": [""]}]},
        {'regex': r"(z)", 'nodes': [{"values": ["z"]}]},
        {'regex': r"(cat)", 'nodes': [{"values": ["cat"]}]},

        {'regex': r"hello(boat)",
         'nodes': [{"values": ["hello"]}, {"values": ["boat"]}]},

        {'regex': r"(cake)awesome",
         'nodes': [{"values": ["cake"]}, {"values": ["awesome"]}]},

        {'regex': r"(foo)(bar)(foo)",
         'nodes': [{"values": ["foo"]}, {"values": ["bar"]}, {"values": ["foo"]}]},

        {'regex': r"dashboard(apple)(purple)",
         'nodes': [{"values": ["dashboard"]}, {"values": ["apple"]}, {"values": ["purple"]}]},

        {'regex': r"(harder)better(faster)",
         'nodes': [{"values": ["harder"]}, {"values": ["better"]}, {"values": ["faster"]}]},

        {'regex': r"(stronger)(it is me)baby",
         'nodes': [{"values": ["stronger"]}, {"values": ["it is me"]}, {"values": ["baby"]}]},

        {'regex': r"new(york)city",
         'nodes': [{"values": ["new"]}, {"values": ["york"]}, {"values": ["city"]}]},

        {'regex': r"()whatever",
         'nodes': [{"values": [""]}, {"values": ["whatever"]}]},

        {'regex': r"this is it()",
         'nodes': [{"values": ["this is it"]}, {"values": [""]}]},

        {'regex': r"this()parser()is()working",
         'nodes': [{"values": ["this"]}, {"values": [""]}, {"values": ["parser"]}, {"values": [""]},
                   {"values": ["is"]},   {"values": [""]}, {"values": ["working"]}]},

        {'regex': r"()()()",
         'nodes': [{"values": [""]}, {"values": [""]}, {"values": [""]}]},
    )
    def test_basic_parenthesis(self, test_case):
        self.assert_regex_is_valid(test_case)




    @ddt.data(
        {'regex': r"(ab|cd|)+", 'nodes': [{"values": ["ab", "cd", ""], "qty": (1, None)}]},
        {'regex': r"(ab||cd)", 'nodes': [{"values": ["ab", "", "cd"]}]},
        {'regex': r"(|ab|cd|ef|gh)+", 'nodes': [{"values": ["", "ab", "cd", "ef", "gh"], "qty": (1, None)}]},
        {'regex': r"(|)+", 'nodes': [{"values": ["", ""], "qty": (1, None)}]},
        {'regex': r"(|||)+", 'nodes': [{"values": ["", "", "", ""], "qty": (1, None)}]},
    )
    def test_or_in_parenthesis(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': r"1|2|3", 'nodes': [{"type": fvt.INT_str, "values": [1,2,3]}]},
        {'regex': r"1|2|3|foo", 'nodes': [{"values": ['1', '2', '3', 'foo']}]},
        {'regex': r"1|foo|2|3", 'nodes': [{"values": ['1', 'foo', '2', '3']}]},
        {'regex': r"foo|1|2|3", 'nodes': [{"values": ['foo', '1', '2', '3']}]},
        {'regex': r"(11|12|13)bar",
         'nodes': [{"type": fvt.INT_str, "values": [11, 12, 13]}, {"values": ['bar']}]},
        {'regex': r"(11|12|13|bar)",
         'nodes': [{"values": ['11', '12', '13', 'bar']}]},
        {'regex': r"234whatever23", 'nodes': [{"values": ['234whatever23']}]},
        {'regex': r"(234whatever23)foobar",
         'nodes': [{"values": ['234whatever23']}, {"values": ['foobar']}]},
        {'regex': r"1113|3435|3344|(hay)",
         'nodes': [{"type": fvt.INT_str, "values": [1113, 3435, 3344]}, {"values": ['hay']}]},
    )
    def test_types_recognition(self, test_case):
        self.assert_regex_is_valid(test_case)



    @ddt.data(
        {'regex': r"[e]", 'nodes': [{"alphabet": "e"}]},
        {'regex': r"[caty]", 'nodes': [{"alphabet": "caty"}]},
        {'regex': r"[abcd][efghij]", 'nodes': [{"alphabet": "abcd"}, {"alphabet": "efghij"}]},
        {'regex': r"[cake]awesome", 'nodes': [{"alphabet": "cake"}, {"values": ["awesome"]}]},

        {'regex': r"[foo][bar][foo]",
         'nodes': [{"alphabet": "foo"}, {"alphabet": "bar"}, {"alphabet": "foo"}]},

        {'regex': r"dashboard[apple][purple]",
         'nodes': [{"values": ["dashboard"]}, {"alphabet": "apple"}, {"alphabet": "purple"}]},

        {'regex': r"[harder]better[faster]",
         'nodes': [{"alphabet": "harder"}, {"values": ["better"]}, {"alphabet": "faster"}]},

        {'regex': r"[stronger][it is me]baby",
         'nodes': [{"alphabet": "stronger"}, {"alphabet": "it is me"}, {"values": ["baby"]}]},

        {'regex': r"new[york]city",
         'nodes': [{"values": ["new"]}, {"alphabet": "york"}, {"values": ["city"]}]},

        {'regex': r"[a-e]", 'nodes': [{"alphabet": "abcde"}]},
        {'regex': r"[a-ewxy]", 'nodes': [{"alphabet": "abcdewxy"}]},
        {'regex': r"[1-9]", 'nodes': [{"alphabet": "123456789"}]},
        {'regex': r"[what1-9]", 'nodes': [{"alphabet": "what123456789"}]},
        {'regex': r"[a-c1-9]", 'nodes': [{"alphabet": "abc123456789"}]},
        {'regex': r"[a-c1-9fin]", 'nodes': [{"alphabet": "abc123456789fin"}]},
        {'regex': r"[a-c9-9fin]", 'nodes': [{"alphabet": "abc9fin"}]},
        {'regex': r"[pa-cwho1-9fin]", 'nodes': [{"alphabet": "pabcwho123456789fin"}]},

        {'regex': r"[\x33]", 'nodes': [{"alphabet": "\x33"}]},
        {'regex': r"[\x33-\x35]", 'nodes': [{"alphabet": "\x33\x34\x35"}]},
        {'regex': r"[e\x33-\x35a]", 'nodes': [{"alphabet": "e\x33\x34\x35a"}]}
    )
    def test_basic_square_brackets(self, test_case):
        self.assert_regex_is_valid(test_case)

    @ddt.data(r"[\x33-\x23]", r"[3-1]", r"[y-a]", r"[\x3-\x34]", r"[\x3g]")
    def test_wrong_alphabet(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data(r"[]", r"stronger[]baby", r"strongerbaby[]", r"[]strongerbaby", r"stro[]nger[]baby[]")
    def test_basic_square_brackets_raise(self, regex):
        self.assert_regex_is_invalid(regex)



    @ddt.data(
        {'regex': r"|", 'nodes': [{"values": ["",""]}]},
        {'regex': r"|||", 'nodes': [{"values": ["", "", "", ""]}]},
        {'regex': r"toto|titi|tata", 'nodes': [{"values": ["toto", "titi", "tata"]}]},
        {'regex': r"toto|titi|", 'nodes': [{"values": ["toto", "titi", ""]}]},
        {'regex': r"toto||tata", 'nodes': [{"values": ["toto", "", "tata"]}]},
        {'regex': r"|titi|tata", 'nodes': [{"values": ["", "titi", "tata"]}]},
        {'regex': r"coucou|[abcd]|", 'nodes': [{"values": ["coucou"]}, {"alphabet": "abcd"}, {"values": [""]}]},

        {'regex': r"|[hao]|[salut]?",
         'nodes': [{"values": [""]}, {"alphabet": "hao"}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': r"coucou||[salut]?",
         'nodes': [{"values": ["coucou", ""]}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': r"coucou||||[salut]?",
         'nodes': [{"values": ["coucou", "", "", ""]}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': r"[whatever]+|[hao]|[salut]?",
         'nodes': [
             {"alphabet": "whatever", "qty": (1, None)},
             {"alphabet": "hao"},
             {"alphabet": "salut", "qty": (0, 1)}
         ]},

        {'regex': r"(whatever)+|(hao)|(salut)?",
         'nodes': [
             {"values": ["whatever"], "qty": (1, None)},
             {"values": ["hao"]},
             {"values": ["salut"], "qty": (0, 1)}
         ]},


        {'regex': r"tata|haha|c*|b*|[abcd]+", 'nodes': [
            {"values": ["tata", "haha"]},
            {"values": ["c"], "qty": (0, None)},
            {"values": ["b"], "qty": (0, None)},
            {"alphabet": "abcd", "qty": (1, None)}
        ]},

        {'regex': r"(tata)+|haha|tata||b*|[abcd]+", 'nodes': [
            {"values": ["tata"], "qty": (1, None)},
            {"values": ["haha", "tata", ""]},
            {"values": ["b"], "qty": (0, None)},
            {"alphabet": "abcd", "qty": (1, None)}
        ]},
    )
    def test_shape(self, test_case):
        self.assert_regex_is_valid(test_case)



    def assert_regex_is_valid(self, test_case):

        self._parser.parse(test_case['regex'], "name")
        self.assertEquals(self._parser._create_terminal_node.call_count, len(test_case['nodes']))

        calls = []
        nodes = test_case['nodes']
        for i in range(0, len(nodes)):

            type = nodes[i]['type'] if 'type' in nodes[i] else vt.String
            values = nodes[i]['values'] if 'values' in nodes[i] else None
            alphabet = nodes[i]['alphabet'] if 'alphabet' in nodes[i] else None
            qty = nodes[i]['qty'] if 'qty' in nodes[i] else (1, 1)

            calls.append(mock.call("name" + str(i + 1), type, values=values, alphabet=alphabet, qty=qty))

        self._parser._create_terminal_node.assert_has_calls(calls)


    def assert_regex_is_invalid(self, regex):
        self.assertRaises(Exception, self._parser.parse, regex, "name")