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


    @ddt.unpack
    @ddt.data(('?', (0, 1)), ('*', (0, None)), ('+', (1, None)),
              ('{7}', (7, 7)), ('{2,7}', (2, 7)),
              ('{0}', (0, 0)), ('{0,0}', (0, 0)),
              ('{3,}', (3, None)))
    def test_7(self, char, qty):
        self._parser.parse(r"salut[abcd]" + char + "ooo", "toto")
        self.assertEquals(self._parser._create_terminal_node.call_count, 3)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=["salut"], alphabet=None, qty=(1, 1)),
             mock.call("toto2", vt.String, contents=None, alphabet="abcd", qty=qty),
             mock.call("toto3", vt.String, contents=["ooo"], alphabet=None, qty=(1, 1))])

    @ddt.unpack
    @ddt.data(('?', (0, 1)), ('*', (0, None)), ('+', (1, None)),
              ('{7}', (7, 7)), ('{2,7}', (2, 7)),
              ('{0}', (0, 0)), ('{0,0}', (0, 0)),
              ('{3,}', (3, None)))
    def test_8(self, char, qty):
        self._parser.parse(r"salu(ttteee|whatever)" + char + "ooo", "toto")
        self.assertEquals(self._parser._create_terminal_node.call_count, 3)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=["salu"], alphabet=None, qty=(1, 1)),
             mock.call("toto2", vt.String, contents=["ttteee", "whatever"], alphabet=None, qty=qty),
             mock.call("toto3", vt.String, contents=["ooo"], alphabet=None, qty=(1, 1))])


    @ddt.data(
        {'regex': r"salut(l\(es)(lou\\lous)cmoi",
         'nodes': [
             {"contents": ["salut"]},
             {"contents": ["l(es"]},
             {"contents": ["lou\lous"]},
             {"contents": ["cmoi"]},
         ]},
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
             {"contents": ["toto"]},
             {"contents": ["", "(ab)", "cd"], "qty": (1, None)},
             {"contents": ["wha"]},
             {"contents": ["t"], "qty": (0, 1)},
             {"contents": ["ever"]}
         ]},
    )
    def test_complete(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': r"()", 'nodes': [{"contents": [""]}]},
        {'regex': r"(z)", 'nodes': [{"contents": ["z"]}]},
        {'regex': r"(cat)", 'nodes': [{"contents": ["cat"]}]},

        {'regex': r"hello(boat)",
         'nodes': [{"contents": ["hello"]}, {"contents": ["boat"]}]},

        {'regex': r"(cake)awesome",
         'nodes': [{"contents": ["cake"]}, {"contents": ["awesome"]}]},

        {'regex': r"(foo)(bar)(foo)",
         'nodes': [{"contents": ["foo"]}, {"contents": ["bar"]}, {"contents": ["foo"]}]},

        {'regex': r"dashboard(apple)(purple)",
         'nodes': [{"contents": ["dashboard"]}, {"contents": ["apple"]}, {"contents": ["purple"]}]},

        {'regex': r"(harder)better(faster)",
         'nodes': [{"contents": ["harder"]}, {"contents": ["better"]}, {"contents": ["faster"]}]},

        {'regex': r"(stronger)(it is me)baby",
         'nodes': [{"contents": ["stronger"]}, {"contents": ["it is me"]}, {"contents": ["baby"]}]},

        {'regex': r"new(york)city",
         'nodes': [{"contents": ["new"]}, {"contents": ["york"]}, {"contents": ["city"]}]},

        {'regex': r"()whatever",
         'nodes': [{"contents": [""]}, {"contents": ["whatever"]}]},

        {'regex': r"this is it()",
         'nodes': [{"contents": ["this is it"]}, {"contents": [""]}]},

        {'regex': r"this()parser()is()working",
         'nodes': [{"contents": ["this"]}, {"contents": [""]}, {"contents": ["parser"]}, {"contents": [""]},
                   {"contents": ["is"]},   {"contents": [""]}, {"contents": ["working"]}]},

        {'regex': r"()()()",
         'nodes': [{"contents": [""]}, {"contents": [""]}, {"contents": [""]}]},
    )
    def test_basic_parenthesis(self, test_case):
        self.assert_regex_is_valid(test_case)




    @ddt.data(
        {'regex': r"(ab|cd|)+", 'nodes': [{"contents": ["ab", "cd", ""], "qty": (1, None)}]},
        {'regex': r"(ab||cd)", 'nodes': [{"contents": ["ab", "", "cd"]}]},
        {'regex': r"(|ab|cd|ef|gh)+", 'nodes': [{"contents": ["", "ab", "cd", "ef", "gh"], "qty": (1, None)}]},
        {'regex': r"(|)+", 'nodes': [{"contents": ["", ""], "qty": (1, None)}]},
        {'regex': r"(|||)+", 'nodes': [{"contents": ["", "", "", ""], "qty": (1, None)}]},
    )
    def test_or_in_parenthesis(self, test_case):
        self.assert_regex_is_valid(test_case)



    @ddt.data(
        {'regex': r"[e]", 'nodes': [{"alphabet": "e"}]},
        {'regex': r"[caty]", 'nodes': [{"alphabet": "caty"}]},
        {'regex': r"[abcd][efghij]", 'nodes': [{"alphabet": "abcd"}, {"alphabet": "efghij"}]},
        {'regex': r"[cake]awesome", 'nodes': [{"alphabet": "cake"}, {"contents": ["awesome"]}]},

        {'regex': r"[foo][bar][foo]",
         'nodes': [{"alphabet": "foo"}, {"alphabet": "bar"}, {"alphabet": "foo"}]},

        {'regex': r"dashboard[apple][purple]",
         'nodes': [{"contents": ["dashboard"]}, {"alphabet": "apple"}, {"alphabet": "purple"}]},

        {'regex': r"[harder]better[faster]",
         'nodes': [{"alphabet": "harder"}, {"contents": ["better"]}, {"alphabet": "faster"}]},

        {'regex': r"[stronger][it is me]baby",
         'nodes': [{"alphabet": "stronger"}, {"alphabet": "it is me"}, {"contents": ["baby"]}]},

        {'regex': r"new[york]city",
         'nodes': [{"contents": ["new"]}, {"alphabet": "york"}, {"contents": ["city"]}]},

        {'regex': r"[a-e]", 'nodes': [{"alphabet": "abcde"}]},
        {'regex': r"[a-ewxy]", 'nodes': [{"alphabet": "abcdewxy"}]},
        {'regex': r"[1-9]", 'nodes': [{"alphabet": "123456789"}]},
        {'regex': r"[what1-9]", 'nodes': [{"alphabet": "what123456789"}]},
        {'regex': r"[a-c1-9]", 'nodes': [{"alphabet": "abc123456789"}]},
        {'regex': r"[a-c1-9fin]", 'nodes': [{"alphabet": "abc123456789fin"}]},

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

        {'regex': r"|", 'nodes': [{"contents": ["",""]}]},
        {'regex': r"|||", 'nodes': [{"contents": ["", "", "", ""]}]},
        {'regex': r"toto|titi|tata", 'nodes': [{"contents": ["toto", "titi", "tata"]}]},
        {'regex': r"toto|titi|", 'nodes': [{"contents": ["toto", "titi", ""]}]},
        {'regex': r"toto||tata", 'nodes': [{"contents": ["toto", "", "tata"]}]},
        {'regex': r"|titi|tata", 'nodes': [{"contents": ["", "titi", "tata"]}]},
        {'regex': r"coucou|[abcd]|", 'nodes': [{"contents": ["coucou"]}, {"alphabet": "abcd"}, {"contents": [""]}]},

        {'regex': r"|[hao]|[salut]?",
         'nodes': [{"contents": [""]}, {"alphabet": "hao"}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': r"coucou||[salut]?",
         'nodes': [{"contents": ["coucou", ""]}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': r"coucou||||[salut]?",
         'nodes': [{"contents": ["coucou", "", "", ""]}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': r"[whatever]+|[hao]|[salut]?",
         'nodes': [
             {"alphabet": "whatever", "qty": (1, None)},
             {"alphabet": "hao"},
             {"alphabet": "salut", "qty": (0, 1)}
         ]},

        {'regex': r"(whatever)+|(hao)|(salut)?",
         'nodes': [
             {"contents": ["whatever"], "qty": (1, None)},
             {"contents": ["hao"]},
             {"contents": ["salut"], "qty": (0, 1)}
         ]},


        {'regex': r"tata|haha|c*|b*|[abcd]+", 'nodes': [
            {"contents": ["tata", "haha"]},
            {"contents": ["c"], "qty": (0, None)},
            {"contents": ["b"], "qty": (0, None)},
            {"alphabet": "abcd", "qty": (1, None)}
        ]},

        {'regex': r"(tata)+|haha|tata||b*|[abcd]+", 'nodes': [
            {"contents": ["tata"], "qty": (1, None)},
            {"contents": ["haha", "tata", ""]},
            {"contents": ["b"], "qty": (0, None)},
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

            contents = nodes[i]['contents'] if 'contents' in nodes[i] else None
            alphabet = nodes[i]['alphabet'] if 'alphabet' in nodes[i] else None
            qty = nodes[i]['qty'] if 'qty' in nodes[i] else (1, 1)

            calls.append(mock.call("name" + str(i + 1), vt.String, contents=contents, alphabet=alphabet, qty=qty))

        self._parser._create_terminal_node.assert_has_calls(calls)


    def assert_regex_is_invalid(self, regex):
        self.assertRaises(Exception, self._parser.parse, regex, "name")