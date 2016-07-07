from framework.data_model_helpers import *
import framework.value_types as vt
import unittest
import ddt
from test import mock


@ddt.ddt
class RegexParserTest(unittest.TestCase):
    """Test case used to test the 'ProbeUser' class."""

    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        """Initialisation des tests."""
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
        self.assertRaises(Exception, self._parser.parse, regex, "name")


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


    @ddt.unpack
    @ddt.data(
        (r"salut(l\(es)(lou\\lous)cmoi", [(["salut"], None, (1, 1)),
                                (["l(es"], None, (1, 1)),
                                (["lou\lous"], None, (1, 1)),
                                (["cmoi"], None, (1, 1))]),

        (r"salut(l\(es)lou\\lous(cmoi)", [(["salut"], None, (1, 1)),
                                (["l(es"], None, (1, 1)),
                                (["lou\lous"], None, (1, 1)),
                                          (["cmoi"], None, (1, 1))]),

        (r"()+whatever",            [([""], None, (1, None)),
                                     (["whatever"], None, (1, 1))]),

        (r"salut[abc]ooo",          [(["salut"], None, (1, 1)),
                                     (None, "abc", (1, 1)),
                                     (["ooo"], None, (1, 1))]),
    )
    def test_various(self, regex, nodes):
        self.regex_assert(regex, nodes)



    @ddt.data(r"?", r"*", r"+", r"{1,2}", r"what{,}ever", r"bj{}er"
              r"what{1, 2}", r"what{,3}ever", r"ee{l1, 2}ever", r"whddddat{\13, 2}eyyyver",
              r"wat{3,2d}eyyyver", r"w**r", r"w+*r", r"w*?r")
    def test_quantifier_raise(self, regex):
        self.regex_raise(regex)

    @ddt.data(r"salut(", r"dd[", r"(", r"[", r"{0")
    def test_wrong_end_raise(self, regex):
        self.regex_raise(regex)


    def regex_raise(self, regex):
        self.assertRaises(Exception, self._parser.parse, regex, "name")


    def regex_assert(self, regex, nodes):

        self._parser.parse(regex, "name")
        self.assertEquals(self._parser._create_terminal_node.call_count, len(nodes))

        calls = []
        for node in nodes:
            calls.append(mock.call("name" + str(nodes.index(node) + 1), vt.String,
                                   contents=node[0], alphabet=node[1], qty=node[2]))

        self._parser._create_terminal_node.assert_has_calls(calls)


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
        self.regex_assert_json(test_case)


    @ddt.unpack
    @ddt.data(
        (r"(ab|cd|)+", [(["ab", "cd", ""], None, (1, None))]),
        (r"(ab||cd)", [(["ab", "", "cd"], None, (1, 1))]),
        (r"(|ab|cd|ef|gh)+", [(["", "ab", "cd", "ef", "gh"], None, (1, None))]),
        (r"(|)+", [(["", ""], None, (1, None))]),
        (r"(|||)+", [(["", "", "", ""], None, (1, None))]),
    )
    def test_or_in_parenthesis(self, regex, nodes):
        self.regex_assert(regex, nodes)


    @ddt.unpack
    @ddt.data(
        (r"tata|haha|c*|b*|[abcd]+",        [(["tata", "haha"],         None,   (1, 1)),
                                             (["c"],                    None,   (0, None)),
                                             (["b"],                    None,   (0, None)),
                                             (None,                     "abcd", (1, None))]),

        (r"(tata)+|haha|tata||b*|[abcd]+",  [(["tata"],                 None,   (1, None)),
                                             (["haha", "tata", ""],     None,   (1, 1)),
                                             (["b"],                    None,   (0, None)),
                                             (None,                     "abcd", (1, None))]),

        (r"toto|titi|tata",                 [(["toto", "titi", "tata"], None,   (1, 1))]),

        (r"|",                              [(["",""],                  None,   (1, 1))]),

        (r"coucou|[abcd]|",                 [(["coucou"],               None,   (1, 1)),
                                             (None,                     "abcd", (1, 1)),
                                             ([""],                     None,   (1, 1))]),

        (r"[whatever]+|[hao]|[salut]?",     [(None,                     "whatever", (1, None)),
                                             (None,                     "hao", (1, 1)),
                                             (None,                     "salut", (0, 1))]),

        (r"|[hao]|[salut]?",                [([""],                     None, (1, 1)),
                                             (None,                     "hao", (1, 1)),
                                             (None,                     "salut", (0, 1))]),
        (r"coucou||[salut]?",               [(["coucou", ""],           None, (1, 1)),
                                             (None,                     "salut", (0, 1))]),
        (r"coucou||||[salut]?",             [(["coucou", "", "", ""], None, (1, 1)),
                                             (None, "salut", (0, 1))])
    )
    def test_pick(self, regex, nodes):
        self.regex_assert(regex, nodes)




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
        self.regex_assert_json(test_case)



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
    )
    def test_basic_square_brackets(self, test_case):
        self.regex_assert_json(test_case)


    @ddt.data(r"[]", r"stronger[]baby", r"strongerbaby[]", r"[]strongerbaby", r"stro[]nger[]baby[]")
    def test_basic_square_brackets_raise(self, regex):
        self.regex_raise(regex)


    def regex_assert_json(self, test_case):

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