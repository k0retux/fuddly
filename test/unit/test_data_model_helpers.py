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
              r"whatever|toto?ff", r"whate?ver|toto", r"(toto)*ohoho|haha", r"(toto)ohoho|haha")
    def test_invalid_regexes(self, regex):
        self.assertRaises(Exception, self._parser.run, regex, "toto")

    @ddt.data(r"", r"b", r"salut")
    def test_one_word(self, regex):
        self._parser.run(regex, "toto")
        self._parser._create_terminal_node.assert_called_once_with("toto1", vt.String,
                                                                   contents=[regex],
                                                                   alphabet=None, qty=(1, 1))

    @ddt.data(r"(salut)(les)(louloux)", r"(salut)les(louloux)",
              r"salut(les)(louloux)", r"(salut)(les)louloux", r"salut(les)louloux")
    def test_with_parenthesis(self, regex):
        nodes = self._parser.run(regex, "toto")
        self.assertEquals(len(nodes), 3)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=["salut"], alphabet=None, qty=(1, 1)),
             mock.call("toto2", vt.String, contents=["les"], alphabet=None, qty=(1, 1)),
             mock.call("toto3", vt.String, contents=["louloux"], alphabet=None, qty=(1, 1))])


    @ddt.data(r"salut(l\(es)(lou\\loux)cmoi", r"salut(l\(es)lou\\loux(cmoi)")
    def test_escape_char(self, regex):
        nodes = self._parser.run(regex, "toto")
        self.assertEquals(len(nodes), 4)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=["salut"], alphabet=None, qty=(1, 1)),
             mock.call("toto2", vt.String, contents=["l(es"], alphabet=None, qty=(1, 1)),
             mock.call("toto3", vt.String, contents=["lou\loux"], alphabet=None, qty=(1, 1)),
             mock.call("toto4", vt.String, contents=["cmoi"], alphabet=None, qty=(1, 1))])

    @ddt.unpack
    @ddt.data(('?', (0, 1)), ('*', (0, None)), ('+', (1, None)),
              ('{7}', (7, 7)), ('{2,7}', (2, 7)),
              ('{0}', (0, 0)), ('{0,0}', (0, 0)),
              ('{3,}', (3, None)), ('{,15}', (0, 15)))
    def test_7(self, char, qty):
        nodes = self._parser.run(r"salut" + char + "ooo", "toto")
        self.assertEquals(len(nodes), 3)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=["salu"], alphabet=None, qty=(1, 1)),
             mock.call("toto2", vt.String, contents=["t"], alphabet=None, qty=qty),
             mock.call("toto3", vt.String, contents=["ooo"], alphabet=None, qty=(1, 1))])

    @ddt.unpack
    @ddt.data(('?', (0, 1)), ('*', (0, None)), ('+', (1, None)),
              ('{7}', (7, 7)), ('{2,7}', (2, 7)),
              ('{0}', (0, 0)), ('{0,0}', (0, 0)),
              ('{3,}', (3, None)), ('{,15}', (0, 15)))
    def test_7(self, char, qty):
        nodes = self._parser.run(r"salut[abcd]" + char + "ooo", "toto")
        self.assertEquals(len(nodes), 3)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=["salut"], alphabet=None, qty=(1, 1)),
             mock.call("toto2", vt.String, contents=None, alphabet="abcd", qty=qty),
             mock.call("toto3", vt.String, contents=["ooo"], alphabet=None, qty=(1, 1))])

    @ddt.unpack
    @ddt.data(('?', (0, 1)), ('*', (0, None)), ('+', (1, None)),
              ('{7}', (7, 7)), ('{2,7}', (2, 7)),
              ('{0}', (0, 0)), ('{0,0}', (0, 0)),
              ('{3,}', (3, None)), ('{,15}', (0, 15)))
    def test_8(self, char, qty):
        nodes = self._parser.run(r"salu(ttteee|whatever)"
                                 + char
                                 + "ooo", "toto")
        self.assertEquals(len(nodes), 3)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=["salu"], alphabet=None, qty=(1, 1)),
             mock.call("toto2", vt.String, contents=["ttteee", "whatever"], alphabet=None, qty=qty),
             mock.call("toto3", vt.String, contents=["ooo"], alphabet=None, qty=(1, 1))])


    def test_alphabet(self):
        nodes = self._parser.run(r"salut[abc]ooo", "toto")
        self.assertEquals(len(nodes), 3)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=["salut"], alphabet=None, qty=(1, 1)),
             mock.call("toto2", vt.String, contents=None, alphabet="abc", qty=(1, 1)),
             mock.call("toto3", vt.String, contents=["ooo"], alphabet=None, qty=(1, 1))])


    def test_empty_parenthesis_before(self):
        nodes = self._parser.run(r"()+whatever", "toto")
        self.assertEquals(len(nodes), 2)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=[""], alphabet=None, qty=(1, None)),
             mock.call("toto2", vt.String, contents=["whatever"], alphabet=None, qty=(1, 1))])

    def test_empty_brackets(self):
        nodes = self._parser.run(r"[]whatever", "toto")
        self.assertEquals(len(nodes), 2)
        self._parser._create_terminal_node.assert_has_calls(
            [mock.call("toto1", vt.String, contents=None, alphabet="", qty=(1, 1)),
             mock.call("toto2", vt.String, contents=["whatever"], alphabet=None, qty=(1, 1))])


    def regex_assert(self, regex, nodes):

        ns = self._parser.run(regex, "name")
        self.assertEquals(len(ns), len(nodes))

        calls = []
        for node in nodes:
            calls.append(mock.call("name" + str(nodes.index(node) + 1), vt.String,
                                   contents=node[0], alphabet=node[1], qty=node[2]))

        self._parser._create_terminal_node.assert_has_calls(calls)


    @ddt.unpack
    @ddt.data(
        # (regex, nodes=[(contents, alphabet, qty)])
        (r"[abcd]*toto(|\(ab\)|cd)+what?ever", [(None, "abcd", (0, None)),
                                                (["toto"], None, (1, 1)),
                                                (["", "(ab)", "cd"], None, (1, None)),
                                                (["wha"], None, (1, 1)),
                                                (["t"], None, (0, 1)),
                                                (["ever"], None, (1, 1))])
    )
    def test_complete(self, regex, nodes):
        self.regex_assert(regex, nodes)


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
