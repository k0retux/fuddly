from framework.node_builder import *
import framework.value_types as vt
import unittest
import ddt
import six
from test import mock

ASCII_EXT = ''.join([(chr if sys.version_info[0] == 2 else six.unichr)(i) for i in range(0, 0xFF + 1)])


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

    @ddt.data({'regex': "(sa(lu))(les)(louloux)"}, {'regex': "(salut)(les(louloux)"},
              {'regex': "(salut))les(louloux)"}, {'regex': "(sal*ut)oo"}, {'regex': "(sal?ut)oo"},
              {'regex': "sal{utoo"}, {'regex': "(sal+ut)oo"}, {'regex': "(sal{u)too"},
              {'regex': "(sal{2}u)too"}, {'regex': "sal{2,1}utoo"}, {'regex': "sal(u[t]o)o"},
              {'regex': "salut[abcd]{,15}rr"}, {'regex': "[]whatever"},
              {'regex': "t{,15}"}, {'regex': "whatever(bar.foo)"})
    def test_invalid_regexes(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data(
        {'regex': "whatever|toto?ff",
         'nodes': [
             {'values': ['whatever']},
             {'values': ['tot']},
             {'values': ['o'], 'qty': (0, 1)},
             {'values': ['ff']}]},
        {'regex': "whate?ver|toto",
         'nodes': [
             {'values': ['what']},
             {'values': ['e'], 'qty': (0, 1)},
             {'values': ['ver']},
             {'values': ['toto']}]},
        {'regex': "(toto)*ohoho|haha",
         'nodes': [
             {'values': ['toto'], 'qty':(0, None)},
             {'values': ['ohoho']},
             {'values': ['haha']}]},
        {'regex': "(toto)ohoho|haha",
         'nodes': [
             {'values': ['toto']},
             {'values': ['ohoho']},
             {'values': ['haha']}]},
        {'regex': "hi|b?whatever",
         'nodes': [
             {'values': ['hi']},
             {'values': ['b'], 'qty': (0, 1)},
             {'values': ['whatever']}]},
        {'regex': "hi|b{3}whatever",
         'nodes': [
             {'values': ['hi']},
             {'values': ['b'], 'qty': (3, 3)},
             {'values': ['whatever']}]},
    )
    def test_shapes(self, test_case):
        self.assert_regex_is_valid(test_case)

    @ddt.data(
        {'regex': ".", 'nodes': [{"alphabet": ASCII_EXT}]},
        {'regex': "this.is",
         'nodes': [
             {"values": ["this"]},
             {"alphabet": ASCII_EXT},
             {"values": ["is"]}]},
        {'regex': "[fo.bar]hello", 'nodes': [{"alphabet": "fo.bar"}, {"values": ["hello"]}]},
        {'regex': "[bar].(hel).+lo",
         'nodes': [
             {"alphabet": "bar"},
             {"alphabet": ASCII_EXT},
             {"values": ["hel"]},
             {"alphabet": ASCII_EXT, 'qty': (1, None)},
             {"values": ["lo"]}]},
    )
    def test_dot(self, test_case):
        self.assert_regex_is_valid(test_case)

    @ddt.data(
        {'regex': "[abcd]?", 'nodes': [{"alphabet": "abcd", "qty": (0, 1)}]},
        {'regex': "[abcd]*", 'nodes': [{"alphabet": "abcd", "qty": (0, None)}]},
        {'regex': "[abcd]+", 'nodes': [{"alphabet": "abcd", "qty": (1, None)}]},
        {'regex': "[abcd]{7}", 'nodes': [{"alphabet": "abcd", "qty": (7, 7)}]},
        {'regex': "[abcd]{2,7}", 'nodes': [{"alphabet": "abcd", "qty": (2, 7)}]},
        {'regex': "[abcd]{0}", 'nodes': [{"alphabet": "abcd", "qty": (0, 0)}]},
        {'regex': "[abcd]{0,0}", 'nodes': [{"alphabet": "abcd", "qty": (0, 0)}]},
        {'regex': "[abcd]{3,}", 'nodes': [{"alphabet": "abcd", "qty": (3, None)}]},
    )
    def test_quantifiers(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': "salut(l\(es)(lou\\\\lous)cmoi",
         'nodes': [
             {"values": ["salut"]},
             {"values": ["l(es"]},
             {"values": ["lou\lous"]},
             {"values": ["cmoi"]},
         ]},
        {'regex': "hi\x58", 'nodes': [{"values": ["hi\x58"]}]},
        {'regex': "hi\x00hola", 'nodes': [{"values": ["hi\x00hola"]}]},
        {'regex': "\xFFdom", 'nodes': [{"values": ["\xFFdom"]}]},
        {'regex': "\ddom",
         'nodes': [{"values": [i for i in range(0,10)], "type": vt.INT_str}, {"values": ["dom"]}]},
        {'regex': "dom[abcd\d]", 'nodes': [{"values": ["dom"]}, {"alphabet": "abcd0123456789"}]},
        {'regex': "[abcd]\x43", 'nodes': [{"alphabet": "abcd"}, {"values": ["\x43"]}]},
        {'regex': "(abcd)\x53", 'nodes': [{"values": ["abcd"]}, {"values": ["\x53"]}]},
        {'regex': "\x43[abcd]", 'nodes': [{"values": ["\x43"]}, {"alphabet": "abcd"}]},
        {'regex': "\x43(abcd)", 'nodes': [{"values": ["\x43"]}, {"values": ["abcd"]}]},
        {'regex': u"\u0443(abcd)", "charset": MH.Charset.UNICODE,
         'nodes': [{"values": [u"\u0443"]}, {"values": [u"abcd"]}]},
        {'regex': u"hi(ab\u0443cd)", "charset": MH.Charset.UNICODE,
         'nodes': [{"values": [u"hi"]}, {"values": [u"ab\u0443cd"]}]},
        {'regex': u"(333|444)|foo-bar|\d|[th|is]",
         'nodes': [
             {"type": fvt.INT_str, "values": [333,444]},
             {"values": [u"foo-bar"]},
             {"values": [i for i in range(0,10)], "type": vt.INT_str},
             {"alphabet": "th|is"}]},
        {'regex': u"(333|444)|foo-bar|\||[th|is]",
         'nodes': [
             {"type": fvt.INT_str, "values": [333, 444]},
             {"values": [u"foo-bar", "|"]},
             {"alphabet": "th|is"}]},

    )
    def test_escape(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data({'regex': "?"}, {'regex': "*"}, {'regex': "+"}, {'regex': "{1,2}"}, {'regex': "what{,}ever"},
              {'regex': "bj{}er"},{'regex': "what{1, 2}"}, {'regex': "what{,3}ever"}, {'regex': "ee{l1, 2}ever"},
              {'regex': "whddddat{\13, 2}eyyyver"}, {'regex': "wat{3,2d}eyyyver"}, {'regex': "w**r"},
              {'regex': "w+*r"}, {'regex': "w*?r"})
    def test_quantifier_raise(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data({'regex': "salut("}, {'regex': "dd["}, {'regex': "("}, {'regex': "["}, {'regex': "{0"})
    def test_wrong_end_raise(self, regex):
        self.assert_regex_is_invalid(regex)


    @ddt.data(
        {'regex': "[abcd]*toto(|\(ab\)|cd)+what?ever",
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
        {'regex': "()", 'nodes': [{"values": [""]}]},
        {'regex': "(z)", 'nodes': [{"values": ["z"]}]},
        {'regex': "(cat)", 'nodes': [{"values": ["cat"]}]},

        {'regex': "hello(boat)",
         'nodes': [{"values": ["hello"]}, {"values": ["boat"]}]},

        {'regex': "(cake)awesome",
         'nodes': [{"values": ["cake"]}, {"values": ["awesome"]}]},

        {'regex': "(foo)(bar)(foo)",
         'nodes': [{"values": ["foo"]}, {"values": ["bar"]}, {"values": ["foo"]}]},

        {'regex': "dashboard(apple)(purple)",
         'nodes': [{"values": ["dashboard"]}, {"values": ["apple"]}, {"values": ["purple"]}]},

        {'regex': "(harder)better(faster)",
         'nodes': [{"values": ["harder"]}, {"values": ["better"]}, {"values": ["faster"]}]},

        {'regex': "(stronger)(it is me)baby",
         'nodes': [{"values": ["stronger"]}, {"values": ["it is me"]}, {"values": ["baby"]}]},

        {'regex': "new(york)city",
         'nodes': [{"values": ["new"]}, {"values": ["york"]}, {"values": ["city"]}]},

        {'regex': "()whatever",
         'nodes': [{"values": [""]}, {"values": ["whatever"]}]},

        {'regex': "this is it()",
         'nodes': [{"values": ["this is it"]}, {"values": [""]}]},

        {'regex': "this()parser()is()working",
         'nodes': [{"values": ["this"]}, {"values": [""]}, {"values": ["parser"]}, {"values": [""]},
                   {"values": ["is"]},   {"values": [""]}, {"values": ["working"]}]},

        {'regex': "()()()",
         'nodes': [{"values": [""]}, {"values": [""]}, {"values": [""]}]},
    )
    def test_basic_parenthesis(self, test_case):
        self.assert_regex_is_valid(test_case)




    @ddt.data(
        {'regex': "(ab|cd|)+", 'nodes': [{"values": ["ab", "cd", ""], "qty": (1, None)}]},
        {'regex': "(ab||cd)", 'nodes': [{"values": ["ab", "", "cd"]}]},
        {'regex': "(|ab|cd|ef|gh)+", 'nodes': [{"values": ["", "ab", "cd", "ef", "gh"], "qty": (1, None)}]},
        {'regex': "(|)+", 'nodes': [{"values": ["", ""], "qty": (1, None)}]},
        {'regex': "(|||)+", 'nodes': [{"values": ["", "", "", ""], "qty": (1, None)}]},
    )
    def test_or_in_parenthesis(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': "1|2|3", 'nodes': [{"type": fvt.INT_str, "values": [1,2,3]}]},
        {'regex': "1|2|3|foo", 'nodes': [{"values": ['1', '2', '3', 'foo']}]},
        {'regex': "1|foo|2|3", 'nodes': [{"values": ['1', 'foo', '2', '3']}]},
        {'regex': "foo|1|2|3", 'nodes': [{"values": ['foo', '1', '2', '3']}]},
        {'regex': "(11|12|13)bar",
         'nodes': [{"type": fvt.INT_str, "values": [11, 12, 13]}, {"values": ['bar']}]},
        {'regex': "(11|12|13|bar)",
         'nodes': [{"values": ['11', '12', '13', 'bar']}]},
        {'regex': "234whatever23", 'nodes': [{"values": ['234whatever23']}]},
        {'regex': "(234whatever23)foobar",
         'nodes': [{"values": ['234whatever23']}, {"values": ['foobar']}]},
        {'regex': "1113|3435|3344|(hay)",
         'nodes': [{"type": fvt.INT_str, "values": [1113, 3435, 3344]}, {"values": ['hay']}]},
    )
    def test_types_recognition(self, test_case):
        self.assert_regex_is_valid(test_case)



    @ddt.data(
        {'regex': "[e]", 'nodes': [{"alphabet": "e"}]},
        {'regex': "[caty]", 'nodes': [{"alphabet": "caty"}]},
        {'regex': "[abcd][efghij]", 'nodes': [{"alphabet": "abcd"}, {"alphabet": "efghij"}]},
        {'regex': "[cake]awesome", 'nodes': [{"alphabet": "cake"}, {"values": ["awesome"]}]},

        {'regex': "[foo][bar][foo]",
         'nodes': [{"alphabet": "foo"}, {"alphabet": "bar"}, {"alphabet": "foo"}]},

        {'regex': "dashboard[apple][purple]",
         'nodes': [{"values": ["dashboard"]}, {"alphabet": "apple"}, {"alphabet": "purple"}]},

        {'regex': "[harder]better[faster]",
         'nodes': [{"alphabet": "harder"}, {"values": ["better"]}, {"alphabet": "faster"}]},

        {'regex': "[stronger][it is me]baby",
         'nodes': [{"alphabet": "stronger"}, {"alphabet": "it is me"}, {"values": ["baby"]}]},

        {'regex': "new[york]city",
         'nodes': [{"values": ["new"]}, {"alphabet": "york"}, {"values": ["city"]}]},

        {'regex': "[a-e]", 'nodes': [{"alphabet": "abcde"}]},
        {'regex': "[a-ewxy]", 'nodes': [{"alphabet": "abcdewxy"}]},
        {'regex': "[1-9]", 'nodes': [{"values": [i for i in range(1,10)], 'type': vt.INT_str}]},
        {'regex': "[what1-9]", 'nodes': [{"alphabet": "what123456789"}]},
        {'regex': "[a-c1-9]", 'nodes': [{"alphabet": "abc123456789"}]},
        {'regex': "[a-c1-9fin]", 'nodes': [{"alphabet": "abc123456789fin"}]},
        {'regex': "[a-c9-9fin]", 'nodes': [{"alphabet": "abc9fin"}]},
        {'regex': "[pa-cwho1-9fin]", 'nodes': [{"alphabet": "pabcwho123456789fin"}]},

        {'regex': "[\x33]", 'nodes': [{"values": [3], 'type': vt.INT_str}]},
        {'regex': "[\x33-\x35]", 'nodes': [{"values": [3,4,5], 'type': vt.INT_str}]},
        {'regex': "[e\x33-\x35a]", 'nodes': [{"alphabet": "e\x33\x34\x35a"}]},

        {'regex': u"[\u0033]", "charset": MH.Charset.UNICODE,
         'nodes': [{"values": [3], 'type': vt.INT_str}]},
        {'regex': u"[\u0003-\u0005]", "charset": MH.Charset.UNICODE,
         'nodes': [{"alphabet": u"\u0003\u0004\u0005"}]},
        {'regex': u"[\u0333-\u0335]", "charset": MH.Charset.UNICODE,
         'nodes': [{"alphabet": u"\u0333\u0334\u0335"}]},
        {'regex': u"[e\u4133-\u4135a]", "charset": MH.Charset.UNICODE,
         'nodes': [{"alphabet": u"e\u4133\u4134\u4135a"}]}
    )
    def test_basic_square_brackets(self, test_case):
        self.assert_regex_is_valid(test_case)

    @ddt.data({'regex': "[\x33-\x23]"}, {'regex': "[3-1]"}, {'regex': "[y-a]"},
              {'regex': u"[\u7633-\u7323]", "charset": MH.Charset.UNICODE})
    def test_wrong_alphabet(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data({'regex': "[]"}, {'regex': "stronger[]baby"}, {'regex': "strongerbaby[]"},
              {'regex': "[]strongerbaby"}, {'regex': "stro[]nger[]baby[]"})
    def test_basic_square_brackets_raise(self, regex):
        self.assert_regex_is_invalid(regex)



    @ddt.data(
        {'regex': "|", 'nodes': [{"values": ["",""]}]},
        {'regex': "|||", 'nodes': [{"values": ["", "", "", ""]}]},
        {'regex': "toto|titi|tata", 'nodes': [{"values": ["toto", "titi", "tata"]}]},
        {'regex': "toto|titi|", 'nodes': [{"values": ["toto", "titi", ""]}]},
        {'regex': "toto||tata", 'nodes': [{"values": ["toto", "", "tata"]}]},
        {'regex': "|titi|tata", 'nodes': [{"values": ["", "titi", "tata"]}]},
        {'regex': "coucou|[abcd]|", 'nodes': [{"values": ["coucou"]}, {"alphabet": "abcd"}, {"values": [""]}]},

        {'regex': "|[hao]|[salut]?",
         'nodes': [{"values": [""]}, {"alphabet": "hao"}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': "coucou||[salut]?",
         'nodes': [{"values": ["coucou", ""]}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': "coucou||||[salut]?",
         'nodes': [{"values": ["coucou", "", "", ""]}, {"alphabet": "salut", "qty": (0, 1)}]},

        {'regex': "[whatever]+|[hao]|[salut]?",
         'nodes': [
             {"alphabet": "whatever", "qty": (1, None)},
             {"alphabet": "hao"},
             {"alphabet": "salut", "qty": (0, 1)}
         ]},

        {'regex': "(whatever)+|(hao)|(salut)?",
         'nodes': [
             {"values": ["whatever"], "qty": (1, None)},
             {"values": ["hao"]},
             {"values": ["salut"], "qty": (0, 1)}
         ]},


        {'regex': "tata|haha|c*|b*|[abcd]+", 'nodes': [
            {"values": ["tata", "haha"]},
            {"values": ["c"], "qty": (0, None)},
            {"values": ["b"], "qty": (0, None)},
            {"alphabet": "abcd", "qty": (1, None)}
        ]},

        {'regex': "(tata)+|haha|tata||b*|[abcd]+", 'nodes': [
            {"values": ["tata"], "qty": (1, None)},
            {"values": ["haha", "tata", ""]},
            {"values": ["b"], "qty": (0, None)},
            {"alphabet": "abcd", "qty": (1, None)}
        ]},
    )
    def test_shape(self, test_case):
        self.assert_regex_is_valid(test_case)



    def assert_regex_is_valid(self, test_case):

        charset = test_case['charset'] if 'charset' in test_case else MH.Charset.ASCII_EXT
        self._parser.parse(test_case['regex'], "name", charset)


        calls = []
        nodes = test_case['nodes']
        for i in range(0, len(nodes)):

            type = nodes[i]['type'] if 'type' in nodes[i] else vt.String
            values = nodes[i]['values'] if 'values' in nodes[i] else None
            alphabet = nodes[i]['alphabet'] if 'alphabet' in nodes[i] else None
            qty = nodes[i]['qty'] if 'qty' in nodes[i] else (1, 1)

            calls.append(mock.call("name" + "_" + str(i + 1), type, values=values, alphabet=alphabet, qty=qty))

        self._parser._create_terminal_node.assert_has_calls(calls)

        self.assertEqual(self._parser._create_terminal_node.call_count, len(test_case['nodes']))


    def assert_regex_is_invalid(self, test_case):
        charset = test_case['charset'] if 'charset' in test_case else MH.Charset.ASCII_EXT
        self.assertRaises(Exception, self._parser.parse, test_case['regex'], "name", charset)