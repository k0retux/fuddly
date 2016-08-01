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

    @ddt.data(u"(sa(lu))(les)(louloux)", u"(salut)(les(louloux)", u"(salut))les(louloux)",
              u"(sal*ut)oo", u"(sal?ut)oo", u"sal{utoo", u"(sal+ut)oo", u"(sal{u)too",
              u"(sal{2}u)too", u"sal{2,1}utoo", u"sal(u[t]o)o",
              u"whatever|toto?ff", u"whate?ver|toto", u"(toto)*ohoho|haha", u"(toto)ohoho|haha",
              u"salut[abcd]{,15}rr", u"[]whatever", u"t{,15}", u"hi|b?whatever", u"hi|b{3}whatever")
    def test_invalid_regexes(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data(
        {'regex': u"[abcd]?", 'nodes': [{"alphabet": u"abcd", "qty": (0, 1)}]},
        {'regex': u"[abcd]*", 'nodes': [{"alphabet": u"abcd", "qty": (0, None)}]},
        {'regex': u"[abcd]+", 'nodes': [{"alphabet": u"abcd", "qty": (1, None)}]},
        {'regex': u"[abcd]{7}", 'nodes': [{"alphabet": u"abcd", "qty": (7, 7)}]},
        {'regex': u"[abcd]{2,7}", 'nodes': [{"alphabet": u"abcd", "qty": (2, 7)}]},
        {'regex': u"[abcd]{0}", 'nodes': [{"alphabet": u"abcd", "qty": (0, 0)}]},
        {'regex': u"[abcd]{0,0}", 'nodes': [{"alphabet": u"abcd", "qty": (0, 0)}]},
        {'regex': u"[abcd]{3,}", 'nodes': [{"alphabet": u"abcd", "qty": (3, None)}]},
    )
    def test_quantifiers(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': u"salut(l\(es)(lou\\\\lous)cmoi",
         'nodes': [
             {"values": [u"salut"]},
             {"values": [u"l(es"]},
             {"values": [u"lou\lous"]},
             {"values": [u"cmoi"]},
         ]},
        {'regex': u"hi\x58", 'nodes': [{"values": [u"hi\x58"]}]},
        {'regex': u"hi\x00hola", 'nodes': [{"values": [u"hi\x00hola"]}]},
        {'regex': u"\xFFdom", 'nodes': [{"values": [u"\xFFdom"]}]},
        {'regex': u"\ddom", 'nodes': [{"alphabet": u"0123456789"}, {"values": [u"dom"]}]},
        {'regex': u"dom[abcd\d]", 'nodes': [{"values": [u"dom"]}, {"alphabet": u"abcd0123456789"}]},
        {'regex': u"[abcd]\x43", 'nodes': [{"alphabet": u"abcd"}, {"values": [u"\x43"]}]},
        {'regex': u"(abcd)\x53", 'nodes': [{"values": [u"abcd"]}, {"values": [u"\x53"]}]},
        {'regex': u"\x43[abcd]", 'nodes': [{"values": [u"\x43"]}, {"alphabet": u"abcd"}]},
        {'regex': u"\x43(abcd)", 'nodes': [{"values": [u"\x43"]}, {"values": [u"abcd"]}]},
        {'regex': u"\u0443(abcd)", 'nodes': [{"values": [u"\u0443"]}, {"values": [u"abcd"]}]},
        {'regex': u"hi(ab\u0443cd)", 'nodes': [{"values": [u"hi"]}, {"values": [u"ab\u0443cd"]}]},
    )
    def test_escape(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(u"?", u"*", u"+", u"{1,2}", u"what{,}ever", u"bj{}er"
              u"what{1, 2}", u"what{,3}ever", u"ee{l1, 2}ever", u"whddddat{\13, 2}eyyyver",
              u"wat{3,2d}eyyyver", u"w**r", u"w+*r", u"w*?r")
    def test_quantifier_raise(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data(u"salut(", u"dd[", u"(", u"[", u"{0")
    def test_wrong_end_raise(self, regex):
        self.assert_regex_is_invalid(regex)


    @ddt.data(
        {'regex': u"[abcd]*toto(|\(ab\)|cd)+what?ever",
         'nodes': [
             {"alphabet": u"abcd", "qty": (0, None)},
             {"values": [u"toto"]},
             {"values": [u"", u"(ab)", u"cd"], "qty": (1, None)},
             {"values": [u"wha"]},
             {"values": [u"t"], "qty": (0, 1)},
             {"values": [u"ever"]}
         ]},
    )
    def test_complete(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': u"()", 'nodes': [{"values": [u""]}]},
        {'regex': u"(z)", 'nodes': [{"values": [u"z"]}]},
        {'regex': u"(cat)", 'nodes': [{"values": [u"cat"]}]},

        {'regex': u"hello(boat)",
         'nodes': [{"values": [u"hello"]}, {"values": [u"boat"]}]},

        {'regex': u"(cake)awesome",
         'nodes': [{"values": [u"cake"]}, {"values": [u"awesome"]}]},

        {'regex': u"(foo)(bar)(foo)",
         'nodes': [{"values": [u"foo"]}, {"values": [u"bar"]}, {"values": [u"foo"]}]},

        {'regex': u"dashboard(apple)(purple)",
         'nodes': [{"values": [u"dashboard"]}, {"values": [u"apple"]}, {"values": [u"purple"]}]},

        {'regex': u"(harder)better(faster)",
         'nodes': [{"values": [u"harder"]}, {"values": [u"better"]}, {"values": [u"faster"]}]},

        {'regex': u"(stronger)(it is me)baby",
         'nodes': [{"values": [u"stronger"]}, {"values": [u"it is me"]}, {"values": [u"baby"]}]},

        {'regex': u"new(york)city",
         'nodes': [{"values": [u"new"]}, {"values": [u"york"]}, {"values": [u"city"]}]},

        {'regex': u"()whatever",
         'nodes': [{"values": [u""]}, {"values": [u"whatever"]}]},

        {'regex': u"this is it()",
         'nodes': [{"values": [u"this is it"]}, {"values": [u""]}]},

        {'regex': u"this()parser()is()working",
         'nodes': [{"values": [u"this"]}, {"values": [u""]}, {"values": [u"parser"]}, {"values": [u""]},
                   {"values": [u"is"]},   {"values": [u""]}, {"values": [u"working"]}]},

        {'regex': u"()()()",
         'nodes': [{"values": [u""]}, {"values": [u""]}, {"values": [u""]}]},
    )
    def test_basic_parenthesis(self, test_case):
        self.assert_regex_is_valid(test_case)




    @ddt.data(
        {'regex': u"(ab|cd|)+", 'nodes': [{"values": [u"ab", u"cd", u""], "qty": (1, None)}]},
        {'regex': u"(ab||cd)", 'nodes': [{"values": [u"ab", u"", u"cd"]}]},
        {'regex': u"(|ab|cd|ef|gh)+", 'nodes': [{"values": [u"", u"ab", u"cd", u"ef", u"gh"], "qty": (1, None)}]},
        {'regex': u"(|)+", 'nodes': [{"values": [u"", u""], "qty": (1, None)}]},
        {'regex': u"(|||)+", 'nodes': [{"values": [u"", u"", u"", u""], "qty": (1, None)}]},
    )
    def test_or_in_parenthesis(self, test_case):
        self.assert_regex_is_valid(test_case)


    @ddt.data(
        {'regex': u"1|2|3", 'nodes': [{"type": fvt.INT_str, "values": [1,2,3]}]},
        {'regex': u"1|2|3|foo", 'nodes': [{"values": [u'1', u'2', u'3', u'foo']}]},
        {'regex': u"1|foo|2|3", 'nodes': [{"values": [u'1', u'foo', u'2', u'3']}]},
        {'regex': u"foo|1|2|3", 'nodes': [{"values": [u'foo', u'1', u'2', u'3']}]},
        {'regex': u"(11|12|13)bar",
         'nodes': [{"type": fvt.INT_str, "values": [11, 12, 13]}, {"values": [u'bar']}]},
        {'regex': u"(11|12|13|bar)",
         'nodes': [{"values": [u'11', u'12', u'13', u'bar']}]},
        {'regex': u"234whatever23", 'nodes': [{"values": [u'234whatever23']}]},
        {'regex': u"(234whatever23)foobar",
         'nodes': [{"values": [u'234whatever23']}, {"values": [u'foobar']}]},
        {'regex': u"1113|3435|3344|(hay)",
         'nodes': [{"type": fvt.INT_str, "values": [1113, 3435, 3344]}, {"values": [u'hay']}]},
    )
    def test_types_recognition(self, test_case):
        self.assert_regex_is_valid(test_case)



    @ddt.data(
        {'regex': u"[e]", 'nodes': [{"alphabet": u"e"}]},
        {'regex': u"[caty]", 'nodes': [{"alphabet": u"caty"}]},
        {'regex': u"[abcd][efghij]", 'nodes': [{"alphabet": u"abcd"}, {"alphabet": u"efghij"}]},
        {'regex': u"[cake]awesome", 'nodes': [{"alphabet": u"cake"}, {"values": [u"awesome"]}]},

        {'regex': u"[foo][bar][foo]",
         'nodes': [{"alphabet": "foo"}, {"alphabet": "bar"}, {"alphabet": "foo"}]},

        {'regex': u"dashboard[apple][purple]",
         'nodes': [{"values": [u"dashboard"]}, {"alphabet": u"apple"}, {"alphabet": u"purple"}]},

        {'regex': u"[harder]better[faster]",
         'nodes': [{"alphabet": u"harder"}, {"values": [u"better"]}, {"alphabet": u"faster"}]},

        {'regex': u"[stronger][it is me]baby",
         'nodes': [{"alphabet": u"stronger"}, {"alphabet": u"it is me"}, {"values": [u"baby"]}]},

        {'regex': u"new[york]city",
         'nodes': [{"values": [u"new"]}, {"alphabet": u"york"}, {"values": [u"city"]}]},

        {'regex': u"[a-e]", 'nodes': [{"alphabet": u"abcde"}]},
        {'regex': u"[a-ewxy]", 'nodes': [{"alphabet": u"abcdewxy"}]},
        {'regex': u"[1-9]", 'nodes': [{"alphabet": u"123456789"}]},
        {'regex': u"[what1-9]", 'nodes': [{"alphabet": u"what123456789"}]},
        {'regex': u"[a-c1-9]", 'nodes': [{"alphabet": u"abc123456789"}]},
        {'regex': u"[a-c1-9fin]", 'nodes': [{"alphabet": u"abc123456789fin"}]},
        {'regex': u"[a-c9-9fin]", 'nodes': [{"alphabet": u"abc9fin"}]},
        {'regex': u"[pa-cwho1-9fin]", 'nodes': [{"alphabet": u"pabcwho123456789fin"}]},

        {'regex': u"[\x33]", 'nodes': [{"alphabet": u"\x33"}]},
        {'regex': u"[\x33-\x35]", 'nodes': [{"alphabet": u"\x33\x34\x35"}]},
        {'regex': u"[e\x33-\x35a]", 'nodes': [{"alphabet": u"e\x33\x34\x35a"}]},

        {'regex': u"[\u0033]", 'nodes': [{"alphabet": u"\u0033"}]},
        {'regex': u"[\u0003-\u0005]", 'nodes': [{"alphabet": u"\u0003\u0004\u0005"}]},
        {'regex': u"[\u0333-\u0335]", 'nodes': [{"alphabet": u"\u0333\u0334\u0335"}]},
        {'regex': u"[e\u4133-\u4135a]", 'nodes': [{"alphabet": u"e\u4133\u4134\u4135a"}]}
    )
    def test_basic_square_brackets(self, test_case):
        self.assert_regex_is_valid(test_case)

    @ddt.data(u"[\x33-\x23]", u"[\u7633-\u7323]", u"[3-1]", u"[y-a]")
    def test_wrong_alphabet(self, regex):
        self.assert_regex_is_invalid(regex)

    @ddt.data(u"[]", u"stronger[]baby", u"strongerbaby[]", u"[]strongerbaby", u"stro[]nger[]baby[]")
    def test_basic_square_brackets_raise(self, regex):
        self.assert_regex_is_invalid(regex)



    @ddt.data(
        {'regex': u"|", 'nodes': [{"values": [u"",u""]}]},
        {'regex': u"|||", 'nodes': [{"values": [u"", u"", u"", u""]}]},
        {'regex': u"toto|titi|tata", 'nodes': [{"values": [u"toto", u"titi", u"tata"]}]},
        {'regex': u"toto|titi|", 'nodes': [{"values": [u"toto", u"titi", u""]}]},
        {'regex': u"toto||tata", 'nodes': [{"values": [u"toto", u"", u"tata"]}]},
        {'regex': u"|titi|tata", 'nodes': [{"values": [u"", u"titi", u"tata"]}]},
        {'regex': u"coucou|[abcd]|", 'nodes': [{"values": [u"coucou"]}, {"alphabet": u"abcd"}, {"values": [u""]}]},

        {'regex': u"|[hao]|[salut]?",
         'nodes': [{"values": [u""]}, {"alphabet": u"hao"}, {"alphabet": u"salut", "qty": (0, 1)}]},

        {'regex': u"coucou||[salut]?",
         'nodes': [{"values": [u"coucou", u""]}, {"alphabet": u"salut", "qty": (0, 1)}]},

        {'regex': u"coucou||||[salut]?",
         'nodes': [{"values": [u"coucou", u"", u"", u""]}, {"alphabet": u"salut", "qty": (0, 1)}]},

        {'regex': u"[whatever]+|[hao]|[salut]?",
         'nodes': [
             {"alphabet": u"whatever", "qty": (1, None)},
             {"alphabet": u"hao"},
             {"alphabet": u"salut", "qty": (0, 1)}
         ]},

        {'regex': u"(whatever)+|(hao)|(salut)?",
         'nodes': [
             {"values": [u"whatever"], "qty": (1, None)},
             {"values": [u"hao"]},
             {"values": [u"salut"], "qty": (0, 1)}
         ]},


        {'regex': u"tata|haha|c*|b*|[abcd]+", 'nodes': [
            {"values": [u"tata", u"haha"]},
            {"values": [u"c"], "qty": (0, None)},
            {"values": [u"b"], "qty": (0, None)},
            {"alphabet": u"abcd", "qty": (1, None)}
        ]},

        {'regex': u"(tata)+|haha|tata||b*|[abcd]+", 'nodes': [
            {"values": [u"tata"], "qty": (1, None)},
            {"values": [u"haha", u"tata", u""]},
            {"values": [u"b"], "qty": (0, None)},
            {"alphabet": u"abcd", "qty": (1, None)}
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