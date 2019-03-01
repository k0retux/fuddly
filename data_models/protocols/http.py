################################################################################
#
#  Copyright 2016 Julien Baladier
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

from framework.data_model import *
from framework.node_builder import NodeBuilder
from framework.value_types import *


class HTTPModel(DataModel):
    name = 'HTTP'

    def build_data_model(self):

        OCTET = "\x00-\xFF"         # any 8-bit sequence of data
        CHAR  = "\x00-\x7F"         # any US-ASCII character (octets 0-127)
        UPALPHA = "A-Z"             # any US-ASCII uppercase letter ("A".."Z")
        LOALPHA = "a-z"             # any US-ASCII lowercase letter ("a".."z")
        ALPHA = UPALPHA + LOALPHA   # UPALPHA or LOALPHA
        DIGIT = "0-9"               # any US-ASCII digit ("0".."9")
        HEX = string.hexdigits
        CTL = "\x7F\x00-\x1F"       # any US-ASCII control character (octets 0 - 31) and DEL (127)

        CR = "\x0D"                 # US-ASCII CR, carriage return (13)>
        LF = "\x0A"                 # US-ASCII LF, linefeed (10)
        SP = ' '                    # US-ASCII SP, space (32)
        HT = '\x09'                 # US-ASCII HT, horizontal-tab (9)

        VCHAR = "\x21-\x7E"         # visible (printing) characters (%x21-7E)

        CRLF = CR + LF

        LWS = "" + CRLF + "(" + SP + "|" + HT + ")+"  # [CRLF] 1 * (SP | HT)

        OWS = "[" + SP + HT + "]*"  # optional whitespace: *( SP / HTAB )
        RWS = "[" + SP + HT + "]+"  # required whitespace: 1*( SP / HTAB )
        BWS = OWS                   # "bad" whitespace

        tchar = r"!#$%&'\*\+\-.^_`\|~" + DIGIT + ALPHA
        token = "[" + tchar + "]+"

        obs_text = "\x80-\xFF"

        obs_fold = CRLF + RWS       # obsolete line folding

        qvalue = "0(.\d{0,3})?|1(.0{0,3})?"
        weight = OWS + ";" + OWS + "q=" + qvalue


        HTTP_message = \
            {'name': 'HTTP_message',
             'shape_type': MH.Ordered,
             'contents': [
                 {'name': 'start_line',
                  'shape_type': MH.Pick,
                  'separator': {'contents': {'name': ('CRLF', 'start_line'), 'contents': CRLF},
                                'prefix': False, 'suffix': True},
                  'contents': [
                      {'name': 'request_line',
                       'separator': {'contents': {'name': ('SP', 'request_line'), 'contents': SP},
                                     'prefix': False, 'suffix': False},
                       'contents': [
                           {'name': 'method',
                            'contents': token,
                            'alt': [
                                {'conf': 'standard',
                                 'contents': "GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE"
                                 }]
                            },
                           {'name': 'request_target', 'contents': String()},  # ...
                           {'name': ('HTTP_version', 1), 'contents': '(HTTP)/[0-9]\.[0-9]'}
                       ]},

                      {'name': 'status_line',
                       'separator': {'contents': {'name': ('SP', 'status_line'), 'contents': SP},
                                     'prefix': False, 'suffix': False},
                       'contents': [
                           {'name': ('HTTP_version', 2), 'clone': ('HTTP_version', 1)},
                           {'name': 'status_code',
                            'contents': "\d{3}",
                            'alt': [
                                {'conf': 'standard',
                                 'shape_type': MH.Pick,
                                 'contents': [{'name': 'status_code_informational',
                                               'contents': "100|101"},
                                              {'name': 'status_code_successful',
                                               'contents': "200|201|202|203|204|205|206"},
                                              {'name': 'status_code_redirection',
                                               'contents': "300|301|302|303|304|305|307"},
                                              {'name': 'status_code_client_error',
                                               'contents': "400|401|402|403|404|405|406|407|408|409|" +
                                                           "410|411|412|413|414|415|416|417|426"},
                                              {'name': 'status_code_server_error',
                                               'contents': "500|501|502|503|504|505"}
                                              ]
                                 }]
                            },
                           {'name': 'reason_phrase',
                            'contents': "[" + VCHAR + HT + SP + obs_text + "]*",
                            'alt': [
                                {'conf': 'standard',
                                 'contents': [
                                     {"name": "reason_phrase_100",
                                      "exists_if": (RawCondition('100'), 'status_code_informational'),
                                      "contents": "Continue"},
                                     {"name": "reason_phrase_101",
                                      "exists_if": (RawCondition('101'), 'status_code_informational'),
                                      "contents": "Switching Protocols"},

                                     {"name": "reason_phrase_200",
                                      "exists_if": (RawCondition('200'), 'status_code_successful'),
                                      "contents": "OK"},
                                     {"name": "reason_phrase_201",
                                      "exists_if": (RawCondition('201'), 'status_code_successful'),
                                      "contents": "Created"},
                                     {"name": "reason_phrase_202",
                                      "exists_if": (RawCondition('200'), 'status_code_successful'),
                                      "contents": "Accepted"},
                                     {"name": "reason_phrase_203",
                                      "exists_if": (RawCondition('203'), 'status_code_successful'),
                                      "contents": "Non-Authoritative Information"},
                                     {"name": "reason_phrase_204",
                                      "exists_if": (RawCondition('204'), 'status_code_successful'),
                                      "contents": "No Content"},
                                     {"name": "reason_phrase_205",
                                      "exists_if": (RawCondition('205'), 'status_code_successful'),
                                      "contents": "Reset Content"},
                                     {"name": "reason_phrase_206",
                                      "exists_if": (RawCondition('206'), 'status_code_successful'),
                                      "contents": "Partial Content"},

                                     {"name": "reason_phrase_300",
                                      "exists_if": (RawCondition('300'), 'status_code_redirection'),
                                      "contents": "Multiple Choices"},
                                     {"name": "reason_phrase_301",
                                      "exists_if": (RawCondition('301'), 'status_code_redirection'),
                                      "contents": "Moved Permanently"},
                                     {"name": "reason_phrase_302",
                                      "exists_if": (RawCondition('302'), 'status_code_redirection'),
                                      "contents": "Found"},
                                     {"name": "reason_phrase_303",
                                      "exists_if": (RawCondition('303'), 'status_code_redirection'),
                                      "contents": "See Other"},
                                     {"name": "reason_phrase_304",
                                      "exists_if": (RawCondition('304'), 'status_code_redirection'),
                                      "contents": "Not Modified"},
                                     {"name": "reason_phrase_305",
                                      "exists_if": (RawCondition('305'), 'status_code_redirection'),
                                      "contents": "Use Proxy"},
                                     {"name": "reason_phrase_307",
                                      "exists_if": (RawCondition('307'), 'status_code_redirection'),
                                      "contents": "Temporary Redirect"},

                                     {"name": "reason_phrase_400",
                                      "exists_if": (RawCondition('400'), 'status_code_client_error'),
                                      "contents": "Bad Request"},
                                     {"name": "reason_phrase_401",
                                      "exists_if": (RawCondition('401'), 'status_code_client_error'),
                                      "contents": "Unauthorized"},
                                     {"name": "reason_phrase_402",
                                      "exists_if": (RawCondition('402'), 'status_code_client_error'),
                                      "contents": "Payment Required"},
                                     {"name": "reason_phrase_403",
                                      "exists_if": (RawCondition('403'), 'status_code_client_error'),
                                      "contents": "Forbidden"},
                                     {"name": "reason_phrase_404",
                                      "exists_if": (RawCondition('404'), 'status_code_client_error'),
                                      "contents": "Not Found"},
                                     {"name": "reason_phrase_405",
                                      "exists_if": (RawCondition('405'), 'status_code_client_error'),
                                      "contents": "Method Not Allowed"},
                                     {"name": "reason_phrase_406",
                                      "exists_if": (RawCondition('406'), 'status_code_client_error'),
                                      "contents": "Not Acceptable"},
                                     {"name": "reason_phrase_407",
                                      "exists_if": (RawCondition('407'), 'status_code_client_error'),
                                      "contents": "Proxy Authentication Required"},
                                     {"name": "reason_phrase_408",
                                      "exists_if": (RawCondition('408'), 'status_code_client_error'),
                                      "contents": "Request Timeout"},
                                     {"name": "reason_phrase_409",
                                      "exists_if": (RawCondition('409'), 'status_code_client_error'),
                                      "contents": "Conflict"},
                                     {"name": "reason_phrase_410",
                                      "exists_if": (RawCondition('410'), 'status_code_client_error'),
                                      "contents": "Gone"},
                                     {"name": "reason_phrase_411",
                                      "exists_if": (RawCondition('411'), 'status_code_client_error'),
                                      "contents": "Length Required"},
                                     {"name": "reason_phrase_412",
                                      "exists_if": (RawCondition('412'), 'status_code_client_error'),
                                      "contents": "Precondition Failed"},
                                     {"name": "reason_phrase_413",
                                      "exists_if": (RawCondition('413'), 'status_code_client_error'),
                                      "contents": "Payload Too Large"},
                                     {"name": "reason_phrase_414",
                                      "exists_if": (RawCondition('414'), 'status_code_client_error'),
                                      "contents": "URI Too Long"},
                                     {"name": "reason_phrase_415",
                                      "exists_if": (RawCondition('415'), 'status_code_client_error'),
                                      "contents": "Unsupported Media Type"},
                                     {"name": "reason_phrase_416",
                                      "exists_if": (RawCondition('416'), 'status_code_client_error'),
                                      "contents": "Range Not Satisfiable"},
                                     {"name": "reason_phrase_417",
                                      "exists_if": (RawCondition('417'), 'status_code_client_error'),
                                      "contents": "Expectation Failed"},
                                     {"name": "reason_phrase_426",
                                      "exists_if": (RawCondition('426'), 'status_code_client_error'),
                                      "contents": "Upgrade Required"},

                                     {"name": "reason_phrase_500",
                                      "exists_if": (RawCondition('500'), 'status_code_server_error'),
                                      "contents": "Internal Server Error"},
                                     {"name": "reason_phrase_501",
                                      "exists_if": (RawCondition('501'), 'status_code_server_error'),
                                      "contents": "Not Implemented"},
                                     {"name": "reason_phrase_502",
                                      "exists_if": (RawCondition('502'), 'status_code_server_error'),
                                      "contents": "Bad Gateway"},
                                     {"name": "reason_phrase_503",
                                      "exists_if": (RawCondition('503'), 'status_code_server_error'),
                                      "contents": "Service Unavailable"},
                                     {"name": "reason_phrase_504",
                                      "exists_if": (RawCondition('504'), 'status_code_server_error'),
                                      "contents": "Gateway Timeout"},
                                     {"name": "reason_phrase_505",
                                      "exists_if": (RawCondition('505'), 'status_code_server_error'),
                                      "contents": "HTTP Version Not Supported"},
                                 ]}]
                            }]}
                       ]},

                 {'name': 'header_fields',
                  'separator': {'contents': {'name': ('CRLF', "header_fields"), 'contents': CRLF},
                                'prefix': False, 'suffix': True},
                  'contents':[
                      {'name': 'header_field',
                       'qty': (0, -1),
                       'contents': [
                           {'name': 'field_name',
                            'contents': token,
                            'alt': [
                                {'conf': 'standard',
                                 'shape_type': MH.Pick,
                                 'contents': [
                                     {'name': 'field_name_controls',
                                      'shape_type': MH.Pick,
                                      'contents': [
                                          {'name': 'field_name_others',
                                           'contents': 'Cache-Control|Expect|Host|Pragma|Range|TE'},
                                          {'name':'field_name_max_forwards', 'contents': 'Max-Forwards',
                                           'exists_if': (RawCondition(['TRACE', 'OPTIONS']), 'method')}
                                      ]},
                                     {'name': 'field_name_conditionals',
                                      'contents': 'If-Match|If-None-Match|If-Modified-Since|' +
                                                  'If-Unmodified-Since|If-Range'},
                                     {'name': 'field_name_content_negotiation',
                                      'contents': 'Accept|Accept-Charset|Accept-Encoding|Accept-Language'},
                                     {'name': 'field_name_authentication_credentials',
                                      'contents': 'Authorization|Proxy-Authorization'},
                                     {'name': 'field_name_request_context',
                                      'contents': 'From|Referer|User-Agent'},
                                 ]}
                            ]},
                           {'name': 'header_field_name_value_separator:', 'contents': ":"},
                           {'name': 'header_field_ows_1', 'contents': OWS},
                           {'name': 'field_value',
                            'shape_type': MH.Pick,
                            'contents': [
                                {'name': 'field_content',
                                 'qty': (1, -1),
                                 'separator': {'contents': {'name': 'RWS', 'contents': RWS},
                                                            'prefix': False, 'suffix': False},
                                 'contents': [{'name': 'field_vchar', 'contents': "[" + VCHAR + obs_text + "]"}]},
                                {'name': 'obs_fold', 'contents': obs_fold}
                            ],
                            'alt': [
                                {'conf': 'standard',
                                 'contents': [
                                     {'name': 'field_value_expect',
                                      'exists_if': (RawCondition('Expect'), 'field_name_controls'),
                                      'contents': '100-continue'},
                                     {'name': 'field_value_max_forwards',
                                      'exists_if': (RawCondition('Max-Forwards'), 'field_name_controls'),
                                      'contents': '\d+'},
                                     # { ... }
                                 ]}
                            ]},
                           {'name': 'header_field_ows_2', 'clone': 'header_field_ows_1'},
                       ]}
                  ]},

                 {'name': 'CRLF', 'contents': CRLF},
                 {'name': 'message_body', 'contents': "[" + OCTET + "]*"}

            ]}

        model_helper = NodeBuilder(self)
        model_root_node = model_helper.create_graph_from_desc(HTTP_message)
        model_root_node.set_current_conf(conf="standard", recursive=True)
        self.register(model_root_node)


data_model = HTTPModel()
