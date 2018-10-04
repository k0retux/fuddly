################################################################################
#
#  Copyright 2017 Eric Lacombe <eric.lacombe@security-labs.org>
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

from framework.node import *
from framework.dmhelpers.generic import *
import framework.value_types as fvt
import framework.global_resources as gr
from enum import Enum

class TAG_TYPE(Enum):
    standard = 1
    comment = 2
    proc_instr = 3

def tag_builder(tag_name, params=None, refs=None, contents=None, node_name=None, codec='latin-1',
                tag_name_mutable=True, struct_mutable=True, determinist=True, condition=None,
                absorb_regexp=None,
                tag_type=TAG_TYPE.standard, nl_prefix=False, nl_suffix=False):
    """
    Helper for modeling an XML tag.

    Args:
      tag_name (str): name of the XML tag.
      params (dict): optional attributes to be added in the XML tag
      refs (dict): if provided it should give for each parameter key (provided in ``params`` dict)
        the name to be used for the node representing the corresponding value. Useful when
        the parameter ``condition`` is in use and needs to relate to the value of specific parameters.
      contents: can be either None (empty tag), a :class:`framework.data_model.Node`,
        a dictionary (Node description), a string or a string list (string-Node values).
      node_name (str): name of the node to be created.
      codec (str): codec to be used for generating the XML tag.
      tag_name_mutable (bool): if ``False``, the tag name will not be mutable, meaning that
        its ``Mutable`` attribute will be cleared.
      struct_mutable (bool): if ``False`` the XML structure "will not" be mutable, meaning
        that each node related to the structure will have its ``Mutable`` attribute cleared.
      determinist (bool): if ``False``, the attribute order could change from one retrieved
        data to another.
      condition (tuple): optional existence condition for the tag. If not ``None`` a keyword ``exists_if``
        will be added to the root node with this parameter as a value.
      absorb_regexp (str): regex for ``contents`` absorption
      tag_type (TAG_TYPE): specify the type of notation
      nl_prefix (bool): add a new line character before the tag
      nl_suffix (bool): add a new line character after the tag

    Returns:
      dict: Node-description of the XML tag.
    """

    if params is not None:
        assert isinstance(params, dict)
        cts = []
        idx = 1
        refs = {} if refs is None else refs
        for k, v in params.items():
            if gr.is_string_compatible(v):
                val_ref = refs.get(k, ('val', uuid.uuid1()))
                v = v if isinstance(v, list) else [v]
                nd_desc = {'name': val_ref, 'contents': fvt.String(values=v, codec=codec)}
            elif isinstance(v, dict):
                nd_desc = v
            elif isinstance(v, Node):
                nd_desc = (v, 1, 1)
            else:
                raise ValueError

            sep_id = uuid.uuid1()
            cts.append({'name': ('attr'+str(idx), uuid.uuid1()),
                        'contents': [
                            {'name': ('key', uuid.uuid1()), 'contents': fvt.String(values=[k], codec=codec)},
                            {'name': ('eq', uuid.uuid1()), 'contents': fvt.String(values=['='], codec=codec),
                             'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                            {'name': ('sep', sep_id), 'contents': fvt.String(values=['"'], codec=codec),
                             'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                            nd_desc,
                            {'name': ('sep', sep_id)},
                        ]})
            idx += 1

        if not determinist:
            params_desc = {'section_type': MH.FullyRandom, 'contents': cts}
        else:
            params_desc = {'section_type': MH.Ordered, 'contents': cts}
    else:
        params_desc = None

    if tag_type in [TAG_TYPE.comment, TAG_TYPE.proc_instr]:
        assert contents is None
        if tag_type is TAG_TYPE.proc_instr:
            prefix = '<?'
        elif tag_type is TAG_TYPE.comment:
            prefix = '<!--'
        else:
            raise ValueError
    else:
        prefix = '</' if contents is None else '<'

    tag_start_open_desc = \
        {'name': ('prefix', uuid.uuid1()),
         'contents': fvt.String(values=[prefix], codec=codec),
         'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

    tag_cts = [{'name': ('tag_name', uuid.uuid1()),
                'contents': fvt.String(values=[tag_name], codec=codec),
                'mutable': tag_name_mutable}]
    if params_desc is not None:
        tag_cts.append(params_desc)

    tag_start_cts_desc = \
        {'name': ('content', uuid.uuid1()),
         'random': not determinist,
         'separator': {'contents': {'name': ('spc', uuid.uuid1()),
                                    'contents': fvt.String(values=[' '], max_sz=100,
                                                           absorb_regexp='\s+', codec=codec),
                                    'mutable': struct_mutable,
                                    'absorb_csts': AbsNoCsts(size=True, regexp=True)},
                       'prefix': False, 'suffix': False, 'unique': False},
         'contents': tag_cts}

    if tag_type in [TAG_TYPE.comment, TAG_TYPE.proc_instr]:
        if tag_type is TAG_TYPE.proc_instr:
            suffix = '?>'
        elif tag_type is TAG_TYPE.comment:
            suffix = '-->'
        else:
            raise ValueError
    else:
        suffix = '>'

    tag_start_close_desc = \
        {'name': ('suffix', uuid.uuid1()),
         'contents': fvt.String(values=[suffix], codec=codec),
         'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

    tag_start_desc = \
    {'name': ('start-tag', uuid.uuid1()),
     'contents': [tag_start_open_desc, tag_start_cts_desc, tag_start_close_desc]}

    tag_end_desc = \
        {'name': ('end-tag', uuid.uuid1()),
         'contents': [
            {'name': ('prefix', uuid.uuid1()),
             'contents': fvt.String(values=['</'], codec=codec),
             'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator},
            {'name': ('content', uuid.uuid1()),
             'contents': fvt.String(values=[tag_name], codec=codec),
             'mutable': tag_name_mutable},
            {'name': ('suffix', uuid.uuid1()),
             'contents': fvt.String(values=['>'], codec=codec),
             'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator},
         ]}

    if contents is None:
        tag_desc = tag_start_desc
    else:
        if isinstance(contents, Node):
            cts = [tag_start_desc,
                   (contents, 1, 1),
                   tag_end_desc]
        elif isinstance(contents, dict):
            cts = [tag_start_desc,
                   contents,
                   tag_end_desc]
        elif isinstance(contents, list) and not gr.is_string_compatible(contents[0]):
            cts = [tag_start_desc]
            for c in contents:
                cts.append(c)
            cts.append(tag_end_desc)
        else:
            assert gr.is_string_compatible(contents)
            if not isinstance(contents, list):
                contents = [contents]
            content_desc = {'name': ('elt-content', uuid.uuid1()),
                            'contents': fvt.String(values=contents, codec=codec, absorb_regexp=absorb_regexp)}
            if absorb_regexp is not None:
                content_desc['absorb_csts'] = AbsNoCsts(regexp=True)

            cts = [tag_start_desc,
                   content_desc,
                   tag_end_desc]

        tag_desc = \
        {'name': tag_name if node_name is None else node_name,
         'separator': {'contents': {'name': ('nl', uuid.uuid1()),
                                    'contents': fvt.String(values=['\n'], max_sz=100,
                                                           absorb_regexp='\s*', codec=codec),
                                    'absorb_csts': AbsNoCsts(regexp=True)},
                       'prefix': nl_prefix, 'suffix': nl_suffix, 'unique': False},
         'contents': cts}

    if condition:
        tag_desc['exists_if'] = condition

    return tag_desc

def xml_decl_builder():
    version_desc = {'name': 'version',
                    'contents': '[123456789]\.\d'}

    encoding_list = ['UTF-8', 'UTF-16', 'ISO-10646-UCS-2','ISO-10646-UCS-4',
                     'ISO-2022-JP', 'Shift_JIS', 'EUC-JP'] + \
                     ['ISO-8859-{:d}'.format(x) for x in range(1, 10)]

    return tag_builder('xml', params={'version': version_desc,
                                      'encoding': encoding_list,
                                      'standalone': ['no', 'yes']},
                       tag_type=TAG_TYPE.proc_instr)
