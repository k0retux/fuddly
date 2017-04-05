from framework.node import *
from framework.dmhelpers.generic import *
import framework.value_types as fvt
import framework.global_resources as gr

def tag_builder(tag_name, params=None, contents=None, node_name=None, codec='latin-1',
                tag_name_mutable=True, struct_mutable=True, determinist=True):
    """
    Helper for modeling an XML tag.

    Args:
      tag_name (str): name of the XML tag.
      params (dict): optional attributes to be added in the XML tag
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

    Returns:
      dict: Node-description of the XML tag.
    """

    if params is not None:
        assert isinstance(params, dict)
        cts = []
        idx = 1
        for k, v in params.items():
            assert gr.is_string_compatible(v)
            v = v if isinstance(v, list) else [v]
            sep_id = uuid.uuid1()
            cts.append({'name': ('attr'+str(idx), uuid.uuid1()),
                        'contents': [
                            {'name': ('key', uuid.uuid1()), 'contents': fvt.String(values=[k], codec=codec)},
                            {'name': ('eq', uuid.uuid1()), 'contents': fvt.String(values=['='], codec=codec),
                             'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                            {'name': ('sep', sep_id), 'contents': fvt.String(values=['"'], codec=codec),
                             'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                            {'name': ('val', uuid.uuid1()), 'contents': fvt.String(values=v, codec=codec)},
                            {'name': ('sep', sep_id)},
                        ]})
            idx += 1

        if not determinist:
            params_desc = {'section_type': MH.FullyRandom, 'contents': cts}
        else:
            params_desc = {'section_type': MH.Ordered, 'contents': cts}
    else:
        params_desc = None

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

    tag_start_close_desc = \
        {'name': ('suffix', uuid.uuid1()),
         'contents': fvt.String(values=['>'], codec=codec),
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
        else:
            assert gr.is_string_compatible(contents)
            if not isinstance(contents, list):
                contents = [contents]
            cts = [tag_start_desc,
                   {'name': 'elt-content',
                    'contents': fvt.String(values=contents, codec=codec)},
                   tag_end_desc]

        tag_desc = \
        {'name': tag_name if node_name is None else node_name,
         'separator': {'contents': {'name': ('nl', uuid.uuid1()),
                                    'contents': fvt.String(values=['\n'], max_sz=100,
                                                           absorb_regexp='[\r\n|\n]+', codec=codec),
                                    'absorb_csts': AbsNoCsts(regexp=True)},
                       'prefix': False, 'suffix': False, 'unique': False},
         'contents': cts}

    return tag_desc
