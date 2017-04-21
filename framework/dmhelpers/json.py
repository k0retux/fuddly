################################################################################
#
#  Copyright 2017 Rockwell Collins Inc.
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
import uuid

def json_builder(tag_name, params=None, node_name=None, codec='latin-1',
                tag_name_mutable=True, struct_mutable=True, determinist=True):
    """
    Helper for modeling an JSON structure.

    Args:
      tag_name (str): name of the XML tag.
      params (dict): the JSON structure to be converted to a fuddly structure
      node_name (str): name of the node to be created.
      codec (str): codec to be used for generating the JSON structure.
      tag_name_mutable (bool): if ``False``, the tag name will not be mutable, meaning that
        its ``Mutable`` attribute will be cleared.
      struct_mutable (bool): if ``False`` the JSON structure "will not" be mutable, meaning
        that each node related to the structure will have its ``Mutable`` attribute cleared.
      determinist (bool): if ``False``, the attribute order could change from one retrieved
        data to another.k

    Returns:
      dict: Node-description of the JSON structure.
    """

    if params is not None:
        assert isinstance(params, dict)
        cts = []
        idx = 1
        for k, v in params.items():
            #assert gr.is_string_compatible(v) #TODO need to update this
            v = v if isinstance(v, list) else [v]
            sep_id = uuid.uuid1() # The separator for the " in the key param.  e.g., "<key>"
            
            subType = False
            for subV in range(len(v)):
                
                # If the type of v is a dictionary, build a sub JSON structure for it.
                if type(v[subV]) == type({}):
                    v[subV] = json_builder(tag_name + "_" + str(idx), v[subV])
                    subType = True

            vVal = fvt.String(values=v, codec=codec) if not subType else v
            
            cts.append({'name': ('attr'+str(idx), uuid.uuid1()),
                        'contents': [
                            {'name': ('sep', sep_id), 'contents' : fvt.String(values=['"'], codec=codec)},
                            {'name': ('key', uuid.uuid1()), 'contents' : fvt.String(values=[k], codec=codec)},
                            {'name': ('sep', sep_id)},
                            {'name': ('col', uuid.uuid1()), 'contents' : fvt.String(values=[':'], codec=codec),
                               'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                            {'name': ('val', uuid.uuid1()), 'contents': vVal},
                            {'name': ('com', uuid.uuid1()), 'contents': fvt.String(values=[','], codec=codec),
                                'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                        ]})
            idx += 1

        if not determinist:
            params_desc = {'section_type': MH.FullyRandom, 'contents': cts}
        else:
            params_desc = {'section_type': MH.Ordered, 'contents': cts}
    else:
        params_desc = None

    tag_start_open_desc = \
        {'name': ('prefix', uuid.uuid1()),
         'contents': fvt.String(values=['{'], codec=codec),
         'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

    tag_cts = []

    if params_desc is not None:
        tag_cts.append(params_desc)

    tag_start_cts_desc = \
        {'name': ('contents', uuid.uuid1()),
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
         'contents': fvt.String(values=['}'], codec=codec),
         'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

    tag_start_desc = \
    {'name': tag_name if node_name is None else node_name,
     'contents': [tag_start_open_desc, tag_start_cts_desc, tag_start_close_desc]}

    tag_desc = tag_start_desc
    
    return tag_desc
