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
      tag_name (str): name of the JSON tag.
      params (dict): the JSON structure to be converted to a fuddly structure
      node_name (str): name of the node to be created.
      codec (str): codec to be used for generating the JSON structure.
      tag_name_mutable (bool): if ``False``, the tag name will not be mutable, meaning that
        its ``Mutable`` attribute will be cleared.
      struct_mutable (bool): if ``False`` the JSON structure "will not" be mutable, meaning
        that each node related to the structure will have its ``Mutable`` attribute cleared.
      determinist (bool): if ``False``, the attribute order could change from one retrieved
        data to another.

    Returns:
      dict: Node-description of the JSON structure.
    """

    if params is not None:
        assert isinstance(params, dict)
        cts = []
        idx = 1
        for k, v in params.items():
            sep_id = uuid.uuid1() # The separator for the " in the key param.  e.g., "<key>"

            params = [
                {'name': ('sep', sep_id), 'contents' : fvt.String(values=['"'], codec=codec),
                 'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                {'name': ('key', uuid.uuid1()), 'contents' : fvt.String(values=[k], codec=codec)},
                {'name': ('sep', sep_id)},
                {'name': ('col', uuid.uuid1()), 'contents' : fvt.String(values=[':'], codec=codec),
                 'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable} ]

            if isinstance(v, list):
                modeled_v = []
                val_id = uuid.uuid1()
                for subidx, value in enumerate(v):
                    assert not isinstance(value, list)
                    if isinstance(value, dict):
                        # If the type of v is a dictionary, build a sub JSON structure for it.
                        modeled_v.append(json_builder(tag_name + "_" + str(idx)+str(subidx), params=value))
                    else:
                        checked_value = value if gr.is_string_compatible(value) else str(value)
                        modeled_v.append( 
                            {'name': ('val'+str(subidx), val_id),
                             'contents': [
                                 {'name': ('sep', sep_id)},
                                 {'name': ('cts', uuid.uuid1()),
                                  'contents': fvt.String(values=[checked_value], codec=codec)},
                                 {'name': ('sep', sep_id)} ]}
                        )

                attr_value = \
                    {'name': ('cts', uuid.uuid1()),
                     'contents': modeled_v,
                     'separator': {'contents': {'name': ('comma', uuid.uuid1()),
                                                'contents': fvt.String(values=[','], max_sz=100,
                                                                       absorb_regexp='\s*,\s*', codec=codec),
                                                'mutable': struct_mutable,
                                                'absorb_csts': AbsNoCsts(size=True, regexp=True)},
                                   'prefix': False, 'suffix': False, 'unique': False} }

                params.append({'name': ('attr_val'+str(idx), uuid.uuid1()),
                               'contents': [
                                   {'contents': fvt.String(values=['['], codec=codec),
                                    'mutable': struct_mutable, 'name': 'prefix'+str(idx)},
                                   attr_value,
                                   {'contents': fvt.String(values=[']'], codec=codec),
                                    'mutable': struct_mutable, 'name': 'suffix'+str(idx)} ]})

            elif isinstance(v, dict):
                params.append(json_builder(tag_name + "_" + str(idx), params=v))

            elif gr.is_string_compatible(v):
                params += [ {'name': ('sep', sep_id)},
                            {'name': ('val', uuid.uuid1()), 'contents': fvt.String(values=[v], codec=codec)},
                            {'name': ('sep', sep_id)} ]
            else:
                raise DataModelDefinitionError
            
            cts.append({'name': ('attr'+str(idx), uuid.uuid1()),
                        'contents': params})
            idx += 1

        if not determinist:
            params_desc = {'section_type': MH.FullyRandom, 'contents': cts}
        else:
            params_desc = {'section_type': MH.Ordered, 'contents': cts}
    else:
        raise DataModelDefinitionError

    tag_start_open_desc = \
        {'name': ('prefix', uuid.uuid1()),
         'contents': fvt.String(values=['{'], codec=codec),
         'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

    tag_start_cts_desc = \
        {'name': ('contents', uuid.uuid1()),
         'random': not determinist,
         'separator': {'contents': {'name': ('comma', uuid.uuid1()),
                                    'contents': fvt.String(values=[','], max_sz=100,
                                                           absorb_regexp='\s*,\s*', codec=codec),
                                    'mutable': struct_mutable,
                                    'absorb_csts': AbsNoCsts(size=True, regexp=True)},
                       'prefix': False, 'suffix': False, 'unique': False},
         'contents': [params_desc]}

    tag_start_close_desc = \
        {'name': ('suffix', uuid.uuid1()),
         'contents': fvt.String(values=['}'], codec=codec),
         'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

    tag_start_desc = \
    {'name': tag_name if node_name is None else node_name,
     'contents': [tag_start_open_desc, tag_start_cts_desc, tag_start_close_desc]}

    return tag_start_desc
