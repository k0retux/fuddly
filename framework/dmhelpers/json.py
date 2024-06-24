################################################################################
#
#  Copyright 2019 Eric Lacombe <eric.lacombe@security-labs.org>
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


def json_model_builder(node_name, schema, struct_mutable=True, determinist=False,
                       ignore_pattern=False, codec='latin-1', value_suffix='_value'):
    """
    Helper for modeling an JSON structure from a JSON schema.

    Args:
      node_name: name of the node to be created
      schema (dict): the JSON schema to be translated to a fuddly node descriptor
      struct_mutable (bool): if ``False`` the JSON structure "will not" be mutable, meaning
        that each node related to the structure will have its ``Mutable`` attribute cleared.
      determinist (bool): if ``False``, the attribute order could change from one retrieved
        data to another.
      ignore_pattern (bool): if ``True``, the ``pattern`` attribute of ``string`` types will be
        ignored
      codec (str): codec to be used for generating the JSON structure.

    Returns:
      dict: Node-description of the JSON structure.
    """

    if schema is None:
        raise DataModelDefinitionError

    sc_type = schema.get('type')
    sc_desc = schema.get('description')

    if sc_type == 'object':
        properties = schema.get('properties')
        if properties is None:
            raise DataModelDefinitionError

        required_keys = schema.get('required')

        tag_start = \
            {'name': ('obj_start', uuid.uuid1()),
             'contents': fvt.String(values=['{'], codec=codec),
             'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

        tag_end = \
            {'name': ('obj_end', uuid.uuid1()),
             'contents': fvt.String(values=['}'], codec=codec),
             'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

        obj_cts = []

        for key, value in properties.items():
            sep_id = uuid.uuid1()
            prop = [
                {'name': ('sep', sep_id), 'contents' : fvt.String(values=['"'], codec=codec),
                 'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                {'name': ('key', uuid.uuid1()), 'contents' : fvt.String(values=[key], codec=codec)},
                {'name': ('sep', sep_id)},
                {'name': ('col', uuid.uuid1()), 'contents' : fvt.String(values=[':'], codec=codec),
                 'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable}
            ]

            prop_value = json_model_builder(node_name=key + value_suffix, schema=value, determinist=determinist,
                                            codec=codec, struct_mutable=struct_mutable,
                                            ignore_pattern=ignore_pattern)
            prop.append(prop_value)
            if required_keys and key in required_keys:
                prop_desc = {'name': (key, uuid.uuid1()), 'contents': prop}
            else:
                prop_desc = {'name': (key, uuid.uuid1()), 'contents': prop, 'qty': (0,1)}
            obj_cts.append(prop_desc)

        obj_desc = \
            {'name': ('attrs', uuid.uuid1()),
             'shape_type': MH.Ordered if determinist else MH.FullyRandom,
             'random': not determinist,
             'separator': {'contents': {'name': ('obj_sep', uuid.uuid1()),
                                        'contents': fvt.String(values=[',\n'], max_sz=100,
                                                               absorb_regexp=r'\s*,\s*', codec=codec),
                                        'mutable': struct_mutable,
                                        'absorb_csts': AbsNoCsts(size=True, regexp=True)},
                           'prefix': False, 'suffix': False, 'unique': False},
             'contents': obj_cts}

        node_desc = \
            {'name': (node_name, uuid.uuid1()),
             'contents': [tag_start, obj_desc, tag_end]}

    elif sc_type == 'string':
        min_len = schema.get('minLength')
        max_len = schema.get('maxLength', 30)
        pattern = schema.get('pattern')
        enum = schema.get('enum')

        format = schema.get('format')
        if format == 'ipv4':
            pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

        if pattern is None or ignore_pattern:
            str_desc = \
                {'name': ('string', uuid.uuid1()),
                 'contents': fvt.String(values=enum, min_sz=min_len, max_sz=max_len, codec=codec,
                                        absorb_regexp=pattern)}
            if pattern is not None:
                str_desc['absorb_csts'] = AbsNoCsts(size=True, regexp=True)
        else:
            str_desc = \
                {'name': ('string', uuid.uuid1()),
                 'contents': pattern}

        str_desc['semantics'] = node_name[:-len(value_suffix)]

        sep_id = uuid.uuid1()
        node_desc = \
            {'name': (node_name, uuid.uuid1()),
             'contents': [
                {'name': ('sep', sep_id), 'contents' : fvt.String(values=['"'], codec=codec),
                 'set_attrs': MH.Attr.Separator, 'mutable': struct_mutable},
                str_desc,
                {'name': ('sep', sep_id)},
            ]}

    elif sc_type == 'integer':
        mini = schema.get('minimum')
        ex_mini = schema.get('exclusiveMinimum')
        if ex_mini is not None:
            mini = ex_mini+1
        maxi = schema.get('maximum')
        ex_maxi = schema.get('exclusiveMaximum')
        if ex_maxi is not None:
            maxi = ex_maxi-1

        node_desc = \
            {'name': (node_name, uuid.uuid1()),
             'semantics': node_name[:-len(value_suffix)],
             'contents': fvt.INT_str(min=mini, max=maxi)}

    elif sc_type == 'boolean':
        node_desc = \
            {'name': (node_name, uuid.uuid1()),
             'semantics': node_name[:-len(value_suffix)],
             'contents': fvt.String(values=['true', 'false'])}

    elif sc_type == 'null':
        node_desc = \
            {'name': (node_name, uuid.uuid1()),
             'semantics': node_name[:-len(value_suffix)],
             'contents': fvt.String(values=['null'])}

    elif sc_type == 'array':

        tag_start = \
            {'name': ('array_start', uuid.uuid1()),
             'contents': fvt.String(values=['['], codec=codec),
             'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

        tag_end = \
            {'name': ('array_end', uuid.uuid1()),
             'contents': fvt.String(values=[']'], codec=codec),
             'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

        items_type= schema.get('items')
        if items_type is not None:
            item_desc = json_model_builder(node_name='item', schema=items_type, determinist=determinist,
                                           codec=codec, struct_mutable=struct_mutable,
                                           ignore_pattern=ignore_pattern)
        else:
            item_desc = {'name': ('item', uuid.uuid1()), 'contents': fvt.INT_str()}

        min_items = schema.get('minItems', 0)
        max_items = schema.get('maxItems', -1)

        item_desc['qty'] = (min_items, max_items)

        array_desc = \
            {'name': ('items', uuid.uuid1()),
             'shape_type': MH.Ordered if determinist else MH.FullyRandom,
             'random': not determinist,
             'custo_clear': MH.Custo.NTerm.FrozenCopy,
             'separator': {'contents': {'name': ('obj_sep', uuid.uuid1()),
                                        'contents': fvt.String(values=[','], max_sz=100,
                                                               absorb_regexp=r'\s*,\s*', codec=codec),
                                        'mutable': struct_mutable,
                                        'absorb_csts': AbsNoCsts(size=True, regexp=True)},
                           'prefix': False, 'suffix': False, 'unique': False},
             'contents': [item_desc]}

        node_desc = \
            {'name': (node_name, uuid.uuid1()),
             'contents': [tag_start, array_desc, tag_end]}


    else:
        raise DataModelDefinitionError

    node_desc['description'] = sc_desc

    return node_desc


def json_builder(node_name, sample=None, codec='latin-1',
                 tag_name_mutable=True, struct_mutable=True, determinist=True):
    """
    Helper for modeling an JSON structure from JSON samples.

    Args:
      node_name (str): name of the node to be created.
      sample (dict): the JSON structure to be converted to a fuddly structure
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

    if sample is not None:
        assert isinstance(sample, dict)
        cts = []
        idx = 1
        for k, v in sample.items():
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
                        modeled_v.append(json_builder(node_name + "_" + str(idx) + str(subidx), sample=value))
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
                                                                       absorb_regexp=r'\s*,\s*', codec=codec),
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
                params.append(json_builder(node_name + "_" + str(idx), sample=v))

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
                                                           absorb_regexp=r'\s*,\s*', codec=codec),
                                    'mutable': struct_mutable,
                                    'absorb_csts': AbsNoCsts(size=True, regexp=True)},
                       'prefix': False, 'suffix': False, 'unique': False},
         'contents': [params_desc]}

    tag_start_close_desc = \
        {'name': ('suffix', uuid.uuid1()),
         'contents': fvt.String(values=['}'], codec=codec),
         'mutable': struct_mutable, 'set_attrs': MH.Attr.Separator}

    tag_start_desc = \
    {'name': node_name,
     'contents': [tag_start_open_desc, tag_start_cts_desc, tag_start_close_desc]}

    return tag_start_desc
