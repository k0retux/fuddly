################################################################################
#
#  Copyright 2026 Eric Lacombe <eric.lacombe@security-labs.org>
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

from fuddly.framework.dmhelpers.generic import *
from fuddly.framework import value_types as fvt

def ASN1UPER_IA5String_Builder(name: str, size=None, min_sz=None, max_sz=None,
                               values=None, default=None, desc=None):

    assert (size is None and min_sz is not None) or (size is not None and min_sz is None)
    if min_sz is not None or max_sz is not None:
        assert min_sz is not None and max_sz is not None

    if size is not None:

        template = [
            {'name': name,
             'description': desc,
             'contents': fvt.ASN1UPER_IA5String(size=size, binvalues=values,
                                                bindefault=default)},
        ]

    else:
        assert min_sz < max_sz
        len_node_name = name + '_len'
        nb_of_different_len = max_sz - min_sz

        template = [
            {'name': len_node_name,
             'description': f'Length of {desc if desc is not None else name}',
             'contents': fvt.BitString(variable_size=False,
                                       min_intvalue=0, max_intvalue=nb_of_different_len)},
            {'name': name,
             'description': desc,
             'sync_size_with': (len_node_name, -min_sz),
             'contents': fvt.ASN1UPER_IA5String(min_sz=min_sz, max_sz=max_sz, binvalues=values,
                                                bindefault=default)},
        ]

    return template


def ASN1UPER_NumericString_Builder(name: str, size=None, min_sz=None, max_sz=None,
                                   default=None, with_space=True, desc=None):

    assert (size is None and min_sz is not None) or (size is not None and min_sz is None)
    if min_sz is not None or max_sz is not None:
        assert min_sz is not None and max_sz is not None

    if size is not None:

        template = [
            {'name': name,
             'contents': fvt.ASN1UPER_NumericString(size=size, bindefault=default,
                                                    with_space=with_space)},
        ]

    else:
        assert min_sz < max_sz
        len_node_name = name + '_len'
        nb_of_different_len = max_sz - min_sz

        template = [
            {'name': len_node_name,
             'description': f'Length of {desc if desc is not None else name}',
             'contents': fvt.BitString(variable_size=False,
                                       min_intvalue=0, max_intvalue=nb_of_different_len)},
            {'name': name,
             'description': desc,
             'sync_size_with': (len_node_name, -min_sz),
             'contents': fvt.ASN1UPER_NumericString(min_sz=min_sz, max_sz=max_sz, bindefault=default,
                                                    with_space=with_space)},
        ]

    return template

