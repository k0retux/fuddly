#!/usr/bin/python

################################################################################
#
#  Copyright 2014-2016 Eric Lacombe <eric.lacombe@security-labs.org>
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

import sys
import os
import copy
import re
import functools
import struct
import random
import zlib

sys.path.append('.')

from framework.plumbing import *
from framework.data_model import *
from framework.data_model_builder import *
from framework.value_types import *
from framework.fuzzing_primitives import *
from framework.basic_primitives import *
import framework.global_resources as gr

def gather_pdf_objects(path=gr.imported_data_folder):

    r_pdf_file = re.compile(".*\.pdf$")
    def is_pdf_file(fname):
        if r_pdf_file.match(fname):
            return True
        else:
            return False

    pdf_files = []
    for (dirpath, dirnames, filenames) in os.walk(path):
        pdf_files.extend(filenames)
        break

    pdf_files = list(filter(is_pdf_file, pdf_files))

    pdf_objs = {
        "basic": [],
        "complex": []
        }

    for name in pdf_files:
        with open(path + name, 'rb') as f:
            buff = f.read()

    return None
    

class PDFObj(object):
    '''
    Node semantics:

    TBC

    '''


    enc_Deflate = 1
    enc_ASCII = 2

    external_pdf_objs = None

    pdf_reserved_char = "%()<>[]{}/#"
    __alphabet = None

    __obj_id = 1
    __obj_gen_num = 0

    @staticmethod
    def __calc_prefix_wrapper_obj(ident, gen):
        e_sep = Node('sep', values=[' '])

        if ident is None:
            ident = PDFObj.__obj_id
            PDFObj.__obj_id += 1

        e_id = Node('id', values=[str(ident)])

        if gen is None:
            gen = PDFObj.__obj_gen_num

        e_gen = Node('gen_nb', values=[str(gen)])
        e_text = Node('text', values=["obj\n"])

        return Node('obj_prefix', subnodes=[e_id, e_sep, e_gen, e_sep, e_text]), ident

    @staticmethod
    def __calc_suffix_wrapper_obj():
        return Node('obj_suffix', values=["\nendoj\n"])

    @staticmethod
    def create_wrapped_obj(name, node, ident=None, gen=None):
        e_start, ident = PDFObj.__calc_prefix_wrapper_obj(ident, gen)
        e_end = PDFObj.__calc_suffix_wrapper_obj()

        e = Node('wrapped_%d_'%ident + name, subnodes=[e_start, node, e_end])
        e.set_private(ident)

        return e


    @staticmethod
    def get_pdfobj_id():
        ident = PDFObj.__obj_id
        PDFObj.__obj_id += 1

        return ident

    # valid_pdf_headers = ["%PDF-1.{:d}\n%\n".format(x) for x in range(1, 7)]
    valid_pdf_headers = ["%PDF-1.5\n%\n"]

    @staticmethod
    def get_pdf_header_node():
        e = Node('Hdr', values=PDFObj.valid_pdf_headers)

        return e


    @staticmethod
    def get_bool(name, vals=None):  
        if not vals:
            vals = ['true', 'false']
        e = Node(name, values=vals)

        return PDFObj.create_wrapped_obj(name, e)

    @staticmethod
    def get_number(name, int_m=0, int_M=2**40, dec_m=0, dec_M=2**20, enforce_unsigned=False, indirect=True):
        if enforce_unsigned:
            sign = Node('sign', values=['+'])
        else:
            sign = Node('sign', values=['+','-'])

        int_part = Node('int_part', value_type=INT_str(min=int_m, max=int_M, determinist=False))
        int_part.add_conf('ALT')
        int_part.set_values(value_type=INT_str(values=[20000000]), conf='ALT')

        dot = Node('dot', values=['.'])
        val = Node('val', value_type=INT_str(min=dec_m, max=dec_M, determinist=False))
        end = Node('float_part', subnodes=[dot, val])

        e = Node(name)
        e.set_subnodes_with_csts([
            2, ['u>', [sign, 0, 1], [int_part, 0, 1], [end, 1]],
            3, ['u>', [sign, 0, 1], [int_part, 1], [end, 0, 1]],
            1, ['u>', [sign, 0, 1], [int_part, 1], [dot, 1]]
            ])

        e.set_semantics(NodeSemantics(['PDF_number', 'basic_type']))

        if indirect:
            return PDFObj.create_wrapped_obj(name, e)
        else:
            return e
 

    @property
    def alphabet(self):
        if self.__alphabet is None:
            pdf_reserved_char = "%()<>[]{}/#"
            self.__alphabet = [chr(x) for x in range(0x21, 0x7F)]
            for a in pdf_reserved_char:
                self.__alphabet.remove(a)

        return self.__alphabet

    # alphabet = __calc_alphabet()

    @staticmethod
    def get_name(name, vals=None):
        prefix = Node('prefix', values=['/'])
        prefix.add_conf('ALT')
        prefix.set_values(['#', '//'], conf='ALT')
        prefix.set_semantics(NodeSemantics(['delim']))

        valid_names = [rand_string(min=1, max=30, str_set=PDFObj.alphabet) for x in range(20)]
        invalid_names = ['A'*128, # max name length = 127 bytes
                         '#41'*128,
                         'A'*126 + '\\',
                         'A'*126 + '#',
                         '0AAAAAA#FF#',
                         '1AAAA##42',
                         '2AAAA#07#00AAA',
                         '3AAAA#17AAAA',
                         '4AAAA\x07\x18\x00AAAA',
                         '\x00']

        ident = Node('ident', values=valid_names)
        ident.add_conf('ALT')
        ident.set_values(invalid_names, conf='ALT')
        ident.make_determinist(conf='ALT')
        ident.set_semantics(NodeSemantics(['PDF_name', 'RAW']))

        e = Node(name, subnodes=[prefix, ident])
        e.set_semantics(NodeSemantics(['PDF_name', 'basic_type']))

        return PDFObj.create_wrapped_obj(name, e)

    @staticmethod
    def get_string(name, vals=None):
        e_prefix = Node('prefix', values=['('])
        e_prefix.add_conf('ALT')
        e_prefix.set_values(['<<', '>>', '(', '('], conf='ALT')
        e_prefix.make_determinist(conf='ALT')
        e_prefix.set_semantics(NodeSemantics(['delim']))

        e_suffix = Node('suffix', values=[')'])
        e_suffix.add_conf('ALT')
        e_suffix.set_values(['>>', '(', ']', ''], conf='ALT')
        e_suffix.make_determinist(conf='ALT')
        e_suffix.set_semantics(NodeSemantics(['delim']))

        valid_strings = [rand_string(min=1, max=50) for x in range(20)]
        invalid_strings = ['',
                           'A'*2**16, # valid strings have 65535 max chars
                           '1AAAA\\666\\777',
                           '2AAAA\\007',
                           '3AAAA<7F><00><07>',
                           '4AAAA<29>AAA']
        e_strings = Node('strings', values=valid_strings)
        e_strings.add_conf('ALT')
        e_strings.set_values(invalid_strings, conf='ALT')
        e_strings.make_determinist(conf='ALT')
        e_strings.set_semantics(NodeSemantics(['PDF_string', 'RAW']))

        e = Node(name, subnodes=[e_prefix, e_strings, e_suffix])
        e.set_semantics(NodeSemantics(['PDF_string', 'basic_type']))

        return PDFObj.create_wrapped_obj(name, e)


    @staticmethod
    def get_array(name, nodes=None, vals=None, alt_vals=None, indirect=True, return_knob=False, return_rawlist=False):
        '''
        @vals: if provided shall be a list of value list
        '''
        e_sep = Node('sep', values=[' '])

        l = []
        if vals is not None:
            l = []
            cpt = 0
            if alt_vals is not None:
                for v, av in zip(vals, alt_vals):
                    e = Node('entry{:d}'.format(cpt), values=v)
                    if av is not None:
                        e.add_conf('ALT')
                        e.set_values(av, conf='ALT')
                    l.append(e)
                    l.append(e_sep)
                    cpt += 1
            else:
                for v in vals:
                    l.append(Node('entry{:d}'.format(cpt), values=v))
                    l.append(e_sep)
                    cpt += 1

            l.pop()

        elif nodes is not None:
            for e in nodes:
                l.append(e)
                l.append(e_sep)
            l.pop()

        else:
            raise ValueError

        if return_rawlist:
            return l

        e_start = Node('start', values=['['])
        e_end = Node('end', values=[']'])
        e_node_list = Node('nodes', subnodes=l)
        e = Node(name, subnodes=[e_start, e_node_list, e_end])

        e.set_semantics(NodeSemantics(['PDF_array', 'basic_type']))

        if indirect:
            ret = PDFObj.create_wrapped_obj(name, e)
        else:
            ret = e

        if return_knob:
            return ret, e_node_list
        else:
            return ret


    @staticmethod
    def get_dictionary(name, nodes=None, vals=None, alt_vals=None, indirect=True, return_knob=False, return_rawlist=False):
        '''
        @vals: if provided shall be a list of value list
        '''
        e_sep = Node('sep', values=['\n'])

        l = []
        if vals is not None:
            l = []
            cpt = 0
            if alt_vals is not None:
                for v, av in zip(vals, alt_vals):
                    e = Node('entry{:d}'.format(cpt), values=v)
                    if av is not None:
                        e.add_conf('ALT')
                        e.set_values(av, conf='ALT')
                    l.append(e)
                    l.append(e_sep)
                    cpt += 1
            else:
                for v in vals:
                    l.append(Node('entry{:d}'.format(cpt), values=v))
                    l.append(e_sep)
                    cpt += 1

            l.pop()

        elif nodes is not None:
            for e in nodes:
                l.append(e)
                l.append(e_sep)
            l.pop()

        else:
            raise ValueError

        if return_rawlist:
            return l


        e_start = Node('start', values=['<<'])
        e_end = Node('end', values=['>>'])
        e_node_list = Node('nodes', subnodes=l)
        e = Node(name, subnodes=[e_start, e_node_list, e_end])

        e.set_semantics(NodeSemantics(['PDF_dictionary', 'basic_type']))

        if indirect:
            ret = PDFObj.create_wrapped_obj(name, e)
        else:
            ret = e

        if return_knob:
            return ret, e_node_list
        else:
            return ret


#    stream_pdfbomb = None

    @staticmethod
    def get_stream(name, stream=None, enc_stream=None, enc_mode=enc_Deflate, use_generator_func=False):

        if stream is None and enc_stream is None:
            raise ValueError

        def _encode_stream_zlib(stream, enc_stream):
            e_filter = Node('filter', values=['/FlateDecode'])
            e_filter.add_conf('ALT')
            e_filter.set_values(['['+'/FlateDecode ' + '/ASCIIHexDecode '*100 + ']', '/LZWDecode'], conf='ALT')

            if enc_stream is None:
                if use_generator_func:
                    e_stream = Node('stream_wrapper')
                    def gen_func(stream):
                        enc = zlib.compress(stream)
                        return Node('stream', values=[enc])

                    e_stream.set_generator_func(gen_func, func_arg=stream)
                    e_stream.customize(GenFuncCusto(items_to_set=GenFuncCusto.CloneExtNodeArgs))
                else:
                    e_stream = Node('stream')
                    func = lambda x: zlib.compress(x)
                    e_stream.set_func(func, func_arg=stream)

            else:
                e_stream = Node('stream', values=[enc_stream])

            return e_filter, e_stream

        def _encode_stream_ascii(stream, enc_stream):
            e_filter = Node('filter', values=['/ASCIIHexDecode'])
            e_filter.add_conf('ALT')
            e_filter.set_values(['[' + '/ASCIIHexDecode '*100 + ']', '/LZWDecode'], conf='ALT')

            if enc_stream is None:
                func = lambda x: x
                e_stream = Node('stream')
                e_stream.set_func(func, func_arg=stream)
            else:
                e_stream = Node('stream', values=[enc_stream])

            return e_filter, e_stream
        
        e_filter, e_stream = {PDFObj.enc_Deflate: _encode_stream_zlib,
                              PDFObj.enc_ASCII: _encode_stream_ascii
                              }[enc_mode](stream, enc_stream)
        
        e_filter_entry = make_wrapped_node('E_Filter',
                                          node = e_filter,
                                          prefix = ["/Filter "])
        
        def gen_length_func(e_stream):
            return Node('length', value_type=INT_str(values=[len(e_stream.to_bytes())]))

        if use_generator_func:
            e_length = Node('length_wrapper')
            e_length.set_generator_func(gen_length_func, func_node_arg=e_stream)
            e_length.customize(GenFuncCusto(items_to_set=GenFuncCusto.CloneExtNodeArgs))
        else:
            e_length = Node('length', value_type=INT_str(values=[len(e_stream.to_bytes())]))

        e_length_entry = make_wrapped_node('E_Length',
                                          node = e_length,
                                          prefix = ["/Length "])
        
        e_dic = PDFObj.get_dictionary('dico',
                                      nodes=[e_filter_entry, e_length_entry],
                                      indirect=False)
        
        e_wrapped_stream = make_wrapped_node('WStream',
                                            node = e_stream,
                                            prefix = ["\nstream\n"],
                                            suffix = ["\nendstream"])


        e_stream_pdfobj = Node(name, subnodes=[e_dic, e_wrapped_stream])

        return PDFObj.create_wrapped_obj(name, e_stream_pdfobj)


    jpg_node = None

    @staticmethod
    def get_jpg(name):

        if PDFObj.jpg_node is None:
            raise ValueError

        name = 'IMG_XObj' + name

        length = len(PDFObj.jpg_node.to_bytes())
        priv = PDFObj.jpg_node.get_private()
        w, h = priv['width'], priv['height']

        xobj_prefix = ("<< /Type /XObject"
                       " /Subtype /Image"
                       " /Width {width:d}"
                       " /Height {height:d}"
                       " /ColorSpace /DeviceRGB"
                       " /BitsPerComponent 8"
                       " /Length {length:d}"
                       " /Filter /DCTDecode >>\n"
                       "stream\n").format(width=w, height=h, length=length)
        
        e_pref = Node('XObject_prefix', values=[xobj_prefix])

        xobj_suffix = 'endstream'
        e_suffix = Node('XObject_suffix', values=[xobj_suffix])

        e_jpg_xobj_internals = Node('IMG_XObj_' + name, subnodes=[e_pref, PDFObj.jpg_node, e_suffix])
        e_jpg_xobj = PDFObj.create_wrapped_obj('IMG_XObj_' + name, e_jpg_xobj_internals)

        xobj_id = e_jpg_xobj.get_private()
        e_resources_internals = make_wrapped_node('IMG_XObj_resource_' + name,
                                                 node=Node("xobj_id", value_type=INT_str(values=[xobj_id])),
                                                 prefix=["<< /ProcSet [/PDF /ImageC]\n /XObject << /Im1 "],
                                                 suffix=[" 0 R >> >>"])
        e_resources = PDFObj.create_wrapped_obj('IMG_XObj_resource_' + name, e_resources_internals)

        cmd_str = ("q\n"
                   "{width:d} 0 0 {height:d} 0 0 cm\n"
                   "/Im1 Do\n"
                   "Q\n").format(width=w, height=h)

        contents = ("<</Length {length:d}>>\n"
                    "stream\n").format(length=len(cmd_str)) + cmd_str + "endstream"
        
        e_contents_internals = Node('IMG_XObj_contents_' + name, values=[contents])
        e_contents = PDFObj.create_wrapped_obj('IMG_XObj_contents_' + name, e_contents_internals)

        return PageLeaf_Internals(e_resources, e_contents, other_nodes=[e_jpg_xobj])


    @staticmethod
    def make_page_node(name, page_node_id, kids_id=[4444], parent_id=None, count=None):
        e_prefix = Node('prefix', values=["<<\n"])

        l = []
        for i in kids_id:
            l.append(Node("kid_%d"%i, values=["%d 0 R"%i]))

        e_kids_array, e_kids_id = PDFObj.get_array("array", nodes=l, indirect=False, return_knob=True)
        e_kids = make_wrapped_node("Kids_E",
                                  node=e_kids_array,
                                  prefix=["/Kids "],
                                  suffix=["\n"])

        cpt = count if count is not None else len(l)

        e_count_nb = Node("count", value_type=INT_str(values=[cpt]))
        e_count = make_wrapped_node("Count_E",
                                   node=e_count_nb,
                                   prefix=["/Count "],
                                   suffix=["\n"])
        
        if parent_id is not None:
            e_parent_id = Node("parent_id", value_type=INT_str(values=[parent_id]))
            e_parent = make_wrapped_node("Parent_E",
                                        node=e_parent_id,
                                        prefix=["/Parent "],
                                        suffix=[" 0 R\n"])
        else:
            e_parent_id = None

        e_suffix = Node('suffix', values=["/Type /Pages\n>>"])

        if parent_id is not None:
            e = Node(name, subnodes=[e_prefix, e_parent, e_kids, e_count, e_suffix])
        else:
            e = Node(name, subnodes=[e_prefix, e_kids, e_count, e_suffix])

        return PageNode(PDFObj.create_wrapped_obj(name, e, ident=page_node_id), e_parent_id, e_kids_id, e_count_nb)


    @staticmethod
    def make_page_leaf(name, parent_id=4444, resources_id=4444, contents_id=4444,
                          media_box_nodes=None,
                          media_box_vals=[['0'], ['0'], ['595.276'], ['841.89']]):

        e_prefix = Node('prefix', values=["<<\n"])

        e_parent_id = Node("parent_id", value_type=INT_str(values=[parent_id]))
        e_parent = make_wrapped_node("Parent_E",
                                    node=e_parent_id,
                                    prefix=["/Parent "],
                                    suffix=[" 0 R\n"])

        if media_box_nodes is not None:
            e = PDFObj.get_array("array",
                                 nodes=media_box_nodes,
                                 indirect=False)
        else:
            e = PDFObj.get_array("array",
                                 vals=media_box_vals,
                                 alt_vals=[['0'], ['0'], ['20000000'], ['20000000']],
                                 indirect=False)


        e_media_box = make_wrapped_node("MediaBox_E",
                                       node=e,
                                       prefix=["/MediaBox "],
                                       suffix=["\n"])

        e_resources_id = Node("resource_id", value_type=INT_str(values=[resources_id]))
        e_resources = make_wrapped_node("Resources_E",
                                       node=e_resources_id,
                                       prefix=["/Resources "],
                                       suffix=[" 0 R\n"])

        e_contents_id = Node("contents_id", value_type=INT_str(values=[contents_id]))
        e_contents = make_wrapped_node("Contents_E",
                                      node=e_contents_id,
                                      prefix=["/Contents "],
                                      suffix=[" 0 R\n"])

        e_suffix = Node('suffix', values=["/Type /Page\n>>"])
        
        e_optional_entries = Node('other_entries', values=[''])

        l = [e_prefix, e_parent, e_media_box, e_resources, e_contents, e_optional_entries, e_suffix]

        e = Node(name, subnodes=l)
        return PageLeaf(PDFObj.create_wrapped_obj(name, e), e_parent_id, e_resources_id, e_contents_id, e_optional_entries)




    @staticmethod
    def __generate_pagetree_flat(pdf_contents):
        '''              
        postcondition: the catalog Node shall be put at the end
        '''
        l = []
        pagetree_id = PDFObj.get_pdfobj_id()

        obj_ids = []
        for p in pdf_contents.leafs:
            p[1].set_parent_id(pagetree_id)
            obj_ids.append(p[1].get_id())
            l.append(p[1].e_leaf)

        nb_objs = len(obj_ids)

        page_node = PDFObj.make_page_node('Page_Tree',
                                          page_node_id=pagetree_id,
                                          kids_id=obj_ids)
        e_pagetree = page_node.e_node
        l.append(e_pagetree)

        return l, pagetree_id


    @staticmethod
    def __generate_pagetree_pageloop(pdf_contents):
        '''              
        postcondition: the catalog Node shall be put at the end
        '''
        l = []
        pagetree_id = PDFObj.get_pdfobj_id()


        action_next_page = ('/AA <<\n'
                            ' /O <<\n'
                            '  /S Named\n'
                            '  /N NextPage\n'
                            ' >>\n'
                            '>>\n')

        action_first_page = ('/AA <<\n'
                            ' /O <<\n'
                            '  /S Named\n'
                            '  /N FirstPage\n'
                            ' >>\n'
                            '>>\n')

        obj_ids = []
        for p in pdf_contents.leafs:
            p[1].set_parent_id(pagetree_id)
            p[1].set_actions(vals=[action_next_page])
            obj_ids.append(p[1].get_id())
            l.append(p[1].e_leaf)

        pdf_contents.leafs[-1][1].set_actions(vals=[action_first_page])

        nb_objs = len(obj_ids)

        page_node = PDFObj.make_page_node('Page_Tree',
                                          page_node_id=pagetree_id,
                                          kids_id=obj_ids)
        e_pagetree = page_node.e_node
        l.append(e_pagetree)

        return l, pagetree_id



    @staticmethod
    def __generate_pagetree_branchloop(pdf_contents):

        pagetree_id = PDFObj.get_pdfobj_id()

        l = [p[1].e_leaf for p in pdf_contents.leafs]

        leafs = copy.copy(pdf_contents.leafs)
        nb_leafs = len(leafs)
        leafs_for_node12 = [leafs.pop() for i in range(nb_leafs//2)]
        leafs_for_node2 = leafs

        # print('DEBUG: ', leafs_for_node12, leafs_for_node2)

        node1_id = PDFObj.get_pdfobj_id()
        node12_id = PDFObj.get_pdfobj_id()
        node2_id = PDFObj.get_pdfobj_id()

        node12 = PDFObj.make_page_node('Node_1-2',
                                       parent_id=node1_id,
                                       page_node_id=node12_id,
                                       count=len(leafs_for_node12)+1)
        l.append(node12.e_node)
        kids_id = [p[1].get_id() for p in leafs_for_node12]
        kids_id.append(node2_id)
        node12.change_kids_id(kids_id)

        for p in leafs_for_node12:
            p[1].set_parent_id(node12_id)

        node1 = PDFObj.make_page_node('Node_1',
                                         parent_id=pagetree_id,
                                         page_node_id=node1_id,
                                         kids_id=[node12_id],
                                         count=len(leafs_for_node12)+1)
        l.append(node1.e_node)

        node2 = PDFObj.make_page_node('Node_2',
                                      parent_id=pagetree_id,
                                      page_node_id=node2_id,
                                      count=len(leafs_for_node2)+len(leafs_for_node12)+1)
        l.append(node2.e_node)
        kids_id = [p[1].get_id() for p in leafs_for_node2]
        kids_id.insert(0, node1_id)
        node2.change_kids_id(kids_id)

        for p in leafs_for_node2:
            p[1].set_parent_id(node2_id)

        page_tree = PDFObj.make_page_node('Page_Tree',
                                          page_node_id=pagetree_id,
                                          kids_id=[node1_id, node2_id],
                                          count=nb_leafs+1)
        e_pagetree = page_tree.e_node
        l.append(e_pagetree)

        random.shuffle(l)

        return l, pagetree_id



    @staticmethod
    def __get_pdf_generator_node(name, pdf_contents, catalog_type=None, xref_type=None):

        def _generate_pdf_body(pdf_contents, args):

            PDFObj.__obj_id = args[0][0]
            PDFObj.__obj_gen_num = args[0][1]

            pagetree_generator_func = args[1]

            obj_list = []
            pl_itl = []
            for p in pdf_contents.leafs:
                if p[0].e_resources not in pl_itl:
                    pl_itl.append(p[0].e_resources)
                    obj_list.append(p[0].e_resources)
                    if p[0].e_resources != p[0].e_contents:
                        obj_list.append(p[0].e_contents)
                    for e in p[0].other_nodes:
                        obj_list.append(e)

            random.shuffle(obj_list)

            pagetree_objs, pagetree_id = pagetree_generator_func(pdf_contents)

            node_list = obj_list + pagetree_objs

            e_raw_catalog = make_wrapped_node("Catalog",
                                             node=Node("pagetree_id", value_type=INT_str(values=[pagetree_id])),
                                             prefix=["<<\n/Pages "],
                                             suffix=[" 0 R\n/Type /Catalog\n>>"])
            e_catalog = PDFObj.create_wrapped_obj("Catalog", e_raw_catalog)

            node_list.append(e_catalog)

            # for e in obj_list:
            #     print('DEBUG: ', e.get_private(), e)

            e_pdf_body = Node('dyn', subnodes=node_list)

            context = (PDFObj.__obj_id, PDFObj.__obj_gen_num)
            return e_pdf_body, context


        def _generate_xref(objs):

            e_hdr, e_pdfobjs_gen = objs

            hdr = e_hdr.to_bytes()
            header_len = len(hdr)

            node_list = []

            e_pdfobjs_gen.get_value()
            PDFObj.__obj_id, PDFObj.__obj_gen_num = e_pdfobjs_gen.get_private()

            for e in e_pdfobjs_gen.cc.generated_node.cc.frozen_node_list:
                node_list.append(e)

            catalog = node_list[-1]
            # node_list last Node is the catalog
            catalog_id = catalog.get_private()

            values = list(map(lambda x: x.to_bytes(), node_list))
            sorted_node_list = sorted(node_list, key=lambda x: x.get_private())

            nb_objs = len(node_list) + 1  # we have to count the object 0

            off = header_len

            objs_offset = {}
            for v, e in zip(values, node_list):
                obj_len = len(v)
                objs_offset[e] = off
                off += obj_len

            xref_str = "xref\n0 {:d}\n0000000000 65535 f \n".format(nb_objs)
            for e in sorted_node_list:
                xref_str += "{:0>10d}".format(objs_offset[e]) + " 00000" + " n \n"

            e_xref = Node('xref', values=[xref_str])
            e_xref.set_private(off)

            trailer_str = ("trailer\n"
                           "<< /Size {size:d}\n"
                           "/Root {root_id:d} 0 R\n>>\n"
                           "startxref\n{xref_off:d}\n%%EOF\n").format(size=nb_objs, root_id=catalog_id, xref_off=off)

            e_trailer = Node('trailer', values=[trailer_str])

            e_pdf = Node('dyn', subnodes=[e_hdr, e_pdfobjs_gen, e_xref, e_trailer])

            return e_pdf


        def _generate_xref_loop(objs):

            e_hdr, e_pdfobjs_gen = objs

            hdr = e_hdr.to_bytes()
            header_len = len(hdr)

            node_list = []

            e_pdfobjs_gen.get_value()
            PDFObj.__obj_id, PDFObj.__obj_gen_num = e_pdfobjs_gen.get_private()

            for e in e_pdfobjs_gen.cc.generated_node.cc.frozen_node_list:
                node_list.append(e)

            catalog = node_list[-1]
            # node_list last Node is the catalog
            catalog_id = catalog.get_private()

            values = list(map(lambda x: x.to_bytes(), node_list))
            sorted_node_list = sorted(node_list, key=lambda x: x.get_private())

            nb_objs = len(node_list) + 1  # we have to count the object 0

            off = header_len

            objs_offset = {}
            for v, e in zip(values, node_list):
                obj_len = len(v)
                objs_offset[e] = off
                off += obj_len

            xref_str = ("xref\n0 1\n0000000000 65535 f \n"
                        "2 {:d}\n").format(nb_objs - 1) # obj 0 shall not be counted here
            for e in sorted_node_list:
                xref_str += "{:0>10d}".format(objs_offset[e]) + " 00000" + " n \n"

            e_xref = Node('xref', values=[xref_str])
            e_xref.set_private(off)

            e_random_obj = PDFObj.get_stream('random_obj', stream=b'RANDOM OBJECT!')

            rand_obj_len = len(e_random_obj.to_bytes())
            
            incomplete_trailer = ("trailer\n"
                                  "<< /Size {size:d}\n"
                                  "/Root {root_id:d} 0 R\n"
                                  "/Prev \n>>\n"
                                  "startxref\n{xref_off:d}\n%%EOF\n").format(size=nb_objs+1, root_id=catalog_id, xref_off=off)
            
            nt_off_approx1 = off + len(xref_str) + len(incomplete_trailer) + rand_obj_len
            nt_off_approx2 = nt_off_approx1 + len(str(nt_off_approx1))

            if len(str(nt_off_approx2)) > len(str(nt_off_approx1)):
                raise ValueError

            while len(str(nt_off_approx2)) < len(str(nt_off_approx1)):
                nt_off_approx2 += 1

            trailer_str = ("trailer\n"
                           "<< /Size {size:d}\n"
                           "/Root {root_id:d} 0 R\n"
                           "/Prev {next_trailer_off:d}\n>>\n"
                           "startxref\n{xref_off:d}\n%%EOF\n")
            trailer_str = trailer_str.format(size=nb_objs+1, root_id=catalog_id, next_trailer_off=nt_off_approx2, xref_off=off)
                           
            e_trailer = Node('trailer', values=[trailer_str])
            
            off_rand_obj = off + len(xref_str) + len(trailer_str)

            xref2_str = ("xref\n"
                        "0 1\n0000000000 65535 f \n"
                        "{:d} 1\n").format(e_random_obj.get_private())
            xref2_str += "{:0>10d}".format(off_rand_obj) + " 00000" + " n \n"

            e_xref2 = Node('xref2', values=[xref2_str])
            e_xref2.set_private(off)

            trailer2_str = ("trailer\n"
                            "<< /Size {size:d}\n"
                            "/Root {root_id:d} 0 R\n"
                            "/Prev {prev_trailer_off:d}\n>>\n"
                            "startxref\n{xref_off:d}\n%%EOF\n")
            trailer2_str = trailer2_str.format(size=nb_objs+2, root_id=catalog_id, prev_trailer_off=off, xref_off=nt_off_approx2)

            e_trailer2 = Node('trailer2', values=[trailer2_str])

            e_pdf = Node('dyn', subnodes=[e_hdr, e_pdfobjs_gen, e_xref, e_trailer, e_random_obj, e_xref2, e_trailer2])

            return e_pdf


        context = (PDFObj.__obj_id, PDFObj.__obj_gen_num)

        e_pdf_body_gen = Node('Body')

        if catalog_type == PDFObj.t_ctg_flat:
            e_pdf_body_gen.set_generator_func(_generate_pdf_body, func_node_arg=pdf_contents,
                                              func_arg=(context, PDFObj.__generate_pagetree_flat))
            e_pdf_body_gen.customize(GenFuncCusto(items_to_set=GenFuncCusto.CloneExtNodeArgs))
            e_pdf_body_gen.add_conf('pagetree_branchloop')
            e_pdf_body_gen.set_generator_func(_generate_pdf_body, func_node_arg=pdf_contents,
                                              func_arg=(context, PDFObj.__generate_pagetree_branchloop), conf='pagetree_branchloop')
            e_pdf_body_gen.c['pagetree_branchloop'].customize(GenFuncCusto(items_to_set=GenFuncCusto.CloneExtNodeArgs))

        elif catalog_type == PDFObj.t_ctg_pagetree_loop:
            e_pdf_body_gen.set_generator_func(_generate_pdf_body, func_node_arg=pdf_contents,
                                              func_arg=(context, PDFObj.__generate_pagetree_branchloop))
            e_pdf_body_gen.customize(GenFuncCusto(items_to_set=GenFuncCusto.CloneExtNodeArgs))
        elif catalog_type == PDFObj.t_ctg_page_loop:
            e_pdf_body_gen.set_generator_func(_generate_pdf_body, func_node_arg=pdf_contents,
                                              func_arg=(context, PDFObj.__generate_pagetree_pageloop))
            e_pdf_body_gen.customize(GenFuncCusto(items_to_set=GenFuncCusto.CloneExtNodeArgs))
        else:
            raise ValueError

        e_pdf_gen = Node(name)

        if xref_type == PDFObj.t_xref_valid:
            e_pdf_gen.set_generator_func(_generate_xref, [pdf_contents.e_hdr, e_pdf_body_gen])
            e_pdf_gen.customize(GenFuncCusto(items_to_set=GenFuncCusto.CloneExtNodeArgs))
        elif xref_type == PDFObj.t_xref_loop:
            e_pdf_gen.set_generator_func(_generate_xref_loop, [pdf_contents.e_hdr, e_pdf_body_gen])
            e_pdf_gen.customize(GenFuncCusto(items_to_set=GenFuncCusto.CloneExtNodeArgs))
        else:
            raise ValueError

        return e_pdf_gen



    @staticmethod
    def __generate_random_page_leafs(use_unallocated_id=False):
        pages = []

        if use_unallocated_id:
            unallocated_id = PDFObj.get_pdfobj_id()

        for i in range(1):
            internals = PDFObj.get_jpg(str(i))

            if use_unallocated_id:
                internals.e_resources.set_private(unallocated_id)

            # nb_leafs = random.randint(10,40)
            nb_leafs = 5
            for j in range(nb_leafs):
                # mb_vals = [['0'], ['0'],
                #            [str(random.randint(0, 5000))],
                #            [str(random.randint(0, 5000))]]

                mb_nodes = [Node('X', values=['0']), Node('Y', values=['0']),
                           PDFObj.get_number('width', int_m=50, int_M=1000, enforce_unsigned=False, indirect=False),
                           PDFObj.get_number('height', int_m=50, int_M=1000, enforce_unsigned=False, indirect=False)]
                
                page_leaf = PDFObj.make_page_leaf('JPG_leaf_%d-%d'%(i,j),
                                                  resources_id=internals.e_resources.get_private(),
                                                  contents_id=internals.e_contents.get_private(),
                                                  media_box_nodes=mb_nodes)
                                                  # media_box_vals=mb_vals)

                pages.append((internals, page_leaf))

        return pages


    @staticmethod
    def __generate_pdfbomb_leafs():
        pages = []

#        e_pdf_bomb = PDFObj.get_stream('PDFbomb', enc_stream=PDFObj.stream_pdfbomb, dynamic=True)
        e_pdf_bomb = PDFObj.get_stream('PDFbomb', stream=b'A'*2**30, use_generator_func=True)
        internals = PageLeaf_Internals(e_pdf_bomb, e_pdf_bomb)

        page_leaf = PDFObj.make_page_leaf('PDFbomb_leaf',
                                          resources_id=e_pdf_bomb.get_private(),
                                          contents_id=e_pdf_bomb.get_private())

        pages.append((internals, page_leaf))

        return pages


    ## Define various kind of malformed PDF, that can be used as a
    ## starting point for fuzzing

    ## 1. PDF objects types:
    # pagetree is correct
    t_obj_basic = 1
    # pdfbomb
    t_obj_pdfbomb = 2

    ## 2. PDF catalog types:
    # valid flat catalog
    t_ctg_flat = 1
    # loop in pagetree
    t_ctg_pagetree_loop = 2
    # loop in pages via PDF actions
    t_ctg_page_loop = 3

    ## 3. PDF xref types:
    # valid xref
    t_xref_valid = 1
    # infinite loop with 2 xref --> implement xref infinite loop for obj 1 access
    # which is used as the resource_id for the pages
    t_xref_loop = 2


    @staticmethod
    def make_pdf_node(name, pdfobj_type=t_obj_basic, catalog_type=t_ctg_flat, xref_type=t_xref_valid):

        PDFObj.__obj_id = 1
        PDFObj.__obj_gen_num = 0

        def _make_obj_basic():
            if xref_type == PDFObj.t_xref_loop:
                return PDFObj.__generate_random_page_leafs(use_unallocated_id=True)
            else:
                return PDFObj.__generate_random_page_leafs()

        def _make_obj_pdfbomb():
            return PDFObj.__generate_pdfbomb_leafs()

        leafs = {PDFObj.t_obj_basic: _make_obj_basic,
                 PDFObj.t_obj_pdfbomb: _make_obj_pdfbomb
                 }[pdfobj_type]()

        e_hdr = PDFObj.get_pdf_header_node()

        pdf_contents = PDFContents()
        pdf_contents.leafs = leafs
        pdf_contents.e_hdr = e_hdr

        e_pdf = PDFObj.__get_pdf_generator_node(name, pdf_contents, catalog_type, xref_type)

        return e_pdf



class PageNode(object):
    def __init__(self, node, e_parent_id, e_kids_id, e_count_nb):
        self.e_node = node
        self.e_parent_id = e_parent_id
        self.e_count_nb = e_count_nb
        self.e_kids_id = e_kids_id

    def change_kids_id(self, kids_id, count_update=None):
        l = []
        for i in kids_id:
            l.append(Node("kid_%d"%i, values=["%d 0 R"%i]))

        rawlist = PDFObj.get_array("array", nodes=l, indirect=False, return_rawlist=True)
        self.e_kids_id.set_subnodes_basic(rawlist)

        if count_update is not None:
            self.e_count_nb.set_values(value_type=INT_str(values=[count_update]))


class PageLeaf(object):
    def __init__(self, leaf, e_parent_id, e_resources_id, e_contents_id, e_optional_entries):
        self.e_leaf = leaf
        self.e_parent_id = e_parent_id
        self.e_resources_id = e_resources_id
        self.e_contents_id = e_contents_id
        self.e_optional_entries = e_optional_entries

    def get_id(self):
        return self.e_leaf.get_private()

    def set_parent_id(self, pid):
        self.e_parent_id.set_values(value_type=INT_str(values=[pid]))

    def set_actions(self, subnodes=None, vals=None):
        if subnodes is not None:
            self.e_optional_entries.set_subnodes(subnodes)
        elif vals is not None:
            self.e_optional_entries.set_values(vals)
        else:
            raise ValueError


class PageLeaf_Internals(object):
    def __init__(self, e_resources, e_contents, other_nodes=[]):
        self.e_resources = e_resources
        self.e_contents = e_contents
        self.other_nodes = other_nodes

    def __hash__(self):
        return id(self)


class PDFContents(NodeAbstraction):

    def __init__(self):
        self.e_hdr = None
        self.leafs = None

    def get_concrete_nodes(self):
        l = []
        for p in self.leafs:
            l.append(p[0].e_resources)
            l.append(p[0].e_contents)
            for e in p[0].other_nodes:
                l.append(e)
            l.append(p[1].e_leaf)
            l.append(p[1].e_parent_id)
            l.append(p[1].e_resources_id)
            l.append(p[1].e_contents_id)
            l.append(p[1].e_optional_entries)

        l.append(self.e_hdr)

        return l

    def set_concrete_nodes(self, nodes_args):
        self.e_hdr = nodes_args[-1]

        i = 0
        new_leafs = []
        for nb in range(len(self.leafs)):
            onodes = self.leafs[nb][0].other_nodes
            nb_onodes = len(onodes)

            # print('DEBUG: ', nb_onodes)

            l = []
            for idx in range(nb_onodes):
                l.append(nodes_args[i+2+idx])
                
            itl = PageLeaf_Internals(nodes_args[i], nodes_args[i+1], l)
            pl = PageLeaf(nodes_args[i+nb_onodes+2], nodes_args[i+nb_onodes+3], nodes_args[i+nb_onodes+4],
                          nodes_args[i+nb_onodes+5], nodes_args[i+nb_onodes+6])
            new_leafs.append((itl, pl))

            i += (7 + nb_onodes)
            
        self.leafs = new_leafs

    def make_private(self):
        pass


### NEED TO BE REVAMPED
class PDF_DataModel(DataModel):

    file_extension = 'pdf'

    def build_data_model(self):
               
        PDFObj.external_pdf_objs = gather_pdf_objects()

        e_jpg = self.get_external_node(dm_name='jpg', data_id='jpg_00')

        PDFObj.jpg_node = e_jpg

        e_pdf_nodes = []


        e_pdf_nodes.append(PDFObj.make_pdf_node('PDF_basic',
                                              pdfobj_type=PDFObj.t_obj_basic,
                                              catalog_type=PDFObj.t_ctg_flat))

        e_pdf_nodes.append(PDFObj.make_pdf_node('PDF_pagetree_loop',
                                              pdfobj_type=PDFObj.t_obj_basic,
                                              catalog_type=PDFObj.t_ctg_pagetree_loop))

        e_pdf_nodes.append(PDFObj.make_pdf_node('PDF_page_loop',
                                              pdfobj_type=PDFObj.t_obj_basic,
                                              catalog_type=PDFObj.t_ctg_page_loop))

        e_pdf_nodes.append(PDFObj.make_pdf_node('PDF_xref_loop',
                                              pdfobj_type=PDFObj.t_obj_basic,
                                              catalog_type=PDFObj.t_ctg_flat,
                                              xref_type=PDFObj.t_xref_loop))

        e_pdf_nodes.append(PDFObj.make_pdf_node('PDF_bomb',
                                              pdfobj_type=PDFObj.t_obj_pdfbomb,
                                              catalog_type=PDFObj.t_ctg_flat))

        self.register_nodes(*e_pdf_nodes)



data_model = PDF_DataModel()

if __name__ == "__main__":

    from framework.plumbing import *
    fmk = FmkPlumbing()

    dm = data_model
    dm.load_data_model(fmk._name2dm)

    print("\n[ PDF Number ]\n")

    e = PDFObj.get_number('test')
    for i in range(60):
        print(e.to_bytes())
        e.unfreeze()

    print("\n[ PDF Names ]\n")

    e = PDFObj.get_name('test')
    for i in range(10):
        print(e.to_bytes())
        e.unfreeze()
    print("\n --- invalid names:\n")
    for i in range(10):
        s = NodeSemanticsCriteria(mandatory_criteria=['PDF_name', 'RAW'])
        l = e.get_reachable_nodes(semantics_criteria=s)
        for node in l: node.set_current_conf('ALT', recursive=False)
        print(e.to_bytes())
        for node in l: node.set_current_conf('MAIN', reverse=True, recursive=False)
        e.unfreeze_all()

        print(e.to_bytes(conf='ALT'))
        e.unfreeze_all()

    print("\n --- invalid delim:\n")
    for i in range(10):
        s = NodeSemanticsCriteria(mandatory_criteria=['delim'])
        l = e.get_reachable_nodes(semantics_criteria=s)
        for node in l: node.set_current_conf('ALT', recursive=False)
        print(e.to_bytes())
        for node in l: node.set_current_conf('MAIN', reverse=True, recursive=False)
        e.unfreeze_all()

    print("\n[ PDF strings ]\n")

    e = PDFObj.get_string('test')
    for i in range(10):
        print(e.to_bytes())
        e.unfreeze()
    print("\n --- invalid names:\n")
    for i in range(10):
        s = NodeSemanticsCriteria(mandatory_criteria=['PDF_string', 'RAW'])
        l = e.get_reachable_nodes(semantics_criteria=s)
        for node in l: node.set_current_conf('ALT', recursive=False)
        msg = e.to_bytes()
        for node in l: node.set_current_conf('MAIN', reverse=True, recursive=False)
        print(msg[:1000])
        e.unfreeze_all()

    print("\n --- invalid delim:\n")
    for i in range(10):
        l = e.get_reachable_nodes(semantics_criteria=NodeSemanticsCriteria(mandatory_criteria=['delim']))
        for node in l: node.set_current_conf('ALT', recursive=False)
        print(e.to_bytes())
        for node in l: node.set_current_conf('MAIN', reverse=True, recursive=False)
        e.unfreeze_all()

    print("\n[ PDF get objects ]\n")

    for i in range(10):
        e = PDFObj.get_string('test')
        print(e.to_bytes())
        print('id: ', e.get_private())

    print("\n[ Tests copy and private attribute ]\n")

    e2 = Node('test', base_node=e)
    print(e2.to_bytes())
    print('id(e2): ', e2.get_private())
    
    e2.set_private('OK!')
    print('new_id(e2): ', e2.get_private())

    print('id(e) : ', e.get_private())
    

    print("\n[ PDF generation ]\n")

    pdf = dm.get_data('PDF_basic')

    val = pdf.to_bytes()
    val2 = pdf.to_bytes()

    print('freezen? ', val == val2)
    if val != val2:
        raise ValueError


    with open(gr.workspace_folder + 'TEST_FUZZING_PDF-orig' + '.pdf', 'wb') as f:
        f.write(val)

    leaf0 = pdf.get_node_by_path('PDF.*leaf_0-0$').to_bytes()
    pdf.set_current_conf('ALT', root_regexp='PDF.*leaf_0-0$')
    leaf1 = pdf.get_node_by_path('PDF.*leaf_0-0$').to_bytes()

    print(leaf0)
    print(leaf1)

    pdf.unfreeze()

    val3 = pdf.to_bytes()
    with open(gr.workspace_folder + 'TEST_FUZZING_PDF-big_page' + '.pdf', 'wb') as f:
        f.write(val3)

    pdf.set_current_conf('MAIN', root_regexp='PDF.*leaf_0-0$')

    pdf_buff = {}
    for e_id in dm.data_identifiers():
        if e_id == 'PDF_bomb':
            continue

        print('DEBUG: ', e_id)

        pdf = dm.get_data(e_id)
        pdf_buff[e_id] = pdf.to_bytes()

        with open(gr.workspace_folder + e_id + '.pdf', 'wb') as f:
            f.write(pdf_buff[e_id])
