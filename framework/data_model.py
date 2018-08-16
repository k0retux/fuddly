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

import framework.global_resources as gr
from framework.data import *
from framework.dmhelpers.generic import *
from framework.node_builder import NodeBuilder
from libs.external_modules import *


#### Data Model Abstraction

class DataModel(object):
    """ 
    Data Model Abstraction
    """

    file_extension = 'bin'
    name = None

    knowledge_source = None

    def pre_build(self):
        """
        This method is called when a data model is loaded.
        It is executed before build_data_model().
        To be implemented by the user.
        """
        pass


    def build_data_model(self):
        """
        This method is called when a data model is loaded.
        It is called only the first time the data model is loaded.
        To be implemented by the user.
        """
        pass


    def absorb(self, raw_data, idx):
        """
        If your data model is able to absorb raw data, do it here.  This
        function is called for each files (with the right extension)
        present in imported_data/<data_model_name>.
        
        It should return an modeled data (atom)
        """
        return raw_data

    def cleanup(self):
        pass

    def __init__(self):
        self.node_backend = NodeBackend(self)
        self._dm_db = None
        self._built = False
        self._dm_hashtable = {}
    #     self._knowledge_soure = None
    #
    # @property
    # def knowledge_source(self):
    #     return self._knowledge_source
    #
    # @knowledge_source.setter
    # def knowledge_source(self, src):
    #     self._knowledge_source = src
    #     self.node_backend.knowledge_source = src
    #     for atom in self._dm_hashtable.values():
    #         self._backend(atom).update_knowledge_source(atom)

    def _backend(self, atom):
        if isinstance(atom, (Node, dict)):
            return self.node_backend
        else:
            raise NotImplementedError

    def __str__(self):
        return self.name if self.name is not None else 'Unnamed'

    def register(self, *atom_list):
        for a in atom_list:
            if a is None: continue
            key, prepared_atom = self._backend(a).prepare_atom(a)
            self._dm_hashtable[key] = prepared_atom

    def get_atom(self, hash_key, name=None):
        if hash_key in self._dm_hashtable:
            atom = self._dm_hashtable[hash_key]
            return self._backend(atom).atom_copy(atom, new_name=name)
        else:
            raise ValueError('Requested data does not exist!')

    def get_external_atom(self, dm_name, data_id, name=None):
        dm = self._dm_db[dm_name]
        dm.load_data_model(self._dm_db)
        try:
            atom = dm.get_atom(data_id, name=name)
        except ValueError:
            return None

        return atom

    def load_data_model(self, dm_db):
        self.pre_build()
        if not self._built:
            self._dm_db = dm_db
            self.build_data_model()
            self._built = True

    def merge_with(self, data_model):
        for k, v in data_model._dm_hashtable.items():
            if k in self._dm_hashtable:
                raise ValueError("the data ID {:s} exists already".format(k))
            else:
                self._dm_hashtable[k] = v

        self.node_backend.merge_with(data_model.node_backend)

    def atom_identifiers(self):
        hkeys = sorted(self._dm_hashtable.keys())
        for k in hkeys:
            yield k

    def update_atom(self, atom):
        self._backend(atom).update_atom(atom)

    def show(self):
        print(colorize(FontStyle.BOLD + '\n-=[ Data Types ]=-\n', rgb=Color.INFO))
        idx = 0
        for data_key in self._dm_hashtable:
            print(colorize('[%d] ' % idx + data_key, rgb=Color.SUBINFO))
            idx += 1

    def import_file_contents(self, extension=None, absorber=None,
                             subdir=None, path=None, filename=None):

        if absorber is None:
            absorber = self.absorb

        if extension is None:
            extension = self.file_extension
        if path is None:
            path = self.get_import_directory_path(subdir=subdir)

        r_file = re.compile(".*\." + extension + "$")
        def is_good_file_by_ext(fname):
            return bool(r_file.match(fname))

        def is_good_file_by_fname(fname):
            return filename == fname

        files = []
        for (dirpath, dirnames, filenames) in os.walk(path):
            files.extend(filenames)
            break

        if filename is None:
            files = list(filter(is_good_file_by_ext, files))
        else:
            files = list(filter(is_good_file_by_fname, files))
        msgs = {}
        idx = 0

        for name in files:
            with open(os.path.join(path, name), 'rb') as f:
                buff = f.read()
                d_abs = absorber(buff, idx)
                if d_abs is not None:
                    msgs[name] = d_abs
            idx +=1

        return msgs

    def get_import_directory_path(self, subdir=None):
        if subdir is None:
            subdir = self.name
        if subdir is None:
            path = gr.imported_data_folder
        else:
            path = os.path.join(gr.imported_data_folder, subdir)

        if not os.path.exists(path):
            os.makedirs(path)

        return path

class NodeBackend(object):

    def __init__(self, data_model):
        self._dm = data_model
        self._confs = set()
        # self._knowledge_source = None

    # @property
    # def knowledge_source(self):
    #     return self._knowledge_source
    #
    # @knowledge_source.setter
    # def knowledge_source(self, src):
    #     self._knowledge_source = src
    #
    # def update_knowledge_source(self, atom):
    #     if self.knowledge_source is not None:
    #         atom.env.knowledge_source = self.knowledge_source

    def merge_with(self, node_backend):
        self._confs = self._confs.union(node_backend._confs)

    def prepare_atom(self, atom):
        if not atom:
            msg = "\n*** WARNING: nothing to register for " \
                  "the data model '{nm:s}'!"\
                  "\n   [probable reason: {fdata:s}/imported_data/{nm:s}/ not " \
                  "populated with sample files]".format(nm=self._dm.name, fdata=gr.fuddly_data_folder)
            raise UserWarning(msg)

        if isinstance(atom, dict):
            mb = NodeBuilder(dm=self._dm)
            desc_name = 'Unreadable Name'
            try:
                desc_name = atom['name']
                atom = mb.create_graph_from_desc(atom)
            except:
                print('-'*60)
                traceback.print_exc(file=sys.stdout)
                print('-'*60)
                msg = "*** ERROR: problem encountered with the '{desc:s}' descriptor!".format(desc=desc_name)
                raise UserWarning(msg)

        if atom.env is None:
            self.update_atom(atom)
        else:
            self.update_atom(atom, existing_env=True)

        self._confs = self._confs.union(atom.gather_alt_confs())

        return atom.name, atom

    def atom_copy(self, orig_atom, new_name=None):
        name = orig_atom.name if new_name is None else new_name
        node = Node(name, base_node=orig_atom, ignore_frozen_state=False, new_env=True)
        # self.update_knowledge_source(node)
        return node

    def update_atom(self, atom, existing_env=False):
        if not existing_env:
            atom.set_env(Env())
        atom.env.set_data_model(self._dm)
        # self.update_knowledge_source(atom)

    def get_all_confs(self):
        return sorted(self._confs)
