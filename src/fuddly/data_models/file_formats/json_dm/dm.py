import json

from fuddly.framework.data_model import *
from fuddly.framework.value_types import *
from fuddly.framework.dmhelpers.json import json_model_builder, json_builder

class JSON_DataModel(DataModel):

    name = 'json'
    file_extension = 'json'

    def _create_atom_from_raw_data_specific(self, data, idx, filename):
        json_data = json.loads(data)
        node_name = 'json_'+filename[:-len(self.file_extension)-1]
        if '$schema' in json_data:
            try:
                return json_model_builder(node_name=node_name, schema=json_data, ignore_pattern=False)
            except:
                print('\n*** WARNING: Node creation attempt failed. New attempt, but now ignore '
                      'regex patterns from string JSON types.')
                return json_model_builder(node_name=node_name, schema=json_data, ignore_pattern=True)
        else:
            return json_builder(node_name=node_name, sample=json_data)

    def build_data_model(self):
        pass


data_model = JSON_DataModel()
