import copy
import itertools
import traceback

from fuddly.libs.external_modules import colorize, Color
from fuddly.framework.data_model import DataModel
from fuddly.framework.error_handling import ScenarioDefinitionError
# from fuddly.framework.scenario import *
from fuddly.framework.scenario_bricks import ScenarioBrick, FragmentationBrick

class ScenarioBuilder(object):

    def __init__(self):
        self._dm = None
        self.kwargs = None
        self._sbrick = None
        self._sbrick_in_id = 1
        self._sbrick_out_id = 1
        self._starting_sbrick = None
        self._ending_sbrick = None
        self._starting_sbrick_out_id = None
        self._ending_sbrick_in_id = None
        self._starting_sbrick_connect_params = None
        self._ending_sbrick_connect_params = None


    def load(self, dm: DataModel):
        raise NotImplementedError

    def set_starting_sbrick(self, sbrick: ScenarioBrick, out_connector_id = 1, **connect_params):
        self._starting_sbrick = sbrick
        self._starting_sbrick_out_id = out_connector_id
        self._starting_sbrick_connect_params = connect_params

    def set_ending_sbrick(self, sbrick: ScenarioBrick, in_connector_id = 1, **connect_params):
        self._ending_sbrick = sbrick
        self._ending_sbrick_in_id = in_connector_id
        self._ending_sbrick_connect_params = connect_params

    def set_scenario_params(self, name, **kwargs):
        self.name = name
        self.kwargs = kwargs

    def setup(self, dm: DataModel):
        self._sbrick: ScenarioBrick = self.load(dm)

    @property
    def dm(self):
        return self._dm

    @dm.setter
    def dm(self, dm: DataModel):
        self._dm = dm

    def __iter__(self):
        for sid in self._sbrick.shape_ids:
            new_brick = self._sbrick.clone()
            new_brick.setup(shape_id=sid)

            if self._starting_sbrick is not None:
                new_brick.connect_in_to(self._starting_sbrick,
                                           in_idx=self._sbrick_in_id,
                                           out_idx=self._starting_sbrick_out_id,
                                           **self._starting_sbrick_connect_params)
            if self._ending_sbrick is not None:
                new_brick.connect_out_to(self._ending_sbrick,
                                            out_idx=self._sbrick_out_id,
                                            in_idx=self._ending_sbrick_in_id,
                                            **self._ending_sbrick_connect_params)

            new_brick.build_connection(auto_update_starting_step=True,
                                       auto_update_ending_step=True)
            new_brick.find_and_finalize_ending_sbrick(new_brick)

            yield new_brick.get_scenario()


class FragmentationScenarioBuilder(ScenarioBuilder):

    def load(self, dm: DataModel):
        frag_brick = FragmentationBrick(self.name, **self.kwargs)
        frag_brick.prepare_shapes(dm)

        return frag_brick
