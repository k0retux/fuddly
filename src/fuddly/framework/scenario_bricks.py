import copy
import itertools
import traceback
import random

from fuddly.libs.external_modules import colorize, Color
from fuddly.framework.data_model import DataModel
from fuddly.framework.error_handling import ScenarioDefinitionError, ScenarioParameterError
from fuddly.framework.scenario import *
import fuddly.framework.node as nd
import fuddly.framework.value_types as vt

class ScenarioBrick(object):

    INIT_SHAPE = 'init_shape'
    shape_ids = None
    description = 'No description'
    _scenario = None

    def __init__(self, name=None, start: bool = True, final: bool = False,
                 auto_update_starting_step=True, auto_update_ending_step=True,
                 default_shape_id=None,
                 **kwargs):

        self._name = self.__class__.__name__ if name is None else name
        self._scenario = None
        self._dm = None
        self.shape_ids = self.shape_ids if self.shape_ids is not None else [ScenarioBrick.INIT_SHAPE]
        self.default_shape_id = default_shape_id
        self.out_connection = {}
        self.in_connection = {}
        self._final = final
        self._start = start
        self._auto_update_starting_step = auto_update_starting_step
        self._auto_update_ending_step = auto_update_ending_step
        self._kwargs = kwargs

    @property
    def name(self):
        return self._name

    @property
    def dm(self):
        return self._dm

    @dm.setter
    def dm(self, dm: DataModel):
        self._dm = dm

    @classmethod
    def description_from_shape_id(cls, shape_id):
        """

        :param shape_id:
        :return:
        """
        return cls.description


    @classmethod
    def scenario_parameters_per_shape_id(cls, shape_id):
        """

        :param shape_id:
        :return:
        """
        return None

    def prepare_shapes(self, dm: DataModel):
        self.dm = dm
        self.pre_build(dm, **self._kwargs)

    def pre_build(self, dm: DataModel = None, **kwargs):
        """
        To be overloaded
        e.g., to prepare self.shape_ids

        :param kwargs:
        :return:
        """
        return

    def build(self, user_context: UI, shape_id: str, **kwargs):
        """
        To be overloaded

        :param shape_id:
        :param user_context:
        :param kwargs:
        :return:

        """
        raise NotImplementedError

    def setup(self, shape_id=None):
        self.default_shape_id = shape_id

        if self._scenario is None:
            ok = self._build(auto_update_starting_step=self._auto_update_starting_step,
                             auto_update_ending_step=self._auto_update_ending_step,
                             shape_id=self.default_shape_id,
                             **self._kwargs)
            if not ok:
                raise ScenarioDefinitionError
        else:
            sys.stderr.write(colorize(f"\n*** WARNING: {self.__class__.__name__}._setup() "
                                      f" scenario is already setup\n",
                                      rgb=Color.WARNING))

    def connect_out_to(self, scbrick, out_idx=None, in_idx=None, **connect_kwargs):
        out_idx = 1 if out_idx is None else out_idx
        in_idx = 1 if in_idx is None else in_idx

        self.out_connection[out_idx] = (in_idx, scbrick, connect_kwargs)

    def connect_in_to(self, scbrick, in_idx=None, out_idx=None, **connect_kwargs):
        out_idx = 1 if out_idx is None else out_idx
        in_idx = 1 if in_idx is None else in_idx

        self.in_connection[in_idx] = (out_idx, scbrick, connect_kwargs)


    def in_connectors(self, idx):
        return self._scenario.in_connectors(idx)

    def out_connectors(self, idx):
        return self._scenario.out_connectors(idx)


    def _build(self, auto_update_starting_step=True, auto_update_ending_step=True, shape_id=None, **kwargs):

        uc = UI(shape_id=shape_id)

        try:
            starting_step, in_connectors, out_connectors = self.build(user_context=uc, shape_id=shape_id,
                                                                      **kwargs)
        except Exception as e:
            self._scenario = None
            sys.stderr.write(colorize(f"\n*** ERROR: {self.__class__.__name__}._build() "
                                      f"raise the exception [{e}]\n",
                                      rgb=Color.ERROR))
            traceback.print_exc()
            return False
        else:
            assert starting_step is not None

        self._scenario = Scenario(self._name, anchor=starting_step, user_context=uc)
        self._scenario.set_in_connectors(in_connectors)
        self._scenario.set_out_connectors(out_connectors)

        self.build_connection(auto_update_starting_step=auto_update_starting_step,
                              auto_update_ending_step=auto_update_ending_step)

        return True

    def build_connection(self, auto_update_starting_step=True, auto_update_ending_step=True):

        for out_idx, obj in self.out_connection.items():
            in_idx, scbrick, connect_kwargs = obj
            if isinstance(scbrick, ScenarioBrick):
                if not scbrick.is_setup():
                    scbrick.setup()
                self._scenario.set_scenario_env(scbrick._scenario.env, merge_user_contexts=True)
                self.out_connectors(out_idx).connect_to(scbrick.in_connectors(in_idx), **connect_kwargs)
            else:
                raise NotImplementedError

        for in_idx, obj in self.in_connection.items():
            out_idx, scbrick, connect_kwargs = obj
            if isinstance(scbrick, ScenarioBrick):
                if not scbrick.is_setup():
                    scbrick.setup()
                self._scenario.set_scenario_env(scbrick._scenario.env, merge_user_contexts=True)
                scbrick.out_connectors(out_idx).connect_to(self.in_connectors(in_idx), **connect_kwargs)
            else:
                raise NotImplementedError

        if auto_update_ending_step:
            self.find_ending_sbrick_and_flag_it_final(self)

        if auto_update_starting_step:
            self.find_starting_sbrick_and_flag_it_start(self)
            self.find_and_set_starting_sbrick(self)


    def set_starting_sbrick(self, scbrick):
        for _, obj in self.in_connection.items():
            _, scb, _ = obj
            if scbrick is scb:
                scbrick.start = True
                self.starting_step = scbrick.starting_step
                break


    def set_ending_sbrick(self, scbrick, finalize=False):
        for _, obj in self.out_connection.items():
            _, scb, _ = obj
            if scbrick is scb:
                scbrick.final = True
                if finalize:
                    scbrick.finalize()
                break


    def find_and_set_starting_sbrick(self, current_scb):
        if current_scb.is_starting_brick():
            self.starting_step = current_scb.starting_step
        else:
            for _, connected_scb, _ in current_scb.in_connection.values():
                if connected_scb.is_starting_brick():
                    self.starting_step = connected_scb.starting_step
                    break
                else:
                    for _, scb, _ in connected_scb.in_connection.values():
                        self.find_and_set_starting_sbrick(scb)

    def find_starting_sbrick_and_flag_it_start(self, current_scb):
        if not current_scb.in_connection.values():
            current_scb.start = True
        else:
            current_scb.start = False
            for _, connected_scb, _ in current_scb.in_connection.values():
                if not connected_scb.in_connection.values():
                    connected_scb.start = True
                else:
                    connected_scb.start = False
                    for _, scb, _ in connected_scb.in_connection.values():
                        self.find_starting_sbrick_and_flag_it_start(scb)


    def find_and_finalize_ending_sbrick(self, current_scb):
        if current_scb.is_ending_brick():
            current_scb.finalize()
        else:
            for _, connected_scb, _ in current_scb.out_connection.values():
                if connected_scb.is_ending_brick():
                    connected_scb.finalize()
                    break
                else:
                    for _, scb, _ in connected_scb.out_connection.values():
                        self.find_and_finalize_ending_sbrick(scb)


    def find_ending_sbrick_and_flag_it_final(self, current_scb):
        if not current_scb.out_connection.values():
            current_scb.final = True
        else:
            current_scb.final = False
            for _, connected_scb, _ in current_scb.out_connection.values():
                if not connected_scb.out_connection.values():
                    connected_scb.final = True
                else:
                    connected_scb.final = False
                    for _, scb, _ in connected_scb.out_connection.values():
                        self.find_ending_sbrick_and_flag_it_final(scb)

    def finalize(self, **kwargs):
        self.final = True
        for s in self._scenario._out_connectors.values():
            if isinstance(s, FinalStep):
                fs = s
                break
        else:
            fs = FinalStep()

        for s in self._scenario._out_connectors.values():
            if not isinstance(s, FinalStep):
                s.connect_to(fs, **kwargs)

    def is_starting_brick(self):
        return self._start

    def is_ending_brick(self):
        return self._final

    @property
    def final(self):
        return self._final

    @final.setter
    def final(self, value):
        self._final = value

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value):
        self._start = value

    def is_setup(self):
        return self._scenario is not None

    @property
    def starting_step(self):
        return self._scenario.anchor

    @starting_step.setter
    def starting_step(self, step):
        self._scenario.set_anchor(step)

    def clone(self, name=None):
        new_brick = copy.copy(self)
        if name is not None:
            new_brick._name = name
        return new_brick

    def name_with_shape_id(self, shape_id):
        return f'{self._name}_{shape_id}'

    def get_scenario(self):
        name = self.name_with_shape_id(self.default_shape_id) if self.default_shape_id is not None else self._name
        sc_clone: Scenario = self._scenario.clone(name)
        params = self.scenario_parameters_per_shape_id(self.default_shape_id)
        sc_clone.set_scenario_parameters(params=params)
        # sc_clone.merge_user_context_with(UI(shape_id=self.default_shape_id))
        sc_clone.description = self.description_from_shape_id(self.default_shape_id)
        return sc_clone

    def __copy__(self):
        new_scbrick = type(self)()
        new_scbrick.__dict__.update(self.__dict__)
        new_scbrick._scenario = None
        new_scbrick.in_connection = {}
        new_scbrick.out_connection = {}

        return new_scbrick

class FRAG_POL(Enum):
    EQUAL_SZ = 1
    INCREASING_SZ = 2
    DECREASING_SZ = 3

class FragmentationBrick(ScenarioBrick):

    VALID_ORDERED_SHAPE = 'valid_ordered'
    VALID_UNORDERED_SHAPE = 'valid_unordered'
    SZ01_SHAPE = 'sz01'
    ALT01A_SHAPE = 'alt01A'
    ALT02A_SHAPE = 'alt02A'
    ALT01B_SHAPE = 'alt01B'
    ALT02B_SHAPE = 'alt02B'
    ALT03_SHAPE = 'alt03'
    ALT04_SHAPE = 'alt04'
    ALT05A_SHAPE = 'alt05A'
    ALT06A_SHAPE = 'alt06A'
    ALT07A_SHAPE = 'alt07A'
    ALT05B_SHAPE = 'alt05B'
    ALT06B_SHAPE = 'alt06B'
    ALT07B_SHAPE = 'alt07B'
    ALT08_SHAPE = 'alt08'
    ALT09_SHAPE = 'alt09'
    ALT10_SHAPE = 'alt10'
    ALT11_SHAPE = 'alt11'


    @classmethod
    def scenario_parameters_per_shape_id(cls, shape_id):

        match shape_id:
            case cls.VALID_ORDERED_SHAPE | cls.VALID_UNORDERED_SHAPE \
                 | cls.ALT07A_SHAPE | cls.ALT07B_SHAPE | cls.ALT08_SHAPE | cls.ALT09_SHAPE \
                 | cls.ALT06A_SHAPE | cls.ALT06B_SHAPE | cls.ALT05A_SHAPE | cls.ALT05B_SHAPE \
                 | cls.ALT01A_SHAPE | cls.ALT01B_SHAPE | cls.ALT02A_SHAPE | cls.ALT02B_SHAPE \
                 | cls.ALT10_SHAPE | cls.ALT11_SHAPE | cls.ALT03_SHAPE | cls.ALT04_SHAPE:
                params = {
                    'fragment_count': ('Number of fragment to generate [parameter used when relevant]', 3, int),
                    'fragment_policy': ('Policy for fragment generation ('
                                        'FRAG_POL.DECREASING_SZ, '
                                        'FRAG_POL.INCREASING_SZ, '
                                        'FRAG_POL.EQUAL_SZ) '
                                        '[parameter used when relevant]', FRAG_POL.DECREASING_SZ, FRAG_POL)
                }

            case cls.SZ01_SHAPE:
                params = {
                    'fragment_count': ('Number of fragment to generate [parameter used when relevant]', 3, int),
                }

            case _:
                params = {}

        match shape_id:
            case cls.ALT01A_SHAPE | cls.ALT01B_SHAPE | cls.ALT02A_SHAPE | cls.ALT02B_SHAPE \
                 | cls.ALT03_SHAPE | cls.ALT04_SHAPE:
                params.update({
                    'add_frag_to_send': ('Number of fragment to be sent in addition '
                                         'to the nominal case (by repeating some fragment)', 5, int)
                })
            case cls.ALT05A_SHAPE | cls.ALT05B_SHAPE | cls.ALT06A_SHAPE | cls.ALT06B_SHAPE \
                 | cls.ALT07A_SHAPE | cls.ALT07B_SHAPE | cls.ALT08_SHAPE | cls.ALT09_SHAPE \
                 | cls.ALT10_SHAPE | cls.ALT11_SHAPE:
                params.update({
                    'add_frag_to_send': ('Number of fragment to be sent in addition '
                                         'to the nominal case (by repeating some fragment)', 100, int)
                })

        params.update({
            'update_pld_size': ('Force the size value of the node referenced by @pldsz_ref in '
                                'the fragment wrt. the payload size before sending. '
                                '(necessary if the data model does not apply'
                                'this constraint automatically)', False, bool)
        })


        return params


    
    def description_from_shape_id(self, shape_id):

        desc = '\n'

        match shape_id:
            case self.VALID_ORDERED_SHAPE:
                desc += (f'Valid fragmentation scenario [{shape_id}]:\n'
                         f' - fragments are sent in order')

            case self.VALID_UNORDERED_SHAPE:
                desc += (f'Valid fragmentation scenario [{shape_id}]:\n'
                         f' - fragments are not sent in order')

            case self.ALT01A_SHAPE | self.ALT01B_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'{self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'while the maximum is specified to be {self.count_max}.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n'
                         f' - fragment size ordering is following the @fragment_policy\n'
                         f'   (when no fragment list is provided)\n')

            case self.ALT02A_SHAPE | self.ALT02B_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'{self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'while the maximum is specified to be {self.count_max},\n'
                         f'and we never send the expected last fragment.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n'
                         f' - fragment size ordering is following the @fragment_policy\n'
                         f'   (when no fragment list is provided)\n')

            case self.ALT03_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'{self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'with always the same fragment index\n'
                         f'but with different payload.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n')

            case self.ALT04_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'{self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'with always the same fragment index\n'
                         f'and the same payload.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n')

            case self.ALT05A_SHAPE | self.ALT05B_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'{self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'cycling from the 1st fragment to penultimate fragment\n'
                         f'never completing the full message.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n'
                         f' - fragment size ordering is following the @fragment_policy\n'
                         f'   (when no fragment list is provided)\n')

            case self.ALT06A_SHAPE | self.ALT06B_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'{self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'cycling from the last fragment to 2nd fragment\n'
                         f'never completing the full message.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n'
                         f' - fragment size ordering is following the @fragment_policy\n'
                         f'   (when no fragment list is provided)\n')

            case self.ALT07A_SHAPE | self.ALT07B_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'{self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'randomly but never completing the full message.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n'
                         f' - the penultimate fragment will never be sent.\n')

            case self.ALT08_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'empty fragments will be sent')

            case self.ALT09_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'an empty fragment will be sent among the other fragments')

            case self.ALT10_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'The fragment count is set to its specified maximum {self.count_max},\n'
                         f'and {self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'randomly.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n')

            case self.ALT11_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'The fragment count is set to its possible maximum {self.count_vtype_max} '
                         f'(wrt. its node type),\n'
                         f'and {self.count_max} + @add_frag_to_send fragments will be sent\n'
                         f'randomly.\n'
                         f'\nNotes:\n'
                         f' - the number of individual fragments is equal to @fragment_count\n'
                         f'   (when no fragment list is provided)\n')

            case self.SZ01_SHAPE:
                desc += (f'Invalid fragmentation scenario [{shape_id}]:\n'
                         f'Two fragment payloads are generated based on the original payload:\n'
                         f'- one with a size equal to the maximum value {self.fsz_vtype_max} that\n'
                         f' can fit in the specified node type\n'
                         f'- another one which is empty\n'
                         f'Then they are sent alternatively until @fragment_count have been sent.\n')

            case _:
                desc += 'Unknown'

        match shape_id[-1]:
            case 'B':
                desc += '\n\nNote: All the fragments are the same.'
            case 'A':
                desc += '\n\nNote: The fragments are different or cycle.'
            case _:
                pass

        desc += '\n'

        return desc


    def _generate_fragments(self, payload: str | bytes, fragment_count: int, fragment_policy: FRAG_POL):
        fragments = []
        payload_sz = len(payload)

        match fragment_policy:
            case FRAG_POL.EQUAL_SZ:
                fsz = payload_sz // fragment_count
                for fg in range(fragment_count):
                    idx_start = fg * fsz
                    pld = payload[idx_start:idx_start + fsz] if fg < fragment_count - 1 else payload[idx_start:]
                    fragments.append(pld)
            case FRAG_POL.DECREASING_SZ | FRAG_POL.INCREASING_SZ:
                qty = (fragment_count + 1) * fragment_count // 2
                remaining_sz = payload_sz - qty
                if remaining_sz < fragment_count:
                    raise ValueError(f'the size of the payload ({payload_sz}) is too small compared to the '
                                     f'number of fragments ({fragment_count}) requested for creating fragments with '
                                     f'decreasing size or increasing size')
                frag_init_sz = remaining_sz // fragment_count
                idx_start = 0
                for fg in range(fragment_count):
                    idx_end = idx_start + frag_init_sz
                    if fg == 0 and fragment_policy == FRAG_POL.DECREASING_SZ:
                        left_over = remaining_sz % fragment_count
                        idx_end += left_over
                    idx_end += (fragment_count - fg) if fragment_policy == FRAG_POL.DECREASING_SZ else fg + 1
                    if fg == fragment_count - 1:
                        pld = payload[idx_start:]
                    else:
                        pld = payload[idx_start:idx_end]
                        idx_start = idx_end
                    fragments.append(pld)

        return fragments

    def pre_build(self, dm: DataModel = None,
                  host_name: Node = None,
                  fragment_list: list = None,
                  payload: bytes | str = None,
                  fragidx_ref: str = None, fragcount_ref: str = None, pld_ref: str = None,
                  pldsz_ref: str = None,
                  fbk_timeout = None):

        self.shape_ids = [
            self.VALID_ORDERED_SHAPE,
            self.VALID_UNORDERED_SHAPE,
        ]

        self.payload = payload
        if self.payload is None:
            assert fragment_list is not None
            self.fragment_list = list(fragment_list)
            self.fragment_count = len(fragment_list)

        self.host_name = host_name
        self.fragidx_ref = fragidx_ref
        self.fragcount_ref = fragcount_ref
        self.pld_ref = pld_ref
        self.pldsz_ref = pldsz_ref

        self.fragidx_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.fragidx_ref])
        self.fragcount_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.fragcount_ref])
        self.pld_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.pld_ref])
        if self.pldsz_ref is not None:
            self.pldsz_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.pldsz_ref])
            self.shape_ids.append(self.SZ01_SHAPE)

        atom = self.dm.get_atom(self.host_name)
        pld_a = atom[self.pld_sem][0]
        self.new_pld_node = pld_a.is_nonterm()

        fidx_a = atom[self.fragidx_sem][0]
        if fidx_a.is_term():
            vtype = fidx_a.value_type
            assert isinstance(vtype, vt.INT)
            self.idx_min = vtype.mini
            self.idx_max = vtype.maxi
            self.idx_vtype = vtype.__class__.__name__
            self.idx_vtype_min = vtype.__class__.mini
            self.idx_vtype_max = self.idx_max + 10 if vtype.__class__.maxi is None else vtype.__class__.maxi

            # print(
            #     f'|= fragment index type: {self.idx_vtype}\n'
            #     f'|            vtype min: {self.idx_vtype_min}\n'
            #     f'|            vtype max: {self.idx_vtype_max}\n'
            #     f'|        specified min: {self.idx_min}\n'
            #     f'|        specified max: {self.idx_max}\n'
            # )

        else:
            raise NotImplementedError(f'Unrecognized fragment index type [{fidx_a.cc}]')

        fcount_a = atom[self.fragcount_sem][0]
        if fcount_a.is_term():
            vtype = fcount_a.value_type
            assert isinstance(vtype, vt.INT)
            self.count_min = vtype.mini
            self.count_max = vtype.maxi
            self.count_vtype = vtype.__class__.__name__
            self.count_vtype_min = vtype.__class__.mini
            self.count_vtype_max = self.count_max + 10 if vtype.__class__.maxi is None else vtype.__class__.maxi

            # print(
            #     f'|= fragment count type: {self.count_vtype}\n'
            #     f'|            vtype min: {self.count_vtype_min}\n'
            #     f'|            vtype max: {self.count_vtype_max}\n'
            #     f'|        specified min: {self.count_min}\n'
            #     f'|        specified max: {self.count_max}\n'
            # )

        else:
            raise NotImplementedError(f'Unrecognized fragment count type [{fcount_a.cc}]')

        if self.pldsz_ref is not None:
            fsize_a = atom[self.pldsz_sem][0]
            if fsize_a.is_term():
                vtype = fsize_a.value_type
                assert isinstance(vtype, vt.INT)
                self.fsz_min = vtype.mini
                self.fsz_max = vtype.maxi
                self.fsz_vtype = vtype.__class__.__name__
                self.fsz_vtype_min = vtype.__class__.mini
                self.fsz_vtype_max = self.fsz_max + 10 if vtype.__class__.maxi is None else vtype.__class__.maxi

                # print(
                #     f'|= fragment size type: {self.fsz_vtype}\n'
                #     f'|            vtype min: {self.fsz_vtype_min}\n'
                #     f'|            vtype max: {self.fsz_vtype_max}\n'
                #     f'|        specified min: {self.fsz_min}\n'
                #     f'|        specified max: {self.fsz_max}\n'
                # )

            else:
                raise NotImplementedError(f'Unrecognized fragment size type [{fsize_a.cc}]')


        self.frag_idx_init = self.idx_min

        if self.idx_vtype_max is None or self.idx_vtype_max > self.count_max - 1:
            self.shape_ids += [
                self.ALT01A_SHAPE, self.ALT01B_SHAPE,
                self.ALT02A_SHAPE, self.ALT02B_SHAPE,
            ]

        self.shape_ids += [
            self.ALT03_SHAPE,
            self.ALT04_SHAPE,
            self.ALT05A_SHAPE, self.ALT05B_SHAPE,
            self.ALT06A_SHAPE, self.ALT06B_SHAPE,
            self.ALT07A_SHAPE, self.ALT07B_SHAPE,
            self.ALT08_SHAPE, self.ALT09_SHAPE,
            self.ALT10_SHAPE
        ]

        if self.count_vtype_max is None or self.count_vtype_max > self.count_max:
            self.shape_ids.append(self.ALT11_SHAPE)


    def build(self, user_context: UI, shape_id: str,
              host_name: Node = None,
              fragment_list: list = None,
              payload: bytes | str = None,
              fragidx_ref: str = None, fragcount_ref: str = None, pld_ref: str = None,
              pldsz_ref: str = None,
              fbk_timeout = None):

        user_context.merge_with(UI(fbk_timeout=fbk_timeout))

        def init_frag(env, step):

            shape_id = env.user_context.shape_id

            if self.payload is not None:
                self.fragment_count = env.fragment_count
                if shape_id in [self.SZ01_SHAPE]:
                    fp = FRAG_POL.EQUAL_SZ
                else:
                    fp = env.fragment_policy
                self.fragment_list = self._generate_fragments(self.payload,
                                                              fragment_count=self.fragment_count,
                                                              fragment_policy=fp)


            env.fragment_list = list(self.fragment_list)
            env.fragment_count = self.fragment_count

            self.fragidx_list = list(range(self.frag_idx_init, env.fragment_count+ self.frag_idx_init))

            if shape_id in [FragmentationBrick.ALT07A_SHAPE, FragmentationBrick.ALT07B_SHAPE]:
                if env.fragment_count<= 2:
                    raise ScenarioParameterError
                else:
                    self.fragidx_incomplete_list = list(self.fragidx_list)
                    self.fragidx_incomplete_list.pop(-2)

            elif shape_id in [FragmentationBrick.SZ01_SHAPE]:
                orig_pld = self.fragment_list[0] if self.payload is None else self.payload
                pld_len = len(orig_pld)
                if pld_len < self.fsz_vtype_max:
                    qty = self.fsz_vtype_max // pld_len
                    left_over = self.fsz_vtype_max % pld_len
                    env.max_frag_pld = orig_pld * qty + orig_pld[:left_over]
                else:
                    env.max_frag_pld = orig_pld[:self.fsz_vtype_max]

            elif shape_id == FragmentationBrick.ALT08_SHAPE:
                env.fragment_list = ['' for i in range(env.fragment_count)]

            elif shape_id == FragmentationBrick.ALT09_SHAPE:
                if env.fragment_count < self.count_max:
                    env.fragment_count += 1
                    env.fragment_list.insert(1, '')
                    env._test = env.fragment_count
                elif env.fragment_count == self.count_max:
                    env.fragment_list.pop(-1)
                    env.fragment_list.insert(1, '')
                    env._test = env.fragment_count
                else:
                    raise ScenarioParameterError

            self.cycling_payload = itertools.cycle(env.fragment_list)
            env.frag_idx = self.frag_idx_init
            env._loop_count = 0
            env.fidx_list = list(self.fragidx_list)

            self._nb_of_sent_frag = 0
            match shape_id:
                case FragmentationBrick.ALT01A_SHAPE | FragmentationBrick.ALT01B_SHAPE \
                     | FragmentationBrick.ALT02A_SHAPE | FragmentationBrick.ALT02B_SHAPE \
                     | FragmentationBrick.ALT03_SHAPE | FragmentationBrick.ALT04_SHAPE \
                     | FragmentationBrick.ALT05A_SHAPE | FragmentationBrick.ALT05B_SHAPE \
                     | FragmentationBrick.ALT06A_SHAPE | FragmentationBrick.ALT06B_SHAPE \
                     | FragmentationBrick.ALT07A_SHAPE | FragmentationBrick.ALT07B_SHAPE \
                     | FragmentationBrick.ALT10_SHAPE | FragmentationBrick.ALT11_SHAPE:

                    self._planned_nb_fragments_to_send = self.count_max + env.add_frag_to_send

                case _:
                    self._planned_nb_fragments_to_send = env.fragment_count


        def build_frag(env, step):
            data = Data()
            atom = env.dm.get_atom(self.host_name)
            atom.freeze(resolve_csp=True)
            shape_id = env.user_context.shape_id

            match shape_id:
                case FragmentationBrick.VALID_ORDERED_SHAPE | FragmentationBrick.ALT08_SHAPE \
                     | FragmentationBrick.ALT09_SHAPE:
                    atom[self.fragidx_sem] = env.frag_idx
                    atom[self.fragcount_sem] = env.fragment_count
                    obj = env.fragment_list[env.frag_idx - self.frag_idx_init]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.VALID_UNORDERED_SHAPE:
                    fidx = random.choice(env.fidx_list)
                    env.fidx_list.remove(fidx)
                    atom[self.fragidx_sem] = fidx
                    atom[self.fragcount_sem] = env.fragment_count
                    obj = env.fragment_list[env.frag_idx - self.frag_idx_init]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.SZ01_SHAPE:
                    atom[self.fragidx_sem] = env.frag_idx
                    atom[self.fragcount_sem] = env.fragment_count
                    obj = env.max_frag_pld if env.frag_idx % 2 else ''
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.ALT01A_SHAPE | FragmentationBrick.ALT01B_SHAPE:
                    atom[self.fragidx_sem] = env.frag_idx
                    atom[self.fragcount_sem] = env.fragment_count
                    if shape_id == FragmentationBrick.ALT01A_SHAPE:
                        obj = next(self.cycling_payload)
                    else:
                        obj = env.fragment_list[0]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.ALT02A_SHAPE | FragmentationBrick.ALT02B_SHAPE:
                    if env.frag_idx + (1 - self.frag_idx_init) == env.fragment_count:
                        env.frag_idx += 1
                    atom[self.fragidx_sem] = env.frag_idx
                    atom[self.fragcount_sem] = env.fragment_count
                    if shape_id == FragmentationBrick.ALT02A_SHAPE:
                        obj = next(self.cycling_payload)
                    else:
                        obj = env.fragment_list[0]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.ALT03_SHAPE:
                    atom[self.fragidx_sem] = self.frag_idx_init
                    atom[self.fragcount_sem] = env.fragment_count
                    obj = next(self.cycling_payload)
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.ALT04_SHAPE:
                    atom[self.fragidx_sem] = self.frag_idx_init
                    atom[self.fragcount_sem] = env.fragment_count
                    obj = env.fragment_list[0]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.ALT05A_SHAPE | FragmentationBrick.ALT05B_SHAPE:
                    fidx = ((env.frag_idx + env._loop_count) - self.frag_idx_init) % env.fragment_count
                    if fidx == env.fragment_count-1:
                        fidx = 0
                        env._loop_count += 1
                    atom[self.fragidx_sem] = fidx + self.frag_idx_init
                    atom[self.fragcount_sem] = env.fragment_count
                    if shape_id == FragmentationBrick.ALT05A_SHAPE:
                        obj = env.fragment_list[fidx]
                    else:
                        obj = env.fragment_list[0]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.ALT06A_SHAPE | FragmentationBrick.ALT06B_SHAPE:
                    fidx_modulo = ((env.frag_idx + env._loop_count) - self.frag_idx_init) % env.fragment_count
                    fidx = env.fragment_count - fidx_modulo - 1
                    if fidx == 0:
                        fidx = env.fragment_count - 1
                        env._loop_count += 1
                    atom[self.fragidx_sem] = fidx + self.frag_idx_init
                    atom[self.fragcount_sem] = env.fragment_count
                    if shape_id == FragmentationBrick.ALT06A_SHAPE:
                        obj = env.fragment_list[fidx]
                    else:
                        obj = env.fragment_list[0]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.ALT07A_SHAPE | FragmentationBrick.ALT07B_SHAPE:
                    rand_idx = random.choice(self.fragidx_incomplete_list)
                    atom[self.fragidx_sem] = rand_idx
                    atom[self.fragcount_sem] = env.fragment_count
                    if shape_id == FragmentationBrick.ALT07A_SHAPE:
                        obj = env.fragment_list[rand_idx - self.frag_idx_init]
                    else:
                        obj = env.fragment_list[0]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case FragmentationBrick.ALT10_SHAPE | FragmentationBrick.ALT11_SHAPE:
                    rand_idx = random.choice(self.fragidx_list)
                    atom[self.fragidx_sem] = rand_idx
                    if shape_id == FragmentationBrick.ALT10_SHAPE:
                        cnt = self.count_max
                    else:
                        cnt = self.count_vtype_max
                    atom[self.fragcount_sem] = cnt

                    obj = env.fragment_list[rand_idx - self.frag_idx_init]
                    if self.new_pld_node:
                        obj = Node('new_pld', value_type=vt.String(values=[obj]))
                    atom[self.pld_sem] = obj

                case _:
                    pass

            env.frag_idx += 1

            if self.pldsz_ref is not None:
                if env.update_pld_size:
                    atom[self.pldsz_sem] = len(atom[self.pld_sem][0].to_bytes())
                else:
                    atom[self.pldsz_sem][0].unfreeze(recursive=True, dont_change_state=True, reevaluate_constraints=True)
                    atom.freeze()

            current_frag_idx = atom[self.fragidx_sem][0].get_raw_value()
            current_frag_count = atom[self.fragcount_sem][0].get_raw_value()
            self._nb_of_sent_frag += 1

            data.add_info(f'fragment info:')
            data.add_info(f' - idx: {current_frag_idx} / count: {current_frag_count}')
            if self.pldsz_ref is not None:
                current_frag_sz = atom[self.pldsz_sem][0].get_raw_value()
                data.add_info(f' - size: {current_frag_sz}')
            data.add_info(f'scenario info:')
            data.add_info(f' - sent fragments: {self._nb_of_sent_frag}')
            data.add_info(f' - fragments to send: {self._planned_nb_fragments_to_send}')

            data.update_from(atom)
            step.data_desc = data

        def check_max_loop(env, current_step, next_step, fbkgate):
            shape_id = env.user_context.shape_id

            match shape_id:
                case FragmentationBrick.ALT01A_SHAPE | FragmentationBrick.ALT01B_SHAPE \
                     | FragmentationBrick.ALT02A_SHAPE | FragmentationBrick.ALT02B_SHAPE \
                     | FragmentationBrick.ALT03_SHAPE | FragmentationBrick.ALT04_SHAPE \
                     | FragmentationBrick.ALT05A_SHAPE | FragmentationBrick.ALT05B_SHAPE \
                     | FragmentationBrick.ALT06A_SHAPE | FragmentationBrick.ALT06B_SHAPE \
                     | FragmentationBrick.ALT07A_SHAPE | FragmentationBrick.ALT07B_SHAPE \
                     | FragmentationBrick.ALT10_SHAPE | FragmentationBrick.ALT11_SHAPE:
                    if env.frag_idx-self.frag_idx_init < self.count_max + env.add_frag_to_send:
                        ret = False
                    else:
                        env.frag_idx = self.frag_idx_init
                        ret = True

                case _:
                    if env.frag_idx-self.frag_idx_init < env.fragment_count:
                        ret = False
                    else:
                        env.frag_idx = self.frag_idx_init
                        ret = True

            return ret

        step_init = NoDataStep(do_before_data_processing=init_frag,
                               step_desc='Init Fragment SBrick')
        step_send_frag = StepStub(do_before_data_processing=build_frag, fbk_timeout=fbk_timeout,
                                  step_desc='Send Fragment')
        step_out = NoDataStep(step_desc='Exit Fragment SBrick')

        step_init.connect_to(step_send_frag)
        step_send_frag.connect_to(step_out, cbk_after_fbk=check_max_loop)

        starting_step = step_init
        in_connectors = [step_init]
        out_connectors = [step_out]

        return starting_step, in_connectors, out_connectors
