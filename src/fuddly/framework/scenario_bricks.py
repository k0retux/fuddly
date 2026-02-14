import copy
import itertools
import traceback
import random

from fuddly.libs.external_modules import colorize, Color
from fuddly.framework.data_model import DataModel
from fuddly.framework.error_handling import ScenarioDefinitionError
from fuddly.framework.scenario import *
import fuddly.framework.node as nd
import fuddly.framework.value_types as vt

class ScenarioBrick(object):

    BASIC_SHAPE = 'basic'
    shape_ids = None

    _scenario = None

    def __init__(self, name=None):

        self._name = self.__class__.__name__ if name is None else name
        self._scenario = None
        self._dm = None
        self.shape_ids = [ScenarioBrick.BASIC_SHAPE]
        self.out_connection = {}
        self.in_connection = {}
        self._final = None
        self._start = None

    @property
    def dm(self):
        return self._dm

    @dm.setter
    def dm(self, dm: DataModel):
        self._dm = dm

    def description_from_shape_id(self, shape_id):
        """

        :param shape_id:
        :return:
        """
        return 'No description'

    def build(self, user_context: UI, **kwargs):
        """
        To be overloaded

        :param user_context:
        :param kwargs:
        :return:

        """
        raise NotImplementedError

    def setup(self, start: bool = True, final: bool = False,
              auto_update_starting_step=True, auto_update_ending_step=True,
              **kwargs):
        self._final = final
        self._start = start

        if self._scenario is None:
            ok = self._build(auto_update_starting_step=auto_update_starting_step,
                             auto_update_ending_step=auto_update_ending_step,
                             **kwargs)
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


    def _build(self, auto_update_starting_step=True, auto_update_ending_step=True, **kwargs):

        uc = UI(shape_id=None)

        try:
            starting_step, in_connectors, out_connectors = self.build(user_context=uc, **kwargs)
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
            # elif isinstance(scbrick, Step):
            #     self.out_connectors(out_idx).connect_to(scbrick, **connect_kwargs)
            else:
                raise NotImplementedError

        for in_idx, obj in self.in_connection.items():
            out_idx, scbrick, connect_kwargs = obj
            if isinstance(scbrick, ScenarioBrick):
                if not scbrick.is_setup():
                    scbrick.setup()
                self._scenario.set_scenario_env(scbrick._scenario.env, merge_user_contexts=True)
                scbrick.out_connectors(out_idx).connect_to(self.in_connectors(in_idx), **connect_kwargs)
            # elif isinstance(scbrick, Step):
            #     scbrick.connect_to(self.in_connectors(in_idx))
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

    @final.setter
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

    def clone(self):
        return copy.copy(self)

    def get_scenario(self, shape_id: str = '', full_name=None):
        name = f'{self._name}_{shape_id}' if full_name is None else full_name
        sc_clone = self._scenario.clone(name)
        sc_clone.merge_user_context_with(UI(shape_id=shape_id))
        sc_clone.description = self.description_from_shape_id(shape_id)
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

    VALID_SHAPE_ORDER = 'valid_ordered'
    VALID_SHAPE_UNORDER = 'valid_unordered'
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

    
    def description_from_shape_id(self, shape_id):

        match shape_id:
            case FragmentationBrick.VALID_SHAPE_ORDER:
                desc = (f'Valid fragmentation scenario.\n'
                        f'(Fragments are sent in order)')

            case FragmentationBrick.VALID_SHAPE_UNORDER:
                desc = (f'Valid fragmentation scenario.\n'
                        f'(Fragments are not sent in order.)')

            case FragmentationBrick.ALT01A_SHAPE | FragmentationBrick.ALT01B_SHAPE:
                desc = (f'Invalid fragmentation scenario "{shape_id}":\n'
                        f'{self.inv_big_fragments_number} fragments will be sent\n'
                        f'while the maximum is specified to be {self.count_max-1}.')

            case FragmentationBrick.ALT02A_SHAPE | FragmentationBrick.ALT02B_SHAPE:
                desc = (f'Invalid fragmentation scenario "{shape_id}":\n'
                        f'{self.inv_big_fragments_number} fragments will be sent\n'
                        f'while the maximum is specified to be {self.count_max-1},\n'
                        f'and we never send the expected last fragment.')

            case FragmentationBrick.ALT03_SHAPE:
                desc = (f'Invalid fragmentation scenario "{shape_id}":\n'
                        f'{self.inv_big_fragments_number} fragments will be sent\n'
                        f'with always the same fragment index\n'
                        f'but with different payload.')

            case FragmentationBrick.ALT04_SHAPE:
                desc = (f'Invalid fragmentation scenario "{shape_id}":\n'
                        f'{self.inv_big_fragments_number} fragments will be sent\n'
                        f'with always the same fragment index\n'
                        f'and the same payload.')

            case FragmentationBrick.ALT05A_SHAPE | FragmentationBrick.ALT05B_SHAPE:
                desc = (f'Invalid fragmentation scenario "{shape_id}":\n'
                        f'{self.inv_max_fragments_number} fragments will be sent\n'
                        f'cycling from 1st fragment to penultimate fragment\n'
                        f'never completing the full message.')

            case FragmentationBrick.ALT06A_SHAPE | FragmentationBrick.ALT06B_SHAPE:
                desc = (f'Invalid fragmentation scenario "{shape_id}":\n'
                        f'{self.inv_max_fragments_number} fragments will be sent\n'
                        f'cycling from last fragment to 2nd fragment\n'
                        f'never completing the full message.')

            case FragmentationBrick.ALT07A_SHAPE | FragmentationBrick.ALT07B_SHAPE:
                desc = (f'Invalid fragmentation scenario "{shape_id}":\n'
                        f'{self.inv_max_fragments_number} fragments will be sent\n'
                        f'randomly but never completing the full message.\n'
                        f'(The penultimate fragment will never be sent.)')

            case _:
                desc = 'Unknown'

        match shape_id[-1]:
            case 'A':
                desc += '\n\nNote: All the fragments are the same.'
            case 'B':
                desc += '\n\nNote: The fragments are different or cycle.'
            case _:
                pass

        desc = desc.replace('\n', '\\n')
        return desc

    def build(self, user_context: UI,
              host_name: Node = None,
              payload_list: list = None,
              payload: bytes | str = None, frag_amount = 3, frag_policy: FRAG_POL = FRAG_POL.EQUAL_SZ,
              fragidx_ref: str = None, fragcount_ref: str = None, pld_ref: str = None,
              pldsz_ref: str = None,
              fbk_timeout = 2):

        user_context.merge_with(UI(fbk_timeout=fbk_timeout))

        self.shape_ids = [
            FragmentationBrick.VALID_SHAPE_ORDER,
            FragmentationBrick.VALID_SHAPE_UNORDER,
        ]

        if payload is None:
            assert payload_list is not None
            self.payload_list = payload_list
            self.fragment_count = len(payload_list)
        else:
            self.payload_list = []
            self.fragment_count = frag_amount
            payload_sz = len(payload)

            match frag_policy:
                case FRAG_POL.EQUAL_SZ:
                    fsz = payload_sz // frag_amount
                    for fg in range(frag_amount):
                        idx_start = fg * fsz
                        pld = payload[idx_start:idx_start + fsz] if fg < frag_amount - 1 else payload[idx_start:]
                        self.payload_list.append(pld)
                case FRAG_POL.DECREASING_SZ | FRAG_POL.INCREASING_SZ:
                    qty = (frag_amount+1)*frag_amount//2
                    remaining_sz = payload_sz - qty
                    if remaining_sz < frag_amount:
                        raise ValueError(f'the size of the payload ({payload_sz}) is too small compared to the '
                                         f'number of fragments ({frag_amount}) requested for creating fragments with '
                                         f'decreasing size or increasing size')
                    frag_init_sz = remaining_sz // frag_amount
                    idx_start = 0
                    for fg in range(frag_amount):
                        idx_end = idx_start+frag_init_sz
                        if fg ==0 and frag_policy == FRAG_POL.DECREASING_SZ:
                            left_over = remaining_sz % frag_amount
                            idx_end += left_over
                        idx_end += (frag_amount-fg) if frag_policy == FRAG_POL.DECREASING_SZ else fg+1
                        if fg == frag_amount-1:
                            pld = payload[idx_start:]
                        else:
                            pld = payload[idx_start:idx_end]
                            idx_start = idx_end
                        self.payload_list.append(pld)

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

        atom = self.dm.get_atom(self.host_name)
        fidx_a = atom[self.fragidx_sem][0]
        if fidx_a.is_term():
            vtype = fidx_a.value_type
            assert isinstance(vtype, vt.INT)
            self.idx_min = vtype.mini
            self.idx_max = vtype.maxi
            self.idx_vtype = vtype.__class__.__name__
            self.idx_vtype_min = vtype.__class__.mini
            self.idx_vtype_max = vtype.__class__.maxi

            print(
                f'|= fragment index type: {self.idx_vtype}\n'
                f'|            vtype min: {self.idx_vtype_min}\n'
                f'|            vtype max: {self.idx_vtype_max}\n'
                f'|        specified min: {self.idx_min}\n'
                f'|        specified max: {self.idx_max}\n'
            )

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
            self.count_vtype_max = vtype.__class__.maxi

            print(
                f'|= fragment count type: {self.count_vtype}\n'
                f'|            vtype min: {self.count_vtype_min}\n'
                f'|            vtype max: {self.count_vtype_max}\n'
                f'|        specified min: {self.count_min}\n'
                f'|        specified max: {self.count_max}\n'
            )

        else:
            raise NotImplementedError(f'Unrecognized fragment count type [{fcount_a.cc}]')

        self.frag_idx_init = self.idx_min
        self.cycling_payload = itertools.cycle(self.payload_list)

        self.fragidx_list = list(range(self.frag_idx_init, self.fragment_count + self.frag_idx_init))

        self.inv_big_fragments_number = self.count_max + 5
        self.inv_max_fragments_number = self.count_max + 100

        if self.idx_vtype_max is None or self.idx_vtype_max > self.count_max - 1:
            self.shape_ids += [
                FragmentationBrick.ALT01A_SHAPE, FragmentationBrick.ALT01B_SHAPE,
                FragmentationBrick.ALT02A_SHAPE, FragmentationBrick.ALT02B_SHAPE,
            ]

        self.shape_ids += [
            FragmentationBrick.ALT03_SHAPE,
            FragmentationBrick.ALT04_SHAPE,
            FragmentationBrick.ALT05A_SHAPE, FragmentationBrick.ALT05B_SHAPE,
            FragmentationBrick.ALT06A_SHAPE, FragmentationBrick.ALT06B_SHAPE,
        ]

        if self.fragment_count > 2:
            self.fragidx_incomplete_list = list(range(self.frag_idx_init, self.fragment_count + self.frag_idx_init))
            self.fragidx_incomplete_list.pop(-2)
            self.shape_ids.append(FragmentationBrick.ALT07A_SHAPE)
            self.shape_ids.append(FragmentationBrick.ALT07B_SHAPE)

        def init_frag(env, step):
            env._frag_idx = self.frag_idx_init
            env._fidx_list = list(self.fragidx_list)

        def change_fragmax(env, step):
            pass

        def send_frag(env, step):
            data = Data()
            atom = env.dm.get_atom(self.host_name)
            shape_id = env.user_context.shape_id

            match shape_id:
                case FragmentationBrick.VALID_SHAPE_ORDER:
                    data.add_info(f'fragment {env._frag_idx - self.frag_idx_init + 1}/{self.fragment_count}')
                    atom[self.fragidx_sem] = env._frag_idx
                    atom[self.fragcount_sem] = self.fragment_count
                    atom[self.pld_sem] = self.payload_list[env._frag_idx-self.idx_min]
                    env._frag_idx += 1

                case FragmentationBrick.VALID_SHAPE_UNORDER:
                    fidx = random.choice(env._fidx_list)
                    env._fidx_list.remove(fidx)
                    data.add_info(f'fragment {fidx - self.frag_idx_init + 1}/{self.fragment_count}')
                    atom[self.fragidx_sem] = env._frag_idx
                    atom[self.fragcount_sem] = self.fragment_count
                    atom[self.pld_sem] = self.payload_list[env._frag_idx-self.frag_idx_init]
                    env._frag_idx += 1

                case FragmentationBrick.ALT01A_SHAPE | FragmentationBrick.ALT01B_SHAPE:
                    atom[self.fragidx_sem] = env._frag_idx
                    atom[self.fragcount_sem] = self.fragment_count
                    if shape_id == FragmentationBrick.ALT01A_SHAPE:
                        atom[self.pld_sem] = next(self.cycling_payload)
                    else:
                        atom[self.pld_sem] = self.payload_list[0]
                    env._frag_idx += 1

                case FragmentationBrick.ALT02A_SHAPE | FragmentationBrick.ALT02B_SHAPE:
                    if env._frag_idx + (self.idx_min - 1) == self.fragment_count:
                        env._frag_idx += 1
                    atom[self.fragidx_sem] = env._frag_idx
                    atom[self.fragcount_sem] = self.fragment_count
                    if shape_id == FragmentationBrick.ALT02A_SHAPE:
                        atom[self.pld_sem] = next(self.cycling_payload)
                    else:
                        atom[self.pld_sem] = self.payload_list[0]
                    env._frag_idx += 1

                case FragmentationBrick.ALT03_SHAPE:
                    atom[self.fragidx_sem] = self.frag_idx_init
                    atom[self.fragcount_sem] = self.fragment_count
                    atom[self.pld_sem] = next(self.cycling_payload)
                    env._frag_idx += 1

                case FragmentationBrick.ALT04_SHAPE:
                    atom[self.fragidx_sem] = self.frag_idx_init
                    atom[self.fragcount_sem] = self.fragment_count
                    atom[self.pld_sem] = env.user_context.payload[0]
                    env._frag_idx += 1

                case FragmentationBrick.ALT05A_SHAPE | FragmentationBrick.ALT05B_SHAPE:
                    fidx = env._frag_idx % (self.fragment_count+self.frag_idx_init-1)
                    if fidx == 0:
                        fidx = self.frag_idx_init
                    atom[self.fragidx_sem] = fidx
                    atom[self.fragcount_sem] = self.fragment_count
                    if shape_id == FragmentationBrick.ALT05A_SHAPE:
                        atom[self.pld_sem] = next(self.cycling_payload)
                    else:
                        atom[self.pld_sem] = self.payload_list[0]
                    env._frag_idx += 1

                case FragmentationBrick.ALT06A_SHAPE | FragmentationBrick.ALT06B_SHAPE:
                    fidx = self.fragment_count + (self.frag_idx_init - 1) - (env._frag_idx - self.frag_idx_init)
                    if fidx == self.frag_idx_init+1:
                        fidx = self.fragment_count + (self.frag_idx_init - 1)
                    atom[self.fragidx_sem] = fidx
                    atom[self.fragcount_sem] = self.fragment_count
                    if shape_id == FragmentationBrick.ALT06A_SHAPE:
                        atom[self.pld_sem] = next(self.cycling_payload)
                    else:
                        atom[self.pld_sem] = self.payload_list[0]
                    env._frag_idx += 1

                case FragmentationBrick.ALT07A_SHAPE | FragmentationBrick.ALT07B_SHAPE:
                    atom[self.fragidx_sem] = random.choice(self.fragidx_incomplete_list)
                    atom[self.fragcount_sem] = self.fragment_count
                    if shape_id == FragmentationBrick.ALT07A_SHAPE:
                        atom[self.pld_sem] = next(self.cycling_payload)
                    else:
                        atom[self.pld_sem] = self.payload_list[0]
                    env._frag_idx += 1

                case _:
                    pass

            if self.pldsz_ref is not None:
                atom[self.pldsz_sem] = len(atom[self.pld_sem][0].to_bytes())

            data.update_from(atom)
            step.data_desc = data

        def check_max_loop(env, current_step, next_step, fbkgate):
            shape_id = env.user_context.shape_id

            match shape_id:
                case FragmentationBrick.VALID_SHAPE_ORDER | FragmentationBrick.VALID_SHAPE_UNORDER:
                    if env._frag_idx-self.frag_idx_init < self.fragment_count:
                        ret = False
                    else:
                        env._frag_idx = self.frag_idx_init
                        ret = True
                case FragmentationBrick.ALT01A_SHAPE | FragmentationBrick.ALT01B_SHAPE \
                     | FragmentationBrick.ALT2A_SHAPE | FragmentationBrick.ALT02B_SHAPE \
                     | FragmentationBrick.ALT03_SHAPE | FragmentationBrick.ALT04_SHAPE:
                    if env._frag_idx-self.frag_idx_init < self.inv_big_fragments_number:
                        ret = False
                    else:
                        env._frag_idx = self.frag_idx_init
                        ret = True

                case FragmentationBrick.ALT05A_SHAPE | FragmentationBrick.ALT05B_SHAPE \
                     | FragmentationBrick.ALT06A_SHAPE | FragmentationBrick.ALT06B_SHAPE \
                     | FragmentationBrick.ALT07A_SHAPE | FragmentationBrick.ALT07B_SHAPE:
                    if env._frag_idx-self.frag_idx_init < self.inv_max_fragments_number:
                        ret = False
                    else:
                        env._frag_idx = self.frag_idx_init
                        ret = True
                case _:
                    ret = True


            return ret

        step_init = NoDataStep(fbk_timeout=0, do_before_data_processing=init_frag,
                               step_desc='Init')
        step_send_frag = StepStub(do_before_data_processing=send_frag, fbk_timeout=fbk_timeout)
        step_out = NoDataStep()

        step_init.connect_to(step_send_frag)
        step_send_frag.connect_to(step_out, cbk_after_fbk=check_max_loop)

        starting_step = step_init
        in_connectors = [step_init]
        out_connectors = [step_out]

        return starting_step, in_connectors, out_connectors
