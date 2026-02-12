import copy
import itertools
import traceback

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

    def setup(self, start: bool = True, final: bool = False, **kwargs):
        self._final = final
        self._start = start

        if self._scenario is None:
            ok = self._build(**kwargs)
            if not ok:
                raise ScenarioDefinitionError
        else:
            sys.stderr.write(colorize(f"\n*** WARNING: {self.__class__.__name__}._setup() "
                                      f" scenario is already setup\n",
                                      rgb=Color.WARNING))

    def _build(self, **kwargs):

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

        self.build_connection()

        return True

    def build_connection(self):

        for out_idx, obj in self.out_connection.items():
            in_idx, scbrick, connect_kwargs = obj
            if isinstance(scbrick, ScenarioBrick):
                if not scbrick.is_setup():
                    scbrick.setup()
                self._scenario.set_scenario_env(scbrick._scenario.env, merge_user_contexts=True)
                self.out_connectors(out_idx).connect_to(scbrick.in_connectors(in_idx), **connect_kwargs)
            elif isinstance(scbrick, Step):
                self.out_connectors(out_idx).connect_to(scbrick, **connect_kwargs)
            else:
                raise NotImplementedError

        for in_idx, obj in self.in_connection.items():
            out_idx, scbrick, connect_kwargs = obj
            if isinstance(scbrick, ScenarioBrick):
                if not scbrick.is_setup():
                    scbrick.setup()
                self._scenario.set_scenario_env(scbrick._scenario.env, merge_user_contexts=True)
                scbrick.out_connectors(out_idx).connect_to(self.in_connectors(in_idx), **connect_kwargs)
            elif isinstance(scbrick, Step):
                scbrick.connect_to(self.in_connectors(in_idx))
            else:
                raise NotImplementedError

        self.find_ending_sbrick_and_flag_it_final(self)

        self.find_starting_sbrick_and_flag_it_start(self)
        self.find_and_set_starting_sbrick(self)

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



    def in_connectors(self, idx):
        return self._scenario.in_connectors(idx)

    def out_connectors(self, idx):
        return self._scenario.out_connectors(idx)

    def connect_out_to(self, scbrick, out_idx=None, in_idx=None, **connect_kwargs):
        out_idx = 1 if out_idx is None else out_idx
        in_idx = 1 if in_idx is None else in_idx

        self.out_connection[out_idx] = (in_idx, scbrick, connect_kwargs)

    def connect_in_to(self, scbrick, in_idx=None, out_idx=None, **connect_kwargs):
        out_idx = 1 if out_idx is None else out_idx
        in_idx = 1 if in_idx is None else in_idx

        self.in_connection[in_idx] = (out_idx, scbrick, connect_kwargs)

    def finalize(self, **kwargs):
        self._final = True
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


class FragmentationBrick(ScenarioBrick):

    def description_from_shape_id(self, shape_id):

        match shape_id:
            case ScenarioBrick.BASIC_SHAPE:
                desc = f'Nominal fragmentation scenario'

            case 'alt_1':
                desc = (f'Invalid fragmentation scenario "{shape_id}":\n'
                        f'{self.shape_alt1_max_fidx} fragments will be '
                        f'sent while the maximum is specified to be {self.count_max-1}')

            case _:
                desc = 'Unknown'

        desc = desc.replace('\n', '\\n')
        return desc

    def build(self, user_context: UI,
              pod_atom_name=None, payload=None, fragidx_ref=None, fragcount_ref=None, pld_ref=None, fbk_timeout=2):

        user_context.merge_with(UI(fbk_timeout=fbk_timeout, payload=payload))

        self.atom_name = pod_atom_name
        self.fragidx_ref = fragidx_ref
        self.fragcount_ref = fragcount_ref
        self.pld_ref = pld_ref

        self.fragidx_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.fragidx_ref])
        self.fragcount_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.fragcount_ref])
        self.pld_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.pld_ref])

        atom = self.dm.get_atom(self.atom_name)
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

        if self.idx_vtype_max is None or self.idx_vtype_max > self.count_max - 1:
            self.shape_ids.append('alt_1')
            self.shape_alt1_max_fidx = self.count_max + 5
            self.shape_alt1_iter_pld = itertools.cycle(payload)

        def init_frag(env, step):
            env._payload_frag_count = len(env.user_context.payload)
            env._frag_idx = self.frag_idx_init

        def change_fragmax(env, step):
            pass

        def send_frag(env, step):
            data = Data()
            atom = env.dm.get_atom(self.atom_name)
            shape_id = env.user_context.shape_id

            match shape_id:
                case ScenarioBrick.BASIC_SHAPE:
                    data.add_info(f'fragment {env._frag_idx}/{env._payload_frag_count}')
                    atom[self.fragidx_sem] = env._frag_idx
                    atom[self.fragcount_sem] = env._payload_frag_count
                    atom[self.pld_sem] = env.user_context.payload[env._frag_idx]
                    env._frag_idx += 1

                case 'alt_1':
                    atom[self.fragidx_sem] = env._frag_idx
                    atom[self.fragcount_sem] = env._payload_frag_count
                    atom[self.pld_sem] = next(self.shape_alt1_iter_pld)
                    env._frag_idx += 1

                case _:
                    pass

            data.update_from(atom)
            step.data_desc = data

        def check_max_loop(env, current_step, next_step, fbkgate):
            shape_id = env.user_context.shape_id

            match shape_id:
                case ScenarioBrick.BASIC_SHAPE:
                    if env._frag_idx < env._payload_frag_count:
                        ret = False
                    else:
                        env._frag_idx = self.frag_idx_init
                        ret = True
                case 'alt_1':
                    if env._frag_idx < self.shape_alt1_max_fidx:
                        ret = False
                    else:
                        env._frag_idx = self.frag_idx_init
                        ret = True
                case _:
                    ret = True


            return ret

        step_init = NoDataStep(fbk_timeout=0, do_before_data_processing=init_frag,
                               step_desc='Init')
        # step_change_fragmax = NoDataStep(do_before_data_processing=change_fragmax)
        step_send_frag = StepStub(do_before_data_processing=send_frag, fbk_timeout=fbk_timeout)
        step_out = NoDataStep()

        step_init.connect_to(step_send_frag)
        step_send_frag.connect_to(step_out, cbk_after_fbk=check_max_loop)

        starting_step = step_init
        in_connectors = [step_init]
        out_connectors = [step_out]

        return starting_step, in_connectors, out_connectors
