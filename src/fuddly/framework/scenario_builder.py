import copy

from fuddly.framework.error_handling import ScenarioDefinitionError
from fuddly.framework.scenario import *
import fuddly.framework.node as nd


class ScenarioBrick(object):

    _scenario = None

    def __init__(self):

        self._name = self.__class__.__name__
        self._scenario = None

    def build(self, user_context: UI = None, **kwargs):
        """
        To be overloaded

        :param user_context:
        :param kwargs:
        :return:

        """
        raise NotImplementedError

    def setup(self, final: bool = False, **kwargs):
        self._final = final
        if self._scenario is None:
            ret = self._build(**kwargs)
            if ret is None:
                raise ScenarioDefinitionError


    def _build(self, **kwargs):

        uc = UI()

        try:
            starting_step, in_connectors, out_connectors = self.build(user_context=uc, **kwargs)
        except:
            self._scenario = None
            return False
        else:
            assert starting_step is not None

        self._scenario = Scenario(self._name, anchor=starting_step, user_context=uc)
        self._scenario.set_in_connectors(in_connectors)
        self._scenario.set_out_connectors(out_connectors)

        if self._final:
            self.finalize()

        return True

    def in_connectors(self, idx):
        return self._scenario.in_connectors(idx)

    def out_connectors(self, idx):
        return self._scenario.out_connectors(idx)

    def connect_out_to(self, scbrick, out_idx=None, in_idx=None, **connect_kwargs):
        out_idx = 1 if out_idx is None else out_idx
        in_idx = 1 if in_idx is None else in_idx
        if isinstance(scbrick, ScenarioBrick):
            self._scenario.set_scenario_env(scbrick._scenario.env, merge_user_contexts=True)
            self.out_connectors(out_idx).connect_to(scbrick.in_connectors(in_idx), **connect_kwargs)
        elif isinstance(scbrick, Step):
            self.out_connectors(out_idx).connect_to(scbrick, **connect_kwargs)
        else:
            raise NotImplementedError

    def connect_in_to(self, scbrick, in_idx=None, out_idx=None, **connect_kwargs):
        out_idx = 1 if out_idx is None else out_idx
        in_idx = 1 if in_idx is None else in_idx
        if isinstance(scbrick, ScenarioBrick):
            self._scenario.set_scenario_env(scbrick._scenario.env, merge_user_contexts=True)
            self.in_connectors(in_idx).connect_to(scbrick.out_connectors(out_idx), **connect_kwargs)
        elif isinstance(scbrick, Step):
            scbrick.connect_to(self.in_connectors(in_idx))
        else:
            raise NotImplementedError

    def finalize(self, **kwargs):
        fs = FinalStep()
        for s in self._scenario._out_connectors.values():
            s.connect_to(fs, **kwargs)

    @property
    def starting_step(self):
        return self._scenario.anchor

    def clone(self):
        return copy.copy(self)

    def get_scenario(self, name: str = None):
        return self._scenario.clone(self._name if name is None else name)

    def __copy__(self):
        new_scbrick = type(self)()
        new_scbrick.__dict__.update(self.__dict__)
        new_scbrick._scenario = None

        return new_scbrick


class FragmentationBrick(ScenarioBrick):

    def build(self, user_context: UI = None,
              pod_atom_name=None, payload=None, fragidx_ref=None, fragmax_ref=None, pld_ref=None, fbk_timeout=2):

        user_context.merge_with(UI(fbk_timeout=fbk_timeout, payload=payload))

        self.atom_name = pod_atom_name
        self.fragidx_ref = fragidx_ref
        self.fragmax_ref = fragmax_ref
        self.pld_ref = pld_ref

        self.fragidx_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.fragidx_ref])
        self.fragmax_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.fragmax_ref])
        self.pld_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.pld_ref])

        def init_frag(env, step):
            env._frag_idx = 0
            env._payload_frag_max = len(env.user_context.payload)

        def change_fragmax(env, step):
            pass

        def send_frag(env, step):
            atom = env.dm.get_atom(self.atom_name)
            env._frag_idx += 1
            atom[self.fragidx_sem] = env._frag_idx
            atom[self.fragmax_sem] = env._payload_frag_max
            atom[self.pld_sem] = env.user_context.payload[env._frag_idx-1]
            step.data_desc = Data(atom)

        def check_max_loop(env, current_step, next_step, fbkgate):
            if env._frag_idx < env._payload_frag_max:
                return False
            else:
                env._frag_idx = 0
                return True

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


class ScenarioBuilder(object):

    def __init__(self):
        pass

    def build_fragmentation_scenario(self, name,
                                     pod_atom_name, payload,
                                     fragidx_ref, fragmax_ref, pld_ref, fbk_timeout=2):

        frag_brick = FragmentationBrick()
        frag_brick.setup(final=True, pod_atom_name=pod_atom_name, payload=payload,
                         fragidx_ref=fragidx_ref, fragmax_ref=fragmax_ref,
                         pld_ref=pld_ref, fbk_timeout=fbk_timeout)
        return frag_brick.get_scenario(name)
