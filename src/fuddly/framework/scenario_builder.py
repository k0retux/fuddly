import copy

from fuddly.framework.scenario import *
import fuddly.framework.node as nd


class ScenarioBrick(object):

    _scenario = None

    def __init__(self, name: str, starting_step: Step = None,
                 in_connectors: list = None, out_connectors: list = None,
                 final: bool = False, user_context: UI = None):

        self._name = name
        self._final = final
        uc = UI() if user_context is None else user_context

        if in_connectors is not None and out_connectors is not None and starting_step is not None:
            self._scenario = Scenario(self._name, anchor=starting_step, user_context=uc)
            self._scenario.set_in_connectors(in_connectors)
            self._scenario.set_out_connectors(out_connectors)
            # self._in_connectors = self._scenario._in_connectors
            # self._out_connectors = self._scenario._out_connectors

        else:
            # used during copy
            assert in_connectors is None and out_connectors is None and starting_step is None


        if final:
            self.finalize()

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

    def get_scenario(self, name: str):
        sc = self._scenario.clone(name)
        return sc

    def __copy__(self):
        new_scbrick = type(self)(name=self._name, final=self._final)
        new_scbrick.__dict__.update(self.__dict__)
        new_scbrick._scenario = copy.copy(self._scenario)
        # new_scbrick._in_connectors = new_scbrick._scenario._in_connectors
        # new_scbrick._out_connectors = new_scbrick._scenario._out_connectors

        return new_scbrick


class ScenarioTemplate(object):

    def __init__(self, **kwargs):
        self.scenario_template = None

    def instantiate_scenario(self, name, ui=None):
        new_sc = copy.copy(self.scenario_template)
        new_sc.name = name
        if ui is not None:
            new_sc.merge_user_context_with(ui)
        return new_sc

class FragScenarioTemplate(ScenarioTemplate):

    def __init__(self, atom_name, fragidx_ref, fragmax_ref, pld_ref, fbk_timeout=2):
        ScenarioTemplate.__init__(self)
        self.atom_name = atom_name
        self.fragidx_ref = fragidx_ref
        self.fragmax_ref = fragmax_ref
        self.pld_ref = pld_ref

        self.fragidx_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.fragidx_ref])
        self.fragmax_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.fragmax_ref])
        self.pld_sem = nd.NodeSemanticsCriteria(mandatory_criteria=[self.pld_ref])

        def init_frag(env, step):
            env._frag_idx = 0
            # pld = env.user_context.payload
            env._payload_frag_max = len(env.user_context.payload)

        # def change_fragid(env, step):
        #     atom = env.dm.get_atom(self.atom_name)
        #     # fragidx_node = atom[self.fragidx_sem]
        #     # fragmax_node = atom[self.fragmax_sem]
        #     env._frag_idx += 1
        #     atom[self.fragidx_sem] = env._frag_idx
        #     atom[self.fragmax_sem] = env._payload_frag_max
        #
        #     env._header = atom


        def change_fragmax(env, step):
            pass

        def send_frag(env, step):
            atom = env.dm.get_atom(self.atom_name)
            # fragidx_node = atom[self.fragidx_sem]
            # fragmax_node = atom[self.fragmax_sem]
            env._frag_idx += 1
            atom[self.fragidx_sem] = env._frag_idx
            atom[self.fragmax_sem] = env._payload_frag_max
            atom[self.pld_sem] = env.user_context.payload[env._frag_idx-1]
            step.data_desc = Data(atom)

            # step.set_dmaker_reset()
            # step.data_desc = DataProcess(
            #     process=[('ADD', UI(raw=env.user_context.payload[env._frag_idx-1]))],
            #     seed=Data(atom))

        def check_max_loop(env, current_step, next_step, fbkgate):
            if env._frag_idx < env._payload_frag_max:
                return False
            else:
                env._frag_idx = 0
                return True

        step_init = NoDataStep(fbk_timeout=0, do_before_data_processing=init_frag,
                               step_desc='Init')
        # step_change_fragidx = NoDataStep(do_before_data_processing=change_fragid)
        step_change_fragmax = NoDataStep(do_before_data_processing=change_fragmax)
        step_send_frag = StepStub(do_before_data_processing=send_frag, fbk_timeout=fbk_timeout)

        step_init.connect_to(step_send_frag)
        step_send_frag.connect_to(FinalStep(), cbk_after_fbk=check_max_loop)

        self.scenario_template = Scenario(self.__class__.__name__, anchor=step_init,
                                          user_context=UI(fbk_timeout=fbk_timeout))


class ScenarioBuilder(object):

    def __init__(self):
        pass

    def set_frag_scenario_template(self, atom_name, fragidx_ref, fragmax_ref, pld_ref, fbk_timeout=2):
        self.frag_sc = FragScenarioTemplate(atom_name, fragidx_ref=fragidx_ref, fragmax_ref=fragmax_ref, pld_ref=pld_ref, fbk_timeout=fbk_timeout)

    def build_frag_scenarios_from(self, name, payload):
        return self.frag_sc.instantiate_scenario(name, ui=UI(payload=payload))