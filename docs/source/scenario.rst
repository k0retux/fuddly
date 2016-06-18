.. _scenario-desc:

Scenario Description
********************

Overview
========

The `Scenario Infrastructure` enables you to describe protocols which are based on the data
described in a data model. You can do whatever you want, either by following a standard
or playing around it.

Once a `scenario` has been defined and registered, ``Fuddly`` will automatically create a specific
`Generator` that comply to what you described.

.. note:: The ``Fuddly`` shell command ``show_dmaker_types`` displays all the data maker,
  `Generators` and `Disruptors`. The Generators which are backed by a scenario are prefixed by
  ``SC_``.

A `scenario` is a state-machine. Its description follow an oriented graph where the nodes, called
`steps`, define the data to be sent to the target. The transitions that interconnect these
steps can be guarded by different kinds of callbacks that trigger at different moment (before
the framework sends the data, after sending the data, or after having retrieved any feedback
from the target or any probes registered to monitor the target).

A First Example
===============

Let's begin with a simple example that interconnect 3 steps in a loop without any callback.

.. note:: All the examples (or similar ones) of this chapter are provided in the file
  ``<fuddly_root>/data_models/tuto_strategy.py``.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4, 9, 13, 18, 20

    from framework.tactics_helpers import Tactics
    from framework.scenario import *

    tactics = Tactics()

    periodic1 = Periodic(Data('Periodic (5s)\n'), period=5)
    periodic2 = Periodic(Data('One Shot\n'), period=None)

    step1 = Step('exist_cond', fbk_timeout=2, set_periodic=[periodic1, periodic2])
    step2 = Step('separator', fbk_timeout=5)
    step3 = Step('off_gen', fbk_timeout=2, clear_periodic=[periodic1])

    step1.connect_to(step2)
    step2.connect_to(step3)
    step3.connect_to(step1)

    sc1 = Scenario('ex1')
    sc1.set_anchor(step1)

    tactics.register_scenarios(sc1)

You should first note that scenarios have to be described in a ``*_strategy.py`` file that match
the data model you base your scenarios on. In our case we use the data model ``mydf`` defined in
``tuto.py`` (refer to :ref:`dm:mydf` for further explanation on file organization).
The special object ``tactics`` (line 4) is usually used to register the data makers (`disruptors` or
`generators`) specific to a data model (refer to :ref:`tuto:disruptors` for details). It is also used
to register scenarios as shown in line 20.

From line 9 to 11 we define 3 :class:`framework.scenario.Step`:

- The first one commands the framework to send a data of type ``exist_cond`` (which is the name of a data registered
  in the data model ``mydf``) as well as starting 2 tasks (threaded entities of the framework) that
  will emit each one a specific data. The first one will send the specified string every 5 seconds
  while the other one will send another string only once. Finally, the step set also the maximum
  time duration that ``Fuddly`` should respect for collecting the feedback from the target (feedback
  timeout). This timeout is actually handled by the ``Target`` object, which may decide to respect it
  or not. For instance the ``NetworkTarget`` respect it while the ``EmptyTarget`` (default target)
  do not.

- The second step commands the framework to send a data of type ``separator`` and change the
  feedback timeout to 5.

- The third step requests to send a data of type ``off_gen`` and change back the feedback timeout to
  2. Additionally it commands the framework to stop the periodic task which is currently running.

.. note:: The feedback timeout will directly influence the time that seperates the execution of
   each step

The linking of these steps is carried out from the line 13 to 15. Then in line 17,
a :class:`framework.scenario.Scenario` object is created with the name ``ex1`` which is used by ``Fuddly``
for naming the `generator` that implements this scenario. It prefixes it with the string ``SC_`` leading to
the name ``SC_EX1``. The `scenario` is then linked to the initial `step` in line 18.

The execution of this scenario will follow the pattern::

  step1 ---------> step2 ---------> step3 ---------> step1 ---------> ...
    |                                 |                |
    \--> periodic1 ...      [periodic1 stopped]        \--> periodic1 ...
    \--> periodic2 ...      [periodic2 stopped]        \--> periodic2 ...


You can play with this scenario by loading the ``tuto`` project with the third ``Target`` which expects
a client listening on a TCP socket bound to the port 12345::

  [fuddly term] >> run_project tuto 3
  [fuddly term] >> send_loop 10 SC_EX1

  [another term] # nc -k -l 12345


Finally, note that a step once executed will display a description related to what it did. You
can override this description by providing the ``step_desc`` parameter of a
:class:`framework.scenario.Step` constructor with a python string.

Transitions and Callbacks
=========================

When two steps are connected together thanks to the method :meth:`framework.scenario.Step.connect_to`
some callbacks can be specified to perform any user-relevant action before crossing the transition
that links up the two steps, but also to decide if this transition can be crossed.

Indeed, a callback has to return `True` if it wants the framework to cross the transition, otherwise
it should return `False`. If no callback is defined the transition is considered to not be
guarded and thus can be crossed without restriction. Besides, only one transition is chosen at
each step. It is the first one, by order of registration, that can be activated (at least one
callback that returns `True`, or no callback at all). Anyway, all the registered callbacks will be
executed no matter the transition to be selected.

Three types of callback can be associated to a transition through the parameters ``cbk_before_sending``,
``cbk_after_sending`` and ``cbk_after_fbk`` of the method :meth:`framework.scenario.Step.connect_to`.
A brief explantion is provided below:

``cbk_before_sending``
  To provide a function that will be executed before the execution of the next step, and just before
  sending the data of the current step. Its signature is as follows::

     def callback(scenario_env, current_step, next_step)

  The ``current_step`` is the one that is in progress and which is connected to ``next_step`` by
  the transition containing the current callback. The ``scenario_env`` is an object shared
  between each step of a scenario. Its attribute ``dm`` is initialized with the currently loaded
  data model.

``cbk_after_sending``
  To provide a function that will be executed before the execution of the next step, and just after
  the sending of the data from the current step. Its signature is as follows::

     def callback(scenario_env, current_step, next_step)


``cbk_after_fbk``
  To provide a function that will be executed before the execution of the next step, and just after
  ``Fuddly`` retrieved the feedback of the target (and/or any registered probes). Its signature
  is as follows::

     def callback(scenario_env, current_step, next_step, feedback)

  This type of callback takes the additional parameter ``feedback`` filled by the framework with
  the target and/or probes feedback further to the current step data sending. It is a dictionnary
  that follows the pattern:

    .. code-block:: python
       :linenos:

        {'feedback source name 1':
            [ {'timestamp': timestamp_1,
               'content': content_1,
               'status': status_code_1 }, ... ]
         'feedback source name 2':
            [ {'timestamp': timestamp_2,
               'content': content_2,
               'status': status_code_2 }, ... ]

        # and so on...
        }

Note that a callback can modify a step. For instance, considering an imaginary protocol, and
after sending a registration request to a network service (initial step), feedback from the target are
provided to the callbacks registered on the next transitions. These callbacks could then look
for an identifier within the feedback and then update the next step to make it sending
a message with the right identifier.

A step has a property ``node`` that provides the root node (:class:`framework.data_model.Node`)
of the modeled data it contains or `None` if the data associated to the step is a raw data
(like ``Data('raw data')``). Any callback can then alter the ``node`` of a step in order to update it
with usefull information. In our example, the ``node`` is updated with the identifier (refer to
line 10-11 of the following code snippet).

.. note:: Accessing to ``next_step.node`` from a callback will provide `None` in the case the next
   step include a raw data. In the case it includes a ``DataProcess``, ``next_step.node`` will
   provide the :class:`framework.data_model.Node` corresponding to the ``DataProcess``'s ``seed`` or
   ``None`` (if no seed is available or the seed is raw data). In the latter case, the data process would
   not have been carried out at the time of the callback execution, hence the ``None`` value.
   (Refer to the section :ref:`sc:dataprocess`)

.. note:: You can leverage the dissection/absorption mechanism of ``Fuddly`` to deal with the feedback
   if you have modeled the responses of the target. Refer to :ref:`tuto:dm-absorption` for further
   explanation on that matter.

Another aspect of callbacks is the ability to prevent the framework from going on (that is
sending further data, and walking through the scenario) until a condition has been reached
(related to the target feedback for instance). For that purpose, the callback needs to call the
method ``make_blocked()`` on the current step and to return `False`. In this case, the callback
``cbk_after_fbk`` will be (re)called after the feedback gathering time has elapsed once again.
Note that you can `block` from any callback, but only ``cbk_after_fbk`` will be called further on
and will be able to `unblock` the situation.

Such ability can be usefull if you are not sure about the time to wait for the answer of a network
service for instance. This is illustrated in the following example in the lines 2-4.

.. code-block:: python
   :linenos:
   :emphasize-lines: 1, 4, 10-11, 18, 19, 25

    def feedback_handler(env, current_step, next_step, feedback):
        if not feedback:
            # While no feedback is retrieved we stay at this step
            current_step.make_blocked()
            return False
        else:
            # Extract info from feedback and add an attribute to the scenario env
            env.identifier = handle_fbk(feedback)
            current_step.make_free()
            if next_step.node:
                next_step.node['off_gen/prefix'] = env.identifier
            return True

    periodic1 = Periodic(Data('1st Periodic (5s)\n'), period=5)
    periodic2 = Periodic(Data('2nd Periodic (3s)\n'), period=3)

    step1 = Step('exist_cond', fbk_timeout=2, set_periodic=[periodic1, periodic2])
    step2 = Step('separator', fbk_timeout=5, cbk_after_fbk=feedback_handler)
    step3 = NoDataStep()
    step4 = Step(DataProcess(process=[('C',None,UI(nb=1)),'tTYPE'], seed='enc'))

    step1.connect_to(step2)
    step2.connect_to(step3, cbk_after_fbk=cbk_transition2)
    step3.connect_to(step4)
    step4.connect_to(FinalStep())

    sc2 = Scenario('ex2')
    sc2.set_anchor(step1)

In line 25 a :class:`framework.scenario.FinalStep` (a step with its ``final`` attribute set to `True`)
is used to terminate the scenario as well as all the associated periodic tasks that are still running.
Note that if a callback set the ``final`` attribute of the ``next_step`` to `True`,
it will trigger the termination of the scenario if this ``next_step`` is indeed the one that will
be selected next.

.. note:: A step with its ``final`` attribute set to ``True`` will never trigger the sending of the
   data it contains.

Remark also the :class:`framework.scenario.NoDataStep` in line 19 (``step3``) which is a step that
does not provide data. Thus, the framework won't send anything during the execution of this kind
of step. Anyway, it is still possible to set or clear some `periodic` in this step (or changing
feedback timeout, ...)

.. note:: A :class:`framework.scenario.NoDataStep` is actually a step
   on which ``make_blocked()`` has been called on it and where ``make_free()`` do nothing.

The execution of this scenario will follow the pattern::

  step1 --> step2 --> step2 ... step2 --> step3 --> step4 --> FinalStep()
    |              |                   |                          |
    |          No feedback          Feedback                      |
    |                                                             |
    \--> periodic1 ...                                     [periodic1 stopped]
    \--> periodic2 ...                                     [periodic2 stopped]

Finally, the last example illustrates a case where one step is connected to two other steps with
a callback that rules the routing decision.

.. code-block:: python
   :linenos:

    def routing_decision(env, current_step, next_step):
        if hasattr(env, 'switch'):
            return False
        else:
            env.switch = False
            return True

    anchor = Step('exist_cond')
    option1 = Step(Data('Option 1'))
    option2 = Step(Data('Option 2'))

    anchor.connect_to(option1, cbk_after_sending=routing_decision)
    anchor.connect_to(option2)
    option1.connect_to(anchor)
    option2.connect_to(anchor)

    sc3 = Scenario('ex3')
    sc3.set_anchor(anchor)


The execution of this scenario will follow the pattern::

  anchor --> option1 --> anchor --> option2 --> anchor --> option2 --> ...


.. _sc:dataprocess:

Data generation process
=======================

The data produced by a :class:`framework.scenario.Step` or a :class:`framework.scenario.Periodic`
is described by a `data descriptor` which can be:

- a python string refering to the name of a registered data from a data model;

- a :class:`framework.data_model.Data`;

- a :class:`framework.scenario.DataProcess`.


A :class:`framework.scenario.DataProcess` is composed of a chain of generators and/or disruptors
(with or without parameters) and optionally a ``seed`` on which the chain of disruptor will be applied to (if no
generator is provided at the start of the chain).

.. seealso:: Refer to :ref:`tuto:dmaker-chain` for more information on disruptor chaining.

.. note:: It follows the same pattern as the instructions that can set a virtual operator
   (:ref:`tuto:operator`). It is actually what the method :meth:`framework.plumbing.FmkPlumbing.get_data`
   takes as parameters.

Here under examples of steps leveraging the different ways to describe their data to send.

.. code-block:: python
   :linenos:

   Step( 'exist_cond' )   # 'exist_cond' is the name of a data from `mydf` data model

   Step( Data('A raw message') )

   Step( DataProcess(process=['ZIP', 'tSTRUCT', ('SIZE', None, UI(sz=100))]) )
   Step( DataProcess(process=['C', 'tTYPE'], seed='enc') )
   Step( DataProcess(process=['C'], seed=Data('my seed')) )

