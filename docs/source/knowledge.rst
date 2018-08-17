.. _knowledge-infra:

Knowledge Infrastructure
************************

The *Knowledge Infrastructure* enables to:

- to dynamically collect feedback from Targets (:ref:`targets`) and Probes
  (:ref:`probes`), and extract information from it through dedicated handlers in order to
  create knowledge (refer to :ref:`kn:handle-fbk`);

- to add knowledge about the targets under test (e.g., the kind of OS, the used programming language,
  the hardware, and so on) in your project file (refer to :ref:`kn:adding`);

- and to leverage this knowledge in relevant fuddly subsystems or in user-defined scenarios,
  disruptors, ... (refer to :ref:`kn:leverage`). For instance, fuzzing a :class:`framework.value_types.Filename`
  typed-node with the disruptor tTYPE will adapt the generated data relative to the OS, Language,
  and so on if this information is available.


.. _kn:get_knowledge:

Get Knowledge about the Targets Under Test
------------------------------------------

.. _kn:handle-fbk:

Defining a Feedback Handler to Create Knowledge from Targets' and Probes' Feedback
==================================================================================

The :class:`knwoledge.feedback_handler.FeedbackHandler` class provides the frame to create knowledge based on
feedback retrieved by fuddly (essentially from targets themselves and the probes that
monitor them).

In your projects, you can use already defined feedback handlers in order to automatically extract information
from feedback and create knowledge that will be directly usable in various relevant fuddly components
(refer to :ref:`kn:leverage`).

Let's illustrate that with the ``tuto`` project (refer to ``<fuddly_root>/projects/tuto_proj.py``) that
register a ``fuddly``-defined feedback handler whose sole purpose is to present the feature:

.. code-block:: python
   :linenos:

    project.register_feedback_handler(TestFbkHandler())

This handler is defined as follows:

.. code-block:: python
   :linenos:

    class TestFbkHandler(FeedbackHandler):

        def extract_info_from_feedback(self, source, timestamp, content, status):

            if content is None:
                return None
            elif b'Linux' in content:
                return OS.Linux
            elif b'Windows' in content:
                return OS.Windows


It implements the method :meth:`knowledge.feedback_handler.FeedbackHandler.extract_info_from_feedback` that is
called each time feedback are retrieved from a target or a probe with parameters enabling you to process it,
and return information about the target (in this case either :const:`OS.Linux` or :const:`OS.Windows`)
if it can or ``None`` if it is not able.

The information concept is implemented through the class :class:`framework.knowledge.information.Info`,
and provide specific methods to increase
or decrease the confidence that we have about a specific information. Each time a feedback handler return
specific information like ``OS.Linux`` for instance, the framework would increase the confidence it has on it
through the method :meth:`framework.knowledge.information.Info.increase_trust`. Note that at any
given time you can look at the current confidence level for any information by using the
:meth:`framework.knowledge.information.Info.show_trust` method.

The accumulation of information and the computed confidence level for each piece of it make up the
knowledge on the targets under test.

If you want to look at the current state of the knowledge pool, you can issue the following
command from the FmkShell::

    >> show_knowledge

That will provide something similar to the following output::

    -=[ Status of Knowledge ]=-

    Info: Language.C [TrustLevel.Maximum --> value: 50]
    Info: Hardware.X86_64 [TrustLevel.Maximum --> value: 50]

As dealing with feedback can be specific to your projects, you can obviously define
your own feedback handlers for matching your specific needs. In order to do that you will have to
create a new class that inherits from :class:`knwoledge.feedback_handler.FeedbackHandler`
and implements your specific behaviors. Then you will only need to register it in your :class:`framework.project.Project`
in order for its methods to be called automatically by fuddly at the relevant times.

.. note::
    Even if initial purpose of feedback handlers is to create knowledge from retrieved information, it can be
    used to trigger other kinds of actions that fit your needs.

:class:`knowledge.feedback_handler.FeedbackHandler` provides other methods that could be useful to overload
to extract more information about the context of the feedback. Indeed, the method
:meth:`knowledge.feedback_handler.FeedbackHandler.notify_data_sending` is called each time data is sent
and provide you with useful contextual information:

- the sent data;
- the date of emission;
- the targets.


.. _kn:adding:

Adding Knowledge About the Targets Under Test in the Project File
=================================================================

As seen in Section :ref:`kn:handle-fbk`, knowledge on the targets under test can be built upon
the information extracted from feedback retrieved while interacting with the targets. But it can also
be something known from the beginning. If you know you are dealing with a C program, and that program
is executed on an x86 architecture, then you would like to provide this knowledge right ahead, so
that fuddly could leverage them to optimize its fuzzing for instance.

In order to provide such knowledge, you simply have to call :meth:`framework.project.Project.add_knowledge`
in your project file with your knowledge on the targets.

.. code-block:: python
   :linenos:

    project.add_knowledge(
        Hardware.X86_64,
        Language.C
    )

Information Categories and How to Define More
=============================================

The current information categories are:

- :class:`framework.knowledge.information.OS`
- :class:`framework.knowledge.information.Hardware`
- :class:`framework.knowledge.information.Language`

Depending on your project, you may want to define new specific information categories. In such case,
You will simply have to define new python enumeration that inherits from
:class:`framework.knowledge.information.Info` in your project file. Then, you would need to use them
in specific feedback handler (refer to :ref:`kn:handle-fbk`) in order to leverage them within
specific scenarios or disruptors for instance.

.. _kn:leverage:

Leveraging the Knowledge
------------------------

Automatic Fuddly Adaptation to Knowledge
========================================

**It is a work in progress.**

Currently, data model that use :class:`framework.value_types.Filename`
within their description will benefit from knowledge about the Language and Operating System used by the
target under test.


Leveraging Knowledge in User-defined Components
===============================================

Knowledge on the targets under tests can be used by various components of the framework and is made
available to the user in various context like:

- Scenario specification (refer to :ref:`scenario-infra`) where all callbacks can access the knowledge pool through the scenario environment
  (:class:`framework.scenario.ScenarioEnv`) under the attribute `knowledge_source`.

- Disruptors or generators implementation (refer to :ref:`tuto:disruptors`), through the attribute
  :attr:`framework.tactics_helpers.DataMaker.knowledge_source`.

- Data model description (refer to :ref:`data-model`), through the attribute
  :attr:`framework.data_model.DataModel.knowledge_source`.

These parameters refer to a global object defined for the project as a set of :class:`framework.knowledge.information.Info`.
