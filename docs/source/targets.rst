.. _targets:

Generic Targets
***************

The following section present some generic targets that inherit from
:class:`fuddly.framework.target_helpers.Target`. They can be directly used as is,
within your project files (refer to :ref:`tuto:project`), or for some
of them they can also be customized by inheriting from them and
implementing some intended methods acting as hooks within the generic
targets.

Some of them will automatically provide feedback if an error occurs,
to make ``fuddly`` aware of it and act accordingly (refer to :ref:`tuto:probes`
for more information on that topic).

Additionally, if the generic target support feedback retrieval, the way it
is retrieved is guided by a feedback timeout and one of the following mode:

- :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_FULL_TIME`: Wait for the full
  time slot allocated for feedback retrieval
- :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_UNTIL_RECV`: Wait until the
  target has sent something back to us

The feedback timeout is set through :meth:`fuddly.framework.target_helpers.Target.set_feedback_timeout`,
while the modes are set through :meth:`fuddly.framework.target_helpers.Target.set_feedback_mode`.

.. note::
   Depending on the generic target, all the feedback modes are not supported.

NetworkTarget
=============

Reference:
  :class:`fuddly.framework.targets.network.NetworkTarget`

Description:
  This generic target enables you to interact with a network target in
  TCP or UDP, through one or more interfaces. Each declared interface
  is customizable, and the generic target itself can be more
  customized by inheriting from it. Especially, the following methods
  are expected to be overloaded, depending on the user needs:

  - :meth:`fuddly.framework.targets.network.NetworkTarget._custom_data_handling_before_emission()`
    for performing some actions related to the data that will be emitted
    right after.
  - :meth:`fuddly.framework.targets.network.NetworkTarget._feedback_handling()` for
    filtering/handling feedback in some ways before transferring it to
    ``fuddly``.
  - :meth:`fuddly.framework.targets.network.NetworkTarget.initialize()` for doing
    specific actions at target initialization.
  - :meth:`fuddly.framework.targets.network.NetworkTarget.terminate()` for doing
    specific actions at target termination.


  .. seealso:: Refer also to the tutorial section :ref:`targets-def`
               that guides you through an example of network target.


Feedback:
  This target will automatically provide feedback on any network-related error
  encountered while delivering data to the target.


Supported Feedback Mode:
  - :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_FULL_TIME`
  - :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_UNTIL_RECV`


Usage Example:
   .. code-block:: python
      :linenos:
      :emphasize-lines: 1-2

       tg = NetworkTarget(host='localhost', port=12345, data_semantics='TG1',
			  hold_connection=True)
       tg.register_new_interface(host='localhost', port=54321,
                                 socket_type=(socket.AF_INET, socket.SOCK_STREAM),
				 data_semantics='TG2', server_mode=True, hold_connection=True)
       tg.add_additional_feedback_interface('localhost', 7777,
                                            socket_type=(socket.AF_INET, socket.SOCK_DGRAM),
					    fbk_id='My Feedback Source', server_mode=True)
       tg.set_timeout(fbk_timeout=5, sending_delay=3)


   line 1-2
     We instantiate the ``NetworkTarget`` by providing the parameters of
     the first interface: a TCP connection to ``localhost`` on port
     ``12345``. We specify that the connection on this interface have to
     be maintained between each data emission to the target though the
     parameter ``hold_connection``. This interface will be considered as
     the default one, through which any data will be routed to unless
     specified differently, through the ``data_semantics`` parameter
     (look at the class API for insight). In this case, data without
     *semantic*, and data with a *semantic* equal to ``'TG1'`` will go
     through this interface.

   line 3-5
     We declare another interface where we specify the real target
     will connect to us (and not otherwise), by using the
     ``server_mode`` parameter. We also set semantics to ``'TG2'``
     which means that only data marked with such semantics will be
     routed to this interface.

   line 6-8
     We declare another interface for only feedback purpose, where the
     source of the feedback will send data to us in UDP
     (``socket.SOCK_DGRAM``) on the port ``7777``. Note that an
     identifier has to be provided (``fbk_id``), and will be used to
     refer to the interface at different points in time. Main
     interfaces (the first one and the ones defined through
     :meth:`fuddly.framework.targets.network.NetworkTarget.register_new_interface()`)
     has also an identifier but it is set automatically by the
     ``NetworkTarget``.

   line 9
     We set some time constraints: ``fbk_timeout`` for gathering
     feedback from all the interfaces; ``sending_delay`` for sending
     data to the target (client mode) or waiting for client connections before
     sending data to them (server mode). Note this method is specific to
     this target and remains consistent with :meth:`fuddly.framework.target_helpers.Target.set_feedback_timeout`.



LocalTarget
===========

Reference:
  :class:`fuddly.framework.targets.local.LocalTarget`

Description:
  This generic target enables you to interact with a program running
  on the same platform as ``fuddly``. It can be customized by
  inheriting from it. The following methods are expected to be
  overloaded, depending on the user needs:

  - :meth:`fuddly.framework.targets.local.LocalTarget.initialize()` for doing
    specific actions at target initialization.
  - :meth:`fuddly.framework.targets.local.LocalTarget.terminate()` for doing
    specific actions at target termination.

Feedback:
  This target will automatically provide feedback if the application writes on
  ``stderr`` or returns a negative status or terminates/crashes.
  ``stdout`` can also be parsed looking for user-provided keywords that will trigger
  some feedback with negative status or even parsed by a user-provided function.

Supported Feedback Mode:
  - :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_UNTIL_RECV`


Usage example:
   .. code-block:: python
      :linenos:
      :emphasize-lines: 3

       import fuddly.framework.global_resources as gr

       tg = LocalTarget(tmpfile_ext='.zip')
       tg.set_target_path('unzip')
       tg.set_post_args('-d ' + gr.workspace_folder)


   line 3
     We declare a ``LocalTarget`` and specify the file extension that
     will be used for interacting with the targeted program.

   line 4
     We set the file system path to the targeted program.

   line 5
     We set some parameters that will be used by ``fuddly`` to make up
     the command to execute for interacting with the targeted
     program. This parameter will be put after the file name, but you
     can also add parameters before it through the method
     :meth:`fuddly.framework.targets.local.LocalTarget.set_pre_args()`. Note the use
     of the variable ``workspace_folder`` that points to the
     ``fuddly`` workspace directory which is typically used when
     temporary files need to be created.


SSHTarget
=========

Reference:
  :class:`fuddly.framework.targets.ssh.SSHTarget`

Description:
  This generic target enables you to interact with a remote target requiring an SSH connection.

Feedback:
  This target will automatically provide the results of the commands sent through SSH.

Supported Feedback Mode:
  - :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_FULL_TIME`
  - :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_UNTIL_RECV`

Usage Example:
   .. code-block:: python
      :linenos:

       tg = SSHTarget(host='192.168.0.1', port=22, username='test', password='test')


PrinterTarget
=============

Reference:
  :class:`fuddly.framework.targets.printer.PrinterTarget`

Description:
  This generic target enables you to interact with a IPP server.

Feedback:
  No feedback is automatically returned.

Usage Example:
   .. code-block:: python
      :linenos:
      :emphasize-lines: 1

       tg = PrinterTarget(tmpfile_ext='.png')
       tg.set_target_ip('127.0.0.1')
       tg.set_target_port(631)     # optional
       tg.set_printer_name('PDF')  # optional


   line 1
     We declare a ``PrinterTarget`` and specify the file extension
     that will be used for interacting with the targeted program.

   line 2
     We set the IP of the IPP server managing the printer.

   line 3
     We set the port for communicating with the printer.

   line 4
     We set the name of the printer of interest.


SIMTarget
=========

Reference:
  :class:`fuddly.framework.targets.sim.SIMTarget`

Description:
  This generic target enables you to interact with a SIM card through a serial line
  (e.g., a SIM card embedded within an USB GSM modem)

Feedback:
  This target will automatically provide feedback if an error is received
  through the serial line used to interact with the SIM card.

Supported Feedback Mode:
  - :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_FULL_TIME`

Usage Example:
   .. code-block:: python
      :linenos:

       tg = SIMTarget(serial_port='/dev/ttyUSB3', baudrate=115200, pin_code='0000'
                      targeted_tel_num='0123456789', zone='33')



TestTarget
==========

Reference:
  :class:`fuddly.framework.targets.debug.TestTarget`

Description:
  This generic target enables you to stimulate a virtual target that could be useful for test
  preparation for instance.
  Some parameters enable to change the behavior of this target.

Feedback:
  This target could provide random feedback, or feedback chosen from a provided sample list, or
  it could repeat the received data as its feedback.

Supported Feedback Mode:
  - :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_FULL_TIME`
  - :const:`fuddly.framework.target_helpers.Target.FBK_WAIT_UNTIL_RECV`

Usage Example:
   .. code-block:: python
      :linenos:

       tg = TestTarget(name='mytest_target', fbk_samples=['OK','ERROR'])
