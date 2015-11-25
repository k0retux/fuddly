.. _targets:

Generic Targets
***************

The following section present some generic targets that inherit from
:class:`fuzzfmk.target.Target`. They can be directly used as is,
within your project files (refer to :ref:`tuto:project`), or for some
of them they can also be customized by inheriting from them and
implementing some intended methods acting as hooks within the generic
targets.


NetworkTarget
=============

Reference:
  :class:`fuzzfmk.target.NetworkTarget`

Description:
  This generic target enables you to interact with a network target in
  TCP or UDP, through one or more interfaces. Each declared interface
  is customizable, and the generic target itself can be more
  customized by inheriting from it. Especially, the following methods
  are expected to be overloaded, depending on the user needs:

  - :meth:`fuzzfmk.target.NetworkTarget._custom_data_handling_before_emission()`
    for performing some actions related to the data that will be emitted
    right after.
  - :meth:`fuzzfmk.target.NetworkTarget._feedback_handling()` for
    filtering/handling feedback in some ways before transferring it to
    ``fuddly``.
  - :meth:`fuzzfmk.target.NetworkTarget.initialize()` for doing
    specific actions at target initialization.
  - :meth:`fuzzfmk.target.NetworkTarget.terminate()` for doing
    specific actions at target termination.


  .. seealso:: Refer also to the tutorial section :ref:`targets-def`
               that guides you through an example of network target.


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

   line 6-7
     We declare another interface for only feedback purpose, where the
     source of the feedback will send data to us in UDP
     (``socket.SOCK_DGRAM``) on the port ``7777``. Note that an
     identifier has to be provided (``fbk_id``), and will be used to
     refer to the interface at different points in time. Main
     interfaces (the first one and the ones defined through
     :meth:`fuzzfmk.target.NetworkTarget.register_new_interface()`)
     has also an identifier but it is set automatically by the
     ``NetworkTarget``.

   line 8
     We set some time constraints: ``fbk_timeout`` for gathering
     feedback from all the interfaces; ``sending_delay`` for sending
     data to the target or waiting for client connections before
     sending data to them.



LocalTarget
===========

Reference:
  :class:`fuzzfmk.target.LocalTarget`

Description:
  This generic target enables you to interact with a program running
  on the same platform as ``fuddly``. It can be customized by
  inheriting from it. The following methods are expected to be
  overloaded, depending on the user needs:

  - :meth:`fuzzfmk.target.LocalTarget.initialize()` for doing
    specific actions at target initialization.
  - :meth:`fuzzfmk.target.LocalTarget.terminate()` for doing
    specific actions at target termination.


Usage example:
   .. code-block:: python
      :linenos:
      :emphasize-lines: 3

       import fuzzfmk.global_resources as gr

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
     :meth:`fuzzfmk.target.LocalTarget.set_pre_args()`. Note the use
     of the variable ``workspace_folder`` that points to the
     ``fuddly`` workspace directory which is typically used when
     temporary files need to be created.



PrinterTarget
=============

Reference:
  :class:`fuzzfmk.target.PrinterTarget`

Description:
  This generic target enables you to interact with a IPP server.

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
