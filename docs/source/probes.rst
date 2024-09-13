.. _probes:

Generic Probes and Backend
**************************

The following section present some generic probes that inherit from
:class:`fuddly.framework.monitor.Probe`. They can be used within your project
files (refer to :ref:`tuto:project`) by inheriting from them
and providing the expected parameters. Besides, you have to provide them with a means to
access the monitored system, namely a :class:`fuddly.framework.monitor.Backend`. Note that you can use
the same backend for simultaneous probes.

.. seealso::
   To define your own probe refer to :ref:`tuto:probes`.

Let's illustrate this with the following example where two probes are used to monitor a process
through an SSH connection. One is used to check if the PID of the process has changed after each
data sending, and the other one to check if the memory used by the process has exceeded
its initial memory footprint by 5% (with a probing period of 0.2 second).

The project file should look like this:

   .. code-block:: python
      :linenos:

        # Assuming your Project() is referred by the 'project' variable

        ssh_backend = SSH_Backend(username='user', password='pass',
                                  sshd_ip='127.0.0.1', sshd_port=22)

        @blocking_probe(project)
        class health_check(ProbePID):
            process_name = 'the_process_to_monitor'
            backend = ssh_backend

        @probe(project)
        class probe_mem(ProbeMem):
            process_name = 'the_process_to_monitor'
            tolerance = 5
            backend = ssh_backend

        targets = [ (YourTarget(), probe_pid, (probe_mem, 0.2)) ]


Generic Backend
===============

.. seealso:: Refer to the class documentation for more details.

SSH_Backend
-----------

Reference:
  :class:`fuddly.framework.comm_backends.SSH_Backend`

Description:
  This generic backend enables you to interact with a monitored system through an
  SSH connection.


Serial_Backend
--------------

Reference:
  :class:`fuddly.framework.comm_backends.Serial_Backend`

Description:
  This generic backend enables you to interact with a monitored system through an
  serial line.

Shell_Backend
-------------

Reference:
  :class:`fuddly.framework.comm_backends.Shell_Backend`

Description:
  This generic backend enables you to interact with a local monitored system
  through a shell.

Generic Probes
==============

.. seealso:: Refer to the class documentation for more details.

ProbePID
--------

Reference:
  :class:`fuddly.framework.monitor.ProbePID`

Description:
  This generic probe enables you to monitor any modification of a process PID,
  by specifying its name through the parameter ``process_name``.

ProbeMem
--------

Reference:
  :class:`fuddly.framework.monitor.ProbeMem`

Description:
  Generic probe that enables you to monitor the process memory (RSS...) consumption.
  It can be done by specifying a ``threshold`` and/or a ``tolerance`` ratio.


ProbeCmd
--------

Reference:
  :class:`fuddly.framework.monitor.ProbeCmd`

Description:
  Generic probe that enables you to execute shell commands and retrieve the output.
