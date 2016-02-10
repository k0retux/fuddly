.. _probes:

Generic Probes
**************

The following section present some generic probes that inherit from
:class:`fuzzfmk.monitor.Probe`. They can be used within your project
files (refer to :ref:`tuto:project`) by only inheriting from them
and providing the expected parameters,

ProbePID_SSH
============

Reference:
  :class:`fuzzfmk.monitor.ProbePID_SSH`

Description:
  This generic probe enables you to monitor a process PID through an
  SSH connection.

Usage Example:
   Within your project file you can add such a probe like this:

   .. code-block:: python
      :linenos:

        # Assuming your Project() is referred by the 'project' variable

        @blocking_probe(project)
        class health_check(ProbePID_SSH):
            process_name = 'the_process_to_monitor'
            sshd_ip = '127.0.0.1'
            sshd_port = 22
            username = 'user'
            password = 'pass'

   .. seealso:: Refer to the class definition itself to look for the parameters available.

