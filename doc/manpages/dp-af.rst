.. highlight:: console

=====
dp-af
=====

Synopsis
--------

:program:`dp-af` [-i *interface* | -p *pcap* [-r]] [-l *logfile*] [-h]

Description
-----------

:program:`dp-af` is a Python script that is used as a wrapper for the :program:`dns-probe-af` binary. Its purpose in to restart :program:`dns-probe-af` after it has exited with the status of 1, which indicates that the ``restart`` operation was received from Sysrepo. Other exit codes from :program:`dns-probe-af` cause :program:`dp-af` to exit as well.

Options
-------

.. option:: -i interface

   Listen on the network interface with the given name, such as ``eth0``.

.. option:: -p pcap

   Read input from the given PCAP file.

.. option:: -r

   Indicates raw PCAP format.

.. option:: -l logfile

   Write logging messages to *logfile* instead of standard output.

.. option:: -h

   Print help message and exit.
