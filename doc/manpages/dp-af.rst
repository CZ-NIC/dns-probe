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

All options are passed unchanged to :program:`dns-probe-af`, see :doc:`dns-probe-af` man page for details. 
