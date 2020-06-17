.. highlight:: console

=======
dp-dpdk
=======

Synopsis
--------

:program:`dp-dpdk` [-i *interface* | -p *pcap* [-r]] [-l *logfile*] [-h]

Description
-----------

:program:`dp-dpdk` is a shell script that is used as a wrapper for the :program:`dns-probe-dpdk` binary. Its purpose in to restart :program:`dns-probe-dpdk` after it has exited with the status of 1, which indicates that the ``restart`` operation was received from Sysrepo. Other exit codes from :program:`dns-probe-dpdk` cause :program:`dp-dpdk` to exit as well.

All options are passed unchanged to :program:`dns-probe-dpdk`, see :doc:`dns-probe-dpdk` man page for details. 
