.. highlight:: console
.. program:: dns-probe-dpdk

==============
dns-probe-dpdk
==============

Synopsis
--------

:program:`dns-probe-dpdk` [-i *interface* | -p *pcap* [-r]] [-l *logfile*] [-h]

Description
-----------

:program:`dns-probe-dpdk` is a network traffic probe that captures DNS queries and corresponding responses and exports them as configurable records about individual DNS transactions.

:program:`dns-probe-dpdk` can either listen on an interface or read packets from a PCAP file. The :option:`-i` and :option:`-p` options are mutually incompatible but either of them can be used repeatedly.

Depending on the configuration, :program:`dns-probe-dpdk` exports the transaction records in either Parquet or C-DNS format.

Options
-------

.. option:: -i interface

   Listen on the network interface with the given name, such as ``eth0``, or with the given PCI ID, such as ``00:1f.6`` or ``0000:00:1f.6``.

.. option:: -p pcap

   Read input from the given PCAP file.

.. option:: -r

   Indicates raw PCAP format.

.. option:: -l logfile

   Write logging messages to *logfile* instead of standard output.

.. option:: -h

   Print help message and exit.

Exit Status
-----------

**0**
   Normal exit

**1**
   Exit based on receiving ``restart`` operation from Sysrepo