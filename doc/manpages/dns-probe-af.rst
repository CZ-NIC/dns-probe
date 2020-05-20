============
dns-probe-af
============

Synopsis
--------

**dns-probe-af** [-i <INTERFACE> | -p <PCAP>] [-r] [-l <LOGFILE>] [-h]

Description
-----------

:program:`dns-probe-af` is a network traffic probe that captures DNS queries and corresponding responses and exports them as configurable records about individual DNS transactions.

:program:`dns-probe-af` can either listen on an interface or read packets from a PCAP file. The :option:`-i` and :option:`-p` options are mutually incompatible but either of them can be used repeatedly.

Depending on the configuration, :program:`dns-probe-af` exports the transaction records in either Parquet or C-DNS format.

Options
-------

.. program:: dns-probe-af

.. option:: -i <INTERFACE>

   Network interface name to listen on.

.. option:: -p <PCAP>

   Input PCAP file.

.. option:: -r

   Indicates raw PCAP format.

.. option:: -l <LOGFILE>

   Logging messages are written to LOGFILE instead of standard output.

.. option:: -h

   Print help message and exit.
