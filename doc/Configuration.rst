****************************
Configuration and management
****************************

DNS Probe is configured and managed through the `Sysrepo <https://www.sysrepo.org/>`_ system. In the current stage of development, this may seem to be an overkill. However, when everything is in place, Sysrepo is expected to provide the following functionality:

* configuration datastores and data-driven API for configuration and management

* remote configuration and management via standard protocols (NETCONF [RFC6241]_ or RESTCONF [RFC8040]_)

* real-time access to state data and statistics

* RPC operations

* event notifications

* unified configuration and management that includes other system components such as DNS servers or routing daemons.

More information about Sysrepo can be obtained from project `web pages <https://www.sysrepo.org/>`_ or its `Github repository <https://github.com/sysrepo/sysrepo>`_.

Data model
==========

Sysrepo uses the YANG language [RFC7950]_ for modelling configuration and state data, RPC operations and notifications. Section :ref:`YANG module <yang-module>` contains the complete YANG module *cznic-dns-probe* that is used for DNS Probe. Its schema tree looks as follows::

   +--rw cznic-dns-probe:dns-probe
   |  +--rw coremask? <uint64>
   |  +--rw dns-port? <uint16>
   |  +--rw export
   |  |  +--rw cdns-blocks-per-file? <uint64>
   |  |  +--rw cdns-fields? <bits>
   |  |  +--rw cdns-records-per-block? <uint64>
   |  |  +--rw export-dir? <string>
   |  |  +--rw export-format? <enumeration>
   |  |  +--rw file-compression? <boolean>
   |  |  +--rw file-name-prefix? <string>
   |  |  +--rw file-size-limit? <uint64>
   |  |  +--rw parquet-records-per-file? <uint64>
   |  |  +--rw pcap-export? <enumeration>
   |  |  +--rw timeout? <uint32>
   |  +--rw tcp-table
   |  |  +--rw concurrent-connections? <uint32>
   |  |  +--rw timeout? <uint64>
   |  +--rw transaction-table
   |     +--rw match-qname? <boolean>
   |     +--rw max-transactions? <uint32>
   |     +--rw query-timeout? <uint64>
   +---x cznic-dns-probe:restart
   |  +--ro input
   |  +--ro output
   +--ro cznic-dns-probe:statistics
      +--ro exported-pcap-packets? <counter64(uint64)>
      +--ro exported-records? <counter64(uint64)>
      +--ro pending-transactions? <counter64(uint64)>
      +--ro processed-packets? <counter64(uint64)>
      +--ro processed-transactions? <counter64(uint64)>
      +--ro queries-per-second? <decimal64>
      +--ro queries-per-second-ipv4? <decimal64>
      +--ro queries-per-second-ipv6? <decimal64>
      +--ro queries-per-second-tcp? <decimal64>
      +--ro queries-per-second-udp? <decimal64>

For use with Sysrepo, the YANG module has to be installed first. This is normally accomplished as a part of package installation. When installing DNS Probe manually, the following command has to be run in order to install the YANG module:

.. code-block:: shell

   sysrepoctl -i /path/to/cznic-dns-probe.yang

Configuration parameters, RPC operations, state data and statistics defined in the YANG module are described in detail in the following sections.

Configuring DNS Probe via Sysrepo
=================================

.. Note:: Configuration interfaces are somewhat spartan and rudimentary in the current version of DNS Probe. More user-friendly approaches are being worked on.

After installation, Sysrepo configuration datastore is populated with default values of all parameters that are defined in the YANG module *cznic-dns-probe*.

The contents of the configuration datastore can be manipulated using the **sysrepocfg** utility. For example, the command

.. code-block:: shell

   sysrepocfg -E vim -m cznic-dns-probe

opens the `Vim <https://www.vim.org/>`_ editor on an empty document. Changes to the running configuration datastore can be specified in the XML representation. For example, the following snippet

* changes the :ref:`dns-port` parameter to 64
* selects C-DNS as the :ref:`export-format`
* sets :ref:`cdns-records-per-block` to 1000

.. code-block:: xml

   <dns-probe xmlns="https://www.nic.cz/ns/yang/dns-probe">
     <dns-port>64</dns-port>
     <export>
       <export-format>cdns</export-format>
       <cdns-records-per-block>1000</cdns-records-per-block>
     </export>
   </dns-probe>

Other possibilities for using **sysrepocfg** can be found in Sysrepo documentation or by executing

.. code-block:: shell

   sysrepocfg -h

It is also possible to configure and manage DNS Probe remotely using the standard protocols NETCONF [RFC6241]_ or RESTCONF [RFC8040]_. For this, it is necessary to install `Netopeer2 <https://github.com/CESNET/Netopeer2>`_ server.

Configuration parameters
========================

All YANG data nodes representing configuration parameters appear in the top-level ``/cznic-dns-probe:dns-probe`` container.

Configuration parameters are of two basic types:

*static*
   Such parameters can be modified in the Sysrepo datastore but the changes will not take effect until DNS Probe is restarted.

*dynamic*
   Changes to such parameters take effect immediately, no restart is needed.

Static configuration parameters
-------------------------------

This section lists all static configuration parameters in alphabetical order. 

cdns-fields
^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/cdns-fields``
:default: all fields

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It is a bit set that determines which fields from the C-DNS schema defined in [RFC8618]_ will be included in the exported transaction records.

.. _cdns-records-per-block:

cdns-records-per-block
^^^^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/cdns-records-per-block``
:default: 10000

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It specifies the maximum number of exported DNS transaction records per one C-DNS block, see `Section 7.3.2 <https://tools.ietf.org/html/rfc8618#section-7.3.2>`_ in [RFC8618]_.

The default value of 10000 corresponds to the recommendation in `Appendix C.6 <https://tools.ietf.org/html/rfc8618#appendix-C.6>`_ of [RFC8618]_.

coremask
^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/coremask``
:default: 7

Bitmask indicating which CPU cores should DNS Probe use. At least 3 CPU cores are needed, see :ref:`dns-probe-arch`. Setting more than 3 cores in the bitmask will spawn more worker threads that are used for processing incoming packets.

The default value of 7 indicates that DNS Probe should use the first 3 CPU cores with IDs of 0, 1 and 2.

.. _dns-port:

dns-port
^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/dns-port``
:default: 53

Transport protocol port number that DNS Probe will check for in
incoming packets to recognize DNS traffic.

The default value of 53 is the standard DNS server port as defined
in [RFC1035]_.

export-dir
^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/export-dir``
:default: ``.``

Path to an existing local directory for storing export files.

The default value of ``.`` means that DNS Probe will use the current working directory from which it was launched.

.. _export-format:

export-format
^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/export-format``
:default: ``parquet``

This value indicates the format for exporting records about
DNS transactions. Two options are currectly supported:

``parquet``
   `Apache Parquet <https://parquet.apache.org/>`_ columnar format

``cdns``
   Compacted-DNS (C-DNS) [RFC8618]_.

file-compression
^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/file-compression``
:default: **true**

If this flag is true, the exported Parquet or C-DNS files will be
compressed with GZIP. C-DNS export files are compressed in their
entirety, and suffix ``.gz`` is appended to their names. Parquet
format implementation used by DNS Probe compresses only selected parts
of the file, and there is no ``.gz``.

concurrent-connections
^^^^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/tcp-table/concurrent-connections``
:default: 131072

The value of this parameter must be a power of 2. It specifies the maximum number of TCP connections that DNS Probe can handle at any given time, which in turn affects the size of in-memory data structures allocated for keeping the status of TCP connections.

The default value of 131072 (2^17) was determined experimentally – it takes into account the default value for :ref:`max-transactions` and the current common ratio of DNS traffic over UDP and TCP. It is recommended to adjust this parameter to actual traffic circumstances in order to optimize memory consumption.

.. _max-transactions:

max-transactions
^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/transaction-table/max-transactions``
:default: 1048576

The value of this parameter must be a power of 2. It specifies the maximum number of pending DNS transactions that DNS Probe can handle at any given time, which in turn affects the size of in-memory transaction table.

The default value of 1048576 (2^20) was determined experimentally – it should suffice for handling DNS traffic at the line rate of 10 Gb/s. It is recommended to adjust this parameter to actual traffic circumstances in order to optimize memory consumption.

Dynamic configuration parameters
--------------------------------

This section lists all dynamic configuration parameters in alphabetical order. 

.. _cdns-blocks-per-file:

cdns-blocks-per-file
^^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/cdns-blocks-per-file``
:default: 0

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It specifies the maximum number of C-DNS blocks written to one exported file (see `Section 7.3.2 <https://tools.ietf.org/html/rfc8618#section-7.3.2>`_ in [RFC8618]_). If this limit is reached, the export file is closed and a new one started.

The default value of 0 means that there is no limit.

.. _parquet-records-per-file:

parquet-records-per-file
^^^^^^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/parquet-records-per-file``
:default: 5000000

This parameter takes effect only if ``parquet`` is set in :ref:`export-format`. It specifies the maximum number of DNS records per one exported Parquet file. If this limit is reached, the exported file is closed and a new one started.

Parquet format buffers DNS records for one file in memory and then writes them to the file all at once. This can mean significant requirements for RAM as each worker thread buffers data for its own file.

The default value was determined experimentally – the size of an uncompressed export file should then be as close to 128 MB as possible, which is ideal for Hadoop. However, in-memory representation of an exported file of this size can take as much as 1-1.5 GB of RAM!

file-name-prefix
^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/file-name-prefix``
:default: ``dns_``

This option represents the prefix that is prepended to the name of all
files exported by DNS Probe.

timeout
^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/timeout``
:default: 0

This paremeter specifies the time interval (in seconds) after which a newly opened export file will be closed and another one started.

The default value of 0 means that the export file will never be
closed just based on its age. It can however be closed based on other
configuration options described above (:ref:`cdns-blocks-per-file` and
:ref:`parquet-records-per-file`).

file-size-limit
^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/file-size-limit``
:default: 0

This parameter specifies the maximum size of export file in megabytes. It is currently used only for rotating files of the auxiliary PCAP export described in :ref:`pcap-export` below, because estimating the size of data in Parquet or C-DNS files is quite tricky if not impossible.

The default value of 0 means that the export file will never be closed just based on its size.

.. _pcap-export:

pcap-export
^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/export/pcap-export``
:default: ``disabled``

This parameter controls export of packets to a PCAP file in addition to Parquet or C-DNS export. Possible values are the following:

``all``
   export all packets processed by DNS Probe to PCAP

``invalid``
   export only invalid DNS queries or responses
   
``disabled``
   no PCAP export.

query-timeout
^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/transaction-table/query-timeout``
:default: 1000

This parameter specifies the time interval in miliseconds after which the query or response is removed from the transaction table if no corresponding response or query is observed.

match-qname
^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe/transaction-table/match-qname``
:default: **false**

By default, the 5-tuple of source and destination IP address, source and destination port, and transport protocol is used to match a DNS query with the corresponding response. If this parameter is set to **true** the DNS QNAME (if present) is used as a secondary key for matching queries with responses.

timeout
^^^^^^^       

:data node: ``/cznic-dns-probe:dns-probe/tcp-table/timeout``
:default: 60000

This parameter specifies the time interval in miliseconds after which the TCP connection is removed from the tcp table if no new traffic is observed.

Statistics
==========

DNS Probe collects a number of basic run-time statistics and state data. Sysrepo makes the following items available in the ``/cznic-dns-probe:statistics`` container:

**processed-packets**
   overall number of all packets processed by DNS Probe

**processed-transactions**
   overall number of DNS transactions processed by DNS Probe

**exported-records**
   overall number of DNS records exported by DNS Probe

**queries-per-second-ipv4**
   number of IPv4 DNS queries processed per second

**queries-per-second-ipv6**
   number of IPv6 DNS queries processed per second

**queries-per-second-tcp**
   number of TCP DNS queries processed per second

**queries-per-second-udp**
   number of UDP DNS queries processed per second

**queries-per-second**
   overall number of DNS queries processed per second

**pending-transactions**
   number of queries and responses currently waiting in transaction table to be matched

**exported-pcap-packets**
   overall number of packets exported to PCAP.

RPC operations
==============

Currently, only one RPC operation is implemented in Sysrepo:

**restart**
   restart the probe and apply the changes in static configuration.
