cznic-dns-probe module
======================

The YANG module in
`data-model/cznic-dns-probe.yang <https://gitlab.labs.nic.cz/adam/dns-probe/blob/master/data-model/cznic-dns-probe.yang>`__
file provides Sysrepo with configuration options for DNS probe and a set
of basic statistics that the probe collects. The definition of YANG
format can be found in
`RFC7950 <https://tools.ietf.org/html/rfc7950>`__. The file defines a
module *cznic-dns-probe* that contains several groups (containers) of
configuration options for DNS probe as well as a group (container) of
basic real-time statistics.

1) dns-probe container
----------------------

This YANG container defines all configuration options of DNS probe. The
configuration options are of two types - ``static`` and ``dynamic``.
Changes to the ``static`` configuration options take effect only after
the restart of DNS probe. The ``rpc restart`` option defined at the end
of this YANG module can be used to trigger this restart. Changes to the
``dynamic`` configuration take effect immediately during the curent run
of DNS probe.

coremask
''''''''

-  Default value: ``0x7``
-  Static configuration
-  XPath ``/dns-probe/coremask``

Hexadecimal mask indicating which CPU cores should the DNS probe use for
its operation. DNS probe needs at minimum 3 CPU cores to work - 1
configuration core, 1 export core and 1 worker core. Setting more than 3
cores in the bitmask will spawn more worker cores which are used as the
main processing units for incoming packets.

The default value of ``0x7`` indicates that DNS probe should use the
first 3 CPU cores with IDs of 0, 1 and 2.

dns-port
''''''''

-  Default value: ``53``
-  Static configuration
-  XPath ``/dns-probe/dns-port``

Transport protocol port number that the DNS probe will check for in
incoming packets to recognize DNS traffic.

The default value of ``53`` is the standard DNS server port as defined
in `RFC1035 <https://tools.ietf.org/html/rfc1035>`__.

a) Export container
~~~~~~~~~~~~~~~~~~~

This YANG container defines DNS probe's configuration options regarding
export of DNS records.

export-dir
''''''''''

-  Default value: ``.``
-  Static configuration
-  XPath ``/dns-probe/export/export-dir``

Path to the existing local directory where DNS probe will store exported
files containing DNS records.

The default value ``.`` means that DNS probe will store the exported
files to the current directory where it was launched.

export-format
'''''''''''''

-  Default value: ``parquet``
-  Possible values: ``parquet``, ``cdns``
-  Static configuration
-  XPath ``/dns-probe/export/export-format``

This value indicates in which format should DNS probe export the
processed DNS records. The choice is between the `Apache
Parquet <https://parquet.apache.org/>`__ columnar format or
`C-DNS <https://tools.ietf.org/html/rfc8618>`__.

cdns-fields
'''''''''''

-  Default value:
   ``transaction_id time_offset query_name client_hoplimit qr_transport_flags                   client_address client_port server_address server_port query_size qr_dns_flags                   query_ancount query_arcount query_nscount query_qdcount query_opcode                   response_rcode query_classtype query_edns_version query_edns_udp_size                   query_opt_rdata response_additional_sections response_size``
-  Static configuration
-  XPath ``/dns-probe/export/cdns-fields``

This option takes effect only if ``cdns`` is set as the export format in
the ``export-format`` option. It's a bitfield that indicates which
information about the DNS records should be exported according to the
C-DNS schema defined in
`RFC8618 <https://tools.ietf.org/html/rfc8618>`__.

The default value sets for export all fields supported by the DNS probe.

cdns-records-per-block
''''''''''''''''''''''

-  Default value: ``10000``
-  Dynamic configuration
-  XPath ``/dns-probe/export/cdns-records-per-block``

This option takes effect only if ``cdns`` is set as the export format in
the ``export-format`` option. Value indicating the maximum number of
exported DNS records per one C-DNS block as defined in
`RFC8618 <https://tools.ietf.org/html/rfc8618#section-7.3.2>`__.

The default value of ``10000`` is chosen according to the recommendation
in `RFC8618 appendix
C.6 <https://tools.ietf.org/html/rfc8618#appendix-C.6>`__.

cdns-blocks-per-file
''''''''''''''''''''

-  Default value: ``0``
-  Static configuration
-  XPath ``/dns-probe/export/cdns-blocks-per-file``

This option takes effect only if ``cdns`` is set as the export format in
the ``export-format`` option. Value indicating the maximum number of
`C-DNS blocks <https://tools.ietf.org/html/rfc8618#section-7.3.2>`__
written to one exported file. If this limit is reached the exported file
is closed and a new one is started.

The default value of ``0`` means that an unlimited number of C-DNS
blocks can be written to one exported file.

parquet-records-per-file
''''''''''''''''''''''''

-  Default value: ``5000000``
-  Dynamic configuration
-  XPath ``/dns-probe/export/parquet-records-per-file``

This option takes effect only if ``parquet`` is set as the export format
in the ``export-format`` option. Value indicating the maximum number of
DNS records per one exported Parquet file. If this limit is reached the
exported file is closed and a new one is started. Parquet format buffers
DNS records for one file in memory and then writes them to the file all
at once. This can mean significant requirements for RAM as each worker
core of DNS probe buffers its own file.

The default value was determined experimentally to have the uncompressed
exported file's size be as close to 128 MB as possible (ideal for
Hadoop). However the in memory representation of the exported file of
this size can take around 1-1,5 GB of RAM!

file-name-prefix
''''''''''''''''

-  Default value: ``dns_``
-  Dynamic configuration
-  XPath ``/dns-probe/export/file-name-prefix``

This option represents the prefix in the name of all files exported by
the DNS probe.

timeout
'''''''

-  Default value: ``0``
-  Dynamic configuration
-  XPath ``/dns-probe/export/timeout``

Value indicating a time interval in seconds after which a newly opened
export file will be closed and another one will be started.

The default value of ``0`` means that the exported file will never be
closed just based on its age. It can however be closed based on other
configuration options described above (``cdns-blocks-per-file``,
``parquet-records-per-file``).

file-size-limit
'''''''''''''''

-  Default value: ``0``
-  Dynamic configuration
-  XPath ``/dns-probe/export/file-size-limit``

Value indicating the size limit of exported file in megabytes. This
value is currently used only for rotating files of the additional PCAP
export described in ``pcap-export`` option, because getting the size of
data in Parquet or C-DNS files is quite tricky if not impossible.

The default value of ``0`` means that the exported file will never be
closed just based on its size.

file-compression
''''''''''''''''

-  Default value: ``true``
-  Static configuration
-  XPath ``/dns-probe/export/file-compression``

If this flag is true, the exported Parquet or C-DNS files will be
compressed with GZIP. C-DNS files are compressed in their entirety and
given the ``.gz`` sufix. Parquet format implementation used by DNS probe
compresses only certain parts of the file internally due to the nature
of the format so the exported file isn't given the ``.gz`` sufix even
though it is compressed with GZIP.

pcap-export
'''''''''''

-  Default value: ``disabled``
-  Possible values: ``all``, ``invalid``, ``disabled``
-  Dynamic configuration
-  XPath ``/dns-probe/export/pcap-export``

Selector indicating if the DNS probe should export selected packets to
PCAP in addition to Parquet or C-DNS export. \* ``all`` - All packets
processed by the DNS probe will be stored to PCAP \* ``invalid`` -
Invalid packets that the DNS probe couldn't process will be stored to
PCAP \* ``disabled`` - PCAP export is disabled

b) transaction-table container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

DNS probe matches captured DNS queries and responses into records
representing DNS transactions (query-response pairs). Matching of
queries and responses is done via hash table that can be configured by
options in this container.

max-transactions
''''''''''''''''

-  Default value: ``1048576``
-  Static configuration
-  XPath ``/dns-probe/transaction-table/max-transactions``

This value indicates the maximum number of entries in transaction table
at any given time. The value MUST be the power of 2. Memory for
transaction table is preallocated by DNS probe at the start of the
application's run so this value influences the RAM consumption of DNS
probe.

The default value of ``1048576`` represents ``2^20`` and was
experimentally chosen so the probe could theoretically handle 10 Gbit of
DNS traffic. This value can be lowered if the user needs to reduce
memory consumption of the DNS probe and the real volume of processed
traffic doesn't reach 10 Gbit.

query-timeout
'''''''''''''

-  Default value: ``1000``
-  Dynamic configuration
-  XPath ``/dns-probe/transaction-table/query-timeout``

Time interval in miliseconds after which the query or response is
removed from the transaction table if no corresponding response or query
is observed.

match-qname
'''''''''''

-  Default value: ``false``
-  Dynamic configuration
-  XPath ``/dns-probe/transaction-table/match-qname``

By default the 5-tuple of
``source IP, destination IP, source port, destination port, transport protocol``
is used to match DNS query with corresponding response. If this option
is set to ``true`` the DNS QNAME (if present) is used as a secondary key
for matching queries with responses.

The default value of ``false`` turns off the matching of queries and
responses with secondary key.

c) tcp-table container
~~~~~~~~~~~~~~~~~~~~~~

DNS probe supports the processing of DNS traffic sent through the TCP
transport protocol. For this the probe needs to hold information about
currently opened TCP connections containing DNS traffic. A hash table is
used just as in the case of ``transaction-table``. This container
defines options to configure the hash table of opened TCP connections.

concurrent-connections
''''''''''''''''''''''

-  Default value: ``1048576``
-  Static configuration
-  XPath ``/dns-probe/transaction-table/concurrent-connections``

This value indicates the maximum number of entries in tcp table at any
given time. The value MUST be the power of 2. Memory for tcp table is
preallocated by DNS probe at the start of the application's run so this
value influences the RAM consumption of DNS probe.

The default value of ``1048576`` represents ``2^20`` and was
experimentally chosen so the probe could theoretically handle 10 Gbit of
DNS traffic. This value can be lowered if the user needs to reduce
memory consumption of the DNS probe and the real volume of processed
traffic doesn't reach 10 Gbit.

timeout
       

-  Default value: ``60000``
-  Dynamic configuration
-  XPath ``/dns-probe/transaction-table/timeout``

Time interval in miliseconds after which the TCP connection is removed
from the tcp table if no new traffic is observed.

2) statistics container
-----------------------

The DNS probe collects some basic real-time statistics during its run.
It exports these statistics into the Sysrepo datastore where users can
access them. This container contains the definition of these statistics.

-  **processed-packets** - Overall number of all packets processed by
   DNS probe
-  **processed-transactions** - Overall number of all DNS transactions
   processed by DNS probe
-  **exported-records** - Overall number of all DNS records exported by
   DNS probe
-  **queries-per-second-ipv4** - Number of IPv4 DNS queries processed
   per second
-  **queries-per-second-ipv6** - Number of IPv6 DNS queries processed
   per second
-  **queries-per-second-tcp** - Number of TCP DNS queries processed per
   second
-  **queries-per-second-udp** - Number of UDP DNS queries processed per
   second
-  **queries-per-second** - Overall number of DNS queries processed per
   second
-  **pending-transactions** - Number of queries and responses currently
   waiting in transaction table to be matched
-  **exported-pcap-packets** - Overall number of packets exported to
   PCAP

3) rpc restart
--------------

RPC call that the Sysrepo can send to the DNS probe to trigger probe's
restart and the application of static configuration changes.
