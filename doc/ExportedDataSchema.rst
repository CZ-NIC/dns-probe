*************
Exported data
*************

Storing exported data
=====================

DNS Probe supports storing the exported data either to local files or transferring them directly to a remote
location via secure network transfer using `TLS <https://tools.ietf.org/html/rfc8446>`_. This is determined
by the :ref:`location` option in Sysrepo configuration.

Local storage
-------------

If :ref:`location` option is set to ``local`` the exported data will be stored in local files in directory
specified by :ref:`export-dir` option. The names of these files will have the following naming convention:

::

    <prefix>YYYYMMDD-HHMMSS_p<proc_id>_<file_id>.<sufix>

The *<prefix>* is determined by :ref:`file-name-prefix` option in Sysrepo configuration. The *YYYYMMDD-HHMMSS*
represents a UTC timestamp from when the output file was first opened. *<proc_id>* is an internal identification
of process (worker or export thread) which wrote the output file. *<file_id>* represents the number of a file
from files written within the same second to prevent overriding data if more files are exported within
the same second. *<sufix>* is one of ``parquet``, ``cdns`` or ``cdns.gz`` based on the export format and
compression configured in Sysrepo.

Export to remote location
-------------------------

If :ref:`location` option is set to ``remote`` DNS Probe will attempt to transfer the exported data to a remote
server specified by :ref:`remote-ip-address` and :ref:`remote-port` options via encrypted TLS connection with
remote server's authentication.

The transfer uses a simple application layer protocol shown below:

.. code-block:: text

     0  1  2  3  4  5  6  7
    +--+--+--+--+--+--+--+--+
    | File name's length    |
    +--+--+--+--+--+--+--+--+
    | File's name           |
    | ...                   |
    +--+--+--+--+--+--+--+--+
    | File's data           |
    | ...                   |
    | ...                   |
    +--+--+--+--+--+--+--+--+

Each file is transferred using a new TLS connection. The first byte of data determines the length of transferred
file's name. Then the name of the transferred file follows. The transferred file's name follows the same
convention as files saved by DNS Probe locally meaning that the remote server can determine the file's timestamp,
format and compression just from parsing the file's name. After the file's name the exported DNS data in Parquet
or C-DNS format follows until the end of the connection. By correctly closing the connection DNS Probe signals
to remote server that all the data has been sent and remote server can finish the currently transferred file.

To prevent a loss of data due to network outages DNS Probe stores data for the current file to a local directory,
specified in :ref:`export-dir`, first. When the file is finished and DNS Probe is about to perform output
rotation, then the probe tries to transfer the finished file to remote server. If the transfer succeeds
the local file is deleted. DNS Probe will initially attempt to transfer the file three times. If all three
transfer attempts fail the local file is kept. DNS Probe keeps track of files that failed the transfer to
remote server and periodically tries to resend them. The local files are kept until such transfer is successful.


Data schema
===========

DNS Probe exports data in one of two formats -
`Parquet <https://parquet.apache.org/>`_ or
`C-DNS <https://tools.ietf.org/html/rfc8618>`_. The exported data tries
to conform to the `Entrada
schema <https://entrada.sidnlabs.nl/datamodel/>`_ for Hadoop. Parquet
export simply copies the Entrada schema shown in the table below. C-DNS
format has its own schema defined in `RFC
8616 <https://tools.ietf.org/html/rfc8618>`_. DNS Probe tries to fill
this C-DNS schema with only the data needed for reconstructing the
Entrada schema.

+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| Entrada (Parquet) fields        | type      | C-DNS schema field                   | Comment                                                     |
+=================================+===========+======================================+=============================================================+
| id                              | INT32     | transaction-id                       | 16-bit DNS ID                                               |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| unixtime                        | INT64     | earliest-time, time-offset           | Seconds since Epoch                                         |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| time                            | INT64     | earliest-time, time-offset           | Microseconds since Epoch                                    |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| qname                           | STRING    | query-name-index                     | Full qname, without final dot                               |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| domainname                      | STRING    | query-name-index                     | Last two domains (or TLD + 1 label) in lowercase            |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| len                             | INT32     | XXX                                  | Request packet length                                       |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| frag                            | INT32     | XXX                                  | Fragmentation? (Always 0 in Parquet)                        |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| ttl                             | INT32     | client-hoplimit                      | Request TTL                                                 |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| ipv                             | INT32     | qr-transport-flags                   | IP version: 4 / 6                                           |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| prot                            | INT32     | qr-transport-flags                   | TCP/UDP/... (value such as "17" =UDP)                       |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| src                             | STRING    | client-address-index                 | Source (client) IP                                          |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| srcp                            | INT32     | client-port                          | Source (client) port                                        |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| dst                             | STRING    | server-address-index                 | Destination (server) IP                                     |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| dstp                            | INT32     | server-port                          | Destination (server) port                                   |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| udp\_sum                        | INT32     | XXX                                  | UDP checksum                                                |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| dns\_len                        | INT32     | query-size                           | Request DNS payload length                                  |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| aa                              | BOOLEAN   | qr-dns-flags                         | Response AA flag                                            |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| tc                              | BOOLEAN   | qr-dns-flags                         | Response TC flag                                            |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| rd                              | BOOLEAN   | qr-dns-flags                         | Request RD flag                                             |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| ra                              | BOOLEAN   | qr-dns-flags                         | Request RA flag                                             |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| z                               | BOOLEAN   | qr-dns-flags                         | Request Z flag                                              |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| ad                              | BOOLEAN   | qr-dns-flags                         | Request AD flag                                             |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| cd                              | BOOLEAN   | qr-dns-flags                         | Request CD flag                                             |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| ancount                         | INT32     | query-ancount                        | Answers count                                               |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| arcount                         | INT32     | query-arcount                        | Additional records count                                    |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| nscount                         | INT32     | query-nscount                        | Authority records count                                     |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| qdcount                         | INT32     | query-qdcount                        | Questions count                                             |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| opcode                          | INT32     | query-opcode                         | Request opcode (=response)                                  |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| rcode                           | INT32     | response-rcode                       | Response code                                               |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| qtype                           | INT32     | type                                 | Query type                                                  |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| qclass                          | INT32     | class                                | Query class                                                 |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| country                         | STRING    | query-name-index                     | 2 letter code ("CZ", ..) (always empty string in Parquet)   |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| asn                             | STRING    | query-name-index                     | ASN ("AS1234", ...) (always empty string in Parquet)        |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_udp                       | INT32     | query-udp-size                       | UDP payload                                                 |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_version                   | INT32     | query-edns-version                   | EDNS version                                                |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_do                        | BOOLEAN   | qr-dns-flags                         | DO bit                                                      |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_ping                      | BOOLEAN   | response-extended.additional-index   | Tough to detect! (always false in Parquet)                  |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_nsid                      | STRING    | response-extended.additional-index   | NSID string                                                 |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_dnssec\_dau               | STRING    | query-opt-rdata-index                | Comma-separated list "1,3,5"                                |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_dnssec\_dhu               | STRING    | query-opt-rdata-index                | Comma-separated list "1,3,5"                                |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_dnssec\_n3u               | STRING    | query-opt-rdata-index                | Comma-separated list "1,3,5"                                |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_client\_subnet            | STRING    | query-opt-rdata-index                | Always empty string in Parquet                              |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_other                     | STRING    | query-opt-rdata-index                | Always empty string in Parquet                              |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_client\_subnet\_asn       | STRING    | query-opt-rdata-index                | By IP list (Maxmind) (always empty string in Parquet)       |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| edns\_client\_subnet\_country   | STRING    | query-opt-rdata-index                | By IP list (Maxmind) (always empty string in Parquet)       |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| labels                          | INT32     | query-name-index                     | Number of qname labels                                      |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| res\_len                        | INT32     | XXX                                  | Response packet length                                      |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| time\_micro                     | INT64     | earliest-time, time-offset           | Microseconds part of ``time`` field                         |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| resp\_frag                      | INT32     | XXX                                  | Unknown (always 0 in Parquet)                               |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| proc\_time                      | INT32     | XXX                                  | Unknown (always 0 in Parquet)                               |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| is\_google                      | BOOLEAN   | XXX                                  | By IP list (Maxmind) (always false in Parquet)              |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| is\_opendns                     | BOOLEAN   | XXX                                  | By IP list (Maxmind) (always false in Parquet)              |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| dns\_res\_len                   | INT32     | response\_size                       | Response DNS payload length                                 |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
| server\_location                | STRING    | XXX                                  | Server location (allways empty string in Parquet)           |
+---------------------------------+-----------+--------------------------------------+-------------------------------------------------------------+
