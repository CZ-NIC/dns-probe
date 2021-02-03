****************************
Configuration and management
****************************

DNS Probe is configured at startup through a `YAML <https://yaml.org/>`_ file. Runtime remote management API is planned
to be implemented in future releases. When everything is in place, the API is expected to provide the following functionality:

* configuration datastores and data-driven API for configuration and management

* remote configuration and management via standard protocols

* real-time access to state data and statistics

* RPC operations

* event notifications

* unified configuration and management that includes other system components such as DNS servers or routing daemons.

Data model
==========

DNS Probe uses local file in YAML format to load configuration at startup. Its schema tree looks as follows::

   +--rw <instance-id>?
      +--rw coremask? <uint64>
      +--rw dnstap-socket-list?* <string>
      +--rw dns-ports?* <uint16>
      +--rw export
      |  +--rw asn-maxmind-db? <string>
      |  +--rw cdns-blocks-per-file? <uint64>
      |  +--rw cdns-fields?* <string>
      |  +--rw cdns-records-per-block? <uint64>
      |  +--rw country-maxmind-db? <string>
      |  +--rw export-dir? <string>
      |  +--rw export-format? <enumeration>
      |  +--rw file-compression? <boolean>
      |  +--rw file-name-prefix? <string>
      |  +--rw file-size-limit? <uint64>
      |  +--rw location? <enumeration>
      |  +--rw parquet-records-per-file? <uint64>
      |  +--rw pcap-export? <enumeration>
      |  +--rw remote-ca-cert? <string>
      |  +--rw remote-ip-address? <string>
      |  +--rw remote-port? <uint16>
      |  +--rw timeout? <uint32>
      +--rw interface-list?* <string>
      +--rw ipv4-allowlist?* <string>
      +--rw ipv4-denylist?* <string>
      +--rw ipv6-allowlist?* <string>
      +--rw ipv6-denylist?* <string>
      +--rw ip-anonymization
      |  +--rw anonymize-ip? <boolean>
      |  +--rw encryption? <enumeration>
      |  +--rw key-path? <string>
      +--rw log-file? <string>
      +--rw pcap-list?* <string>
      +--rw raw-pcap? <boolean>
      +--rw tcp-table
      |  +--rw concurrent-connections? <uint32>
      |  +--rw timeout? <uint64>
      +--rw transaction-table
         +--rw match-qname? <boolean>
         +--rw max-transactions? <uint32>
         +--rw query-timeout? <uint64>

Configuring DNS Probe via YAML file
===================================

.. Note:: Configuration interfaces are somewhat spartan and rudimentary in the current version of DNS Probe. More user-friendly approaches are being worked on.

After installation, a default YAML configuration file is installed at *<INSTALL_DIR>/etc/dns-probe-<BACKEND>/dns-probe.yml*.
By default, DNS Probe will try to load configuration from this file at startup.

The contents of the default file can be edited by user or a different YAML configuration file can be provided to DNS Probe
via the `-c` command line parameter.

In future releases it will be possible to configure and manage DNS Probe remotely using a remote management API.

Configuration parameters
========================

All YAML configuration parameters appear in the top-level ``instance-id`` container. ``instance-id`` uniquely
identifies given instance of DNS Probe with its configuration. Instance ID of DNS Probe instance can be set at startup
by the `-n` command line parameter. Only configuration with this particular ``instance-id`` will then be loaded
from YAML configuration file. User can configure multiple instances of DNS Probe from one YAML file like this.

A special ``instance-id`` is *default*. Configuration set under *default* instance is loaded by all instances
of DNS Probe before its specific instance configuration. A common configuration for all instances can be set
using this special ``instance-id``.

DNS Probe binaries internally contain default values for all configuration options so the *default* instance
configuration can be ommited from YAML configuration file. This means that user only has to specify options
differing from default values for a specific instance of DNS Probe in the YAML file.

For more information about the YAML configuration file format see :doc:`Default YAML file <YAMLfile>`.

List of configuration parameters
--------------------------------

This section lists all configuration parameters in alphabetical order.

anonymize-ip
^^^^^^^^^^^^

:data node: ``<instance-id>/ip-anonymization/anonymize-ip``
:default: **false**

If this flag is true, client IP addresses in exported data (Parquet or C-DNS, NOT optional PCAPs) will be anonymized using Crypto-PAn prefix-preserving algorithm.

asn-maxmind-db
^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/asn-maxmind-db``
:default: empty

Path to Maxmind ASN database. If this option is set to a valid database file, the ``asn`` implementation field in exported Parquets or C-DNS will be filled with Autonomous System Number (ASN) based on client's IP address.

.. _cdns-blocks-per-file:

cdns-blocks-per-file
^^^^^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/cdns-blocks-per-file``
:default: 0

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It specifies the maximum number of C-DNS blocks written to one exported file (see `Section 7.3.2 <https://tools.ietf.org/html/rfc8618#section-7.3.2>`_ in [RFC8618]_). If this limit is reached, the export file is closed and a new one started.

The default value of 0 means that there is no limit.

cdns-fields
^^^^^^^^^^^

:data node: ``<instance-id>/export/cdns-fields``
:default: all fields

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It is a bit set that determines which fields from the C-DNS schema defined in [RFC8618]_ will be included in the exported transaction records.

.. _cdns-records-per-block:

cdns-records-per-block
^^^^^^^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/cdns-records-per-block``
:default: 10000

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It specifies the maximum number of exported DNS transaction records per one C-DNS block, see `Section 7.3.2 <https://tools.ietf.org/html/rfc8618#section-7.3.2>`_ in [RFC8618]_.

The default value of 10000 corresponds to the recommendation in `Appendix C.6 <https://tools.ietf.org/html/rfc8618#appendix-C.6>`_ of [RFC8618]_.

concurrent-connections
^^^^^^^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/tcp-table/concurrent-connections``
:default: 131072

The value of this parameter must be a power of 2. It specifies the maximum number of TCP connections that DNS Probe can handle at any given time, which in turn affects the size of in-memory data structures allocated for keeping the status of TCP connections.

The default value of 131072 (2^17) was determined experimentally – it takes into account the default value for :ref:`max-transactions` and the current common ratio of DNS traffic over UDP and TCP. It is recommended to adjust this parameter to actual traffic circumstances in order to optimize memory consumption.

coremask
^^^^^^^^

:data node: ``<instance-id>/coremask``
:default: 7

Bitmask indicating which CPU cores should DNS Probe use. At least 3 CPU cores are needed, see :ref:`dns-probe-arch`. Setting more than 3 cores in the bitmask will spawn more worker threads that are used for processing incoming packets.

The default value of 7 indicates that DNS Probe should use the first 3 CPU cores with IDs of 0, 1 and 2.

country-maxmind-db
^^^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/country-maxmind-db``
:default: empty

Path to Maxmind Country database. If this option is set to a valid database file, the ``country`` field in exported Parquets or ``country-code`` implementation field in exported C-DNS will be filled with ISO 3166-1 country code based on client's IP address.

.. _dnstap-socket-list:

dnstap-socket-list
^^^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/dnstap-socket-list``
:default: empty

List of unix sockets to process dnstap data from in addition to sockets passed with '-d'
command line parameter.

.. _dns-ports:

dns-ports
^^^^^^^^^

:data node: ``<instance-id>/dns-ports``
:default: 53

List of transport protocol port numbers that DNS Probe will check for in
incoming packets to recognize DNS traffic.

The default value of 53 is the standard DNS server port as defined
in [RFC1035]_.

.. _encryption:

encryption
^^^^^^^^^^

:data node: ``<instance-id>/ip-anonymization/encryption``
:default: ``aes``

Encryption algorithm to be used during anonymization of client IP addresses if enabled. Four options currently supported:

``aes``
   AES encryption algorithm.

``blowfish``
   Blowfish encryption algorithm.

``md5``
   MD5 hash function.

``sha1``
   SHA1 hash function.

.. _export-dir:

export-dir
^^^^^^^^^^

:data node: ``<instance-id>/export/export-dir``
:default: ``.``

Path to an existing local directory for storing export files.

The default value of ``.`` means that DNS Probe will use the current working directory from which it was launched.

.. _export-format:

export-format
^^^^^^^^^^^^^

:data node: ``<instance-id>/export/export-format``
:default: ``parquet``

This value indicates the format for exporting records about
DNS transactions. Two options are currently supported:

``parquet``
   `Apache Parquet <https://parquet.apache.org/>`_ columnar format

``cdns``
   Compacted-DNS (C-DNS) [RFC8618]_.

file-compression
^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/file-compression``
:default: **true**

If this flag is true, the exported Parquet or C-DNS files will be
compressed with GZIP. C-DNS export files are compressed in their
entirety, and suffix ``.gz`` is appended to their names. Parquet
format implementation used by DNS Probe compresses only selected parts
of the file, and there is no ``.gz``.

.. _file-name-prefix:

file-name-prefix
^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/file-name-prefix``
:default: ``dns_``

This option represents the prefix that is prepended to the name of all
files exported by DNS Probe.

file-size-limit
^^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/file-size-limit``
:default: 0

This parameter specifies the maximum size of export file in megabytes. It is currently used only for rotating files of the auxiliary PCAP export described in :ref:`pcap-export` below, because estimating the size of data in Parquet or C-DNS files is quite tricky if not impossible.

The default value of 0 means that the export file will never be closed just based on its size.

.. _interface-list:

interface-list
^^^^^^^^^^^^^^

:data node: ``<instance-id>/interface-list``
:default: empty

List of network interfaces to process traffic from in addition to interfaces passed with `-i`
command line parameter.

Fill either with NIC interface names such as `eth0` or alternatively with PCI IDs when using DPDK backend
and binding NICs to DPDK-compatible drivers manually.

.. _ipv4-allowlist:

ipv4-allowlist
^^^^^^^^^^^^^^

:data node: ``<instance-id>/ipv4-allowlist``
:default: empty

List of allowed IPv4 addresses to process traffic from.

By default all IPv4 addressess are allowed.

ipv4-denylist
^^^^^^^^^^^^^

:data node: ``<instance-id>/ipv4-denylist``
:default: empty

List of IPv4 addresses from which to NOT process traffic.

By default all IPv4 addresses are allowed.

If :ref:`ipv4-allowlist` is not empty this configuration item doesn't have any effect.

.. _ipv6-allowlist:

ipv6-allowlist
^^^^^^^^^^^^^^

:data node: ``<instance-id>/ipv6-allowlist``
:default: empty

List of allowed IPv6 addresses to process traffic from.

By default all IPv6 addresses are allowed.

ipv6-denylist
^^^^^^^^^^^^^

:data node: ``<instance-id>/ipv6-denylist``
:default: empty

List of IPv6 addresses from which to NOT process traffic.

By default all IPv6 addresses are allowed.

If :ref:`ipv6-allowlist` is not empty this configuration item doesn't have any effect.

key-path
^^^^^^^^

:data node: ``<instance-id>/ip-anonymization/key-path``
:default: ``key.cryptopant``

Path (including file's names) to the file with encryption key that is to be used for client IP anonymization if enabled.
If the file doesn't exist, it is generated by the probe.

The key needs to be compatible with the encryption algorithm set in the :ref:`encryption` option. User should generate
the key using `scramble_ips` tool installed by the cryptopANT dependency like this:

.. code:: shell

   scramble_ips --newkey --type=<encryption> <key_file>

.. _location:

location
^^^^^^^^

:data node: ``<instance-id>/export/location``
:default: ``local``

Location for the storage of exported DNS records. Determines if data is stored to local file or sent
to remote server.

log-file
^^^^^^^^

:data node: ``<instance-id>/log-file``
:default: empty

Path (including file's name) to log file for storing probe's logs (e.g. `/var/log/dns-probe.log`).
Might get overriden by `-l` command line parameter.

By default logs are written to `stdout`.

match-qname
^^^^^^^^^^^

:data node: ``<instance-id>/transaction-table/match-qname``
:default: **false**

By default, the 5-tuple of source and destination IP address, source and destination port, and transport protocol is used to match a DNS query with the corresponding response. If this parameter is set to **true** the DNS QNAME (if present) is used as a secondary key for matching queries with responses.

.. _max-transactions:

max-transactions
^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/transaction-table/max-transactions``
:default: 1048576

The value of this parameter must be a power of 2. It specifies the maximum number of pending DNS transactions that DNS Probe can handle at any given time, which in turn affects the size of in-memory transaction table.

The default value of 1048576 (2^20) was determined experimentally – it should suffice for handling DNS traffic at the line rate of 10 Gb/s. It is recommended to adjust this parameter to actual traffic circumstances in order to optimize memory consumption.

.. _parquet-records-per-file:

parquet-records-per-file
^^^^^^^^^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/parquet-records-per-file``
:default: 5000000

This parameter takes effect only if ``parquet`` is set in :ref:`export-format`. It specifies the maximum number of DNS records per one exported Parquet file. If this limit is reached, the exported file is closed and a new one started.

Parquet format buffers DNS records for one file in memory and then writes them to the file all at once. This can mean significant requirements for RAM as each worker thread buffers data for its own file.

The default value was determined experimentally – the size of an uncompressed export file should then be as close to 128 MB as possible, which is ideal for Hadoop. However, in-memory representation of an exported file of this size can take as much as 1-1.5 GB of RAM!

.. _pcap-export:

pcap-export
^^^^^^^^^^^

:data node: ``<instance-id>/export/pcap-export``
:default: ``disabled``

This parameter controls export of packets to a PCAP file in addition to Parquet or C-DNS export. Possible values are the following:

``all``
   export all packets processed by DNS Probe to PCAP

``invalid``
   export only invalid DNS queries or responses
   
``disabled``
   no PCAP export.

.. _pcap-list:

pcap-list
^^^^^^^^^

:data node: ``<instance-id>/pcap-list``
:default: empty

List of PCAPs to process in addition to PCAPs passed with `-p` command line parameter.

query-timeout
^^^^^^^^^^^^^

:data node: ``<instance-id>/transaction-table/query-timeout``
:default: 1000

This parameter specifies the time interval in miliseconds after which the query or response is removed from the transaction table if no corresponding response or query is observed.

raw-pcap
^^^^^^^^

:data node: ``<instance-id>/raw-pcap``
:default: **false**

Indicates RAW PCAPs as input in :ref:`pcap-list` or from command line with `-p` parameter. Might get
overriden by `-r` command line parameter.

MUST be set to **false** if :ref:`interface-list` or `-i` command line parameter are used.

remote-ca-cert
^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/remote-ca-cert``
:default: empty

Path (including file's name) to the CA certificate against which the remote server's certificate
will be authenticated during TLS handshake. Will be used if :ref:`location` is set to ``remote``.

By default server's certificate will be authenticated against OpenSSL's default directory with CA certificates.

.. _remote-ip-address:

remote-ip-address
^^^^^^^^^^^^^^^^^

:data node: ``<instance-id>/export/remote-ip-address``
:default: ``127.0.0.1``

IP address for remote export of the DNS records. Will be used if :ref:`location` is set to ``remote``.

.. _remote-port:

remote-port
^^^^^^^^^^^

:data node: ``<instance-id>/export/remote-port``
:default: 6378

Tranport protocol port number for remote export of the DNS records. Will be used if :ref:`location` is set to ``remote``.

timeout
^^^^^^^

:data node: ``<instance-id>/export/timeout``
:default: 0

This paremeter specifies the time interval (in seconds) after which a newly opened export file will be closed and another one started.

The default value of 0 means that the export file will never be
closed just based on its age. It can however be closed based on other
configuration options described above (:ref:`cdns-blocks-per-file` and
:ref:`parquet-records-per-file`).

timeout
^^^^^^^       

:data node: ``<instance-id>/tcp-table/timeout``
:default: 60000

This parameter specifies the time interval in miliseconds after which the TCP connection is removed from the tcp table if no new traffic is observed.
