****************************
Configuration and management
****************************

DNS Probe is configured at startup from Sysrepo data store. It can then accept changes to its configuration from Sysrepo at runtime.
Sysrepo provides the following functionality:

* configuration data stores and data-driven API for configuration and management

* remote configuration and management via standard protocols

* real-time access to state data and statistics

* RPC operations

More information about Sysrepo can be obtained from project `web pages <https://www.sysrepo.org/>`_ or its `Github repository <https://github.com/sysrepo/sysrepo>`_.

Data model
==========

Sysrepo uses the YANG language [RFC7950]_ for modelling configuration and state data, RPC operations and notifications.
Section :ref:`YANG module <yang-module>` contains the complete YANG module *cznic-dns-probe* that is used
for DNS Probe. Its schema tree looks as follows::

   +--rw cznic-dns-probe:dns-probe*
      +--rw instance? <string>
      +--rw configuration
      |  +-- coremask? <uint64>
      |  +--rw dnstap-socket-group? <string>
      |  +--rw dnstap-socket-list?* <string>
      |  +--rw dns-ports?* <uint16>
      |  +--rw export
      |  |  +--rw asn-maxmind-db? <string>
      |  |  +--rw cdns-blocks-per-file? <uint64>
      |  |  +--rw cdns-fields?* <string>
      |  |  +--rw cdns-records-per-block? <uint64>
      |  |  +--rw country-maxmind-db? <string>
      |  |  +--rw export-dir? <string>
      |  |  +--rw export-format? <enumeration>
      |  |  +--rw file-compression? <boolean>
      |  |  +--rw file-name-prefix? <string>
      |  |  +--rw file-size-limit? <uint64>
      |  |  +--rw location? <enumeration>
      |  |  +--rw parquet-records-per-file? <uint64>
      |  |  +--rw pcap-export? <enumeration>
      |  |  +--rw remote-ca-cert? <string>
      |  |  +--rw remote-ip-address? <string>
      |  |  +--rw remote-port? <uint16>
      |  |  +--rw timeout? <uint32>
      |  +--rw interface-list?* <string>
      |  +--rw ipv4-allowlist?* <string>
      |  +--rw ipv4-denylist?* <string>
      |  +--rw ipv6-allowlist?* <string>
      |  +--rw ipv6-denylist?* <string>
      |  +--rw ip-anonymization
      |  |  +--rw anonymize-ip? <boolean>
      |  |  +--rw encryption? <enumeration>
      |  |  +--rw key-path? <string>
      |  +--rw knot-socket-count? <uint32>
      |  +--rw knot-socket-path? <string>
      |  +--rw log-file? <string>
      |  +--rw pcap-list?* <string>
      |  +--rw raw-pcap? <boolean>
      |  +--rw statistics
      |  |  +--rw moving-avg-window? <uint16>
      |  +--rw tcp-table
      |  |  +--rw concurrent-connections? <uint32>
      |  |  +--rw timeout? <uint64>
      |  +--rw transaction-table
      |     +--rw match-qname? <boolean>
      |     +--rw max-transactions? <uint32>
      |     +--rw query-timeout? <uint64>
      +--ro statistics
      |  +--ro exported-pcap-packets? <counter64(uint64)>
      |  +--ro exported-records? <counter64(uint64)>
      |  +--ro pending-transactions? <counter64(uint64)>
      |  +--ro processed-packets? <counter64(uint64)>
      |  +--ro processed-transactions? <counter64(uint64)>
      |  +--ro queries-per-second? <decimal64>
      |  +--ro queries-per-second-ipv4? <decimal64>
      |  +--ro queries-per-second-ipv6? <decimal64>
      |  +--ro queries-per-second-tcp? <decimal64>
      |  +--ro queries-per-second-udp? <decimal64>
      +---x restart
         +--ro input
         +--ro output

For use with Sysrepo, the YANG module has to be installed first. This is normally accomplished as a part of package installation.
When installing DNS Probe manually, the following command has to be run in order to install the YANG module to Sysrepo data store:

.. code-block:: shell

   sysrepoctl -i /path/to/cznic-dns-probe.yang

Configuration parameters, RPC operations, state data and statistics defined in the YANG module are described in detail in the following sections.

Configuring DNS Probe via Sysrepo
=================================

.. Note:: Configuration interfaces are somewhat spartan and rudimentary in the current version of DNS Probe. More user-friendly approaches are being worked on.

After installation, Sysrepo configuration data store is populated with default values of all parameters that
are defined in the YANG module *cznic-dns-probe*.

The contents of the configuration data store can be manipulated using the **sysrepocfg** utility. For example,
the command

.. code-block:: shell

   sysrepocfg -E vim -m cznic-dns-probe

opens the `Vim <https://www.vim.org/>`_ editor on an empty document. Changes to the running configuration
data store can be specified in the XML or JSON representation. For example, the following snippet

* sets up configuration for two instances of the probe -- *eth1-inst* and *eth2-inst*
* sets :ref:`interface-list` for both instances to point to correct network interface
* sets :ref:`dns-ports` list to DNS and DoT ports for instance *eth1-inst*
* sets :ref:`dns-ports` list to DoH port for instance *eth2-inst*

.. code-block:: xml

   <dns-probe xmlns="https://www.nic.cz/ns/yang/dns-probe">
     <instance>eth1-inst</instance>
     <configuration>
       <interface-list>eth1</interface-list>
       <dns-ports>53</dns-ports>
       <dns-ports>853</dns-ports>
     </configuration>
   </dns-probe>

   <dns-probe xmlns="https://www.nic.cz/ns/yang/dns-probe">
     <instance>eth2-inst</instance>
     <configuration>
       <interface-list>eth2</interface-list>
       <dns-ports>443</dns-ports>
     </configuration>
   </dns-probe>

Other possibilities for using **sysrepocfg** can be found in Sysrepo documentation or by executing

.. code-block:: shell

   sysrepocfg -h

It is also possible to configure and manage DNS Probe remotely using the standard protocols NETCONF [RFC6241]_ or RESTCONF [RFC8040]_.
For this, it is necessary to install `Netopeer2 <https://github.com/CESNET/Netopeer2>`_ server.

Configuration parameters
========================

The `instance` parameter uniquely identifies given instance of DNS Probe with its configuration in Sysrepo
data store. Instance of DNS Probe can be set at startup by the `-n` command line parameter. Only configuration
with this particular `instance` parameter will then be loaded from Sysrepo. User can configure multiple
instances of DNS Probe in Sysrepo data store like this.

If no instance is specified by the `-n` command line parameter, a special *default* instance is loaded
from Sysrepo with default values for all configuration parameters.

When editing configuration for a given instance, user only has to specify options differing from default
values as the remaining options will be automatically filled by default values by Sysrepo.

All YANG data nodes representing configuration parameters of given instance appear in the `/cznic-dns-probe:dns-probe[instance='<instance>']/configuration` container.

Configuration parameters are of two basic types:

*static*
   Such parameters can be modified in the Sysrepo data store but the changes will not take effect until DNS Probe is restarted.

*dynamic*
   Changes to such parameters take effect immediately, no restart is needed.

.. _static-conf-par:

Static configuration parameters
--------------------------------

This section lists all static configuration parameters in alphabetical order.

anonymize-ip
^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/ip-anonymization/anonymize-ip``
:default: **false**

If this flag is true, client IP addresses in exported data (Parquet or C-DNS, NOT optional PCAPs) will be anonymized using Crypto-PAn prefix-preserving algorithm.

asn-maxmind-db
^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/asn-maxmind-db``
:default: empty

Path to Maxmind ASN database. If this option is set to a valid database file, the ``asn`` implementation field in exported Parquets or C-DNS will be filled with Autonomous System Number (ASN) based on client's IP address.

cdns-fields
^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/cdns-fields``
:default: all fields

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It is a bit set that determines which fields from the C-DNS schema defined in [RFC8618]_ will be included in the exported transaction records.

.. _cdns-records-per-block:

cdns-records-per-block
^^^^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/cdns-records-per-block``
:default: 10000

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It specifies the maximum number of exported DNS transaction records per one C-DNS block, see `Section 7.3.2 <https://tools.ietf.org/html/rfc8618#section-7.3.2>`_ in [RFC8618]_.

The default value of 10000 corresponds to the recommendation in `Appendix C.6 <https://tools.ietf.org/html/rfc8618#appendix-C.6>`_ of [RFC8618]_.

concurrent-connections
^^^^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/tcp-table/concurrent-connections``
:default: 131072

The value of this parameter must be a power of 2. It specifies the maximum number of TCP connections that DNS Probe can handle at any given time, which in turn affects the size of in-memory data structures allocated for keeping the status of TCP connections.

The default value of 131072 (2^17) was determined experimentally – it takes into account the default value for :ref:`max-transactions` and the current common ratio of DNS traffic over UDP and TCP. It is recommended to adjust this parameter to actual traffic circumstances in order to optimize memory consumption.

coremask
^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/coremask``
:default: 7

Bitmask indicating which CPU cores should DNS Probe use. At least 3 CPU cores are needed, see :ref:`dns-probe-arch`. Setting more than 3 cores in the bitmask will spawn more worker threads that are used for processing incoming packets.

The default value of 7 indicates that DNS Probe should use the first 3 CPU cores with IDs of 0, 1 and 2.

country-maxmind-db
^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/country-maxmind-db``
:default: empty

Path to Maxmind Country database. If this option is set to a valid database file, the ``country`` field in exported Parquets or ``country-code`` implementation field in exported C-DNS will be filled with ISO 3166-1 country code based on client's IP address.

dnstap-socket-group
^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/dnstap-socket-group``
:default: empty

Name of existing user group under which to create dnstap sockets specified in :ref:`dnstap-socket-list`. By default the group of probe's process is used.

.. _dnstap-socket-list:

dnstap-socket-list
^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/dnstap-socket-list``
:default: empty

List of unix sockets to process dnstap data from in addition to sockets passed with '-d'
command line parameter.

.. _encryption:

encryption
^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/ip-anonymization/encryption``
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

.. _export-format:

export-format
^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/export-format``
:default: ``parquet``

This value indicates the format for exporting records about
DNS transactions. Two options are currently supported:

``parquet``
   `Apache Parquet <https://parquet.apache.org/>`_ columnar format

``cdns``
   Compacted-DNS (C-DNS) [RFC8618]_.

file-compression
^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/file-compression``
:default: **true**

If this flag is true, the exported Parquet or C-DNS files will be
compressed with GZIP. C-DNS export files are compressed in their
entirety, and suffix ``.gz`` is appended to their names. Parquet
format implementation used by DNS Probe compresses only selected parts
of the file, and there is no ``.gz``.

.. _interface-list:

interface-list
^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/interface-list``
:default: empty

List of network interfaces to process traffic from in addition to interfaces passed with `-i`
command line parameter.

Fill either with NIC interface names such as `eth0` or alternatively with PCI IDs when using DPDK backend
and binding NICs to DPDK-compatible drivers manually.

key-path
^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/ip-anonymization/key-path``
:default: ``key.cryptopant``

Path (including file's names) to the file with encryption key that is to be used for client IP anonymization if enabled.
If the file doesn't exist, it is generated by the probe.

The key needs to be compatible with the encryption algorithm set in the :ref:`encryption` option. User should generate
the key using `scramble_ips` tool installed by the cryptopANT dependency like this:

.. code:: shell

   scramble_ips --newkey --type=<encryption> <key_file>

knot-socket-count
^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/knot-socket-count``
:default: ``0``

Number of Knot interface sockets to create in :ref:`knot-socket-path` directory.
Might get overriden by `-k` comand line parameter.

.. _knot-socket-path:

knot-socket-path
^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/knot-socket-path``
:default: ``/tmp``

Path to directory in which to create unix sockets for reading Knot interface data.
Might get overriden by `-s` command line parameter.

.. _location:

location
^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/location``
:default: ``local``

Location for the storage of exported DNS records. Determines if data is stored to local file or sent
to remote server.

log-file
^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/log-file``
:default: empty

Path (including file's name) to log file for storing probe's logs (e.g. `/var/log/dns-probe.log`).
Might get overriden by `-l` command line parameter.

By default logs are written to `stdout`.

.. _max-transactions:

max-transactions
^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/transaction-table/max-transactions``
:default: 1048576

The value of this parameter must be a power of 2. It specifies the maximum number of pending DNS transactions that DNS Probe can handle at any given time, which in turn affects the size of in-memory transaction table.

The default value of 1048576 (2^20) was determined experimentally – it should suffice for handling DNS traffic at the line rate of 10 Gb/s. It is recommended to adjust this parameter to actual traffic circumstances in order to optimize memory consumption.

.. _pcap-list:

pcap-list
^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/pcap-list``
:default: empty

List of PCAPs to process in addition to PCAPs passed with `-p` command line parameter.

raw-pcap
^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/raw-pcap``
:default: **false**

Indicates RAW PCAPs as input in :ref:`pcap-list` or from command line with `-p` parameter. Might get
overriden by `-r` command line parameter.

MUST be set to **false** if :ref:`interface-list` or `-i` command line parameter are used.

remote-ca-cert
^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/remote-ca-cert``
:default: empty

Path (including file's name) to the CA certificate against which the remote server's certificate
will be authenticated during TLS handshake. Will be used if :ref:`location` is set to ``remote``.

By default server's certificate will be authenticated against OpenSSL's default directory with CA certificates.

.. _dynamic-conf-par:

Dynamic configuration parameters
--------------------------------

This section lists all dynamic configuration parameters in alphabetical order.

.. _cdns-blocks-per-file:

cdns-blocks-per-file
^^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/cdns-blocks-per-file``
:default: 0

This parameter takes effect only if ``cdns`` is set in :ref:`export-format`. It specifies the maximum number of C-DNS blocks written to one exported file (see `Section 7.3.2 <https://tools.ietf.org/html/rfc8618#section-7.3.2>`_ in [RFC8618]_). If this limit is reached, the export file is closed and a new one started.

The default value of 0 means that there is no limit.

.. _dns-ports:

dns-ports
^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/dns-ports``
:default: 53

List of transport protocol port numbers that DNS Probe will check for in
incoming packets to recognize DNS traffic.

The default value of 53 is the standard DNS server port as defined
in [RFC1035]_.

.. _export-dir:

export-dir
^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/export-dir``
:default: ``.``

Path to an existing local directory for storing export files.

The default value of ``.`` means that DNS Probe will use the current working directory from which it was launched.

.. _file-name-prefix:

file-name-prefix
^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/file-name-prefix``
:default: ``dns_``

This option represents the prefix that is prepended to the name of all
files exported by DNS Probe.

file-size-limit
^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/file-size-limit``
:default: 0

This parameter specifies the maximum size of export file in megabytes. It is currently used only for rotating files of the auxiliary PCAP export described in :ref:`pcap-export` below, because estimating the size of data in Parquet or C-DNS files is quite tricky if not impossible.

The default value of 0 means that the export file will never be closed just based on its size.

.. _ipv4-allowlist:

ipv4-allowlist
^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/ipv4-allowlist``
:default: empty

List of allowed IPv4 addresses to process traffic from.

By default all IPv4 addressess are allowed.

ipv4-denylist
^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/ipv4-denylist``
:default: empty

List of IPv4 addresses from which to NOT process traffic.

By default all IPv4 addresses are allowed.

If :ref:`ipv4-allowlist` is not empty this configuration item doesn't have any effect.

.. _ipv6-allowlist:

ipv6-allowlist
^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/ipv6-allowlist``
:default: empty

List of allowed IPv6 addresses to process traffic from.

By default all IPv6 addresses are allowed.

ipv6-denylist
^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/ipv6-denylist``
:default: empty

List of IPv6 addresses from which to NOT process traffic.

By default all IPv6 addresses are allowed.

If :ref:`ipv6-allowlist` is not empty this configuration item doesn't have any effect.

match-qname
^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/transaction-table/match-qname``
:default: **false**

By default, the 5-tuple of source and destination IP address, source and destination port, and transport protocol is used to match a DNS query with the corresponding response. If this parameter is set to **true** the DNS QNAME (if present) is used as a secondary key for matching queries with responses.

moving-avg-window
^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/statistics/moving-avg-window``
:default: 300

Time window in seconds for which to compute moving average of *queries-per-second** statistics.

Window can be set in interval from 1 second to 1 hour. By default, a 5 minute window is set.

.. _parquet-records-per-file:

parquet-records-per-file
^^^^^^^^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/parquet-records-per-file``
:default: 5000000

This parameter takes effect only if ``parquet`` is set in :ref:`export-format`. It specifies the maximum number of DNS records per one exported Parquet file. If this limit is reached, the exported file is closed and a new one started.

Parquet format buffers DNS records for one file in memory and then writes them to the file all at once. This can mean significant requirements for RAM as each worker thread buffers data for its own file.

The default value was determined experimentally – the size of an uncompressed export file should then be as close to 128 MB as possible, which is ideal for Hadoop. However, in-memory representation of an exported file of this size can take as much as 1-1.5 GB of RAM!

.. _pcap-export:

pcap-export
^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/pcap-export``
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

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/transaction-table/query-timeout``
:default: 1000

This parameter specifies the time interval in miliseconds after which the query or response is removed from the transaction table if no corresponding response or query is observed.

.. _remote-ip-address:

remote-ip-address
^^^^^^^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/remote-ip-address``
:default: ``127.0.0.1``

IP address for remote export of the DNS records. Will be used if :ref:`location` is set to ``remote``.

.. _remote-port:

remote-port
^^^^^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/remote-port``
:default: 6378

Tranport protocol port number for remote export of the DNS records. Will be used if :ref:`location` is set to ``remote``.

timeout
^^^^^^^

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/export/timeout``
:default: 0

This paremeter specifies the time interval (in seconds) after which a newly opened export file will be closed and another one started.

The default value of 0 means that the export file will never be
closed just based on its age. It can however be closed based on other
configuration options described above (:ref:`cdns-blocks-per-file` and
:ref:`parquet-records-per-file`).

timeout
^^^^^^^       

:data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/configuration/tcp-table/timeout``
:default: 60000

This parameter specifies the time interval in miliseconds after which the TCP connection is removed from the tcp table if no new traffic is observed.

Statistics
==========

DNS Probe collects a number of basic run-time statistics and state data. Sysrepo makes the following items available in the ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics`` container:

**processed-packets**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/processed-packets``

   Overall number of all packets processed by DNS Probe.

**processed-transactions**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/processed-transactions``

   Overall number of DNS transactions processed by DNS Probe.

**exported-records**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/exported-records``

   Overall number of DNS records exported by DNS Probe.

**queries-per-second-ipv4**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/queries-per-second-ipv4``

   Number of IPv4 DNS queries processed per second.

**queries-per-second-ipv6**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/queries-per-second-ipv6``

   Number of IPv6 DNS queries processed per second.

**queries-per-second-tcp**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/queries-per-second-tcp``

   Number of TCP DNS queries processed per second.

**queries-per-second-udp**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/queries-per-second-udp``

   Number of UDP DNS queries processed per second.

**queries-per-second**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/queries-per-second``

   Overall number of DNS queries processed per second.

**pending-transactions**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/pending-transactions``

   Number of queries and responses currently waiting in transaction table to be matched.

**exported-pcap-packets**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/statistics/exported-pcap-packets``

   Overall number of packets exported to PCAP.

RPC operations
==============

Currently, only one RPC operation is implemented in Sysrepo:

.. _rpc-restart:

**restart**

   :data node: ``/cznic-dns-probe:dns-probe[instance='<instance>']/restart``

   Restart the probe and apply changes in static configuration.
