*****************
Record of Changes
*****************

Overview of changes in documentation from previous editions.
For changes in software see `version descriptions <https://gitlab.nic.cz/adam/dns-probe/-/tags>`_.

.. tabularcolumns:: |p{0.075\textwidth}|p{0.075\textwidth}|p{0.25\textwidth}|p{0.575\textwidth}|

.. list-table::
   :header-rows: 1
   :widths: 8, 8, 26, 58

   * - Version
     - Edition
     - Segment
     - Change description
   * - **1.6.0**
     - **1.0**
     - :doc:`Architecture <Architecture>`, :doc:`Configuration <Configuration>`,
       :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Installation <Installation>`,
       :doc:`Overview <Overview>`, :doc:`Default YAML file <YAMLfile>`
     - Add option to export DNS logs in JSON format
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`Default YAML file <YAMLfile>`
     - Add option to force IP address family for connections to Apache Kafka
   * - **1.5.0**
     - **1.0**
     - :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Default YAML file <YAMLfile>`
     - Add export of 'policy-action' and 'policy-rule' fields in C-DNS output
   * -
     -
     - :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Default YAML file <YAMLfile>`
     - Add export of 'user-id' field in C-DNS output
   * - **1.4.0**
     - **1.0**
     - :doc:`Architecture <Architecture>`, :doc:`Configuration <Configuration>`,
       :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Installation <Installation>`,
       :doc:`Default YAML file <YAMLfile>`
     - Add export of data and run-time statistics to Apache Kafka
   * -
     -
     - :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Default YAML file <YAMLfile>`
     - Add option to export full Authority RRs of responses to C-DNS files
   * -
     -
     - :doc:`Installation <Installation>`
     - Add libsystemd as dependency
   * -
     -
     - :doc:`Installation <Installation>`
     - Update supported Linux distributions
   * -
     -
     - :doc:`Exported Data Schema <ExportedDataSchema>`
     - Fill "edns_other" field in Parquet export
   * - **1.3.0**
     - **1.0**
     - :doc:`Configuration <Configuration>`, :doc:`Exported Data Schema <ExportedDataSchema>`,
       :doc:`Default YAML file <YAMLfile>`
     - Add option to export full Answer and Additional RRs of responses to C-DNS files
   * - **1.2.0**
     - **1.0**
     - :doc:`Configuration <Configuration>`, :doc:`Exported Data Schema <ExportedDataSchema>`,
       :doc:`Default YAML file <YAMLfile>`
     - Add options to configure backup remote storage
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`Default YAML file <YAMLfile>`
     - Add traffic filtering by IP prefix
   * - **1.1.2**
     - **1.0**
     - :doc:`Installation <Installation>`
     - Update list of supported Linux distributions
   * - **1.1.0**
     - **1.0**
     - :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Default YAML file <YAMLfile>`
     - Add export of source IPv4 entropy to run-time statistics
   * - **1.0.0**
     - **1.0**
     - :doc:`Installation <Installation>`
     - Add package installation instructions for RPM based distributions and Arch
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`Exported Data Schema <ExportedDataSchema>`,
       :doc:`Default YAML file <YAMLfile>`
     - Add more granular export of run-time statistics
   * - **0.12.2**
     - **1.0**
     - :doc:`Exported Data Schema <ExportedDataSchema>`
     - Add table describing all exported run-time statistics
   * - **0.12.0**
     - **1.1**
     - :doc:`Configuration <Configuration>`, :doc:`Exported Data Schema <ExportedDataSchema>`
     - Fix typo: run-time statistics have `remote-ip` option, not `remote-ip-address`
   * -
     - **1.0**
     - :doc:`Architecture <Architecture>`, :doc:`Configuration<Configuration>`,
       :doc:`Data Collector <DataCollector>`, :doc:`Exported Data Schema <ExportedDataSchema>`,
       :doc:`Overview <Overview>`, :doc:`References <References>`, :doc:`Default YAML file <YAMLfile>`
     - Add optional export of run-time statistics in JSON format
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`Default YAML file <YAMLfile>`
     - Add configuration option to configure moving average window for run-time statistics
   * - **0.11.3**
     - **1.0**
     - :doc:`Installation <Installation>`
     - Add Debian 11 package information
   * - **0.11.0**
     - **1.0**
     - :doc:`Architecture <Architecture>`, :doc:`Configuration <Configuration>`,
       :doc:`Installation <Installation>`, :doc:`Overview <Overview>`,
       :doc:`Default YAML file <YAMLfile>`, :doc:`AF manual pages <manpages/dns-probe-af>`,
       :doc:`DPDK manual pages <manpages/dns-probe-dpdk>`
     - Add Knot interface as another input data format
   * - **0.10.0**
     - **1.0**
     - :doc:`Exported Data Schema <ExportedDataSchema>`
     - Change precision of tcp_hs_rtt field to microseconds
   * - **0.9.0**
     - **1.0**
     - :doc:`Configuration <Configuration>`, :doc:`Default YAML file <YAMLfile>`
     - Add configuration option for setting user group on dnstap sockets
   * - **0.8.0**
     - **1.0**
     - :doc:`Configuration <Configuration>`, :doc:`Exported Data Schema <ExportedDataSchema>`,
       :doc:`Default YAML file <YAMLfile>`
     - Update ASN, Country Code and RTT fields in exported data schema
   * -
     -
     - :doc:`Installation <Installation>`
     - Add libmaxminddb as dependency
   * -
     -
     - :doc:`Architecture <Architecture>`, :doc:`Configuration <Configuration>`,
       :doc:`Installation <Installation>`, :doc:`Overview <Overview>`,
       :doc:`Default YAML file <YAMLfile>`, :doc:`AF manual pages <manpages/dns-probe-af>`,
       :doc:`DPDK manual pages <manpages/dns-probe-dpdk>`
     - Add dnstap as another input data format
   * - **0.7.0**
     - **1.0**
     - :doc:`Architecture <Architecture>`, :doc:`Configuration <Configuration>`,
       :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Glossary <Glossary>`,
       :doc:`Installation <Installation>`, :doc:`Overview <Overview>`, :doc:`Running DNS Probe <Running>`,
       :doc:`Default YAML file <YAMLfile>`, :doc:`dns-probe-af manpage <manpages/dns-probe-af>`,
       :doc:`dns-probe-dpdk manpage <manpages/dns-probe-dpdk>`
     - Replace Sysrepo with YAML file to configure DNS Probe
   * -
     -
     - YANG module
     - Fix default value for number of concurrent connections in tcp-table
   * -
     -
     - :doc:`Exported Data Schema <ExportedDataSchema>`
     - Update pattern of exported file's names
   * -
     -
     - :doc:`Exported Data Schema <ExportedDataSchema>`, YANG module
     - Add TCP RTT item to exported data schema
   * - **0.6.0**
     - **1.1**
     - :doc:`Exported Data Schema <ExportedDataSchema>`
     - Domainname field in export schema is in lowercase
   * -
     - **1.0**
     - :doc:`Architecture <Architecture>`, :doc:`Configuration <Configuration>`, :doc:`Installation <Installation>`,
       :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Data Collector <DataCollector>`,
       YANG module, :doc:`Manual pages <manpages/dp-collector>`
     - Add secure export to remote location
   * -
     -
     - :doc:`Configuration <Configuration>`, YANG module
     - Fix description of "export-dir" item in YANG module from static to dynamic configuration
   * -
     -
     - :doc:`Configuration <Configuration>`, YANG module, :doc:`Running DNS Probe <Running>`
     - Integrate probe's command line parameters to Sysrepo configuration
   * -
     -
     - :doc:`Installation <Installation>`
     - Update instructions for installation from packages
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`Installation <Installation>`, YANG module
     - Add client IP anonymization
   * -
     -
     - :doc:`Configuration <Configuration>`, YANG module
     - Add IP filtering to YANG module
   * - **0.5.0**
     - **1.1**
     - :doc:`index <index>`, :doc:`Installation <Installation>`, YANG module,
       :doc:`Record Of Changes <RecordOfChanges>`
     - Update GitLab URLs
   * -
     - **1.0**
     - ALL
     - Initial release.
