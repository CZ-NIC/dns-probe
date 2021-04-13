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
   * - **0.9.0**
     - **1.1**
     - :doc:`Exported Data Schema <ExportedDataSchema>`
     - Change precision of tcp_hs_rtt field to microseconds
   * -
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
