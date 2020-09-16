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
   * - **0.6**
     - **1.4**
     - :doc:`YANG module <YANGmodule>`
     - Fix default value for number of concurrent connections in tcp-table
   * -
     - **1.3**
     - :doc:`Exported Data Schema <ExportedDataSchema>`
     - Update pattern of exported file's names
   * -
     - **1.2**
     - :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`YANG module <YANGmodule>`
     - Add TCP RTT item to exported data schema
   * -
     - **1.1**
     - :doc:`Exported Data Schema <ExportedDataSchema>`
     - Domainname field in export schema is in lowercase
   * -
     - **1.0**
     - :doc:`Architecture <Architecture>`, :doc:`Configuration <Configuration>`, :doc:`Installation <Installation>`,
       :doc:`Exported Data Schema <ExportedDataSchema>`, :doc:`Data Collector <DataCollector>`,
       :doc:`YANG module <YANGmodule>`, :doc:`Manual pages <manpages/dp-collector>`
     - Add secure export to remote location
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`YANG module <YANGmodule>`
     - Fix description of "export-dir" item in YANG module from static to dynamic configuration
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`YANG module <YANGmodule>`, :doc:`Running DNS Probe <Running>`
     - Integrate probe's command line parameters to Sysrepo configuration
   * -
     -
     - :doc:`Installation <Installation>`
     - Update instructions for installation from packages
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`Installation <Installation>`, :doc:`YANG module <YANGmodule>`
     - Add client IP anonymization
   * -
     -
     - :doc:`Configuration <Configuration>`, :doc:`YANG module <YANGmodule>`
     - Add IP filtering to YANG module
   * - **0.5**
     - **1.1**
     - :doc:`index <index>`, :doc:`Installation <Installation>`, :doc:`YANG module <YANGmodule>`,
       :doc:`Record Of Changes <RecordOfChanges>`
     - Update GitLab URLs
   * -
     - **1.0**
     - ALL
     - Initial release.
