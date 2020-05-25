=========
DNS Probe
=========

This project contains implementation of probe for collection of DNS
information from scanned requests and responses. The probe can export
collected data into two formats - Parquet and C-DNS. Both formats are
stored locally on probe's disks. For future release it is planned to
export data directly over network to centralized collector.

DNS probe supports analyzing TCP and UDP traffic. The probe currently
implements two ways how to get analyzed packets. The first is with DPDK
backend. This backend allows to read packets directly from NIC and can
process the whole network traffic. Disadvantage of this approach is that
application will seize the NIC and doesn't allow it to be used by OS.
The second available backend is standard Linux's AF packet interface.
This approach is significantly slower then DPDK one but allows monitored
interface to be used by other applications. The selection of which
backend will be used is made during the :ref:`compilation
phase <compilationPhase>`.


.. toctree::
   :caption: Sections
   :name: dns-probe-toc-sections
   :maxdepth: 1

   Configuration
   Installation
   Running
