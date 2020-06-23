********
Overview
********

DNS Probe is a high-speed DNS monitoring software developed as a part of the `ADAM <https://adam.nic.cz/en/>`_ project by CZ.NIC Laboratories in cooperation with Brno University of Technology, Faculty of Information Technology.

DNS Probe is able to extract DNS packets either from live network traffic or `pcap <https://en.wikipedia.org/wiki/Pcap>`_ traces, match client queries with the corresponding server responses and export consolidated records about individual DNS transactions.

DNS Probe is typically deployed together with a DNS server (autoritative or recursive), capturing and processing the traffic received and sent by the server.

Main features
=============

* scalable performance with a configurable number of packet processing threads and uniform packet distribution using `RSS <https://www.kernel.org/doc/Documentation/networking/scaling.txt>`_

* packet capture via either raw socket (AF_PACKET) or, alternatively, `DPDK <https://www.dpdk.org>`_

* DNS queries and responses are extracted from both UDP and TCP

* configurable export of data about DNS transactions in C-DNS [RFC8618]_ or `Apache Parquet <https://parquet.apache.org>`_ formats

* integrated configuration and management via `Sysrepo <https://www.sysrepo.org>`_; this also includes the possibility of using the standard NETCONF protocol [RFC6241]_


License
=======

DNS Probe is licensed under the `GNU General Public License <https://www.gnu.org/copyleft/gpl.html>`_ version 3 or (at your option) any later version.
The full text of the license is available in the COPYING file distributed with source code.
