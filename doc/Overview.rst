********
Overview
********

DNS Probe is a high-speed DNS monitoring software developed as a part of the `ADAM <https://adam.nic.cz/en/>`_ project by CZ.NIC Laboratories in cooperation with Brno University of Technology, Faculty of Information Technology.

DNS Probe is able to extract DNS packets from live network traffic, `pcap <https://en.wikipedia.org/wiki/Pcap>`_ traces, `dnstap <https://dnstap.info/>`_ data supplied by unix sockets or `Knot interface <https://www.knot-dns.cz/docs/3.0/html/modules.html#probe-dns-traffic-probe>`_, match client queries with the corresponding server responses and export consolidated records about individual DNS transactions.

DNS Probe is typically deployed together with a DNS server (autoritative or recursive), capturing and processing the traffic received and sent by the server.

Main features
=============

* scalable performance with a configurable number of packet processing threads and uniform packet distribution using `RSS <https://www.kernel.org/doc/Documentation/networking/scaling.txt>`_

* packet capture via either raw socket (AF_PACKET) or, alternatively, `DPDK <https://www.dpdk.org>`_

* DNS queries and responses are extracted from both UDP and TCP

* configurable export of data about DNS transactions in C-DNS [RFC8618]_ or `Apache Parquet <https://parquet.apache.org>`_ formats

* configuration via `Sysrepo <https://www.sysrepo.org/>`_ data store; provides remote configuration management and export of runtime statistics


License
=======

DNS Probe is licensed under the `GNU General Public License <https://www.gnu.org/copyleft/gpl.html>`_ version 3 or (at your option) any later version.
The full text of the license is available in the COPYING file distributed with source code.
