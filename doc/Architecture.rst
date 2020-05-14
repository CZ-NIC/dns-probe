DNS probe's architecture
========================

DNS probe is a high-speed DNS monitoring software developed by CZ.NIC in
cooperation with the Faculty of Information Technology, VUT Brno. The
probe provides scalable performance with the use of configurable amount
of packet processing threads and uniform packet distribution using
`RSS <https://www.kernel.org/doc/Documentation/networking/scaling.txt>`__.
The probe is highly configurable either locally or from remote location
thanks to the use of `Sysrepo <https://www.sysrepo.org/>`__ datastore.
The probe's configuration options are described in `YANG module
description <https://gitlab.labs.nic.cz/adam/dns-probe/-/wikis/YANG-module-description>`__
Wiki page.

DNS probe's architecture visualized in figure below can be separated
into three parts - worker threads, configuration thread and export
thread. Each thread of the DNS probe is locked to a different logical
core of the CPU. Therefore the probe needs a CPU with at least three
logical cores to run successfully. There's always one configuration
thread, one export thread and at least one worker thread. The amount of
spawned worker threads can be configured in Sysrepo by the ``coremask``
option.

.. figure:: uploads/11b2144a7a14fcef69e2eab48d3053ad/dns_probe_architecture.png
   :alt: dns\_probe\_architecture

   dns\_probe\_architecture
Configuration thread
--------------------

This is the master thread of the DNS probe. The configuration thread
loads the configuration from Sysrepo datastore, initializes the network
ports for packet capture and spawns the worker threads and an export
thread. It also locks those threads to CPU's logical cores. For each
spawned thread the configuration thread also creates a two-way
communication link for sending configuration changes to the threads and
for listening for messages from the threads.

After the initial configuration is done the thread polls for changes to
the Sysrepo configuration and for messages on the communication links.
If a worker or an export thread encounters an error it sends a message
through the communication link to the configuration thread and the
configuration thread is then responsible for shutting down the rest of
the probe. If there's a change of probe's configuration in the Sysrepo
datastore the configuration thread is alerted and it then distributes
the updated configuration to the rest of the probe's threads. It is also
responsible for periodic aggregation of the runtime statistics from all
threads and sending them to the Sysrepo datastore. If time based
rotation of the output is enabled in probe's configuration the
configuration thread takes care of the periodic timer and alerts all
threads when it's time to rotate the output.

Network ports initialization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The configuration thread initializes one RX queue on network port per
each spawned worker thread. The worker threads then read packets only
from their RX queue. The distribution of packets to the RX queues is
done using
`RSS <https://www.kernel.org/doc/Documentation/networking/scaling.txt>`__.
A hash is calculated for each incoming packet from a 5-tuple of source
IP address, destination IP address, source port, destination port and
transport protocol. The packet is then assigned to one of the RX queues
based on this hash value.

The DNS probe supports two backends for reading packets from network
ports - AF\_PACKET sockets and DPDK framework.

AF\_PACKET sockets
''''''''''''''''''

The AF\_PACKET sockets are used for packet processing by the
``dns-probe-af`` binary and by the ``dp-af`` script. The `AF\_PACKET
v3 <https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt>`__
is used with ring buffers shared between kernel and user space. Each RX
queue allocates its own ring buffer to which packets are read from the
network port. The ring buffer is separated into blocks. Kernel reads a
batch of packets to the ring buffer's block and then sets the block's
flag indicating that the ownership of the block transfers from kernel to
user space application (DNS probe). The probe then reads the packets
from the block, processes them and when it's done the probe unsets the
block's flag to give the ownership of the block back to the kernel.

DPDK
''''

The `DPDK <https://www.dpdk.org/>`__ framework is used for packet
processing by the ``dns-probe-dpdk`` binary and by the ``dp-dpdk`` and
``ddp-bind`` scripts. This alternative for reading packets bypasses the
kernel and reads the packets from network port directly to the user
space application. This makes reading the packets several times faster
than with AF\_PACKET sockets. To ensure a proper distribution of packets
to the RX queues including packets from both sides of the same flow
going to the same RX queue we use a `special
key <https://www.ndsl.kaist.edu/~kyoungsoo/papers/TR-symRSS.pdf>`__ for
the RSS hash function in DPDK.

Worker threads
--------------

Worker threads execute the main packet processing pipeline of the probe.
They read packets from RX queues, parse them and create DNS records.
These DNS records are then matched in Transaction table to form a single
record for each pair of DNS request and response. After accumulating
enough records the worker thread then sends them through a ring buffer
to the export thread.

DNS probe handles DNS traffic both in UDP and TCP. Since the probe does
all the packet parsing itself it implements a slightly modified version
of `TCP finite machine <https://tools.ietf.org/html/rfc793#page-23>`__
and a reorder buffer to properly reconstruct TCP streams and extract DNS
traffic from it. The DNS data itself is parsed by the probe and certain
items are extracted from it to form a request or response DNS record.
This DNS record is then inserted to the Transaction table.

Transaction table is a hash table for matching DNS requests with
responses. The matching is done based on a 6-tuple of source IP address,
destination IP address, source port, destination port, transport
protocol and DNS ID. Optionally the user can enable additional matching
based on the QNAME field from DNS question section. If a request is
matched with a response these two records are merged into one and
buffered for output.

Once enough DNS records is buffered on the worker thread or time based
output rotation is triggered the worker thread sends the object with
buffered DNS records to the export thread via a ring buffer.

Export thread
-------------

Export thread handles the export of DNS records to output file.
Currently the probe supports export only to a local file. Direct export
to a remote location via encrypted network transfer is planned for a
future release.

The export thread has a ring buffer to each of the worker threads.
Through these ring buffers it accepts DNS records from worker threads
and writes them to output. The output can be rotated based on the amount
of data written to the current output or on the amount of time elapsed
since the start of the current output. These parameters can be
configured by user in the Sysrepo datastore.

The output data can be exported in one of two formats -
`Parquet <https://parquet.apache.org/>`__ or
`C-DNS <https://tools.ietf.org/html/rfc8618>`__. This can also be
configured in the Sysrepo datastore. The exported data can be optionally
compressed with GZIP. While the current output file is open it ends with
a ``.part`` sufix. Once the output file is finished the ``.part`` sufix
is removed. The Parquet output files end with the sufix ``.parquet``.
The C-DNS output files end with the ``.cdns`` sufix or with ``.cdns.gz``
if they are compressed with GZIP. The Parquet output files don't have
the ``.gz`` sufix when compression is enabled because the Parquet format
doesn't compress the whole file but uses the compression internally only
on certain parts of it.
