*****************
Running DNS Probe
*****************

Running as systemd service
==========================

Installation from packages includes a *systemd* service
``dns-probe-<BACKEND>@.service`` where ``<BACKEND>`` is either ``af`` or
``dpdk`` depending on the package you installed.

The *systemd* service can be run like this:

.. code:: shell

    sudo systemctl start dns-probe-<BACKEND>@<FILE>.service

To stop, enable or restart the service use the appropriate ``systemctl``
subcommands.

The service takes a parameter ``<FILE>`` which is a name of
configuration file located at ``/etc/dns-probe-<BACKEND>/<FILE>.conf``
that contains command line parameters for DNS Probe instance. Without
this file the *systemd* service will fail. Installation from packages
supplies a default configuration file at
``/etc/dns-probe-<BACKEND>/probe.conf`` which looks like this:

::

    DAEMON_ARGS="-i lo -l /var/log/dns-probe-<BACKEND>@probe.log"

This configuration file runs DNS Probe on loopback interface and saves
its logs to ``/var/log/dns-probe-<BACKEND>@probe.log`` file. The user
should change the ``-i`` parameter to a network interface that DNS Probe
should process packets from and then start the *systemd* service.

Running from command line
=========================

After installation of both backends the following executables are
created:

-  ``dns-probe-af`` (AF backend), ``dns-probe-dpdk`` (DPDK backend) -
   These binaries contain the application itself
-  ``dp-af`` (AF backend), ``dp-dpdk`` (DPDK backend) - These scripts
   take command line parameters, pass them to corresponding backend
   binary and start it. When the application receives a restart RPC
   through sysrepo the application exits with return code 1. This
   wrapper detects that code and reruns the application again. If the
   return code differs from 1 than the script exits and returns the same
   code as wrapped application.


Both backend variants support these command line parameters:

-  ``-p <PCAP>`` - Read ``<PCAP>`` file and process it into aggregated
   statistic file. This parameter can be used multiple times. Every
   usage adds one PCAP file into processing. All PCAPs are always
   processed in single thread mode.

-  ``-r`` - Marks pcaps from ``-p`` parameters as raw. Raw PCAP contains
   packets starting with IPv4 or IPv6 header. When the ``-r`` parameter
   is specified it is illegal to use ``-i`` parameter.

-  ``-i <INTERFACE>`` - Read packets from given ``<INTERFACE>``. This
   parameter can be used multiple times. Every usage adds one interface
   for processing packets. Reading from an interface has multi-threaded
   support. The format of ``<INTERFACE>`` depends on used backend.

   -  AF packet backend - The ``<INTERFACE>`` is name of network
      interface defined by kernel. List of available interfaces provides
      for example command ``ip link``.
   -  DPDK backend - The ``<INTERFACE>`` is either name of network interface
      defined by kernel or in format of PCI function ID device. For example
      ``00:1f.6`` where ``00:1f`` is PCI device and ``6`` is funcation number.
      Usually the last part specifies concrete physical interface on NIC.
      For more information about usage with DPDK backend see :ref:`dpdk-backend`.

-  ``-l <LOGFILE>`` - Redirects probe's logs to LOGFILE instead of
   standard output.

-  ``-h`` - Provides basic help.

.. _dpdk-backend:
   
DPDK backend
============

For running the DNS Probe with DPDK backend you have to allocate huge
pages. This requires root privileges and following steps:

1. Mount the huge pages file system

   -  On some system the huge pages FS is automatically allocated. You
      can check it with command ``mount | grep -E ^hugetlbfs``. If the
      command prints some row (e.g.
      ``hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)``),
      then you have huge pages FS mounted.

2. Allocate huge pages

Following script automatically mounts huge pages file system (if
necessary) and allocates 4 GB of memory for huge pages.

.. code:: shell

    # Mounts huge page file system
    if ! (mount | grep -q -E ^hugetlbfs); then # Check if the hugepages is mounted
        mkdir -p /mnt/huge
        mount -t hugetlbfs nodev /mnt/huge # Mount the hugepages
    fi

    function set_pages() {
        # Requires one argument specifying number of gigabytes allocated for hugepages.
        # If the first parameter is zero then all hugepages are deallocated.

        if [ $# -ne 1 ]; then
            echo "Required one argument"
        fi

        pagesize=$(mount | sed -Ene "/^hugetlbfs/s/.*pagesize=(.+[MG]).*/\1/p")
        if [ "$pagesize" == "2M" ]; then
            pages=$((500 * $1))
        elif [ "$pagesize" == "1G" ]; then
            pages=$1
        else
            echo "Unsupported page size of huge page filesystem." > 2
            exit 1
        fi

        sysctl vm.nr_hugepages=$pages # Allocate huge pages
    }

    set_pages 4 # Allocates 4 GB as huge pages

The DNS probe with DPDK backend needs used NIC interfaces to be bound to
DPDK compatible drivers. For binding drivers there are two options.
The easier way is to just run DNS probe normally with ``dns-probe-dpdk`` or
``dp-dpdk``. The probe will attempt to automatically bind given interfaces
to ``uio_pci_generic`` driver and when it exits it will bind the interfaces
back to their original driver. For this to work the ``uio_pci_generic`` module
needs to be loaded by user like this:

.. code:: shell

    sudo modprobe uio_pci_generic

The other way is to bind the interfaces to DPDK compatible drivers manually
before running DNS probe. In this instance the interfaces will then have to
be identified to DNS probe with their PCI IDs. How to bind the interfaces manually is
described in the `DPDK documentation <https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html>`_.