*****************
Running DNS Probe
*****************

It is recommended to run DNS Probe as a `systemd <https://www.freedesktop.org/wiki/Software/systemd/>`_ service. Alternatively, it is possible to start it from the command line using shell scripts that are part of the DNS Probe distribution. These shell scripts can also be used as a basis for integration with other init systems.

Running as systemd service
==========================

Installation packages include a *systemd* unit file
``dns-probe-<BACKEND>.service``, where ``<BACKEND>`` is either ``af``
or ``dpdk`` depending on the :term:`backend` that the package installs.

The *systemd* service can be run like this:

.. code:: shell

    sudo systemctl start dns-probe-<BACKEND>.service

Other ``systemctl`` subcommands can be used to stop, enable or restart the service.

By default the *systemd* service reads packets from loopback interface. To make the service
read packets from different network interface the unit file should be modified like this:

.. code:: shell

    sudo systemctl edit --full dns-probe-<BACKEND>.service

This command copies the unit file to ``/etc/systemd/system/dns-probe-<BACKEND>.service`` and opens it
in default text editor. The line

::

    ExecStart=/path/to/dns-probe-<BACKEND> -i lo -l /var/log/dns-probe-<BACKEND>.log

should then be modified to include the desired network interface from which to read packets.
After the modification is done the *systemd* service can be started as usual.

Running from command line
=========================

For each :term:`backend`, one binary program and one shell script is installed. Their names are shown in :numref:`exec-table`.

.. _exec-table:

.. table:: Installed binaries and wrapper scripts

   +---------+------------------+--------------+
   |Backend  |Binary program    |Wrapper script|
   +=========+==================+==============+
   |AF_PACKET|``dns-probe-af``  |``dp-af``     |
   +---------+------------------+--------------+
   |DPDK     |``dns-probe-dpdk``|``dp-dpdk``   |
   +---------+------------------+--------------+

The binary programs accept several command-line options described in their :ref:`manual pages <manpages>`.

The wrapper shell scripts accept the same options as the corresponding backend binary, and start the binary with these options. If the running binary program receives the :ref:`restart <rpc-restart>` operation through Sysrepo, it exits with return code 1. The wrapper script then starts the same binary again.

For other codes returned by the binary, the wrapper script just exits and returns the same code.

DPDK backend
============

For running DNS Probe with the DPDK backend, a portion of memory with huge
pages has to be allocated. This is done in two steps, both requiring root privileges:

1. mount the huge pages file system
2. allocate huge pages

On some systems, the huge pages FS is mounted automatically, so step #1 can be omitted. It can be checked by running the command

.. code:: shell

   mount | grep -E ^hugetlbfs

If the command prints something similar to

::
 
   hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)

then the huge pages FS is already mounted.

The following script automatically mounts huge pages file system (if
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

Network cards used with the DPDK backend have to be bound to
DPDK-compatible drivers. The easier way of doing this is to run
``dns-probe-dpdk`` or ``dp-dpdk`` with the ``-i`` parameter(s)
specifying the NIC name such as ``eth0``. DNS probe will then attempt
to automatically bind these interfaces to the ``uio_pci_generic``
driver and, when it exits, it will bind the interfaces back to their
original driver. For this to work, the ``uio_pci_generic`` module
needs to be loaded manually like this:

.. code:: shell

    sudo modprobe uio_pci_generic

The other way is to bind the NICs to DPDK-compatible drivers manually
before running DNS Probe. In this case, the NICs have to
be identified by their PCI IDs in ``-i`` options. Details about binding network interfaces manually are described in the `DPDK documentation <https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html>`_.
