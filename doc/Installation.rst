************
Installation
************

DNS Probe can be used on Linux with kernel version at least
3.11. It also requires the system to support C++14 standard.
Installation packages are available from `OBS (openSUSE Build Service)
<https://build.opensuse.org/project/show/home:CZ-NIC:dns-probe>`_.
The following distributions are currently supported: Debian 11, 10 and 9,
Ubuntu 20.04 and 18.04.

The OBS repository also contains packages of several dependencies
that are not provided by the distribution's standard
repositories. These dependencies will be automatically installed as
pre-requisites when installing DNS Probe.

On Linux distributions that are not (yet) supported, DNS Probe has to be compiled and built from source as described below.

Installation from packages
==========================

The first two steps are to add the OBS repository for the given
distribution to the system's repository list, and add the
repository's signing key to the system keyring:

Debian 11
---------

.. code:: shell

   echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Debian_11/ /' | sudo tee /etc/apt/sources.list.d/dns-probe.list
   curl -fsSL https://download.opensuse.org/repositories/home:CZ-NIC:/dns-probe/Debian_11/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/dns-probe.gpg > /dev/null

Debian 10
---------

.. code:: shell

   echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Debian_10/ /' | sudo tee /etc/apt/sources.list.d/dns-probe.list
   curl -fsSL https://download.opensuse.org/repositories/home:CZ-NIC:/dns-probe/Debian_10/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/dns-probe.gpg > /dev/null

Debian 9
--------

.. code:: shell

   echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Debian_9.0/ /' | sudo tee /etc/apt/sources.list.d/dns-probe.list
   curl -fsSL https://download.opensuse.org/repositories/home:CZ-NIC:/dns-probe/Debian_9.0/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/dns-probe.gpg > /dev/null

Ubuntu 20.04
------------

.. code:: shell

   echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/dns-probe.list
   curl -fsSL https://download.opensuse.org/repositories/home:CZ-NIC:/dns-probe/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/dns-probe.gpg > /dev/null

Ubuntu 18.04
------------

.. code:: shell

   echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/xUbuntu_18.04/ /' | sudo tee /etc/apt/sources.list.d/dns-probe.list
   curl -fsSL https://download.opensuse.org/repositories/home:CZ-NIC:/dns-probe/xUbuntu_18.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/dns-probe.gpg > /dev/null


The remaining steps are then identical for all distributions: the repository list is
updated, and finally the DNS Probe package is installed:

.. code:: shell

   sudo apt-get update
   sudo apt-get install dns-probe-af dns-probe-dpdk dns-probe-collector

Three alternative packages are available:

* ``dns-probe-af`` is compiled with support for AF_PACKET sockets
* ``dns-probe-dpdk`` uses the DPDK framework.
* ``dns-probe-collector`` is a collector for data exported from DNS Probe via the remote export feature.

Installation from source
========================

This project has several dependencies that have to be installed
first. The following packages should be available from standard
distribution repositories:

- CMake, version at least 3.5
- Boost (C++ libraries)
- libpcap
- OpenSSL (libssl-dev)
- fstrm
- Protocol Buffers (libprotobuf-dev, protobuf-compiler)
- libmaxminddb
- libknot, version at least 3.0.6
- DPDK (only for DPDK version)

Optionally, to build this user documentation (``make doc``) or manual pages (``make man``)
one additional dependency is required:

- Sphinx

The following instructions describe how to compile DNS Probe and the
remaining dependencies. Also this approach installs all dependencies
into local directory ``dp-dep``.

Build directory
---------------

Start with creating a directory where DNS Probe and dependencies will be built and installed. Installation in a system directory, such as ``/usr/local``, is also possible.

.. code:: shell

   mkdir dp-dep
   mkdir dp-dep/build
   mkdir dp-dep/dl
   cd dp-dep
   DEP_DIR="$(pwd)"

Apache Arrow
------------

Apache Arrow packages can be installed on most distributions from Apache's own
`repositories <https://arrow.apache.org/install/>`_. Debian/Ubuntu ``libarrow-dev``
and ``libparquet-dev`` packages or their equivalents in other distributions need
to be installed for successful compilation of DNS probe.

Sysrepo
-------

`Sysrepo <https://github.com/sysrepo/sysrepo>`_ provides a
configuration and management API. It uses the `libyang
<https://github.com/CESNET/libyang>`_ library that needs to be
installed first. Currently, both these dependencies need to be installed
in their *1.x.x* versions as the probe doesn't support their newest
*2.x.x* releases yet.

.. code:: shell

   curl -L https://github.com/CESNET/libyang/archive/refs/tags/v1.0.240.tar.gz > dl/libyang.tgz
   mkdir build/libyang
   tar -xf dl/libyang.tgz -C build/libyang --strip-components=1
   mkdir -p build/libyang/build
   cd build/libyang/build
   cmake .. -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DGEN_LANGUAGE_BINDINGS=On -DGEN_CPP_BINDINGS=On -DGEN_PYTHON_BINDINGS=Off
   make -j
   make install
   cd "$DEP_DIR"

   curl -L https://github.com/sysrepo/sysrepo/archive/refs/tags/v1.4.140.tar.gz > dl/sysrepo.tgz
   mkdir build/sysrepo
   tar -xf dl/sysrepo.tgz -C build/sysrepo --strip-components=1
   mkdir -p build/sysrepo/build
   cd build/sysrepo/build
   cmake .. -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DGEN_LANGUAGE_BINDINGS=On -DGEN_CPP_BINDINGS=On -DGEN_PYTHON_BINDINGS=Off
   make -j
   make install
   cd "$DEP_DIR"


C-DNS Library
-------------

`C-DNS Library <https://gitlab.nic.cz/knot/c-dns>`_ is used for working with the C-DNS format.

.. code:: shell

   curl -L https://gitlab.nic.cz/knot/c-dns/-/archive/master/c-dns-master.tar.gz > dl/cdns.tgz
   mkdir build/cdns
   tar -xf dl/cdns.tgz -C build/cdns --strip-components=1
   mkdir -p build/cdns/build
   cd build/cdns/build
   # Remove -DCMAKE_INSTALL_PREFIX="$DEP_DIR" if you want to install CDNS into /usr/local
   cmake .. -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release
   make -j
   make install
   cd "$DEP_DIR"

cryptopANT
----------

`Library <https://ant.isi.edu/software/cryptopANT/index.html>`_ for anonymization of IP addresses.

.. code:: shell

   curl -L https://ant.isi.edu/software/cryptopANT/cryptopANT-1.2.2.tar.gz > dl/cryptopant.tgz
   mkdir build/cryptopant
   tar -xf dl/cryptopant.tgz -C build/cryptopant --strip-components=1
   cd build/cryptopant
   ./configure --prefix="$DEP_DIR"
   make -j
   make install
   cd "$DEP_DIR"

libknot
-------

In case your distribution doesn't yet have libknot >= 3.0.6, the latest package can
be installed from `Knot DNS's <https://www.knot-dns.cz/download/>`_ own repositories.
Debian/Ubuntu ``libknot-dev`` package or its equivalent in other distributions needs
to be installed for successful compilation of DNS probe.

DNS Probe
---------

.. code:: shell

   # Replace <GIT_REPO> with path to this repository
   # For disabling DPDK BACKEND remove `-DDPDK_BACKEND=On`
   # For building without IP anonymization support add `-DPROBE_CRYPTOPANT=Off`
   # For building without support for one of the export formats add `-DPROBE_PARQUET=Off` or `-DPROBE_CDNS=Off`
   # For building without support for dnstap input add `-DPROBE_DNSTAP=Off`
   # For building without support for Knot interface input add `-DPROBE_KNOT=Off`
   cmake <GIT_REPO> -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DAF_PACKET_BACKEND=On -DDPDK_BACKEND=On -DBUILD_COLLECTOR=On
   make -j
   make install

Finally, YANG module containing the data model for DNS Probe and default configuration also needs to be installed to Sysrepo data store:

.. code:: shell

   sudo $DEP_DIR/bin/sysrepoctl -i <GIT_REPO>/data-model/cznic-dns-probe.yang
