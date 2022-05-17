************
Installation
************

DNS Probe can be used on Linux with kernel version at least
3.11. It also requires the system to support C++14 standard.
Installation packages are available from `OBS (openSUSE Build Service)
<https://build.opensuse.org/project/show/home:CZ-NIC:dns-probe>`_.
The following distributions are currently supported: Debian 11, 10 and 9;
Ubuntu 22.04, 20.04, 18.04; Fedora 36, 35, Rawhide; EPEL 8 and Arch.

The OBS repository also contains packages with several dependencies
that are not provided by the distribution's standard
repositories. These dependencies will be automatically installed as
pre-requisites when installing DNS Probe.

On Linux distributions that are not (yet) supported, DNS Probe has to be compiled and built from source as described below.

Installation from packages
==========================

Debian/Ubuntu
-------------

.. code:: shell

   sudo apt-get update
   sudo apt-get install -y lsb-release curl gpg

   DISTRO=$(lsb_release -i -s)
   RELEASE=$(lsb_release -r -s)
   if [[ $DISTRO == "Ubuntu" ]]; then DISTRO="xUbuntu"; fi
   if [[ $DISTRO == "Debian" && "$RELEASE" =~ ^9\..*$ ]]; then RELEASE="9.0"; fi

   echo "deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/${DISTRO}_${RELEASE}/ /" | sudo tee /etc/apt/sources.list.d/dns-probe.list
   curl -fsSL https://download.opensuse.org/repositories/home:CZ-NIC:/dns-probe/${DISTRO}_${RELEASE}/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/dns-probe.gpg > /dev/null
   sudo apt-get update
   sudo apt-get install dns-probe-af dns-probe-dpdk dns-probe-collector

Fedora
------

.. code:: shell

   sudo dnf config-manager --add-repo https://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Fedora_$(cut -d: -f5 /etc/system-release-cpe | cut -d. -f1)/home:CZ-NIC:dns-probe.repo
   sudo dnf install dns-probe-af dns-probe-dpdk dns-probe-collector

Fedora Rawhide
--------------

.. code:: shell

   sudo dnf config-manager --add-repo https://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Fedora_Rawhide/home:CZ-NIC:dns-probe.repo
   sudo dnf install dns-probe-af dns-probe-dpdk dns-probe-collector

EPEL 8
------

.. code:: shell

   cd /etc/yum.repos.d/
   sudo wget https://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Fedora_EPEL_8_CentOS/home:CZ-NIC:dns-probe.repo
   sudo yum install dns-probe-af dns-probe-dpdk dns-probe-collector

Arch
----

.. code:: shell

   echo "[home_CZ-NIC_dns-probe_Arch]" | sudo tee -a /etc/pacman.conf
   echo "Server = https://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Arch/$(uname -m)" | sudo tee -a /etc/pacman.conf

   key=$(curl -fsSL https://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Arch/$(uname -m)/home_CZ-NIC_dns-probe_Arch.key)
   fingerprint=$(gpg --quiet --with-colons --import-options show-only --import --fingerprint <<< "${key}" | awk -F: '$1 == "fpr" { print $10 }')

   sudo pacman-key --init
   sudo pacman-key --add - <<< "${key}"
   sudo pacman-key --lsign-key "${fingerprint}"

   sudo pacman -Sy home_CZ-NIC_dns-probe_Arch/c-dns

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
- yaml-cpp
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
