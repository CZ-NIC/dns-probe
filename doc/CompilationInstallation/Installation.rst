Installation
============

Installation from packages
**************************

Packages for Debian 10 and 9 and Ubuntu 20.04, 18.04 and 16.04 are
available from `OBS (openSUSE Build
Service) <https://build.opensuse.org/project/show/home:CZ-NIC:dns-probe>`__.
The OBS repository also contains packages with DNS probe's dependencies
that don't have their own package in the distributions' standard
repositories. These dependencies will be automatically installed as
pre-requisites when installing DNS probe.

First you need to add the OBS repository for given distribution to your
system's repository list and download the repository's signing key:

Debian 10
'''''''''

.. code:: shell

    sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Debian_10/ /' > /etc/apt/sources.list.d/dns-probe.list
    wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/Debian_10/Release.key -O Release.key

Debian 9
''''''''

.. code:: shell

    sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Debian_9.0/ /' > /etc/apt/sources.list.d/dns-probe.list
    wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/Debian_9.0/Release.key -O Release.key

Ubuntu 20.04
''''''''''''

.. code:: shell

    sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/xUbuntu_20.04/ /' > /etc/apt/sources.list.d/dns-probe.list
    wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/xUbuntu_20.04/Release.key -O Release.key

Ubuntu 18.04
''''''''''''

.. code:: shell

    sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/dns-probe.list
    wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/xUbuntu_18.04/Release.key -O Release.key

Ubuntu 16.04
''''''''''''

.. code:: shell

    sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/xUbuntu_16.04/ /' > /etc/apt/sources.list.d/dns-probe.list
    wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/xUbuntu_16.04/Release.key -O Release.key

Now you need to add the signing key to your system, update the
repository list and then you can finally install the DNS probe:

.. code:: shell

    sudo apt-key add - < Release.key
    sudo apt-get update
    sudo apt-get install dns-probe-af dns-probe-dpdk

DNS probe is separated into two packages (``dns-probe-af`` and
``dns-probe-dpdk``) differing by the backend used for processing
packets. The ``dns-probe-af`` package uses AF packet sockets to process
packets whereas the ``dns-probe-dpdk`` package uses DPDK framework. You
can install just one of these packages without the other depending on
which of the packet processing backends you want to use.

The packages also automatically install the YANG module
`cznic-dns-probe.yang <https://gitlab.labs.nic.cz/adam/dns-probe/-/blob/master/data-model/cznic-dns-probe.yang>`__
with default configuration to Sysrepo datastore if you haven't done so
manually yet.

Installation from source
************************

This project has following required dependencies:

-  `CMake >=
   3.5 <https://github.com/Kitware/CMake/releases/download/v3.16.4/cmake-3.16.4.zip>`__
-  `Linux OS (kernel at least 3.11) <http://kernel.org>`__
-  `Boost <https://www.boost.org/>`__
-  `Sysrepo
   1.4.2 <https://github.com/sysrepo/sysrepo/archive/v1.4.2.tar.gz>`__
-  `Arrow
   0.16.0 <https://github.com/apache/arrow/archive/apache-arrow-0.16.0.tar.gz>`__
-  `C-DNS <https://gitlab.labs.nic.cz/knot/c-dns>`__
-  `libPCAP <https://www.tcpdump.org/>`__

For DPDK backend the DNS probe also requires installed DPDK framework:
\* `DPDK >= 16.11 <http://fast.dpdk.org/rel/dpdk-19.11.tar.xz>`__ \*\*
Requires ``libnuma-dev`` and kernel headers installed

Preparing dependencies for DNS Probe
------------------------------------

Following steps describe how to compile all necessary dependencies for
the DNS Probe. You can skip these steps if you have all dependencies
installed through your package manager. Also this approach installs all
dependencies into local directory ``dp-dep``.

Start with creating a folder for dependencies.

.. code:: shell

    mkdir dp-dep
    mkdir dp-dep/build
    mkdir dp-dep/dl
    cd dp-dep
    DEP_DIR="$(pwd)"

Those commands create directory for downloaded packages (``dp-dep/dl``)
and building directory (``dp-dep/build``). The ``dp-dep`` directory is
also used as target to install all compiled packages.

CMake
~~~~~

CMake is usually available through the package managers on any Linux
system. It's essential to have at least version 3.5, otherwise
compilation will fail.

.. code:: shell

    curl -Lhttps://github.com/Kitware/CMake/releases/download/v3.16.4/cmake-3.16.4.zip > dl/cmake.tgz
    mkdir build/cmake
    tar -xf dl/cmake.tgz -C build/cmake --strip-components=1
    cd build/cmake
    ./bootstrap
    make -j
    make install DESTDIR="$DEP_DIR" # Remove `DESTDIR="$DEP_DIR"` if you want to install CMake into /usr/local
    cd "$DEP_DIR"
    PATH="$DEP_DIR/bin;$PATH"

Sysrepo
~~~~~~~

Sysrepo provides API to configuration storage. In the following steps it
will install and compile sysrepo and its dependencies.

.. code:: shell

    curl -L https://github.com/CESNET/libyang/archive/v1.0.130.tar.gz > dl/libyang.tgz
    mkdir build/libyang
    tar -xf dl/libyang.tgz -C build/libyang --strip-components=1
    mkdir -p build/libyang/build
    cd build/libyang/build
    cmake .. -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DGEN_LANGUAGE_BINDINGS=On -DGEN_CPP_BINDINGS=On -DGEN_PYTHON_BINDINGS=Off
    make -j
    make install
    cd "$DEP_DIR"

    curl -L https://github.com/sysrepo/sysrepo/archive/v1.4.2.tar.gz > dl/sysrepo.tgz
    mkdir build/sysrepo
    tar -xf dl/sysrepo.tgz -C build/sysrepo --strip-components=1
    mkdir -p build/sysrepo/build
    cd build/sysrepo/build
    cmake .. -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DGEN_LANGUAGE_BINDINGS=On -DGEN_CPP_BINDINGS=On -DGEN_PYTHON_BINDINGS=Off
    make -j
    make install
    cd "$DEP_DIR"

Arrow
~~~~~

Arrow library provides API for working with parquet files.

.. code:: shell

    curl -L https://github.com/apache/arrow/archive/apache-arrow-0.16.0.tar.gz > dl/arrow.tgz
    mkdir build/arrow
    tar -xf dl/arrow.tgz -C build/arrow --strip-components=1
    mkdir -p build/arrow/cpp/build
    cd build/arrow/cpp/build
    # Remove -DCMAKE_INSTALL_PREFIX="$DEP_DIR" if you want to install Arrow into /usr/local
    cmake .. -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DARROW_WITH_RAPIDJSON=ON -DARROW_BUILD_TESTS=OFF -DARROW_PARQUET=ON
    make -j
    make install
    cd "$DEP_DIR"

CDNS
~~~~

C-DNS is another format used for exporting collected statistics.

.. code:: shell

    curl -L https://github.com/PJK/libcbor/archive/v0.5.0.tar.gz > dl/libcbor.tgz
    mkdir build/libcbor
    tar -xf dl/libcbor.tgz -C build/libcbor --strip-components=1
    mkdir -p build/libcbor/build
    cd build/libcbor/build
    # Remove -DCMAKE_INSTALL_PREFIX="$DEP_DIR" if you want to install libcbor into /usr/local
    cmake .. -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release
    make -j
    make install
    cd "$DEP_DIR"

    curl -L https://gitlab.labs.nic.cz/knot/c-dns/-/archive/master/c-dns-master.tar.gz > dl/cdns.tgz
    mkdir build/cdns
    tar -xf dl/cdns.tgz -C build/cdns --strip-components=1
    mkdir -p build/cdns/build
    cd build/cdns/build
    # Remove -DCMAKE_INSTALL_PREFIX="$DEP_DIR" if you want to install CDNS into /usr/local
    cmake .. -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release
    make -j
    make install
    cd "$DEP_DIR"

DPDK
~~~~

DPDK framework is required only when the DPDK backend is enabled in
compilation process of the DNS Probe.

.. code:: shell

    curl -L http://fast.dpdk.org/rel/dpdk-19.11.tar.xz > dl/dpdk.tgz
    mkdir build/dpdk
    tar -xf dl/dpdk.tgz -C build/dpdk --strip-components=1
    cd build/dpdk
    meson build -Dprefix="$DEP_DIR" # Remove `-Dprefix="$DEP_DIR"` if you want to install DPDK into /usr/local
    cd build
    ninja install
    cd "$DEP_DIR"

After these steps, the directory
``ddp-dep/lib/modules/<kernel_version>/extra/dpdk/`` will contain
compiled drivers. The ``rte_kni.ko`` driver is currently not used by the
DPDK DNS Probe application. ``igb_uio.ko`` is the driver used for
accessing Intel network cards over
`UIO <https://www.kernel.org/doc/html/v4.11/driver-api/uio-howto.html>`__
and it has to be loaded when using these cards.

.. _compilationPhase:

Compiling and installing DNS Probe
----------------------------------

.. code:: shell

    # Replace <GIT_REPO> with path to this repository
    # For disabling DPDK BACKEND remove `-DDPDK_BACKEND=On`
    cmake <GIT_REPO> -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DAF_PACKET_BACKEND=On -DDPDK_BACKEND=On
    make -j
    make install

To run DNS probe the YANG module with default configuration also needs
to be installed to Sysrepo datastore:

.. code:: shell

    sudo sysrepoctl -i <GIT_REPO>/data-model/cznic-dns-probe.yang
