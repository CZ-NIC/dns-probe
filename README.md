# DNS Probe

This project contains implementation of probe for collection of DNS information from scanned requests and responses. The
probe can export collected data into two formats - Parquet and C-DNS. Both formats are stored locally on probe's disks.
For future release it is planned to export data directly over network to centralized collector.

DNS probe supports analyzing TCP and UDP traffic. The probe currently implements two ways how to get analyzed packets.
The first is with DPDK backend. This backend allows to read packets directly from NIC and can process the whole network
traffic. Disadvantage of this approach is that application will seize the NIC and doesn't allow it to be used by OS.
The second available backend is standard Linux's AF packet interface. This approach is significantly slower then DPDK
one but allows monitored interface to be used by other applications. The selection of which backend will be used is
made during the [compilation phase](## Compiling and installing DNS Probe).

## Configuration
The probe is using the [Sysrepo](https://github.com/sysrepo/sysrepo/) as storage for configuration. Sysrepo is using data
models written in YANG language to describe configuration options, their constraints and dependencies. Complete data model
for DNS Probe can be found in directory [data-model/cznic-dns-probe.yang](data-model/cznic-dns-probe.yang). The 
data model contains list of configuration directives which can be changed, description of runtime statistics and
RPC. For modifying and accessing data from sysrepo please see sysrepo's documentation.

The configuration of DNS Probe contains two basic types. Static configuration items can be modified while
the application is running but all changes will be applied after restart of the DNS Probe. Modifications of
dynamic configuration items will be applied instantly after the modification.

#### YANG modules

* [data-model/cznic-dns-probe.yang](data-model/cznic-dns-probe.yang)

# Installation from packages
Packages for Debian 10 and 9 and Ubuntu 20.04, 18.04 and 16.04 are available from
[OBS (openSUSE Build Service)](htts://build.opensuse.org/project/show/home:CZ-NIC:dns-probe).
The OBS repository also contains packages with DNS probe's dependencies that don't have their
own package in the distributions' standard repositories. These dependencies will be automatically
installed as pre-requisites when installing DNS probe.

First you need to add the OBS repository for given distribution to your system's repository list and download the repository's signing key:

##### Debian 10
```shell
sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Debian_10/ /' > /etc/apt/sources.list.d/dns-probe.list
wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/Debian_10/Release.key -O Release.key
```

##### Debian 9
```shell
sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Debian_9.0/ /' > /etc/apt/sources.list.d/dns-probe.list
wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/Debian_9.0/Release.key -O Release.key
```

##### Ubuntu 20.04
```shell
sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/xUbuntu_20.04/ /' > /etc/apt/sources.list.d/dns-probe.list
wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/xUbuntu_20.04/Release.key -O Release.key
```

##### Ubuntu 18.04
```shell
sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/xUbuntu_18.04/ /' > /etc/apt/sources.list.d/dns-probe.list
wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/xUbuntu_18.04/Release.key -O Release.key
```

##### Ubuntu 16.04
```shell
sudo echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/xUbuntu_16.04/ /' > /etc/apt/sources.list.d/dns-probe.list
wget -nv http://download.opensuse.org/repositories/home:CZ-NIC:dns-probe/xUbuntu_16.04/Release.key -O Release.key
```

Now you need to add the signing key to your system, update the repository list and then you can finally install the DNS probe:

```shell
sudo apt-key add - < Release.key
sudo apt-get update
sudo apt-get install dns-probe-af dns-probe-dpdk
```

DNS probe is separated into two packages (`dns-probe-af` and `dns-probe-dpdk`) differing by the backend used for processing packets.
The `dns-probe-af` package uses AF packet sockets to process packets whereas the `dns-probe-dpdk` package uses DPDK framework.
You can install just one of these packages without the other depending on which of the packet processing backends you want to use.

The packages also automatically install the YANG module [cznic-dns-probe.yang](data-model/cznic-dns-probe.yang) with default configuration
to Sysrepo datastore if you haven't done so manually yet.

# Installation from source

This project has following required dependencies:

* [CMake >= 3.5](https://github.com/Kitware/CMake/releases/download/v3.16.4/cmake-3.16.4.zip)
* [Linux OS (kernel at least 3.11)](http://kernel.org)
* [Boost](https://www.boost.org/)
* [Sysrepo 1.4.2](https://github.com/sysrepo/sysrepo/archive/v1.4.2.tar.gz)
* [Arrow 0.16.0](https://github.com/apache/arrow/archive/apache-arrow-0.16.0.tar.gz)
* [C-DNS](https://gitlab.labs.nic.cz/knot/c-dns)
* [libPCAP](https://www.tcpdump.org/)

For DPDK backend the DNS probe also requires installed DPDK framework:
* [DPDK >= 16.11](http://fast.dpdk.org/rel/dpdk-19.11.tar.xz)
** Requires `libnuma-dev` and kernel headers installed


## Preparing dependencies for DNS Probe

Following steps describe how to compile all necessary dependencies for the DNS Probe. You can skip these steps
if you have all dependencies installed through your package manager. Also this approach installs all dependencies into
local directory `dp-dep`.

Start with creating a folder for dependencies.
```shell
mkdir dp-dep
mkdir dp-dep/build
mkdir dp-dep/dl
cd dp-dep
DEP_DIR="$(pwd)"
```
Those commands create directory for downloaded packages (`dp-dep/dl`) and building directory (`dp-dep/build`). 
The `dp-dep` directory is also used as target to install all compiled packages.

### CMake

CMake is usually available through the package managers on any Linux system. It's essential to have at least 
version 3.5, otherwise compilation will fail.

```shell
curl -Lhttps://github.com/Kitware/CMake/releases/download/v3.16.4/cmake-3.16.4.zip > dl/cmake.tgz
mkdir build/cmake
tar -xf dl/cmake.tgz -C build/cmake --strip-components=1
cd build/cmake
./bootstrap
make -j
make install DESTDIR="$DEP_DIR" # Remove `DESTDIR="$DEP_DIR"` if you want to install CMake into /usr/local
cd "$DEP_DIR"
PATH="$DEP_DIR/bin;$PATH"
```

### Sysrepo
Sysrepo provides API to configuration storage. In the following steps it will install and compile sysrepo and its
dependencies. 

```shell
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
```

### Arrow
Arrow library provides API for working with parquet files.

```shell
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
```

### CDNS
C-DNS is another format used for exporting collected statistics.

```shell
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
```


### DPDK
DPDK framework is required only when the DPDK backend is enabled in compilation process of the DNS Probe.

```shell
curl -L http://fast.dpdk.org/rel/dpdk-19.11.tar.xz > dl/dpdk.tgz
mkdir build/dpdk
tar -xf dl/dpdk.tgz -C build/dpdk --strip-components=1
cd build/dpdk
meson build -Dprefix="$DEP_DIR" # Remove `-Dprefix="$DEP_DIR"` if you want to install DPDK into /usr/local
cd build
ninja install
cd "$DEP_DIR"
```

After these steps, the directory `ddp-dep/lib/modules/<kernel_version>/extra/dpdk/` will contain compiled drivers.
The `rte_kni.ko` driver is currently not used by the DPDK DNS Probe application. `igb_uio.ko` is the driver used for
accessing Intel network cards over [UIO](https://www.kernel.org/doc/html/v4.11/driver-api/uio-howto.html) and
it has to be loaded when using these cards.

## Compiling and installing DNS Probe

```shell
# Replace <GIT_REPO> with path to this repository
# For disabling DPDK BACKEND remove `-DDPDK_BACKEND=On`
cmake <GIT_REPO> -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DAF_PACKET_BACKEND=On -DDPDK_BACKEND=On
make -j
make install
```

To run DNS probe the YANG module with default configuration also needs to be installed to Sysrepo datastore:

```shell
sudo sysrepoctl -i <GIT_REPO>/data-model/cznic-dns-probe.yang
```

# Running DNS Probe

## Running as systemd service
Installation from packages includes a *systemd* service `dns-probe-<BACKEND>@.service` where `<BACKEND>` is either `af` or `dpdk` depending
on the package you installed.

The *systemd* service can be run like this:

```shell
sudo systemctl start dns-probe-<BACKEND>@<FILE>.service
```
To stop, enable or restart the service use the appropriate `systemctl` subcommands.

The service takes a parameter `<FILE>` which is a name of configuration file located at `/etc/dns-probe-<BACKEND>/<FILE>.conf` that contains
command line parameters for DNS probe instance. Without this file the *systemd* service will fail. Installation from packages supplies
a default configuration file at `/etc/dns-probe-<BACKEND>/probe.conf` which looks like this:

```
DAEMON_ARGS="-i lo -l /var/log/dns-probe-<BACKEND>@probe.log"
```

This configuration file runs DNS probe on loopback interface and saves its logs to `/var/log/dns-probe-<BACKEND>@probe.log` file. The user
should change the `-i` parameter to a network interface that DNS probe should process packets from and then start the *systemd*
service.

## Running from command line
After installation of both backends the following executables are created:

* `dns-probe-af` (AF backend), `dns-probe-dpdk` (DPDK backend) - These binaries contain the application itself
* `dp-af` (AF backend), `dp-dpdk` (DPDK backend) - These scripts take command line parameters, pass them to corresponding
backend executable and start it. When the application receives a restart RPC
through sysrepo the application exits with return code 1. This wrapper detects
that code and reruns the application again. If the return code differs from
1 than the script exits and returns the same code as wrapped application.

* `ddp-bind` (DPDK backend) - Simplifies the usage of DPDK version. Internally runs `dp-dpdk`.
                                            
Both backend variants support these command line parameters:

* `-p <PCAP>` - Read `<PCAP>` file and process it into aggregated statistic file. This parameter can be used multiple
times. Every usage adds one PCAP file into processing. All PCAPs are always processed in single thread
mode.
                
* `-r` - Marks pcaps from `-p` parameters as raw. Raw PCAP contains packets starting with IPv4 or IPv6 header.
When the `-r` parameter is specified it is illegal to use `-i` parameter. 
                
* `-i <INTERFACE>` - Read packets from given `<INTERFACE>`. This parameter can be used multiple times. Every usage
adds one interface for processing packets. Reading from an interface has multi-threaded support.
The format of `<INTERFACE>` depends on used backend.

    * AF packet backend - The `<INTERFACE>` is name of network interface defined by kernel. List of available interfaces
                          provides for example command `ip link`.
    * DPDK backend - The `<INTERFACE>` is expected in format of PCI function ID device. For example `00:1f.6` where
    `00:1f` is PCI device and `6` is funcation number. Usually the last part specifies concrete physical
    interface on NIC. For more information about usage with DPDK backend see
    [next section](#DPDK backend).
                     
        When the DPDK version is started with `ddp-bind` instead of `dp-dpdk` then `<INTERFACE>` is standard interface
        defined by kernel as in case of AF packet backend.

* `-l <LOGFILE>` - Redirects probe's logs to LOGFILE instead of standard output.

* `-h` - Provides basic help.

# DPDK backend

For running the DNS Probe with DPDK backend you have to allocate huge pages. This requires root privileges
and following steps:

1. Mount the huge pages file system

    * On some system the huge pages FS is automatically allocated. You can check it with command
    `mount | grep -E ^hugetlbfs`. If the command prints some row 
    (e.g. `hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)`), then you have huge pages FS mounted.
     
2. Allocate huge pages

Following script automatically mounts huge pages file system (if necessary) and allocates 4 GB of memory for
huge pages.
 
```shell
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
```

The DNS probe with DPDK backend expects that used NIC interfaces have binded DPDK drivers. 
For binding drivers there are two options. The easiest way is to run DNS probe through script `ddp-bind`. This script is
installed with other executables. Its main purpose is to bind DPDK drivers to given interfaces and launch
DNS probe. When the application stops the script binds original drivers back. Command line arguments are identical to 
those used by `dns-probe-af` so you can specify interfaces by their name instead of PCI ID.

The other way how to bind drivers is decribed in the
[DPDK documentation](https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#running-dpdk-applications).
