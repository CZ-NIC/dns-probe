# DNS Probe

This project contains implementation of probe for collection of DNS information from scanned requests and responses. The
probe can export collected data into two formats - Parquet and C-DNS. Both formats are stored locally on probe's disks.
For future release it is planned to export data directly over network to centralized collector.

DNS probe supports analyzing TCP and UDP traffic. The probe currently implements two ways how to get analyzed packets.
The first is with DPDK backend. This backend allows to read packets directly from NIC and can process the whole network
traffic. Disadvantage of this approach is that application will seize the NIC and doesn't allow it to be used by OS.
The second available backend is standard Linux's AF packet interface. This approach is significantly slower then DPDK
one but allows monitored interface to be used by other applications. The selection of which backend will be used is
made during the [compilation phase](#compiling-and-installing-dns-probe).

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

# Installation
DNS Probe can be used on Linux with kernel version at least 3.11. It also requires the system to support C++14 standard.
Installation packages are available from [OBS (openSUSE Build Service)](https://build.opensuse.org/project/show/home:CZ-NIC:dns-probe).
The following distributions are currently supported: Debian 10 and 9, Ubuntu 20.04, 18.04 and 16.04.

The OBS repository also contains packages with several dependencies that are not provided by the distribution’s standard repositories.
These dependencies will be automatically installed as pre-requisites when installing DNS Probe.

On Linux distributions that are not (yet) supported, DNS Probe has to be compiled and built from source as described below.

## Installation from packages
The first two steps are to add the OBS repository for the given distribution to the system’s repository list, and download the repository’s signing key:

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

The remaining steps are then identical for all distributions: the signing key is added to the system keyring, the repository list
is updated, and finally the DNS Probe package is installed:

```shell
sudo apt-key add - < Release.key
sudo apt-get update
sudo apt-get install dns-probe-af dns-probe-dpdk
```

Two alternative packages are available:

* `dns-probe-af` is compiled with support for AF_PACKET sockets

* `dns-probe-dpdk` uses the DPDK framework.

Package installation also initializes the Sysrepo datastore with a default configuration, if no configuration is found.

# Installation from source

This project has several dependencies that have to be installed first. The following packages
should be available from standard distribution repositories:

* [CMake](https://cmake.org/), version at least 3.5
* [Boost](https://www.boost.org/) (C++ libraries)
* [libpcap](https://www.tcpdump.org/)
* [DPDK](https://www.dpdk.org/) (only for DPDK version)

Optionally, to build user documentation (`make doc`) or manual pages (`make man`) one additional dependency is required:
* [Sphinx](https://www.sphinx-doc.org/en/master/)

The following instructions describe how to compile DNS probe and the remaining dependencies. Also this approach
installs all dependencies into local directory `dp-dep`.

## Build directory

Start with creating a directory where dependencies will be built and installed. Installation in a system directory,
such as `/usr/local`, is also possible.

```shell
mkdir dp-dep
mkdir dp-dep/build
mkdir dp-dep/dl
cd dp-dep
DEP_DIR="$(pwd)"
```
Those commands create directory for downloaded packages (`dp-dep/dl`) and building directory (`dp-dep/build`). 
The `dp-dep` directory is also used as target to install all compiled packages.

### Apache Arrow

Apache Arrow packages can be installed on most distributions from Apache's own [repositories](https://arrow.apache.org/install/).
Debian/Ubuntu `libarrow-dev` and `libparquet-dev` packages or their equivalents in other distributions need to be
installed for successful compilation of DNS probe.

### Sysrepo

[Sysrepo](https://github.com/sysrepo/sysrepo) provides a configuration and management API. It uses
[libyang](https://github.com/CESNET/libyang) library that needs to be installed first.

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

### CDNS
[C-DNS Library](https://gitlab.labs.nic.cz/knot/c-dns) is used for working with the C-DNS format.

```shell
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

## Compiling and installing DNS Probe

```shell
# Replace <GIT_REPO> with path to this repository
# For disabling DPDK BACKEND remove `-DDPDK_BACKEND=On`
cmake <GIT_REPO> -DCMAKE_INSTALL_PREFIX="$DEP_DIR" -DCMAKE_BUILD_TYPE=Release -DAF_PACKET_BACKEND=On -DDPDK_BACKEND=On
make -j
make install
```

Finally, YANG module containing the data model for DNS Probe and default configuration also need to be installed:

```shell
sudo $DEP_DIR/bin/sysrepoctl -i <GIT_REPO>/data-model/cznic-dns-probe.yang
```

# Running DNS Probe

It is recommended to run DNS Probe as a [systemd](https://www.freedesktop.org/wiki/Software/systemd/) service.
Alternatively, it is possible to start it from the command line using shell scripts that are part of the DNS Probe distribution.
These shell scripts can also be used as a basis for integration with other init systems.

## Running as systemd service
Installation packages include a *systemd* unit file `dns-probe-<BACKEND>@.service`, where `<BACKEND>` is either `af` or `dpdk` depending
on the backend that the package installs.

The *systemd* service can be run like this:

```shell
sudo systemctl start dns-probe-<BACKEND>@<FILE>.service
```

Other `systemctl` subcommands can be used to stop, enable or restart the service.

The service takes a parameter `<FILE>` which is a name of configuration file located at `/etc/dns-probe-<BACKEND>/<FILE>.conf` that contains
command line parameters for DNS probe instance. Without this file the *systemd* service will fail. Installation from packages supplies
a default configuration file at `/etc/dns-probe-<BACKEND>/probe.conf` which looks like this:

```
DAEMON_ARGS="-i lo -l /var/log/dns-probe-<BACKEND>@probe.log"
```

This configuration file runs DNS probe on loopback interface and saves its logs to `/var/log/dns-probe-<BACKEND>@probe.log` file.
For normal operation, the `-i` parameter needs to be changes to one or more network interfaces that DNS Probe is to process packets from
and then start the *systemd* service.

## Running from command line
For each backend, one binary program and one shell script is installed. Their names are shown in table below.

| **Backend** | **Binary program** | **Wrapper script** |
| ----------- | ------------------ | ------------------ |
| AF_PACKET   | `dns-probe-af`     | `dp-af`            |
| DPDK        | `dns-probe-dpdk`   | `dp-dpdk`          |

The wrapper shell scripts accept the same options as the corresponding backend binary, and start the binary with these options.
If the running binary program receives the *restart* operation through Sysrepo, it exits with return code 1. The wrapper script
then starts the same binary again.

For other codes returned by the binary, the wrapper script just exits and returns the same code.
                                            
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
    * DPDK backend - The `<INTERFACE>` is either name of network interface defined by kernel or in format of PCI function ID device.
                     For example `00:1f.6` where `00:1f` is PCI device and `6` is funcation number. Usually the last part specifies
                     concrete physical interface on NIC. For more information about usage with DPDK backend see [next section](#DPDK backend).


* `-l <LOGFILE>` - Redirects probe's logs to LOGFILE instead of standard output.

* `-h` - Provides basic help.

# DPDK backend

For running DNS Probe with DPDK backend, a portion of memory with huge pages has to be allocated. This is done in two steps,
both requiring root privileges:

1. mount the huge pages file system
2. allocate huge pages

On some systems, the huge pages FS is mounted automatically, so step #1 can be ommited. It can be checked by runnning the command:
```shell
mount | grep -E ^hugetlbfs
```

If the command prints something similar to 
```shell
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)
```
then the huge pages FS is already mounted.

The following script automatically mounts huge pages file system (if necessary) and allocates 4 GB of memory for
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

Network cards used with the DPDK backend have to be bound to DPDK-compatible drivers. The easier way of doing this is to run
`dns-probe-dpdk` or `dp-dpdk` with the `-i` parameter(s) specifying the NIC name such as `eth0`. DNS Probe will then attempt to
automatically bind these interfaces to the `uio_pci_generic` driver and, when it exits, it will bind the interfaces back to their
original driver. For this to work, the `uio_pci_generic` module needs to be loaded manually like this:

```shell
sudo modprobe uio_pci_generic
```

The other way is to bind the NICs to DPDK-compatible drivers manually before running DNS Probe. In this case, the NICs
have to be identified by their PCI IDs in `-i` options. Details about binding network interfaces manually are described
in the [DPDK documentation](https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html).