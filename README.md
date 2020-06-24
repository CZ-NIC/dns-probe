# DNS Probe

This project contains implementation of probe for collection of DNS information from scanned requests and responses. The
probe can export collected data into two formats - Parquet and C-DNS. Both formats are stored locally on probe's disks.
For future release it is planned to export data directly over network to centralized collector.

DNS probe supports analyzing TCP and UDP traffic. The probe currently implements two ways how to get analyzed packets.
The first is with DPDK backend. This backend allows to read packets directly from NIC and can process the whole network
traffic. Disadvantage of this approach is that application will seize the NIC and doesn't allow it to be used by OS.
The second available backend is standard Linux's AF packet interface. This approach is significantly slower then DPDK
one but allows monitored interface to be used by other applications. The selection of which backend will be used is
made during the [compilation phase](#installation-from-source).

## Configuration

DNS Probe is using [Sysrepo](https://github.com/sysrepo/sysrepo/) as storage for configuration. Check
[Configuration](https://adam.pages.labs.nic.cz/dns-probe/Configuration.html) and [YANG module](https://adam.pages.labs.nic.cz/dns-probe/YANGmodule.html)
sections in user documentation to get more information on configuring DNS Probe.

## Installation
DNS Probe can be used on Linux with kernel version at least 3.11. It also requires the system to support C++14 standard.
Installation packages are available from [OBS (openSUSE Build Service)](https://build.opensuse.org/project/show/home:CZ-NIC:dns-probe).

The following distributions are currently supported: Debian 10 and 9, Ubuntu 20.04, 18.04 and 16.04.

Check the [Installation](https://adam.pages.labs.nic.cz/dns-probe/Installation.html) section in user documentation to see how to obtain the packages.

### Installation from source

This project has several dependencies that have to be installed first:

* [CMake](https://cmake.org/), version at least 3.5
* [Boost](https://www.boost.org/) (C++ libraries)
* [libpcap](https://www.tcpdump.org/)
* [Apache Arrow](https://arrow.apache.org/)
* [Sysrepo](https://github.com/sysrepo/sysrepo)
* [C-DNS library](https://gitlab.labs.nic.cz/knot/c-dns)
* [DPDK](https://www.dpdk.org/) (only for DPDK version)

Optionally, to build user documentation (`make doc`) or manual pages (`make man`) one additional dependency is required:
* [Sphinx](https://www.sphinx-doc.org/en/master/)

Check the [Installation from source](https://adam.pages.labs.nic.cz/dns-probe/Installation.html#installation-from-source)
section in user documentation to see how to install all the dependencies.

The following instructions describe how to compile and install DNS probe:

```shell
git clone https://gitlab.labs.nic.cz/adam/dns-probe.git
cd dns-probe
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DAF_PACKET_BACKEND=On -DDPDK_BACKEND=On
make -j
make install
```

Finally, YANG module containing the data model for DNS Probe and default configuration also need to be installed:

```shell
# Replace <GIT_REPO> with path to DNS Probe's repository
sudo sysrepoctl -i <GIT_REPO>/data-model/cznic-dns-probe.yang
```

## Running DNS Probe

It is recommended to run DNS Probe as a [systemd](https://www.freedesktop.org/wiki/Software/systemd/) service.
Alternatively, it is possible to start it from the command line using shell scripts that are part of the DNS Probe distribution.
These shell scripts can also be used as a basis for integration with other init systems. Check
the [Running DNS Probe](https://adam.pages.labs.nic.cz/dns-probe/Running.html) section in user documentation to see how to run DNS Probe.

See the documentation at [adam.pages.labs.nic.cz/dns-probe](https://adam.pages.labs.nic.cz/dns-probe/index.html) for more options.