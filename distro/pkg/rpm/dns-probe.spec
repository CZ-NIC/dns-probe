Name: dns-probe
Version: {{ version }}
Release: {{ release }}%{?dist}
Summary: DNS traffic monitoring probe
Url: https://gitlab.nic.cz/adam/dns-probe
Source: dns-probe-%{version}.tar.gz
License: GPLv3

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: cmake
BuildRequires: boost-devel
BuildRequires: python3-sphinx
BuildRequires: openssl-devel
BuildRequires: libpcap-devel
BuildRequires: cryptopant-devel
BuildRequires: yaml-cpp-devel
BuildRequires: fstrm-devel
BuildRequires: protobuf-devel
BuildRequires: protobuf-compiler
BuildRequires: libmaxminddb-devel
BuildRequires: knot-devel
BuildRequires: libcdns-devel >= 1.5.0
BuildRequires: systemd-devel
BuildRequires: librdkafka-devel
BuildRequires: dpdk-devel

%if 0%{?fedora} > 35
BuildRequires: libarrow-devel
BuildRequires: parquet-libs-devel
%else
BuildRequires: arrow-devel
BuildRequires: parquet-devel
%endif

%description
High-speed DNS monitoring probe with export to Parquet or C-DNS

%package af
Summary: DNS probe with AF packet backend

%description af
Probe collecting records about DNS traffic in Parquet or C-DNS format.

%package dpdk
Summary: DNS probe with DPDK backend

%description dpdk
Probe collecting records about DNS traffic in Parquet or C-DNS format.

%package collector
Summary: Collector for data exported by DNS probe

%description collector
Collector for data exported by DNS probe with export to remote server enabled.

%prep
%autosetup -p1 -n dns-probe-%{version}
mkdir build

%build
cd build
cmake \
    -DCMAKE_INSTALL_PREFIX:PATH=%{_prefix} \
    -DAF_PACKET_BACKEND=ON \
    -DDPDK_BACKEND=ON \
    -DBUILD_COLLECTOR=ON \
    -DBUILD_DOC=ON \
    -DCMAKE_C_FLAGS="${RPM_OPT_FLAGS}" \
    -DCMAKE_CXX_FLAGS="${RPM_OPT_FLAGS}" \
    ..
make all man

%install
cd build
make DESTDIR=%{buildroot} install

%files af
%{_bindir}/dns-probe-af
%{_bindir}/dp-af
%config(noreplace) %{_sysconfdir}/dns-probe-af/dns-probe.yml
/lib/systemd/system/dns-probe-af@.service
%{_mandir}/man1/dns-probe-af.1.gz

%files dpdk
%{_bindir}/dns-probe-dpdk
%{_bindir}/dp-dpdk
%config(noreplace) %{_sysconfdir}/dns-probe-dpdk/dns-probe.yml
/lib/systemd/system/dns-probe-dpdk@.service
%{_mandir}/man1/dns-probe-dpdk.1.gz

%files collector
%{_bindir}/dp-collector
/lib/systemd/system/dns-probe-collector.service
%config(noreplace) %{_sysconfdir}/dns-probe-collector/dp-collector.conf
%{_mandir}/man1/dp-collector.1.gz

%changelog
* {{ now }} Pavel Dolezal <pavel.dolezal@nic.cz> - {{ version }}-{{ release }}
- upstream package

