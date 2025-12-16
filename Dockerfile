FROM debian:10

MAINTAINER Pavel Doležal (pavel.dolezal@nic.cz)
LABEL version="stable"
LABEL description="Debian 10 with pre-installed DNS Probe"

RUN echo "deb http://archive.debian.org/debian buster main contrib non-free" > /etc/apt/sources.list &&\
    echo "deb http://archive.debian.org/debian-security buster/updates main contrib non-free" >> /etc/apt/sources.list &&\
    echo "deb http://archive.debian.org/debian buster-backports main contrib non-free" >> /etc/apt/sources.list &&\
    apt-get update -yqq &&\
    apt-get install -yqq gnupg curl apt-transport-https ca-certificates lsb-release wget &&\
    wget https://packages.apache.org/artifactory/arrow/$(lsb_release --id --short | tr 'A-Z' 'a-z')/apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb &&\
    apt-get install -yqq -V ./apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb &&\
    echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/dns-probe/Debian_10/ /' | tee /etc/apt/sources.list.d/dns-probe.list &&\
    curl -fsSL https://download.opensuse.org/repositories/home:CZ-NIC:/dns-probe/Debian_10/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/dns-probe.gpg > /dev/null &&\
    wget -O /usr/share/keyrings/cznic-labs-pkg.gpg https://pkg.labs.nic.cz/gpg &&\
    echo "deb [signed-by=/usr/share/keyrings/cznic-labs-pkg.gpg] https://pkg.labs.nic.cz/knot-dns buster main" | tee /etc/apt/sources.list.d/cznic-labs-knot-dns.list &&\
    apt-get update -yqq &&\
    apt-get install -yqq --no-install-recommends \
        pkg-config \
        git \
        g++ \
        make \
        cmake \
        procps \
        doxygen \
        python3 \
        python3-pip \
        python3-pandas \
        python3-sphinx \
        libssl-dev \
        libboost-all-dev \
        libcdns-dev \
        libpcap-dev \
        libarrow-dev \
        libarrow-python-dev \
        libparquet-dev \
        libcryptopant-dev \
        libyaml-cpp-dev \
        libprotobuf-dev \
        protobuf-compiler \
        libfstrm-dev \
        libmaxminddb-dev \
        libknot-dev \
        librdkafka-dev \
        zlib1g-dev \
        rapidjson-dev \
        dpdk-dev \
        dns-probe-af \
        dns-probe-dpdk &&\
    pip3 install pyarrow==2.0.* &&\
    apt-get -qy autoremove &&\
    apt-get -y clean
