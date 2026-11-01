FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn

RUN apt update -y && apt upgrade -y && \
    # Basic build requirements from documentation
    apt-get install -y \
            autoconf \
            automake \
            bison \
            build-essential \
            flex \
            git \
            install-info \
            libc-ares-dev \
            libcap-dev \
            libelf-dev \
            libjson-c-dev \
            libpam0g-dev \
            libreadline-dev \
            libsnmp-dev \
            libsqlite3-dev \
            lsb-release \
            libtool \
            lcov \
            make \
            perl \
            pkg-config \
            python3-dev \
            python3-sphinx \
            screen \
            texinfo \
            tmux \
    && \
    # Protobuf build requirements
    apt-get install -y \
        libprotobuf-c-dev \
        protobuf-c-compiler \
    && \
    # Libyang2 extra build requirements
    apt-get install -y \
        cmake \
        libpcre2-dev \
    && \
    # GRPC extra build requirements
    apt-get install -y \
        libgrpc-dev \
        libgrpc++-dev \
        protobuf-compiler-grpc \
    && \
    # Runtime/triage/testing requirements
    apt-get install -y \
        rsync \
        curl \
        gdb \
        kmod \
        iproute2 \
        iputils-ping \
        liblua5.3-dev \
        libssl-dev \
        lua5.3 \
        net-tools \
        python3 \
        python3-pip \
        snmp \
        snmp-mibs-downloader \
        snmpd \
        sudo \
        time \
        tshark \
        valgrind \
        yodl \
        strace \
        tcpdump \
      && \
    # eBPF compilation requirements
    apt-get install -y \
        clang \
        llvm \
      && \
    download-mibs && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/iana/IANA-IPPM-METRICS-REGISTRY-MIB -O /usr/share/snmp/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/SNMPv2-PDU -O /usr/share/snmp/mibs/ietf/SNMPv2-PDU && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/IPATM-IPMC-MIB -O /usr/share/snmp/mibs/ietf/IPATM-IPMC-MIB && \
    python3 -m pip install wheel && \
    python3 -m pip install 'protobuf<4' grpcio grpcio-tools && \
    python3 -m pip install 'pytest>=6.2.4' 'pytest-xdist>=2.3.0' && \
    python3 -m pip install 'scapy>=2.4.5' && \
    python3 -m pip install xmltodict && \
    python3 -m pip install git+https://github.com/Exa-Networks/exabgp@0659057837cd6c6351579e9f0fa47e9fb7de7311

# Install FRR built packages
RUN mkdir -p /etc/apt/keyrings && \
    curl -s -o /etc/apt/keyrings/frrouting.gpg https://deb.frrouting.org/frr/keys.gpg && \
    echo deb '[signed-by=/etc/apt/keyrings/frrouting.gpg]' https://deb.frrouting.org/frr \
        $(lsb_release -s -c) "frr-stable" > /etc/apt/sources.list.d/frr.list && \
    apt-get update && apt-get install -y librtr-dev libyang2-dev libyang2-tools

RUN apt install -y openvswitch-switch

RUN groupadd -r -g 92 frr \
    && groupadd -r -g 85 frrvty \
    && useradd -c "FRRouting suite" \
               -d /var/run/frr \
               -g frr \
               -G frrvty \
               -r \
               -s /sbin/nologin \
               frr \
    && useradd -d /var/run/exabgp/ \
               -s /bin/false \
               exabgp

# Configure coredumps
RUN echo "" >> /etc/security/limits.conf; \
    echo "* soft core unlimited" >> /etc/security/limits.conf; \
    echo "root soft core unlimited" >> /etc/security/limits.conf; \
    echo "* hard core unlimited" >> /etc/security/limits.conf; \
    echo "root hard core unlimited" >> /etc/security/limits.conf

# Copy run scripts to facilitate users wanting to run the tests
COPY docker/inner /opt/topotests

# libbpf: we need at least 1.3 for TCX in Split Horizon Filter
ARG LIBBPF_VERSION=1.8.0
ARG LIBBPF_CHECKSUM=b7a1e685f90f6a63ead0dd85d053694b222975da8d09c1a966041cff6f0055ff
RUN mkdir /tmp/compile-libbpf \
    && cd /tmp/compile-libbpf \
    && wget --tries=5 --waitretry=10 --retry-connrefused https://github.com/libbpf/libbpf/archive/refs/tags/v$LIBBPF_VERSION.tar.gz \
    && echo "$LIBBPF_CHECKSUM  v$LIBBPF_VERSION.tar.gz" | sha256sum -c - \
    && tar -xvf v$LIBBPF_VERSION.tar.gz \
    && cd libbpf-$LIBBPF_VERSION/src \
    && PREFIX=/usr/local LIBDIR=/usr/local/lib make \
    && PREFIX=/usr/local LIBDIR=/usr/local/lib make install \
    # Required for runtime search of libs in /usr/local/lib
    && ldconfig \
    && cd / \
    && rm -rf /tmp/compile-libbpf \
    ;


# bpftool: Ubuntu package is only wrapper that chooses path
# based on kernel version, this doesn't work under docker
ARG BPFTOOL_VERSION=7.8.1
ARG BPFTOOL_CHECKSUM=fed76b7acb54d810cc3982eb6394726010114977542fd146695887a7d904b60c
RUN mkdir /tmp/compile-bpftool \
    && cd /tmp/compile-bpftool \
    && wget --tries=5 --waitretry=10 --retry-connrefused https://github.com/libbpf/bpftool/releases/download/v$BPFTOOL_VERSION/bpftool-libbpf-v$BPFTOOL_VERSION-sources.tar.gz \
    && echo "$BPFTOOL_CHECKSUM  bpftool-libbpf-v$BPFTOOL_VERSION-sources.tar.gz" | sha256sum -c - \
    && tar -xvf bpftool-libbpf-v$BPFTOOL_VERSION-sources.tar.gz \
    && cd bpftool-libbpf-v$BPFTOOL_VERSION-sources/src \
    && make \
    && prefix=/usr/local make install \
    && rm -rf /tmp/compile-bpftool \
    && cd / \
    ;

ENV PATH "$PATH:/opt/topotests"

RUN echo "cat /opt/topotests/motd.txt" >> /root/.profile && \
      echo "export PS1='(topotests) $PS1'" >> /root/.profile

ENTRYPOINT [ "bash", "/opt/topotests/entrypoint.sh" ]
