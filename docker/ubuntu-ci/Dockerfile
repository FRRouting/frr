ARG UBUNTU_VERSION=22.04
FROM ubuntu:$UBUNTU_VERSION

ARG DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn

# Update and install build requirements.
RUN apt update && apt upgrade -y && \
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
            libtool \
            make \
            perl \
            pkg-config \
            python3-dev \
            python3-sphinx \
            texinfo \
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
    # Runtime/triage/testing requirements
    apt-get install -y \
        curl \
        gdb \
        iproute2 \
        iputils-ping \
        liblua5.3-dev \
        libssl-dev \
        lua5.3 \
        net-tools \
        python2 \
        python3-pip \
        snmp \
        snmp-mibs-downloader \
        snmpd \
        sudo \
        time \
        tshark \
        valgrind \
        yodl \
      && \
    download-mibs && \
    wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/iana/IANA-IPPM-METRICS-REGISTRY-MIB -O /usr/share/snmp/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB && \
    wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/SNMPv2-PDU -O /usr/share/snmp/mibs/ietf/SNMPv2-PDU && \
    wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/IPATM-IPMC-MIB -O /usr/share/snmp/mibs/ietf/IPATM-IPMC-MIB && \
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py && \
    python2 /tmp/get-pip.py && \
    rm -f  /tmp/get-pip.py && \
    python3 -m pip install wheel && \
    python3 -m pip install pytest && \
    python3 -m pip install pytest-sugar && \
    python3 -m pip install pytest-xdist && \
    python3 -m pip install "scapy>=2.4.2" && \
    python3 -m pip install xmltodict && \
    python3 -m pip install grpcio grpcio-tools && \
    python2 -m pip install 'exabgp<4.0.0'

RUN groupadd -r -g 92 frr && \
      groupadd -r -g 85 frrvty && \
      adduser --system --ingroup frr --home /home/frr \
              --gecos "FRR suite" --shell /bin/bash frr && \
      usermod -a -G frrvty frr && \
      useradd -d /var/run/exabgp/ -s /bin/false exabgp && \
      echo 'frr ALL = NOPASSWD: ALL' | tee /etc/sudoers.d/frr && \
      mkdir -p /home/frr && chown frr.frr /home/frr

USER frr:frr

# build and install libyang2
RUN cd && pwd && ls -al && \
    git clone https://github.com/CESNET/libyang.git && \
    cd libyang && \
    git checkout v2.1.80 && \
    mkdir build; cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
          -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make -j $(nproc) && \
    sudo make install

COPY --chown=frr:frr . /home/frr/frr/

RUN cd ~/frr && \
    ./bootstrap.sh && \
    ./configure \
       --prefix=/usr \
       --localstatedir=/var/run/frr \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
       --enable-sharpd \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-config-rollbacks \
       --enable-vty-group=frrvty \
       --enable-snmp=agentx \
       --enable-scripting \
       --with-pkg-extra-version=-my-manual-build && \
    make -j $(nproc) && \
    sudo make install

RUN cd ~/frr && make check || true

COPY docker/ubuntu-ci/docker-start /usr/sbin/docker-start
CMD ["/usr/sbin/docker-start"]
