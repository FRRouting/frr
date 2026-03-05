ARG UBUNTU_VERSION=22.04
FROM ubuntu:$UBUNTU_VERSION

# If passed, update the value
ARG UBUNTU_VERSION
ARG DEBIAN_FRONTEND=noninteractive

# Number of retries for transient network failures
ARG APT_RETRIES=3

# Optional mirror for MIB downloads (expects mirrored https path layout).
ARG MIB_MIRROR_BASE_URL=

# LTTng tracing support (optional)
ARG ENABLE_LTTNG=false

# Configure apt to retry on transient network failures
RUN echo "Acquire::Retries \"${APT_RETRIES}\";" > /etc/apt/apt.conf.d/80-retries && \
    echo 'Acquire::http::Timeout "30";' >> /etc/apt/apt.conf.d/80-retries && \
    echo 'Acquire::https::Timeout "30";' >> /etc/apt/apt.conf.d/80-retries

# Update and install build requirements.
# Retry loop for apt-get update/upgrade/install in case of transient mirror failures
RUN for i in $(seq 1 ${APT_RETRIES}); do \
        apt-get update && \
        apt-get upgrade -y && \
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
            iptables \
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
        ssmping \
        sudo \
        time \
        tshark \
        valgrind \
        yodl \
        && break || sleep 10; \
    done && \
    download-mibs && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/iana/IANA-IPPM-METRICS-REGISTRY-MIB -O /usr/share/snmp/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/SNMPv2-PDU -O /usr/share/snmp/mibs/ietf/SNMPv2-PDU && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/IPATM-IPMC-MIB -O /usr/share/snmp/mibs/ietf/IPATM-IPMC-MIB && \
    rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
    python3 -m pip install wheel && \
    bash -c "PV=($(pkg-config --modversion protobuf | tr '.' ' ')); if (( PV[0] == 3 && PV[1] < 19 )); then python3 -m pip install 'protobuf<4' grpcio grpcio-tools; else python3 -m pip install 'protobuf>=4' grpcio grpcio-tools; fi" && \
    python3 -m pip install 'pytest>=6.2.4' 'pytest-xdist>=3.6.1' 'pytest-asyncio>=0.25.3' && \
    python3 -m pip install 'scapy>=2.4.5' && \
    python3 -m pip install pyyaml && \
    python3 -m pip install xmltodict && \
    python3 -m pip install git+https://github.com/Exa-Networks/exabgp@0659057837cd6c6351579e9f0fa47e9fb7de7311

# LTTng tracing dependencies (conditional)
RUN if [ "$ENABLE_LTTNG" = "true" ]; then \
        apt-get install -y liblttng-ust-dev; \
    fi

COPY docker/ubuntu-ci/ /tmp/ubuntu-ci-assets/

RUN if [ "$UBUNTU_VERSION" = "24.04" ]; then \
        # Fetch with optional mirror fallback and exponential backoff.
        fetch_mib() { \
            src_url="$1"; \
            dest_path="$2"; \
            mirror_url=""; \
            cache_path="/tmp/ubuntu-ci-assets/mib-cache/$(basename "$dest_path")"; \
            if [ -s "$cache_path" ]; then \
                cp "$cache_path" "$dest_path" && return 0; \
            fi; \
            if [ -n "$MIB_MIRROR_BASE_URL" ]; then \
                mirror_url="${MIB_MIRROR_BASE_URL%/}/${src_url#https://}"; \
            fi; \
            attempt=1; \
            max_attempts=8; \
            while [ "$attempt" -le "$max_attempts" ]; do \
                if [ -n "$mirror_url" ]; then \
                    wget --tries=1 --timeout=30 --retry-connrefused "$mirror_url" -O "$dest_path" && return 0; \
                fi; \
                wget --tries=1 --timeout=30 --retry-connrefused "$src_url" -O "$dest_path" && return 0; \
                sleep_time=$((attempt * 5)); \
                echo "Retrying MIB fetch (${attempt}/${max_attempts}) for $src_url in ${sleep_time}s" >&2; \
                sleep "$sleep_time"; \
                attempt=$((attempt + 1)); \
            done; \
            echo "Failed to fetch $src_url after ${max_attempts} attempts" >&2; \
            return 1; \
        }; \
        fetch_mib https://www.iana.org/assignments/ianasmf-mib/ianasmf-mib /usr/share/snmp/mibs/iana/IANA-SMF-MIB && \
        fetch_mib https://www.iana.org/assignments/ianaentity-mib/ianaentity-mib /usr/share/snmp/mibs/iana/IANA-ENTITY-MIB && \
        fetch_mib https://www.iana.org/assignments/ianapowerstateset-mib/ianapowerstateset-mib /usr/share/snmp/mibs/iana/IANAPowerStateSet-MIB && \
        fetch_mib https://www.iana.org/assignments/ianaolsrv2linkmetrictype-mib/ianaolsrv2linkmetrictype-mib /usr/share/snmp/mibs/iana/IANA-OLSRv2-LINK-METRIC-TYPE-MIB && \
        fetch_mib https://www.iana.org/assignments/ianaenergyrelation-mib/ianaenergyrelation-mib /usr/share/snmp/mibs/iana/IANA-ENERGY-RELATION-MIB && \
        fetch_mib https://www.iana.org/assignments/ianabfdtcstd-mib/ianabfdtcstd-mib /usr/share/snmp/mibs/iana/IANA-BFD-TC-STD-MIB && \
        fetch_mib https://www.iana.org/assignments/ianastoragemediatype-mib/ianastoragemediatype-mib /usr/share/snmp/mibs/iana/IANA-STORAGE-MEDIA-TYPE-MIB && \
        fetch_mib https://www.ieee802.org/1/files/public/MIBs/IEEE8021-CFM-MIB.mib /usr/share/snmp/mibs/IEEE8021-CFM-MIB && \
        fetch_mib https://www.ieee802.org/1/files/public/MIBs/LLDP-MIB-200505060000Z.mib /usr/share/snmp/mibs/LLDP-MIB; \
    fi

ARG UID=1010
RUN groupadd -r -g 92 frr && \
      groupadd -r -g 85 frrvty && \
      adduser --system --ingroup frr --home /home/frr \
              --gecos "FRR suite" -u $UID --shell /bin/bash frr && \
      usermod -a -G frrvty frr && \
      useradd -d /var/run/exabgp/ -s /bin/false exabgp && \
      echo 'frr ALL = NOPASSWD: ALL' | tee /etc/sudoers.d/frr && \
      mkdir -p /home/frr && chown frr.frr /home/frr

# Install FRR built packages
# Retry loop for curl in case of transient network failures
RUN mkdir -p /etc/apt/keyrings && \
    for i in $(seq 1 ${APT_RETRIES}); do \
        curl -sf -o /etc/apt/keyrings/frrouting.gpg https://deb.frrouting.org/frr/keys.gpg && break || sleep 10; \
    done && \
    echo deb '[signed-by=/etc/apt/keyrings/frrouting.gpg]' https://deb.frrouting.org/frr \
        $(lsb_release -s -c) "frr-stable" > /etc/apt/sources.list.d/frr.list && \
    for i in $(seq 1 ${APT_RETRIES}); do apt-get update && break || sleep 10; done && \
    apt-get install -y librtr-dev

# build and install libyang3
RUN cd && pwd && ls -al && \
    git clone https://github.com/CESNET/libyang.git && \
    cd libyang && \
    git checkout v3.13.6 && \
    mkdir build; cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
    -DCMAKE_BUILD_TYPE:String="Debug" .. && \
    make -j $(nproc) && \
    sudo make install
RUN python3 -m pip install 'libyang<4'

USER frr:frr

# Re-declare ARG after USER to make it available
ARG ENABLE_LTTNG=false
# CI build arg used to invalidate the compile layer when source revision changes.
ARG FRR_SOURCE_REV=unknown

COPY --chown=frr:frr . /home/frr/frr/

RUN cd ~/frr && \
    echo "Building FRR source revision: ${FRR_SOURCE_REV}" && \
    ./bootstrap.sh && \
    LTTNG_OPT="" && \
    if [ "$ENABLE_LTTNG" = "true" ]; then LTTNG_OPT="--enable-lttng"; fi && \
    ./configure \
       --prefix=/usr \
       --sysconfdir=/etc \
       --localstatedir=/var \
       --sbindir=/usr/lib/frr \
       --enable-gcov \
       --enable-dev-build \
       --enable-mgmtd-test-be-client \
       --enable-rpki \
       --enable-sharpd \
       --enable-multipath=256 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-config-rollbacks \
       --enable-grpc \
       --enable-protobuf \
       --enable-vty-group=frrvty \
       --enable-snmp \
       --enable-scripting \
       $LTTNG_OPT \
       --with-pkg-extra-version=-my-manual-build && \
    make -j $(nproc) && \
    sudo make install

RUN cd ~/frr && make check || true

COPY docker/ubuntu-ci/docker-start /usr/sbin/docker-start
CMD ["/usr/sbin/docker-start"]
