FROM debian:13

ARG DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn

# Add non-free to sources if not already present, needed for snmp-mibs-downloader
RUN sed -i '/^Components:/ {/non-free\([^-]\|$\)/! s/$/ non-free/}' /etc/apt/sources.list.d/debian.sources && \
    apt update -y && apt upgrade -y && \
    # Basic build requirements from docs (building-frr-for-debian13.rst)
    apt-get install -y \
            git \
            autoconf \
            automake \
            libtool \
            make \
            build-essential \
            python3-dev \
            python3-pytest \
            python3-sphinx \
            libjson-c-dev \
            libelf-dev \
            libreadline-dev \
            cmake \
            libcap-dev \
            bison \
            flex \
            pkg-config \
            texinfo \
            gdb \
    && \
    # Optional dependency, but having it only has pros
    apt-get install -y libunwind8 libunwind8-dev \
    && \
    # Debian 13 happens to ship a suitable version of libyang we can install right away
    apt-get install -y libyang-dev \
    && \
    # Diverse protobuf deps from docs (building-frr-for-debian13.rst)
    # Debian ships protobuf-compiler 3.21.X
    apt-get install -y libprotobuf-c-dev \
    protobuf-c-compiler \
    libgrpc-dev \
    libgrpc++-dev \
    python3-grpc-tools \
    libprotoc-dev \
    protobuf-compiler \
    libprotobuf-dev \
    protobuf-compiler-grpc \
    && \
    # Runtime/triage/testing requirements
    apt-get install -y \
        # Deps from topotests.rst "Installing Topotest Requirements"
        gdb \
        iproute2 \
        net-tools \
        python3-pip \
        iputils-ping \
        iptables \
        tshark \
        valgrind \
        ssmping \
        # SNMP Deps from topotests.rst "SNMP Utilities Installation"
        libsnmp-dev \
        snmpd \
        snmp \
        snmptrapd \
        snmp-mibs-downloader \
        # Misc tools needed for debugging and triaging
        # Yeah, we definitely need python, let's make sure it's there
        python3 \
        # Pretty sure someone is going to need it..
        nftables \
        # lcov is needed for code coverage tests
        lcov \
        # RR is a time travel debugger, topotest have built-in support for it
        rr \
        # tmux and screen are recommended for running the tests
        tmux \
        screen \
        # diverse file fetch / sync utilities
        rsync \
        curl \
        wget \
        # Now all the remaining utilities that have accumulated over time
        kmod \
        liblua5.3-dev \
        libssl-dev \
        lua5.3 \
        sudo \
        time \
        yodl \
        strace \
        tcpdump \
      && \
    download-mibs && \
    # SNMP download from docs
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.iana.org/assignments/ianasmf-mib/ianasmf-mib -O /usr/share/snmp/mibs/iana/IANA-SMF-MIB  && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.iana.org/assignments/ianaentity-mib/ianaentity-mib -O /usr/share/snmp/mibs/iana/IANA-ENTITY-MIB  && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.iana.org/assignments/ianapowerstateset-mib/ianapowerstateset-mib -O /usr/share/snmp/mibs/iana/IANAPowerStateSet-MIB  && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.iana.org/assignments/ianaolsrv2linkmetrictype-mib/ianaolsrv2linkmetrictype-mib -O /usr/share/snmp/mibs/iana/IANA-OLSRv2-LINK-METRIC-TYPE-MIB  && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.iana.org/assignments/ianaenergyrelation-mib/ianaenergyrelation-mib -O /usr/share/snmp/mibs/iana/IANA-ENERGY-RELATION-MIB  && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.iana.org/assignments/ianabfdtcstd-mib/ianabfdtcstd-mib -O /usr/share/snmp/mibs/iana/IANA-BFD-TC-STD-MIB  && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.iana.org/assignments/ianastoragemediatype-mib/ianastoragemediatype-mib -O /usr/share/snmp/mibs/iana/IANA-STORAGE-MEDIA-TYPE-MIB  && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.ieee802.org/1/files/public/MIBs/IEEE8021-CFM-MIB.mib -O /usr/share/snmp/mibs/IEEE8021-CFM-MIB  && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://www.ieee802.org/1/files/public/MIBs/LLDP-MIB-200505060000Z.mib -O /usr/share/snmp/mibs/LLDP-MIB  && \
    # Fixup the snmp.conf as descibed in topotests.rst "SNMP Utilities Installation"
    sed -i 's/^mibs :$/mibs +ALL/' /etc/snmp/snmp.conf && \
    # Python deps from topotests.rst "Installing Topotest Requirements"
    # Debian uses a system-managed python, so we install as many deps as debian packages as possible..
    apt-get install -y python3-wheel \
        python3-pytest \
        python3-pytest-asyncio \
        python3-pytest-xdist \
        python3-scapy \
        python3-yaml \
        python3-xmltodict \
        python3-grpcio \
        python3-grpc-tools \
        # Debian ships matching protobuf and python protobuf versions
        python3-protobuf && \
    # some deps are not packaged, and we don't want to deal with running FRR inside venv
    # and for those 2 deps it seems to be okay to "break" the system packages...
    python3 -m pip install --break-system-packages 'libyang<4' && \
    python3 -m pip install --break-system-packages git+https://github.com/Exa-Networks/exabgp@0659057837cd6c6351579e9f0fa47e9fb7de7311


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

ENV PATH "$PATH:/opt/topotests"

RUN echo "cat /opt/topotests/motd.txt" >> /root/.profile && \
      echo "export PS1='(topotests) $PS1'" >> /root/.profile

ENTRYPOINT [ "bash", "/opt/topotests/entrypoint.sh" ]
