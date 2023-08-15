FROM ubuntu:18.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y \
        autoconf \
        binutils \
        bison \
        ca-certificates \
        flex \
        gdb \
        git \
        gpg \
        install-info \
        iputils-ping \
        iproute2 \
        less \
        libtool \
        libjson-c-dev \
        libpcre3-dev \
        libpython-dev \
        libpython3-dev \
        libreadline-dev \
        libc-ares-dev \
        libcap-dev \
        libelf-dev \
        man \
        mininet \
        pkg-config \
        python-pip \
        python3 \
        python3-dev \
        python3-sphinx \
        python3-pytest \
        rsync \
        strace \
        tcpdump \
        texinfo \
        tmux \
        valgrind \
        vim \
        wget \
        x11-xserver-utils \
        xterm \
    && pip install \
        exabgp==3.4.17 \
        "scapy>=2.4.2" \
        ipaddr \
        pytest \
    && rm -rf /var/lib/apt/lists/*

RUN export DEBIAN_FRONTEND=noninteractive \
    && wget -qO- https://deb.frrouting.org/frr/keys.asc | apt-key add - \
    && echo "deb https://deb.frrouting.org/frr bionic frr-stable" > /etc/apt/sources.list.d/frr.list \
    && apt-get update \
    && apt-get install -y libyang-dev \
    && rm -rf /var/lib/apt/lists/*

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

# Install libnl-3.7.0
RUN wget https://github.com/thom311/libnl/releases/download/libnl3_7_0/libnl-3.7.0.tar.gz  -q \
&& tar -xf libnl-3.7.0.tar.gz \
&& cd libnl-3.7.0 \
&& ./configure --prefix=/usr     \
            --sysconfdir=/etc \
            --disable-static  \
&& make -j 8 \
&& make install  > /dev/null 

ENTRYPOINT [ "bash", "/opt/topotests/entrypoint.sh" ]
