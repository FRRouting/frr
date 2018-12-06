FROM ubuntu:18.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y \
        autoconf \
        binutils \
        bison \
        flex \
        gdb \
        git \
        install-info \
        iputils-ping \
        iproute2 \
        less \
        libtool \
        libjson-c-dev \
        libpcre3-dev \
        libpython-dev \
        libreadline-dev \
        libc-ares-dev \
        man \
        mininet \
        pkg-config \
        python-pip \
        python-sphinx \
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
        ipaddr \
        pytest

RUN cd /tmp \
    && wget -q https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-1/Ubuntu-18.04-x86_64-Packages/libyang-dev_0.16.46_amd64.deb \
         -O libyang-dev.deb \
    && wget -q https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-1/Ubuntu-18.04-x86_64-Packages/libyang_0.16.46_amd64.deb \
         -O libyang.deb \
    && echo "039252cc66eb254a97e160b1c325af669470cde8a02d73ec9f7b920ed3c7997c  libyang.deb" | sha256sum -c - \
    && echo "e7e2d5bfc7b33b3218df8bef404432970f9b4ad10d6dbbdcb0e0be2babbb68e9  libyang-dev.deb" | sha256sum -c - \
    && dpkg -i libyang*.deb \
    && rm libyang*.deb

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
