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
        libcap-dev \
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
    && wget -q https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-10/Debian-AMD64-Packages/libyang-dev_0.16.105-1_amd64.deb \
         -O libyang-dev.deb \
    && wget -q https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-10/Debian-AMD64-Packages/libyang0.16_0.16.105-1_amd64.deb \
         -O libyang.deb \
    && echo "34bef017e527a590020185f05dc39203bdf1c86223e0d990839623ec629d8598  libyang.deb" | sha256sum -c - \
    && echo "fe9cc6e3b173ca56ef49428c281e96bf76c0f910aa75cf85098076411484e8f4  libyang-dev.deb" | sha256sum -c - \
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
