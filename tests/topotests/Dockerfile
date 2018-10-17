FROM ubuntu:18.04

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y \
        autoconf \
        binutils \
        bison \
        flex \
        gdb \
        inetutils-ping \
        install-info \
        iproute2 \
        less \
        libtool \
        libjson-c-dev \
        libpython-dev \
        libreadline-dev \
        libc-ares-dev \
        man \
        mininet \
        pkg-config \
        python-pip \
        python-sphinx \
        rsync \
        tcpdump \
        texinfo \
        tmux \
        valgrind \
        vim \
        x11-xserver-utils \
        xterm \
    && pip install \
        exabgp==3.4.17 \
        ipaddr \
        pytest

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
COPY . /root/topotests
WORKDIR /root
ENV PATH "$PATH:/root/topotests/docker"

RUN echo "cat /root/topotests/docker/motd.txt" >> /root/.profile && \
      echo "export PS1='(topotests) $PS1'" >> /root/.profile

ENTRYPOINT [ "bash", "/root/topotests/docker/entrypoint.sh" ]
