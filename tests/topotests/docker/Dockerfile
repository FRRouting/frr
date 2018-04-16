FROM ubuntu:18.04

# Update system repos
RUN DEBIAN_FRONTEND=noninteractive apt update

# Install FRR dependencies
RUN DEBIAN_FRONTEND=noninteractive apt install -y \
      autoconf binutils bison flex libtool libjson-c-dev \
      libpython-dev libreadline-dev libc-ares-dev python-sphinx \
      install-info pkg-config texinfo

# Install useful tools for debugging
RUN DEBIAN_FRONTEND=noninteractive apt install -y \
      gdb inetutils-ping iproute2 valgrind

# Install mininet dependencies
RUN DEBIAN_FRONTEND=noninteractive apt install -y \
      mininet python-pip && \
      pip install ipaddr pytest exabgp==3.4.17

# Install user utilities
RUN DEBIAN_FRONTEND=noninteractive apt install -y \
      x11-xserver-utils xterm tmux vim tcpdump less man rsync

# Configure FRR users
RUN groupadd -r -g 92 frr && \
      groupadd -r -g 85 frrvty && \
      useradd -c "FRRouting suite" -d /var/run/frr -g frr -G frrvty \
        -r -s /sbin/nologin frr

# Configure exabgp user.
RUN useradd -d /var/run/exabgp/ -s /bin/false exabgp

# Configure coredumps.
RUN echo "" >> /etc/security/limits.conf; \
    echo "* soft core unlimited" >> /etc/security/limits.conf; \
    echo "root soft core unlimited" >> /etc/security/limits.conf; \
    echo "* hard core unlimited" >> /etc/security/limits.conf; \
    echo "root hard core unlimited" >> /etc/security/limits.conf

# Copy run scripts to facilitate users wanting to run the tests
COPY . /opt/topotests
WORKDIR /root

RUN echo "cat /opt/topotests/motd.txt" >> /root/.profile && \
      echo "export PS1='(topotests) $PS1'" >> /root/.profile

# Configure volumes
VOLUME [ "/root/frr", "/root/topotests" ]

# Add topotests script directory to path
ENV PATH "$PATH:/opt/topotests"

# Use our custom entrypoint script
ENTRYPOINT [ "bash", "/opt/topotests/entrypoint.sh" ]
