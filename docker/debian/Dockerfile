FROM debian:stretch
MAINTAINER Rob Gil (rob@rem5.com)
RUN apt-get update
RUN apt-get install -y libpcre3-dev apt-transport-https ca-certificates curl wget logrotate \
    libc-ares2 libjson-c3 vim systemd procps
RUN curl -sLO https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-1/Debian-9-x86_64-Packages/libyang_0.16.46_amd64.deb && dpkg -i libyang_0.16.46_amd64.deb
RUN curl -sLO https://github.com/FRRouting/frr/releases/download/frr-6.0.2/frr_6.0.2-0.deb9u1_amd64.deb && dpkg -i frr_6.0.2-0.deb9u1_amd64.deb
ADD daemons /etc/frr/daemons
ADD docker-start /usr/sbin/docker-start
ENTRYPOINT ["/usr/sbin/docker-start"]
