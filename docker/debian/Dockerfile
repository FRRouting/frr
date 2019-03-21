FROM debian:stretch
MAINTAINER Rob Gil (rob@rem5.com)
RUN apt-get update
RUN apt-get install -y libpcre3-dev apt-transport-https ca-certificates curl wget logrotate \
    libc-ares2 libjson-c3 vim systemd procps
RUN addgroup --system --gid 92 frr && \
    addgroup --system --gid 85 frrvty && \
    adduser --system --ingroup frr --home /var/opt/frr/ \
    --gecos "FRR suite" --shell /bin/false frr && \
    usermod -a -G frrvty frr
RUN mkdir -p /etc/frr /var/run/frr && \
    touch /etc/frr/vtysh.conf && \
    touch /etc/frr/zebra.conf && \
    touch /etc/frr/bgpd.conf && \
    touch /etc/frr/ospfd.conf && \
    touch /etc/frr/ospf6d.conf && \
    touch /etc/frr/isisd.conf && \
    touch /etc/frr/ripd.conf && \
    touch /etc/frr/ripngd.conf && \
    touch /etc/frr/pimd.conf && \
    touch /etc/frr/nhrpd.conf && \
    touch /etc/frr/eigrpd.conf && \
    touch /etc/frr/babeld.conf && \
    touch /etc/frr/daemons.conf && \
    chown frr:frr /etc/frr/ /var/run/frr -R && \
    chown frr:frrvty /etc/frr/vtysh.conf && \
    chmod 640 /etc/frr/*.conf
COPY --chown=frr:frrvty bin/ /usr/bin/
COPY --chown=frr:frrvty include/ /usr/include/
COPY --chown=frr:frrvty lib/ /usr/lib/
COPY --chown=frr:frrvty sbin/ /usr/sbin/
COPY --chown=frr:frrvty share/ /usr/share/
COPY --chown=frr:frrvty daemons /etc/frr/daemons
COPY --chown=frr:frrvty docker-start /usr/sbin/docker-start
COPY --chown=frr:frrvty etc/init.d/frr /etc/init.d/frr
COPY --chown=frr:frrvty libyang/extensions/ /usr/local/lib/libyang/extensions/
COPY --chown=frr:frrvty libyang/user_types/ /usr/local/lib/libyang/user_types/
#ADD daemons /etc/frr/daemons
#ADD docker-start /usr/sbin/docker-start
#ENTRYPOINT ["/usr/sbin/docker-start"]
