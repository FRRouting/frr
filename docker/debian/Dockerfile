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
COPY --chown=frr:frrvty bin/ /usr/bin/
COPY --chown=frr:frrvty include/ /usr/include/
COPY --chown=frr:frrvty lib/ /usr/lib/
COPY --chown=frr:frrvty sbin/ /usr/sbin/
COPY --chown=frr:frrvty share/ /usr/share/
#ADD daemons /etc/frr/daemons
#ADD docker-start /usr/sbin/docker-start
#ENTRYPOINT ["/usr/sbin/docker-start"]
