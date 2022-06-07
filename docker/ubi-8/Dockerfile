# This stage builds an rpm from the source
FROM registry.access.redhat.com/ubi8/ubi:8.5 as ubi-8-builder

RUN dnf -y update-minimal --security --sec-severity=Important --sec-severity=Critical

RUN rpm --import https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official \
    && dnf config-manager --disableplugin subscription-manager --add-repo http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os \
    && dnf config-manager --disableplugin subscription-manager --add-repo http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os \
    && dnf config-manager --disableplugin subscription-manager --add-repo http://mirror.centos.org/centos/8-stream/PowerTools/x86_64/os

RUN dnf install -qy https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm \
    && dnf install --enablerepo=* -qy rpm-build git autoconf pcre-devel \
    systemd-devel automake libtool make  readline-devel  texinfo  \
    net-snmp-devel  pkgconfig  groff pkgconfig  json-c-devel pam-devel  \
    bison  flex  python3-pytest  c-ares-devel python3-devel python3-sphinx \
    libcap-devel  platform-python-devel \
    https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-8-x86_64-Packages/libyang2-2.0.0.10.g2eb910e4-1.el8.x86_64.rpm \
    https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-8-x86_64-Packages/libyang2-devel-2.0.0.10.g2eb910e4-1.el8.x86_64.rpm \
    https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-00146/CentOS-7-x86_64-Packages/librtr-0.8.0-1.el7.x86_64.rpm \
    https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-00146/CentOS-7-x86_64-Packages/librtr-devel-0.8.0-1.el7.x86_64.rpm


COPY . /src

ARG PKGVER

RUN echo '%_smp_mflags %( echo "-j$(/usr/bin/getconf _NPROCESSORS_ONLN)"; )' >> /root/.rpmmacros \
    && cd /src \
    && ./bootstrap.sh \
    && ./configure \
        --enable-rpki \
        --enable-snmp=agentx \
        --enable-numeric-version \
        --with-pkg-extra-version="_palmetto_git$PKGVER" \
    && make dist \
    && cd / \
    && mkdir -p /rpmbuild/{SOURCES,SPECS} \
    && cp /src/frr*.tar.gz /rpmbuild/SOURCES \
    && cp /src/redhat/frr.spec /rpmbuild/SPECS \
    && rpmbuild \
        --define "_topdir /rpmbuild" \
        -ba /rpmbuild/SPECS/frr.spec

# This stage installs frr from the rpm
FROM registry.access.redhat.com/ubi8/ubi:8.5
RUN dnf -y update-minimal --security --sec-severity=Important --sec-severity=Critical
ARG FRR_IMAGE_TAG
ARG FRR_RELEASE
ARG FRR_NAME
ARG FRR_VENDOR
LABEL name=$FRR_NAME \
      vendor=$FRR_VENDOR \
      version=$FRR_IMAGE_TAG \
      release=$FRR_RELEASE

RUN rpm --import https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official \
    && dnf config-manager --disableplugin subscription-manager --add-repo http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os \
    && dnf config-manager --disableplugin subscription-manager --add-repo http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os

RUN dnf install -qy https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm \
    && mkdir -p /pkgs/rpm \
    && dnf install --enablerepo=* -qy https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-8-x86_64-Packages/libyang2-2.0.0.10.g2eb910e4-1.el8.x86_64.rpm \
    https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-00146/CentOS-7-x86_64-Packages/librtr-0.8.0-1.el7.x86_64.rpm

COPY --from=ubi-8-builder /rpmbuild/RPMS/ /pkgs/rpm/

RUN dnf install -qy /pkgs/rpm/*/*.rpm \
    && rm -rf /pkgs \
# Own the config / PID files
    && mkdir -p /var/run/frr \
    && chown -R frr:frr /etc/frr /var/run/frr

# Add tini because no CentOS8 package
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /sbin/tini
RUN chmod +x /sbin/tini

# Simple init manager for reaping processes and forwarding signals
ENTRYPOINT ["/sbin/tini", "--"]

# Default CMD starts watchfrr
COPY docker/ubi-8/docker-start /usr/lib/frr/docker-start
CMD ["/usr/lib/frr/docker-start"]
