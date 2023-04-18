# This stage builds an rpm from the source
FROM centos:centos7 as centos-7-builder
RUN yum install -y epel-release
RUN yum install -y rpm-build autoconf automake libtool make \
        readline-devel texinfo net-snmp-devel groff pkgconfig \
        json-c-devel pam-devel bison flex pytest c-ares-devel \
        python3-devel python3-sphinx libcap-devel systemd-devel \
        protobuf-c-devel \
        https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-7-x86_64-Packages/libyang2-2.0.0.10.g2eb910e4-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-7-x86_64-Packages/libyang2-devel-2.0.0.10.g2eb910e4-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-00146/CentOS-7-x86_64-Packages/librtr-0.8.0-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-00146/CentOS-7-x86_64-Packages/librtr-devel-0.8.0-1.el7.x86_64.rpm

COPY . /src
ARG PKGVER

RUN echo '%_smp_mflags %( echo "-j$(/usr/bin/getconf _NPROCESSORS_ONLN)"; )' >> /root/.rpmmacros \
    && cd /src \
    && ./bootstrap.sh \
    && ./configure \
        --enable-rpki \
        --enable-numeric-version \
        --with-pkg-extra-version="_git$PKGVER" \
    && make dist \
    && cd / \
    && mkdir -p /rpmbuild/{SOURCES,SPECS} \
    && cp /src/frr*.tar.gz /rpmbuild/SOURCES \
    && cp /src/redhat/frr.spec /rpmbuild/SPECS \
    && rpmbuild \
        --define "_topdir /rpmbuild" \
        -ba /rpmbuild/SPECS/frr.spec

# This stage installs frr from the rpm
FROM centos:centos7
RUN mkdir -p /pkgs/rpm \
    && yum install -y https://ci1.netdef.org/artifact/LIBYANG-LIBYANGV2/shared/build-2/CentOS-7-x86_64-Packages/libyang2-2.0.0.10.g2eb910e4-1.el7.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-00146/CentOS-7-x86_64-Packages/librtr-0.8.0-1.el7.x86_64.rpm

COPY --from=centos-7-builder /rpmbuild/RPMS/ /pkgs/rpm/

RUN yum install -y /pkgs/rpm/*/*.rpm \
    && rm -rf /pkgs

# Own the config / PID files
RUN mkdir -p /var/run/frr
RUN chown -R frr:frr /etc/frr /var/run/frr

# Add tini because no CentOS7 package
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /sbin/tini
RUN chmod +x /sbin/tini

# Simple init manager for reaping processes and forwarding signals
ENTRYPOINT ["/sbin/tini", "--"]

# Default CMD starts watchfrr
COPY docker/centos-7/docker-start /usr/lib/frr/docker-start
CMD ["/usr/lib/frr/docker-start"]
