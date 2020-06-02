# This stage builds an rpm from the source
FROM centos:centos7 as centos-7-builder
RUN yum install -y epel-release
RUN yum install -y rpm-build autoconf automake libtool make \
        readline-devel texinfo net-snmp-devel groff pkgconfig \
        json-c-devel pam-devel bison flex pytest c-ares-devel \
        python3-devel python3-sphinx systemd-devel libcap-devel \
        https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-10/CentOS-7-x86_64-Packages/libyang-0.16.111-0.x86_64.rpm \
        https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-10/CentOS-7-x86_64-Packages/libyang-devel-0.16.111-0.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-0.7.0-1.el7.centos.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-devel-0.7.0-1.el7.centos.x86_64.rpm

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
    && yum install -y https://ci1.netdef.org/artifact/LIBYANG-YANGRELEASE/shared/build-10/CentOS-7-x86_64-Packages/libyang-0.16.111-0.x86_64.rpm \
        https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-110/CentOS-7-x86_64-Packages/librtr-0.7.0-1.el7.centos.x86_64.rpm

COPY --from=centos-7-builder /rpmbuild/RPMS/ /pkgs/rpm/

RUN yum install -y /pkgs/rpm/*/*.rpm \
    && rm -rf /pkgs
COPY docker/centos-7/docker-start /usr/lib/frr/docker-start
ENTRYPOINT [ "/usr/lib/frr/docker-start" ]
