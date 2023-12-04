# This stage builds an rpm from the source
ARG UBI8_MINIMAL_VERSION
FROM registry.access.redhat.com/ubi8/ubi-minimal:${UBI8_MINIMAL_VERSION} as ubi8-minimal-builder

RUN rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-8

ADD docker/ubi8-minimal/almalinux.repo /etc/yum.repos.d/almalinux.repo

# ubi8-minimal comes with broken tzdata package installed, so we need to remove them
# and later reinstall it again: https://bugzilla.redhat.com/show_bug.cgi?id=1668185
RUN rpm --quiet -e --nodeps tzdata >/dev/null 2>&1

# Keep the list of dependencies alphabetically sorted for easier maintenance
RUN microdnf --disableplugin=subscription-manager --setopt=install_weak_deps=0 install \
    autoconf \
    automake \
    bison \
    c-ares-devel \
    flex \
    git \
    groff \
    json-c-devel \
    libcap-devel \
    libssh-devel \
    libtool \
    make \
    net-snmp-devel \
    openssl \
    pam-devel  \
    pcre-devel \
    pkgconfig \
    platform-python-devel \
    protobuf-c-devel \
    python3-devel \
    python3-pytest \
    python3-sphinx \
    readline-devel \
    rpm-build \
    systemd-devel \
    texinfo \
    tzdata \
    && microdnf --disableplugin=subscription-manager clean all

RUN curl -sSL -o /tmp/libyang2.rpm https://ci1.netdef.org/artifact/LIBYANG-LIBYANG2/shared/build-181/RedHat-8-x86_64-Packages/libyang-2.1.80-1.el8.x86_64.rpm \
    && rpm -i /tmp/libyang2.rpm \
    && rm -f /tmp/libyang2.rpm

RUN curl -sSL -o /tmp/libyang2-devel.rpm https://ci1.netdef.org/artifact/LIBYANG-LIBYANG2/shared/build-181/RedHat-8-x86_64-Packages/libyang-devel-2.1.80-1.el8.x86_64.rpm \
    && rpm -i /tmp/libyang2-devel.rpm \
    && rm -f /tmp/libyang2-devel.rpm

RUN curl -sSL -o /tmp/librtr.rpm https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-149/RedHat-8-x86_64-Packages/librtr-0.8.0-1.el8.x86_64.rpm \
    && rpm -i /tmp/librtr.rpm \
    && rm -f /tmp/librtr.rpm

RUN curl -sSL -o /tmp/librtr-devel.rpm https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-149/RedHat-8-x86_64-Packages/librtr-devel-0.8.0-1.el8.x86_64.rpm \
    && rpm -i /tmp/librtr-devel.rpm \
    && rm -f /tmp/librtr-devel.rpm

COPY . /src

ARG PKGVER

RUN echo '%_smp_mflags %( echo "-j$(/usr/bin/getconf _NPROCESSORS_ONLN)"; )' >> /root/.rpmmacros \
    && cd /src \
    && ./bootstrap.sh \
    && ./configure \
        --enable-rpki \
        --enable-snmp=agentx \
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
FROM registry.access.redhat.com/ubi8/ubi-minimal:${UBI8_MINIMAL_VERSION}
ARG FRR_IMAGE_TAG
ARG FRR_RELEASE
ARG FRR_NAME
ARG FRR_VENDOR
LABEL name=$FRR_NAME \
      vendor=$FRR_VENDOR \
      version=$FRR_IMAGE_TAG \
      release=$FRR_RELEASE

ADD docker/ubi8-minimal/almalinux.repo /etc/yum.repos.d/almalinux.repo

RUN rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-8

# Keep the list of dependencies alphabetically sorted for easier maintenance
RUN microdnf --disableplugin=subscription-manager --setopt=install_weak_deps=0 install \
    c-ares \
    initscripts \
    net-snmp-agent-libs \
    net-snmp-libs \
    openssl \
    protobuf-c \
    python3 \
    shadow-utils \
    systemd \
    && microdnf --disableplugin=subscription-manager clean all

RUN curl -sSL -o /tmp/libyang2.rpm https://ci1.netdef.org/artifact/LIBYANG-LIBYANG2/shared/build-181/RedHat-8-x86_64-Packages/libyang-2.1.80-1.el8.x86_64.rpm \
    && rpm -i /tmp/libyang2.rpm \
    && rm -f /tmp/libyang2.rpm

RUN curl -sSL -o /tmp/librtr.rpm https://ci1.netdef.org/artifact/RPKI-RTRLIB/shared/build-149/RedHat-8-x86_64-Packages/librtr-0.8.0-1.el8.x86_64.rpm \
    && rpm -i /tmp/librtr.rpm \
    && rm -f /tmp/librtr.rpm

COPY --from=ubi8-minimal-builder /rpmbuild/RPMS/ /pkgs/rpm/

# Install packages and create FRR files and folders. Be sure to own the config / PID files
RUN rpm -i /pkgs/rpm/x86_64/*.rpm \
    && rm -rf /pkgs \
    && rm -rf /mnt/rootfs/var/cache/* /mnt/rootfs/var/log/dnf* /mnt/rootfs/var/log/yum.* \
    && mkdir -p /var/run/frr \
    && chown -R frr:frr /etc/frr /var/run/frr

# There is no package for tini, add it manually
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /sbin/tini
RUN chmod +x /sbin/tini

# Simple init manager for reaping processes and forwarding signals
ENTRYPOINT ["/sbin/tini", "--"]

# Default CMD starts watchfrr
COPY docker/ubi8-minimal/docker-start /usr/lib/frr/docker-start
CMD ["/usr/lib/frr/docker-start"]
