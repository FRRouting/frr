# syntax=docker/dockerfile:1
# =============================================================================
# BGP_ASSIGNMENT — FRR build environment
# Ubuntu 22.04 LTS with every dependency FRR 10.x needs to build bgpd.
#
# Build:
#   docker build -t frr-bgp-assignment frr/docker/bgp-assignment/
#
# Run (mount repo, get a shell with the source visible):
#   docker run --rm -it \
#     -v "$(pwd)/frr":/home/frr/frr \
#     --workdir /home/frr/frr \
#     frr-bgp-assignment bash
# =============================================================================

FROM ubuntu:22.04

LABEL maintainer="BGP_ASSIGNMENT Project"
LABEL description="FRR bgpd build environment for crypto-routes SAFI implementation"

ARG DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1.  Core build tools and all FRR apt dependencies
#     Source: frr/doc/developer/building-frr-for-ubuntu2x04.rst
#             frr/docker/ubuntu-ci/Dockerfile
# ---------------------------------------------------------------------------
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        # Build infrastructure
        autoconf \
        automake \
        libtool \
        make \
        build-essential \
        pkg-config \
        git \
        curl \
        wget \
        ca-certificates \
        # Parser generators (FRR uses bison grammar files)
        bison \
        flex \
        # Documentation / info pages
        texinfo \
        install-info \
        # Perl (used by lib/route_types.pl code-gen script)
        perl \
        # Python (clippy code generator + runtime scripts)
        python3 \
        python3-dev \
        python3-pip \
        python3-sphinx \
        # Required FRR libraries
        libreadline-dev \
        libjson-c-dev \
        libc-ares-dev \
        libcap-dev \
        libelf-dev \
        libssl-dev \
        libpam0g-dev \
        libunwind-dev \
        libsqlite3-dev \
        libsnmp-dev \
        # Protobuf (for mgmtd / gRPC path; safe to have even without --enable-grpc)
        libprotobuf-c-dev \
        protobuf-c-compiler \
        # libyang cmake build deps
        cmake \
        libpcre2-dev \
        # Useful for debugging inside the container
        gdb \
        lsb-release \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2.  libyang 3.13.6 — built from source
#     FRR requires >= 2.1.128; Ubuntu 22.04's packaged version is too old.
#     Source: frr/doc/developer/building-libyang.rst
# ---------------------------------------------------------------------------
RUN git clone --depth 1 --branch v3.13.6 \
        https://github.com/CESNET/libyang.git /tmp/libyang && \
    cmake -S /tmp/libyang -B /tmp/libyang/build \
          -DCMAKE_INSTALL_PREFIX=/usr \
          -DCMAKE_BUILD_TYPE=Release && \
    make -C /tmp/libyang/build -j"$(nproc)" && \
    make -C /tmp/libyang/build install && \
    ldconfig && \
    rm -rf /tmp/libyang

# Confirm libyang is discoverable by pkg-config (build will fail if not)
RUN pkg-config --modversion libyang

# ---------------------------------------------------------------------------
# 3.  Python packages the FRR build system needs at configure / make time
# ---------------------------------------------------------------------------
RUN python3 -m pip install --no-cache-dir wheel

# ---------------------------------------------------------------------------
# 4.  Create the frr user/group exactly as FRR expects
#     Matches the UID/GID used by frr's init scripts and default configure flags.
# ---------------------------------------------------------------------------
RUN groupadd -r -g 92 frr && \
    groupadd -r -g 85 frrvty && \
    useradd --system --gid frr --uid 1010 \
            --home /home/frr --create-home \
            --shell /bin/bash \
            --comment "FRR suite" frr && \
    usermod -aG frrvty frr && \
    # Passwordless sudo so make install works inside the container
    echo 'frr ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/frr && \
    chmod 0440 /etc/sudoers.d/frr

RUN apt-get install -y --no-install-recommends sudo \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 5.  Working directory
#     The source tree is mounted here at docker run time — nothing is baked in.
# ---------------------------------------------------------------------------
WORKDIR /home/frr/frr
USER frr

# ---------------------------------------------------------------------------
# 6.  Default command — interactive shell ready to run bootstrap/configure/make
# ---------------------------------------------------------------------------
CMD ["/bin/bash"]
