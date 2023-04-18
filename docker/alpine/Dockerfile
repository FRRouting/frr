# syntax=docker/dockerfile:1

# Create a basic stage set up to build APKs
FROM alpine:3.17 as alpine-builder
RUN apk add \
		--update-cache \
		abuild \
		alpine-conf \
		alpine-sdk \
	&& setup-apkcache /var/cache/apk \
	&& mkdir -p /pkgs/apk \
	&& echo 'builder ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN adduser -D -G abuild builder && su builder -c 'abuild-keygen -a -n'

# This stage builds a dist tarball from the source
FROM alpine:3.17 as source-builder

RUN mkdir -p /src/alpine
COPY alpine/APKBUILD.in /src/alpine
RUN source /src/alpine/APKBUILD.in \
	&& apk add \
		--no-cache \
		--update-cache \
		$makedepends \
		gzip \
		py-pip \
		rtrlib \
		protobuf-c-dev \
	&& pip install pytest
RUN mkdir -p /pkgs/apk
COPY . /src
ARG PKGVER
RUN cd /src \
	&& ./bootstrap.sh \
	&& ./configure \
		--enable-numeric-version \
		--with-pkg-extra-version="_git$PKGVER" \
	&& make dist

# This stage builds an APK from the dist tarball
FROM alpine-builder as alpine-apk-builder
COPY --from=source-builder /src/frr-*.tar.gz /src/alpine/* /dist/
RUN find /pkgs/apk -type f -name APKINDEX.tar.gz -delete
RUN chown -R builder /dist /pkgs
USER builder
RUN cd /dist \
	&& abuild checksum \
	&& git init \
	&& abuild -r -P /pkgs/apk

# This stage installs frr from the apk
FROM alpine:3.17
RUN mkdir -p /pkgs/apk
COPY --from=alpine-apk-builder /pkgs/apk/ /pkgs/apk/
RUN apk add \
		--no-cache \
		--update-cache \
		tini \
	&& apk add \
		--no-cache \
		--allow-untrusted /pkgs/apk/*/*.apk \
	&& rm -rf /pkgs

# Own the config / PID files
RUN mkdir -p /var/run/frr
RUN chown -R frr:frr /etc/frr /var/run/frr

# Simple init manager for reaping processes and forwarding signals
ENTRYPOINT ["/sbin/tini", "--"]

# Default CMD starts watchfrr
COPY docker/alpine/docker-start /usr/lib/frr/docker-start
CMD ["/usr/lib/frr/docker-start"]
