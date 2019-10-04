# This stage builds a dist tarball from the source
FROM alpine:edge as source-builder

RUN mkdir -p /src/alpine
COPY alpine/APKBUILD.in /src/alpine
RUN source /src/alpine/APKBUILD.in \
	&& echo 'http://dl-cdn.alpinelinux.org/alpine/edge/testing' >> /etc/apk/repositories \
	&& apk add \
		--no-cache \
		--update-cache \
		$makedepends \
		gzip \
	&& pip install pytest

COPY . /src
ARG PKGVER
RUN cd /src \
	&& ./bootstrap.sh \
	&& ./configure \
		--enable-numeric-version \
		--with-pkg-extra-version="_git$PKGVER" \
	&& make dist

# This stage builds an apk from the dist tarball
FROM alpine:edge as alpine-builder
# Don't use nocache here so that abuild can use the cache
RUN echo 'http://dl-cdn.alpinelinux.org/alpine/edge/testing' >> /etc/apk/repositories \
	&& apk add \
		--update-cache \
		abuild \
		alpine-conf \
		alpine-sdk \
		py-pip \
	&& pip install pytest \
	&& setup-apkcache /var/cache/apk \
	&& mkdir -p /pkgs/apk \
	&& echo 'builder ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

COPY --from=source-builder /src/frr-*.tar.gz /src/alpine/* /dist/
RUN adduser -D -G abuild builder && chown -R builder /dist /pkgs
USER builder
RUN cd /dist \
	&& abuild-keygen -a -n \
	&& abuild checksum \
	&& abuild -r -P /pkgs/apk

# This stage installs frr from the apk
FROM alpine:edge
RUN mkdir -p /pkgs/apk
COPY --from=alpine-builder /pkgs/apk/ /pkgs/apk/
RUN echo 'http://dl-cdn.alpinelinux.org/alpine/edge/testing' >> /etc/apk/repositories \
	&& apk add \
		--no-cache \
		--update-cache \
		tini \
	&& apk add \
		--no-cache \
		--allow-untrusted /pkgs/apk/*/*.apk \
	&& rm -rf /pkgs
COPY docker/alpine/docker-start /usr/lib/frr/docker-start
ENTRYPOINT [ "/sbin/tini", "--", "/usr/lib/frr/docker-start" ]
