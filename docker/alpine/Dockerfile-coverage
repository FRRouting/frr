FROM alpine:3.7
ARG commit
ARG token
ENV COMMIT=${commit}
ENV TOKEN=${token}
ADD . /src
RUN cd /src && \
	source alpine/APKBUILD.in && \
	apk add --no-cache alpine-sdk $makedepends $checkdepends && \
	./bootstrap.sh && \
	./configure --enable-gcov
ENTRYPOINT [ "/bin/sh", "-c", "cd /src && make && make -j 1 check-coverage" ]
