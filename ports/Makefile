# New ports collection makefile for:	zebra
# Version required:	2.1.5
# Date created:		28 Feb 1998
# Whom:			seirios@matrix.iri.co.jp
#

#DISTNAME=	zebra-980224
DISTNAME=	zebra-current
PKGNAME=	zebra
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.zebra.org/pub/zebra/

MAINTAINER=	seirios@matrix.iri.co.jp

WRKSRC=		${WRKDIR}/zebra-current

#### Under constructing, We cannot support md5
NO_CHECKSUM=	yes

do-build:
	@(cd ${WRKSRC}; sh ./configure; make)

post-install:
	@if [ ! -f ${PREFIX}/etc/rc.d/zebra.sh ]; then \
		echo "Installing ${PREFIX}/etc/rc.d/zebra.sh startup file."; \
		echo "#!/bin/sh" > ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "# zebra" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "if [ -x /usr/local/sbin/zebra -a ! -f /var/run/zebra.pid -a -f /usr/local/etc/zebra.conf ]; then" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "	/usr/local/sbin/zebra -d -f /usr/local/etc/zebra.conf" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "	echo -n ' zebra'" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "fi" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "# bgpd" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "if [ -x /usr/local/sbin/bgpd -a ! -f /var/run/bgpd.pid -a -f /usr/local/etc/bgpd.conf ]; then" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "	/usr/local/sbin/bgpd -d -f /usr/local/etc/bgpd.conf" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "	echo -n ' bgpd'" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "fi" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "# ripd" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "if [ -x /usr/local/sbin/ripd -a ! -f /var/run/ripd.pid -a -f /usr/local/etc/ripd.conf ]; then" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "	/usr/local/sbin/ripd -d -f /usr/local/etc/ripd.conf" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "	echo -n ' ripd'" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "fi" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "# ripngd" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "if [ -x /usr/local/sbin/ripngd -a ! -f /var/run/ripd.pid -a -f /usr/local/etc/ripd.conf ]; then" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "	/usr/local/sbin/ripngd -d -f /usr/local/etc/ripd.conf" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "	echo -n ' ripngd'" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		echo "fi" >> ${PREFIX}/etc/rc.d/zebra.sh; \
		chmod 751 ${PREFIX}/etc/rc.d/zebra.sh; \
	fi
	@echo "If you will access zebra,bgpd,ripd,ripngd with telnet,";
	@echo "then you add some line (written under this line) to /etc/services";
	@echo "	zebrasrv      2600/tcp		  # zebra service";
	@echo "	zebra	      2601/tcp		  # zebra vty";
	@echo "	ripd	      2602/tcp		  # RIPd vty";
	@echo "	ripngd	      2603/tcp		  # RIPngd vty";
	@echo "	ospfd	      2604/tcp		  # OSPFd vty";
	@echo "	bgpd	      2605/tcp		  # BGPd vty";

.include <bsd.port.mk>
