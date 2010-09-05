VER=1.1.pl.1


all:
	cd src; $(MAKE)
#	cd src/modules; $(MAKE)
clean:
	cd src; $(MAKE) clean
	cd src/modules; $(MAKE) clean

cleandist:
	rm -f config.cache config.status config.log *~;
	cd src; rm -f Makefile *o lex.yy.c  y.tab.[ch] *~ *.ln version.h oops
	cd src/modules; rm -f Makefile *o *~ *.ln

tar:
	rm -f oops-${VER}.tar.gz /tmp/oops.tar.gz; \
	cd .. ;tar cvf - oops | gzip > /tmp/oops.tar.gz; \
	mv /tmp/oops.tar.gz oops/oops-${VER}.tar.gz

install:
	cd src; $(MAKE) install
