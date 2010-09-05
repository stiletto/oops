VER=1.4.6


all:
	cd src; $(MAKE)
#	cd src/modules; $(MAKE)
clean:
	cd src; $(MAKE) clean
	cd src/modules; $(MAKE) clean

distclean:
	rm -f config.cache config.status config.log *~;
	cd src; rm -f Makefile *o lex.yy.c  y.tab.[ch] *~ *.ln version.h config.h oops.cfg oops core
	cd src/modules; rm -f Makefile *o oopsctl *~ *.ln

tar:
	$(MAKE) distclean
	rm -Rf ../oops-${VER}.tar.gz /tmp/oops-${VER};
	mkdir /tmp/oops-${VER};
	gtar c --exclude=CVS --exclude=*.#* . | (cd /tmp/oops-${VER}; gtar x);
	( cd /tmp; tar cf - oops-${VER} )| gzip -9 > ../oops-${VER}.tar.gz
	rm -Rf /tmp/oops-${VER}

install:
	cd src; $(MAKE) install
