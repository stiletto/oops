VER=1.5.22

all:
	cd src; $(MAKE)
#	cd src/modules; $(MAKE)
clean:
	rm -rf autom4te.cache
	cd src; $(MAKE) clean
	cd src/modules; $(MAKE) clean
	cd doc; rm -f oops.8 oopsctl.8

distclean:
	rm -f config.cache config.status config.log *~;
	rm -rf autom4te.cache
	cd src; rm -f Makefile *o lex.yy.c  y.tab.[ch] *~ *.ln version.h config.h oops.cfg oops core
	cd src; rm -f getopt.* getopt1.c gnu_regex.* rwlock.* snprintf.c strtok_r.c
	cd src/modules; rm -Rf SunWS_cache Templates.DB Makefile *o oopsctl *~ *.ln
	cd doc; rm -f oops.8 oopsctl.8

tar:
	$(MAKE) distclean
	autoconf
	autoheader
	rm -rf autom4te.cache
	rm -Rf ../oops-${VER}.tar.gz /tmp/oops-${VER};
	mkdir /tmp/oops-${VER};
	gtar c --exclude=CVS --exclude=*.#* . | (cd /tmp/oops-${VER}; gtar x);
	( cd /tmp; tar cf - oops-${VER} )| gzip -9 > ../oops-${VER}.tar.gz
	rm -Rf /tmp/oops-${VER}

install:
	cd src; $(MAKE) install
