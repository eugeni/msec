PACKAGE = msec
VERSION = 0.50.8
SVNPATH = svn+ssh://svn.mandriva.com/svn/soft/msec

all: promisc_check msec_find python
	make -C cron-sh

clean:
	-find . -name '*.o' -o -name '*.py[oc]' -o -name '*~' | xargs rm -f
	rm -f src/promisc_check/promisc_check
	rm -f src/msec_find/msec_find
	rm -f *.bz2
	cd share; make clean

promisc_check: 
	(cd src/promisc_check && make)

msec_find:
	(cd src/msec_find && make)

python:
	-cd share; make

install:
	mkdir -p $(RPM_BUILD_ROOT)/etc/security/msec
	mkdir -p $(RPM_BUILD_ROOT)/usr/share/msec
	mkdir -p $(RPM_BUILD_ROOT)/usr/sbin
	cp init-sh/*.sh $(RPM_BUILD_ROOT)/usr/share/msec
	cp cron-sh/*.sh $(RPM_BUILD_ROOT)/usr/share/msec
	cp init-sh/msec $(RPM_BUILD_ROOT)/usr/sbin
	cp conf/perm.* conf/server.* $(RPM_BUILD_ROOT)/etc/security/msec

	mkdir -p $(RPM_BUILD_ROOT)/var/log
	mkdir -p $(RPM_BUILD_ROOT)/var/log/security
	touch $(RPM_BUILD_ROOT)/etc/security/msec/security.conf
	touch $(RPM_BUILD_ROOT)/var/log/security.log
	cd src/promisc_check && make install
	cd src/msec_find && make install
	mkdir -p $(RPM_BUILD_ROOT)/usr/share/man/man8/
	install -d $(RPM_BUILD_ROOT)/usr/share/man/man8/
	install -m644 man/C/*8 $(RPM_BUILD_ROOT)/usr/share/man/man8/
	for i in man/??* ; do \
	    install -d $(RPM_BUILD_ROOT)/usr/share/man/`basename $$i`/man8 ; \
	    install -m 644 $$i/*.8 $(RPM_BUILD_ROOT)/usr/share/man/`basename $$i`/man8 ; \
	done	
cleandist:
	rm -rf $(PACKAGE)-$(VERSION) $(PACKAGE)-$(VERSION).tar.bz2

dir:
	mkdir $(PACKAGE)-$(VERSION)

tar:
	tar cvf $(PACKAGE)-$(VERSION).tar $(PACKAGE)-$(VERSION)
	bzip2 -9vf $(PACKAGE)-$(VERSION).tar
	rm -rf $(PACKAGE)-$(VERSION)

dist: cleandist dir export tar

changelog: 
	svn up
	svn2cl -o ChangeLog || : 

export:
	rm -fr $(PACKAGE)-$(VERSION)
	svn export -q -rBASE . $(PACKAGE)-$(VERSION)

svntag:
	svn cp -m 'version $(VERSION)' $(SVNPATH)/trunk $(SVNPATH)/tags/v$(VERSION)
