VERSION = 0.15
NAME = msec

all: promisc_check msec_find

clean:
	find . -name *.o -exec rm -f {} \;
	find . -name *~ -exec rm -f {} \;
	rm -f src/promisc_check/promisc_check
	rm -f src/msec_find/msec_find

promisc_check: 
	(cd src/promisc_check && make)

msec_find:
	(cd src/msec_find && make)

dis: clean
	rm -rf msec-$(VERSION) ../msec-$(VERSION).tar*
	mkdir -p msec-$(VERSION)
	find . -not -name "msec-$(VERSION)"|cpio -pd msec-$(VERSION)/
	find msec-$(VERSION) -type d -name CVS|xargs rm -rf 
	perl -p -i -e 's|^%define version.*|%define version $(VERSION)|' msec.spec
	tar cf ../msec-$(VERSION).tar msec-$(VERSION)
	bzip2 -9f ../msec-$(VERSION).tar
	rm -rf msec-$(VERSION)

rpm: dis ../$(NAME)-$(VERSION).tar.bz2 $(RPM)
	cp -f ../$(NAME)-$(VERSION).tar.bz2 $(RPM)/SOURCES
	cp -f $(NAME).spec $(RPM)/SPECS/
	-rpm -ba --clean --rmsource $(NAME).spec
	rm -f ../$(NAME)-$(VERSION).tar.bz2

install:
	(mkdir -p $(RPM_BUILD_ROOT)/etc/security/msec)
	(mkdir -p $(RPM_BUILD_ROOT)/usr/share/msec)
	(mkdir -p $(RPM_BUILD_ROOT)/usr/sbin)
	(cp init-sh/*.sh $(RPM_BUILD_ROOT)/usr/share/msec)
	(cp cron-sh/*.sh $(RPM_BUILD_ROOT)/usr/share/msec)
	(cp init-sh/msec $(RPM_BUILD_ROOT)/usr/sbin)
	(cp conf/perm.* conf/server.* $(RPM_BUILD_ROOT)/etc/security/msec)

	(mkdir -p $(RPM_BUILD_ROOT)/var/log)
	(mkdir -p $(RPM_BUILD_ROOT)/var/log/security)
	(touch $(RPM_BUILD_ROOT)/etc/security/msec/security.conf)
	(touch $(RPM_BUILD_ROOT)/var/log/security.log)
	(cd src/promisc_check && make install)
	(cd src/msec_find && make install)
	(mkdir -p $(RPM_BUILD_ROOT)/usr/man/man8/)
	install -d $(RPM_BUILD_ROOT)/usr/man/man8/
	install -m644 doc/*8 $(RPM_BUILD_ROOT)/usr/man/man8/
	bzip2 -9f $(RPM_BUILD_ROOT)/usr/man/man8/*8


