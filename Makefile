VERSION = 0.8

all: promisc_check

clean:
	find . -name *.o -exec rm -f {} \;
	find . -name *~ -exec rm -f {} \;
	rm -f src/promisc_check/promisc_check

promisc_check: 
	(cd src/promisc_check; make)

rpm_install: all
	rm -rf $(RPM_BUILD_ROOT)
	mkdir -p $(RPM_BUILD_ROOT)/etc/security/msec/{init-sh,cron-sh}/
	mkdir -p $(RPM_BUILD_ROOT)/usr/bin
	cp init-sh/level*.sh $(RPM_BUILD_ROOT)/etc/security/msec/init-sh
	cp init-sh/lib.sh $(RPM_BUILD_ROOT)/etc/security/msec/init-sh
	cp init-sh/init.sh $(RPM_BUILD_ROOT)/etc/security/msec
	cp init-sh/file_perm.sh $(RPM_BUILD_ROOT)/etc/security/msec/init-sh
	cp init-sh/perm.[0-5] $(RPM_BUILD_ROOT)/etc/security/msec/init-sh
	cp init-sh/server.* $(RPM_BUILD_ROOT)/etc/security/msec/init-sh
	cp init-sh/grpuser.sh $(RPM_BUILD_ROOT)/etc/security/msec/init-sh
	cp init-sh/custom.sh $(RPM_BUILD_ROOT)/etc/security/msec/init-sh
	cp cron-sh/*.sh $(RPM_BUILD_ROOT)/etc/security/msec/cron-sh
	touch $(RPM_BUILD_ROOT)/etc/security/msec/security.conf
	install -s src/promisc_check/promisc_check $(RPM_BUILD_ROOT)/usr/bin
	echo "Install complete"

dis: clean
	rm -rf msec-$(VERSION) ../msec-$(VERSION).tar*
	mkdir -p msec-$(VERSION)
	find . -not -name "msec-$(VERSION)"|cpio -pd msec-$(VERSION)/
	find msec-$(VERSION) -type d -name CVS|xargs rm -rf 
	perl -p -i -e 's|^%define version.*|%define version $(VERSION)|' msec.spec
	tar cf ../msec-$(VERSION).tar msec-$(VERSION)
	bzip2 -9f ../msec-$(VERSION).tar
	rm -rf msec-$(VERSION)

install:
	(rm -rf /etc/security/msec)
	(mkdir -p /etc/security/msec/init-sh)
	(cp init-sh/level* /etc/security/msec/init-sh)
	(cp init-sh/init.sh /etc/security/msec/init.sh);
	(cp init-sh/lib.sh /etc/security/msec/init-sh);
	(cp init-sh/grpuser.sh /etc/security/msec/init-sh);
	(cp init-sh/file_perm.sh /etc/security/msec/init-sh);
	(cp init-sh/*.[0-5] /etc/security/msec/init-sh/)
	(cp init-sh/custom.sh /etc/security/msec/init-sh);
	(cp init-sh/server.* /etc/security/msec/init-sh)
	(touch $(RPM_BUILD_ROOT)/etc/security/msec/security.conf)
	(cd src/promisc_check; make install)
	(cd cron-sh; make install)

	@echo
	@echo
	@echo "BE CAREFULL !!!"
	@echo "This is *alpha* release & it does not contains all planned features..."
	@echo "Please help debuging it..."
	@echo "See security.txt to know what is done & all :-)"
	@echo
	@echo
	@echo "To switch between runlevel, just launch init.sh ( in init-sh dir )"
	@echo
	@echo
