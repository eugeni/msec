VERSION = 0.9
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
	(rm -rf $(RPM_BUILD_ROOT)/etc/security/msec)
	(mkdir -p $(RPM_BUILD_ROOT)/etc/security/msec)
	(mkdir -p $(RPM_BUILD_ROOT)/usr/share/msec)
	(cp init-sh/*.sh $(RPM_BUILD_ROOT)/usr/share/msec)
	(cp cron-sh/*.sh $(RPM_BUILD_ROOT)/usr/share/msec)
	(cp init-sh/msec $(RPM_BUILD_ROOT)/usr/sbin)
	(cp conf/perm.* conf/server.* $(RPM_BUILD_ROOT)/etc/security/msec)
	
	(touch $(RPM_BUILD_ROOT)/etc/security/msec/security.conf)
	(touch $(RPM_BUILD_ROOT)/var/log/security.log)
	(mkdir -p $(RPM_BUILD_ROOT)/var/log/security)
	(cd src/promisc_check && make install)
	(cd src/msec_find && make install)

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
