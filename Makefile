all: promisc_check

clean:
	find . -name *.o -exec rm -f {} \;
	find . -name *~ -exec rm -f {} \;
	rm -f src/promisc_check/promisc_check

promisc_check: 
	(cd src/promisc_check; make)

install:
	(rm -rf /etc/security/msec)
	(mkdir -p /etc/security/msec/init-sh)
	(cp init-sh/level* /etc/security/msec/init-sh)
	(cp init-sh/init.sh /etc/security/msec/init.sh);
	(cp init-sh/lib.sh /etc/security/msec/init-sh);
	(cp init-sh/grpuser /etc/security/msec/init-sh);
	(cp init-sh/file_perm.sh /etc/security/msec/init-sh);
	(cp init-sh/*.[1-5] /etc/security/msec/init-sh/)
	(cp init-sh/custom.sh /etc/security/msec/init-sh);
	(cp init-sh/server.* /etc/security/msec/init-sh)
	(touch /etc/security/msec/security.conf)
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

