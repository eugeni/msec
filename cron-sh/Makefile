all:
	for f in *.sh; do bash -n $$f || exit 1; done

install:
	mkdir -p /etc/security/msec/cron-sh
	cp *.sh /etc/security/msec/cron-sh
