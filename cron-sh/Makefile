all:
	for f in *.sh scripts/*.sh; do bash -n $$f || exit 1; done

install:
	mkdir -p $(RPM_BUILD_ROOT)/usr/share/msec/scripts
	for f in *.sh scripts/*.sh; do install -m755 $$f $(RPM_BUILD_ROOT)/usr/share/msec/$$f; done
