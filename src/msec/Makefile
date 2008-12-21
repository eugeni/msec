#---------------------------------------------------------------
# Project         : Mandriva Linux
# Module          : share
# File            : Makefile
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Sat Jan 26 20:17:55 2002
#---------------------------------------------------------------

MAN=../../man/C/mseclib.3
PFILES=Perms.py compile.py draksec_help.py libmsec.py man.py

all: mseclib.py compile man help.pm

compile:
	./compile.py '/usr/share/msec/' *.py

man: $(MAN) levels

help.pm: libmsec.py draksec_help.py
	rm -f $@
	./draksec_help.py libmsec > $@

$(MAN): libmsec.py man.py
	rm -f $@
	./man.py libmsec > $@

levels:
	for l in 0 1 2 3 4 5; do rm -f level.$$l; \
	  ./msec.py -o log=stderr -o print=1 -o nolocal=1 $$l < /dev/null | sort > level.$$l; \
	done
clean:
	rm -f *.pyc *.pyo mseclib.py *~ level.[0-5] help.pm

# Local variables:
# mode: makefile
# End:
#
# Makefile ends here
