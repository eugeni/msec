#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : share
# File            : Makefile
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Sat Jan 26 20:17:55 2002
#---------------------------------------------------------------

all: mseclib.py compile man

compile:
	./compile.py '/usr/share/msec/' *.py
	rm -f msec.pyo

mseclib.py: libmsec.py shadow.py
	rm -f mseclib.py
	./shadow.py libmsec > mseclib.py

man: mseclib.man levels

mseclib.man: libmsec.py man.py
	rm -f mseclib.man
	./man.py libmsec > mseclib.man

levels:
	for l in 0 1 2 3 4 5; do rm -f level.$$l; \
	  ./msec.py -o log=stderr -o print=1 -o nolocal=1 $$l < /dev/null | sort > level.$$l; \
	done
clean:
	rm -f *.pyc *.pyo mseclib.py *~

# Local variables:
# mode: makefile
# End:
#
# Makefile ends here
