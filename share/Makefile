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

man: mseclib.man

mseclib.man: libmsec.py man.py
	rm -f mseclib.man
	./man.py libmsec > mseclib.man

clean:
	rm -f *.pyc *.pyo mseclib.py *~

# Local variables:
# mode: makefile
# End:
#
# Makefile ends here
