#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : share
# File            : Makefile
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Sat Jan 26 20:17:55 2002
#---------------------------------------------------------------

all: mseclib.py compile

compile:
	./compile.py '/usr/share/msec/' *.py
	rm -f msec.pyo

mseclib.py: libmsec.py shadow.py
	rm -f mseclib.py
	./shadow.py libmsec > mseclib.py

clean:
	rm -f *.pyc *.pyo mseclib.py *~

# Local variables:
# mode: makefile
# End:
#
# Makefile ends here
