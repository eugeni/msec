#---------------------------------------------------------------
# Project         : Mandriva Linux
# Module          : share
# File            : Makefile
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Sat Jan 26 20:17:55 2002
#---------------------------------------------------------------

MAN=../../man/C/msec.8
PFILES=msecperms.py compile.py libmsec.py man.py

all: compile man help

compile:
	./compile.py '/usr/share/msec/' *.py

man: $(MAN)

help: libmsec.py help_draksec.py
	./help_draksec.py

$(MAN): libmsec.py man.py
	rm -f $@
	./man.py libmsec > $@

clean:
	rm -f *.pyc *.pyo mseclib.py *~ help.*

# Local variables:
# mode: makefile
# End:
#
# Makefile ends here
