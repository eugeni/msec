#!/usr/bin/python
#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : share
# File            : man.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Sat Jan 26 17:38:39 2002
# Purpose         : loads a python module and creates a man page from
# the doc strings of the functions.
#---------------------------------------------------------------

import sys
import imp
import inspect

header = '''.ds q \N'34'
.TH mseclib 3 V0 msec "Mandrake Linux"
.SH NAME
mseclib
.SH SYNOPSIS
.nf
.B from mseclib import *
.B function1()
.B function2(arg1)
.fi
.SH DESCRIPTION
.B mseclib
is a python library to access the function used by the msec program. This functions can be used
in /etc/security/msec/level.local to override the behaviour of the msec program or in standalone
scripts.
'''

footer = '''.RE
.SH "SEE ALSO"
msec(8)
.SH AUTHORS
Frederic Lepied <flepied@mandrakesoft.com>>
'''

### strings used in the rewritting
function_str = '''
.TP 4
.B \\fI%s%s\\fP
%s
'''

### code
modulename = sys.argv[1]

module = __import__(modulename)

sys.stdout.write(header)

for f in inspect.getmembers(module, inspect.isfunction):
    (args, varargs, varkw, locals) = inspect.getargspec(f[1])
    doc = f[1].__doc__
    if doc and len(doc) > 2:
        doc = doc[2:]    
        argspec = inspect.formatargspec(args, varargs, varkw, locals)
        s = function_str % (f[0], argspec, doc)
        sys.stdout.write(s)

sys.stdout.write(footer)

# man.py ends here