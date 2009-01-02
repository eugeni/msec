#!/usr/bin/python
#---------------------------------------------------------------
# Project         : Mandriva Linux
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

import config
from libmsec import MSEC, Log
try:
    from version import version
except:
    version = "(development version)"

header = '''.ds q \N'34'
.TH mseclib %s msec "Mandriva Linux"
.SH NAME
mseclib
.SH SYNOPSIS
.nf
.B from mseclib import *
.B function1(yes)
.B function2(ignore)
.fi
.SH DESCRIPTION
.B mseclib
is a python library to access the function used by the msec program. This functions can be used
in /etc/security/msec/level.local to override the behaviour of the msec program or in standalone
scripts. The first argument of the functions takes a value of 1 or 0 or -1 (or yes/no/ignore)
except when specified otherwise.
''' % version

footer = '''.RE
.SH "SEE ALSO"
msec(8)
.SH AUTHORS
Frederic Lepied <flepied@mandriva.com>

Eugeni Dodonov <eugeni@mandriva.com>
'''

### strings used in the rewritting
function_str = '''
.TP 4
.B \\fI%s\\fP
%s

MSEC parameter: \\fI%s\\fP

Accepted values: \\fI%s\\fP
'''

### code

# process all configuration parameters
log = Log(log_syslog=False, log_file=False)
msec = MSEC(log)

#print >>sys.stderr, dir(msec.create_server_link)

print header

for variable in config.SETTINGS:
    levels, callback, params = config.SETTINGS[variable]
    func = msec.get_action(callback)
    if func:
        print function_str % (callback, func.__doc__.strip(), variable, ", ".join(params))

print footer

# man.py ends here
