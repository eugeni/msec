#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : msec2
# File            : Log.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Wed Dec  5 23:50:29 2001
# Purpose         : write log through syslog conforming to
#                   the Mandrake Linux guideline for the explanations
#                   in tools. Errors are reported to stderr.
#---------------------------------------------------------------

import syslog
import sys
import string
import Config

_name = ''
_use_syslog = 1

def initlog(name, facility = syslog.LOG_AUTH):
    global _name
    global _use_syslog

    _use_syslog = (Config.get_config('log', 'syslog') == 'syslog')

    if _use_syslog:
        syslog.openlog(name, 0, facility)
        
    _name = name
    
def log(s, level = syslog.LOG_INFO):
    global _use_syslog
    
    if _use_syslog:
        for l in string.split(s, '\n'):
            syslog.syslog(level, l)
    else:
        sys.stderr.write(s + '\n')
    return 1

def closelog():
    global _use_syslog
    
    if _use_syslog:
        syslog.closelog()

def error(s):
    global _name
    
    sys.stderr.write(_name + ': ' + s + '\n')
    log(s)
    
# Log.py ends here
