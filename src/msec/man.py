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
.TH msec %s msec "Mandriva Linux"
.SH NAME
msec \- Mandriva Linux security tools
.SH SYNOPSIS
.nf
.B msec [options]
.B msecperms [options]
.B draksec [options]
.fi
.SH DESCRIPTION
.B msec
is responsible to maintain system security in Mandriva. It supports different security
configurations, which can be organized into several security levels. Currently, three
preconfigured security levels are provided:

.TP
\\fBnone\\fR
this level aims to provide the most basic security. It should be used when you want to
manage all aspects of system security on your own.

.TP
\\fBdefault\\fR
this is the default security level, which configures a reasonably safe set of security
features. It activates several periodic system checks, and sends the results of their
execution by email (by default, the local 'root' account is used).

.TP
\\fBsecure\\fR
this level is configured to provide maximum system security, even at the cost of limiting
the remote access to the system, and local user permissions. It also runs a wider set of
periodic checks, enforces the local password settings, and periodically checks if the
system security settings, configured by msec, were modified directly or by some other
application.

.PP

The security settings are stored in \\fB/etc/security/msec/security.conf\\fR
file, and default settings for each predefined level are stored in
\\fB/etc/security/msec/level.LEVEL\\fR.  Permissions for files and directories
that should be enforced or checked for changes are stored in
\\fB/etc/security/msec/perms.conf\\fR, and default permissions for each
predefined level are stored in \\fB/etc/security/msec/perm.LEVEL\\fR.  Note
that user-modified parameters take precedence over default level settings. For
example, when default level configuration forbids direct root logins, this
setting can be overridden by the user.

.PP

The following options are supported by msec applications:

.TP
\\fBmsec\\fR:
.PP

This is the console version of msec. It is responsible for system security configuration
and checking and transitions between security levels.

When executed without parameters, msec will read the system configuration file
(/etc/security/msec/security.conf), and enforce the specified security
settings. The operations are logged to \\fB/var/log/msec.log\\fP file, and also
to syslog, using \\fBLOG_AUTHPRIV\\fR facility.  Please note that msec should
by run as root.

\\fB\-h, --help\\fR
    This option will display the list of supported command line options.

\\fB\-l, --level <level>\\fR
    List the default configuration for given security level.

\\fB\-f, --force <level>\\fR
    Apply the specified security level to the system, overwritting all
local changes. This is necessary to initialize a security level, either on first
install, on when a change to a different level is required.

\\fB\-d\\fR
    Enable debugging messages.

\\fB\-p, --pretend\\fR
    Verify the actions that will be performed by msec, without actually
doing anything to the system. In this mode of operation, msec performs all the
required tasks, except effectively writting data back to disk.

.TP
\\fBmsecperms\\fR:
.PP

This application is responsible for system permission checking and enforcements.

When executed without parameters, msecperms will read the permissions
configuration file (/etc/security/msec/perms.conf), and enforce the specified
security settings. The operations are logged to \\fB/var/log/msec.log\\fP file,
and also to syslog, using \\fBLOG_AUTHPRIV\\fR facility.  Please note that msecperms
should by run as root.

\\fB\-h, --help\\fR
    This option will display the list of supported command line options.

\\fB\-l, --level <level>\\fR
    List the default configuration for given security level.

\\fB\-f, --force <level>\\fR
    Apply the specified security level to the system, overwritting all
local changes. This is necessary to initialize a security level, either on first
install, on when a change to a different level is required.

\\fB\-e, --enforce\\fR
    Enforce the default permissions on all files.

\\fB\-d\\fR
    Enable debugging messages.

\\fB\-p, --pretend\\fR
    Verify the actions that will be performed by msec, without actually
doing anything to the system. In this mode of operation, msec performs all the
required tasks, except effectively writting data back to disk.

.TP
\\fBdraksec\\fR:
.PP

This is the GTK version of msec. It acts as frontend to all msec functionalities.

\\fB\-h, --help\\fR
    This option will display the list of supported command line options.

\\fB\-d\\fR
    Enable debugging messages.

.SH "SECURITY OPTIONS"

The following security options are supported by msec:

''' % version

footer = '''.RE
.SH NOTES
Msec applications must be run by root.
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
    callback, params = config.SETTINGS[variable]
    func = msec.get_action(callback)
    if func:
        print function_str % (callback, func.__doc__.strip(), variable, ", ".join(params))

print footer

# man.py ends here
