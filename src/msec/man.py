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
.TH msec 8 msec "Mandriva Linux"
.SH NAME
msec \- Mandriva Linux security tools
.SH SYNOPSIS
.nf
.B msec [options]
.B msecperms [options]
.B msecgui [options]
.fi
.SH DESCRIPTION
.B msec
is responsible to maintain system security in Mandriva. It supports different security
configurations, which can be organized into several security levels, stored in
/etc/security/msec/level.LEVELNAME. Currently, three preconfigured security levels are
provided with Mandriva Linux:

.TP
\\fBnone\\fR
this level disables all msec options. It should be used when you want to manage
all aspects of system security on your own.

.TP
\\fBstandard\\fR
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

.TP
Note that besides those levels you may create as many levels as necessary.

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

    Apply the specified security level to the system, overwritting all local
changes in /etc/security/msec/security.conf. This usually should be performed
either on first install, on when a transition to a different level is required.

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
    Apply the specified security level to the system, overwritting all local
changes in /etc/security/msec/perms.conf. This usually should be performed
either on first install, on when a transition to a different level is required.

\\fB\-e, --enforce\\fR
    Enforce the default permissions on all files.

\\fB\-d\\fR
    Enable debugging messages.

\\fB\-p, --pretend\\fR
    Verify the actions that will be performed by msec, without actually
doing anything to the system. In this mode of operation, msec performs all the
required tasks, except effectively writting data back to disk.

.TP
\\fBmsecgui\\fR:
.PP

This is the GTK version of msec. It acts as frontend to all msec functionalities.

\\fB\-h, --help\\fR
    This option will display the list of supported command line options.

\\fB\-d\\fR
    Enable debugging messages.

.SH EXAMPLES

\\fBEnforce system configuration according to /etc/security/msec/security.conf file:\\fP
    msec

\\fBDisplay system configuration changes without enforcing anything:\\fP
    msec -p

\\fBInstall predefined security level 'standard':\\fP
    msec -f standard

\\fBPreview changes inflicted by change to 'standard' level:\\fP
    msec -p -f standard

\\fBCreate a custom security level based on 'standard':\\fP
    cp /etc/security/msec/level.standard /etc/security/msec/level.my
    edit /etc/security/msec/level.my
    msec -f my

\\fBEnforce system permissions according to /etc/security/msec/perms.conf file:\\fP
    msecperms

\\fBDisplay permissions changes without enforcing anything:\\fP
    msecperms -p

\\fBInstall predefined permissions for level 'standard':\\fP
    msecperms -f standard

\\fBPreview changes inflicted by change to 'standard' level:\\fP
    msecperms -p -f standard

\\fBCreate a custom permissions level based on 'secure':\\fP
    cp /etc/security/msec/perm.secure /etc/security/msec/perm.my
    edit /etc/security/msec/level.my
    msecperms -f my

.SH "DEFINING EXCEPTIONS FOR PERIODIC CHECKS"
.B msec
is capable of excluding certain patterns from periodic check reports. For
this, it is possible to define the exceptions in
\\fB/etc/security/msec/exceptions\\fP file, for each supported check.

.PP
For example, to exclude all items that match \\fB/mnt\\fP, Mandriva-based
chrooted installations in \\fB/chroot\\fP and all backup files from the
results of of check for unowned files on the system, it is sufficient to
define the following entry in the exceptions file:

.TP
    CHECK_UNOWNED /mnt
.TP
    CHECK_UNOWNED /chroot/mdv_.*/
.TP
    CHECK_UNOWNED .*~

.PP
In a similar way, it is possible to exclude the results for the
\\fBdeluge\\fP application from the list of open ports as follows:

.TP
    CHECK_OPEN_PORT /deluge

.PP
Each exception entry is a regular exception, and you might define as many
exceptions as necessary.  See below for all msec options that support this
feature.


.SH "SECURITY OPTIONS"

The following security options are supported by msec:

'''

footer = '''.RE
.SH NOTES
Msec applications must be run by root.
.SH AUTHORS
Frederic Lepied

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
    if variable in config.CHECKS_WITH_EXCEPTIONS:
        # this check supports exceptions
        print """(This check supports exceptions via %s variable defined in \\fB/etc/security/msec/exceptions\\fP file)""" % variable

print footer

# man.py ends here
