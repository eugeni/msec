#!/usr/bin/python -O
"""This file is responsible for permissions checking and
(optionally) enforcing.
"""

import glob
import re
import string
import os
import stat
import pwd
import grp
import sys
import logging
import getopt

# localization
import gettext

try:
    gettext.install('msec')
except IOError:
    _ = str

# config
import config

# version
try:
    from version import version
except:
    version = "development version"

# libmsec
from libmsec import Log, PERMS

# {{{ usage
def usage():
    """Prints help message"""
    print """Msec: Mandriva Security Center (%s).

This applications verifies and (when required) enforces permissions
of certain files and directories.

Usage: msecperms [parameters] [list of paths to check]

If no paths to check are specified, all permissions stored in
%s are checked.
Otherwise, only the enties in the list of paths are expanded and checked.

For example:
    msecperms '/tmp/*' '/etc/*'
will cover only files which are covered by '/tmp/*' and '/etc/*' rules of
%s.

Available parameters:
    -h, --help              displays this helpful message.
    -l, --level <level>     displays configuration for specified security
                            level.
    -e, --enforce           enforce permissions on all files.
    -d                      enable debugging messages.
    -p, --pretend           only pretend to change the level, perform no real
                            actions. Use this to see what operations msec
                            will perform.
    -r, --root <path>       path to use as root
    -q, --quiet             run quietly
""" % (version, config.PERMCONF, config.PERMCONF)
# }}}

if __name__ == "__main__":
    # default options
    log_level = logging.INFO
    commit = True
    enforce = False
    quiet = False
    root = ''

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hel=dpr:q', ['help', 'enforce', 'list=', 'debug', 'pretend', 'root=', 'quiet'])
    except getopt.error:
        usage()
        sys.exit(1)
    for o in opt:
        # help
        if o[0] == '-h' or o[0] == '--help':
            usage()
            sys.exit(0)
        # list
        elif o[0] == '-l' or o[0] == '--list':
            level = o[1]
            log = Log(interactive=True, log_syslog=False, log_file=False)
            permconf = config.load_default_perms(log, level)
            params = permconf.list_options()
            if not params:
                print >>sys.stderr, _("Invalid security level '%s'.") % level
                sys.exit(1)
            for file in params:
                user, group, perm, force = permconf.get(file)
                if force:
                    print "!! forcing permissions on %s" % file
                print "%s: %s.%s perm %s" % (file, user, group, perm)
            sys.exit(0)
        # debugging
        elif o[0] == '-d' or o[0] == '--debug':
            log_level = logging.DEBUG
        # permission enforcing
        elif o[0] == '-e' or o[0] == '--enforce':
            enforce = True
        # custom root
        elif o[0] == '-r' or o[0] == '--root':
            root = o[1]
        # check-only mode
        elif o[0] == '-p' or o[0] == '--pretend':
            commit = False
        elif o[0] == '-q' or o[0] == '--quiet':
            quiet = True

    # verifying use id
    if os.geteuid() != 0:
        print >>sys.stderr, _("Msec: Mandriva Security Center (%s)\n") % version
        print >>sys.stderr, _("Error: This application must be executed by root!")
        print >>sys.stderr, _("Run with --help to get help.")
        sys.exit(1)

    # configuring logging
    interactive = sys.stdin.isatty()
    if interactive:
        # logs to file and to terminal
        log = Log(log_path="%s%s" % (root, config.SECURITYLOG), interactive=True, log_syslog=False, log_level=log_level, quiet=quiet)
    else:
        log_level = logging.WARN
        log = Log(log_path="%s%s" % (root, config.SECURITYLOG), interactive=True, log_syslog=False, log_level=log_level, quiet=quiet)

    # loading msec config
    msec_config = config.MsecConfig(log, config="%s%s" % (root, config.SECURITYCONF))
    msec_config.load()
    # find out the base level
    base_level = msec_config.get_base_level()
    # loading permissions
    permconf = config.PermConfig(log, config="%s%s" % (root, config.PERMCONF))
    permconf.load()

    # load variables from base level
    config.merge_with_baselevel(log, permconf, base_level, config.load_default_perms, root='')

    # merge with a legacy perm.local if exists
    if os.access("%s/etc/security/msec/perm.local" % root, os.R_OK):
        permlocal = config.PermConfig(log, config="%s/etc/security/msec/perm.local" % root)
        permlocal.load()
        permconf.merge(permlocal, overwrite=True)

    # reloading levelconf for base level
    levelconf = config.load_default_perms(log, base_level, root=root)

    # load the main permission class
    perm = PERMS(log, root=root)
    # check permissions
    changed_files = perm.check_perms(permconf, files_to_check=args)

    # writing back changes
    perm.commit(really_commit=commit, enforce=enforce)
    # saving updated config
    if commit:
        if not permconf.save(levelconf):
            log.error(_("Unable to save config!"))
    sys.exit(0)
