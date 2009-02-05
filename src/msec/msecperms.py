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
    cat = gettext.Catalog('msec')
    _ = cat.gettext
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
    drakperms '/tmp/*' '/etc/*'
will cover only files which are covered by '/tmp/*' and '/etc/*' rules of
%s.

Available parameters:
    -h, --help              displays this helpful message.
    -l, --level <level>     displays configuration for specified security
                            level.
    -f, --force <level>     force new level, overwriting user settings.
    -e, --enforce <level>   enforce permissions on all files.
    -d                      enable debugging messages.
    -p, --pretend           only pretend to change the level, perform no real
                            actions. Use this to see what operations msec
                            will perform.
    -r, --root <path>       path to use as root
""" % (version, config.PERMCONF, config.PERMCONF)
# }}}

if __name__ == "__main__":
    # default options
    log_level = logging.INFO
    force_level = False
    commit = True
    enforce = False
    root = ''

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hel:f:dpr:', ['help', 'enforce', 'list=', 'force=', 'debug', 'pretend', 'root='])
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
        # force new level
        elif o[0] == '-f' or o[0] == '--force':
            level = o[1]
            force_level = True
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
        log = Log(log_path=config.SECURITYLOG, interactive=True, log_syslog=False, log_level=log_level)
    else:
        log_level = logging.WARN
        log = Log(log_path=config.SECURITYLOG, interactive=True, log_syslog=False, log_level=log_level)

    # loading permissions
    permconf = config.PermConfig(log, config=config.PERMCONF)

    # forcing new level
    if force_level:
        # first load the default configuration for level
        standard_permconf = config.load_default_perms(log, level)
        params = standard_permconf.list_options()
        if not params:
            log.error(_("Level '%s' not found, aborting.") % level)
            sys.exit(1)
        log.info(_("Switching to '%s' level.") % level)
        for opt in params:
            permconf.set(opt, standard_permconf.get(opt))
    else:
        permconf.load()

    # load the main permission class
    perm = PERMS(log, root=root)

    # check permissions
    changed_files = perm.check_perms(permconf, files_to_check=args)

    # writing back changes
    perm.commit(really_commit=commit, enforce=enforce)
    # saving updated config
    if force_level and commit:
        if not permconf.save():
            log.error(_("Unable to save config!"))
    sys.exit(0)
