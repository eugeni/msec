#!/usr/bin/python -O
#---------------------------------------------------------------
# Project         : Mandriva Linux
# Module          : msec/share
# File            : msec.py
# Version         : $Id$
# Author          : Eugeni Dodonov
# Original Author : Frederic Lepied
# Created On      : Wed Dec  5 20:20:21 2001
#---------------------------------------------------------------

import sys
import os
import string
import getopt
import gettext
import imp
import re

# config
import config

# version
try:
    from version import version
except:
    version = "development version"

# libmsec
from libmsec import MSEC, Log

import logging

# localization
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# {{{ usage
def usage():
    """Prints help message"""
    print """Msec: Mandriva Security Center (%s).

When run without parameters, msec will read the configuration from
/etc/security/msec/msec.conf, and enforce the specified security settings.
If no configuration file is found on the system, a default configuration
will be created.

Arguments to msec:
    -h, --help              displays this helpful message.
    -l, --level <level>     displays configuration for specified security
                            level.
    -f, --force <level>     force new level, overwriting user settings.
    -d                      enable debugging messages.
    -p, --pretend           only pretend to change the level, perform no real
                            actions. Use this to see what operations msec
                            will perform.
""" % version
# }}}

if __name__ == "__main__":
    # default options
    force_level = False
    log_level = logging.INFO
    commit = True
    level = config.DEFAULT_LEVEL

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hl:f:dp', ['help', 'list', 'force', 'debug', 'pretend'])
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
            levelconf = config.load_defaults(log, level)
            params = levelconf.list_options()
            if not params:
                print >>sys.stderr, _("Invalid security level '%s'.") % level
                sys.exit(1)
            for item in params:
                print "%s=%s" % (item, levelconf.get(item) )
            sys.exit(0)
        # force new level
        elif o[0] == '-f' or o[0] == '--force':
            level = o[1]
            force_level = True
        # debugging
        elif o[0] == '-d' or o[0] == '--debug':
            log_level = logging.DEBUG
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
        log = Log(log_path=config.SECURITYLOG, interactive=False, log_level=log_level)

    # loading initial config
    msec_config = config.MsecConfig(log, config=config.SECURITYCONF)
    if not msec_config.load():
        log.info(_("Unable to load config, using default values"))

    # forcing new level
    if force_level:
        # first load the default configuration for level
        levelconf = config.load_defaults(log, level)
        params = levelconf.list_options()
        if not params:
            log.error(_("Default configuration for level '%s' not found, aborting.") % level)
            sys.exit(1)
        for opt in params:
            msec_config.set(opt, levelconf.get(opt))

    # load the msec library
    msec = MSEC(log)

    # ok, now the main msec functionality begins. For each
    # security action we call the correspondent callback with
    # right parameter (either default, or specified by user)
    for opt in msec_config.list_options():
        # Determines correspondent function
        action = None
        callback = config.find_callback(opt)
        valid_params = config.find_valid_params(opt)
        if callback:
            action = msec.get_action(callback)
        if not action:
            # The required functionality is not supported
            log.info(_("'%s' is not available in this version") % opt)
            continue
        log.debug("Processing action %s: %s(%s)" % (opt, callback, msec_config.get(opt)))
        # validating parameters
        param = msec_config.get(opt)
        if param not in valid_params and '*' not in valid_params:
            log.error(_("Invalid parameter for %s: '%s'. Valid parameters: '%s'.") % (opt,
                        param,
                        valid_values[opt]))
            continue
        action(msec_config.get(opt))
    # writing back changes
    msec.commit(commit)
    # saving updated config
    if force_level and commit:
        if not msec_config.save():
            log.error(_("Unable to save config!"))
    sys.exit(0)
