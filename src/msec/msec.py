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

# {{{ MsecConfig
class MsecConfig:
    """Msec configuration parser"""
    def __init__(self, log, config="/etc/security/msec/msec.conf"):
        self.config = config
        self.options = {}
        self.comments = []
        self.log = log

    def load(self):
        """Loads and parses configuration file"""
        try:
            fd = open(self.config)
        except:
            self.log.error(_("Unable to load configuration file %s: %s") % (self.config, sys.exc_value))
            return False
        for line in fd.readlines():
            line = line.strip()
            if line[0] == "#":
                # comment
                self.comments.append(line)
                continue
            try:
                option, val = line.split("=", 1)
                self.options[option] = val
            except:
                self.log.warn(_("Bad config option: %s") % line)
                continue
        fd.close()
        return True

    def get(self, option, default=None):
        """Gets a configuration option, or defines it if not defined"""
        if option not in self.options:
            self.options[option] = default
        return self.options[option]

    def remove(self, option):
        """Removes a configuration option."""
        if option in self.options:
            del self.options[option]

    def set(self, option, value):
        """Sets a configuration option"""
        self.options[option] = value

    def list_options(self):
        """Sorts and returns configuration parameters"""
        sortedparams = self.options.keys()
        if sortedparams:
            sortedparams.sort()
        return sortedparams

    def save(self):
        """Saves configuration. Comments go on top"""
        try:
            fd = open(self.config, "w")
        except:
            self.log.error(_("Unable to save %s: %s") % (self.config, sys.exc_value))
            return False
        for comment in self.comments:
            print >>fd, comment
        # sorting keys
        sortedparams = self.options.keys()
        sortedparams.sort()
        for option in sortedparams:
            print >>fd, "%s=%s" % (option, self.options[option])
        return True
# }}}

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
            params, callbacks, values = config.load_defaults(level)
            if not params:
                sys.exit(1)
            for item in params:
                print "%s: %s" % (item, params[item])
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

    # first load the default configuration for level
    params, callbacks, valid_values = config.load_defaults(level)
    if not params:
        sys.exit(1)

    # loading initial config
    msec_config = MsecConfig(log, config=config.SECURITYCONF)
    if not msec_config.load():
        log.info(_("Unable to load config, using default values"))

    # overriding defined parameters from config file
    for opt in params:
        if force_level:
            # forcing new value as user requested it
            msec_config.set(opt, params[opt])
        else:
            # only forcing new value when undefined
            msec_config.get(opt, params[opt])

    # load the msec library
    msec = MSEC(log)

    # ok, now the main msec functionality begins. For each
    # security action we call the correspondent callback with
    # right parameter (either default, or specified by user)
    for opt in msec_config.list_options():
        # Determines correspondent function
        action = None
        if opt in callbacks:
            action = msec.get_action(callbacks[opt])
        if not action:
            # The required functionality is not supported
            log.info(_("'%s' is not available in this version") % opt)
            msec_config.remove(opt)
            continue
        log.debug("Processing action %s: %s(%s)" % (opt, callbacks[opt], msec_config.get(opt)))
        # validating parameters
        param = msec_config.get(opt)
        valid_params = re.compile(valid_values[opt])
        if not valid_params.match(param):
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
