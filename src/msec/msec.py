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

# config
import config

# libmsec
from libmsec import MSEC

# logging
import logging
from logging.handlers import SysLogHandler

# configuration variables
APP_NAME="msec"

def load_defaults(levelname):
    """Loads default configuration for given level"""
    if levelname not in config.SECURITY_LEVELS:
        print >>sys.stderr, _("Error: unknown level '%s'!") % levelname
        return None
    level = config.SECURITY_LEVELS[levelname]
    params = {}
    callbacks = {}
    for item in config.SETTINGS:
        levels, callback = config.SETTINGS[item]
        params[item] = levels[level]
        callbacks[item] = callback
    return params, callbacks

# localization
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# {{{ Log
class Log:
    """Logging class. Logs to both syslog and log file"""
    def __init__(self,
                log_syslog=True,
                log_file=True,
                log_level = logging.INFO,
                log_facility=SysLogHandler.LOG_AUTHPRIV,
                syslog_address="/dev/log",
                log_path="/var/log/msec.log",
                interactive=True):
        self.log_facility = log_facility
        self.log_path = log_path

        # common logging stuff
        self.logger = logging.getLogger(APP_NAME)

        # syslog
        if log_syslog:
            self.syslog_h = SysLogHandler(facility=log_facility, address=syslog_address)
            formatter = logging.Formatter('%(name)s: %(levelname)s: %(message)s')
            self.syslog_h.setFormatter(formatter)
            self.logger.addHandler(self.syslog_h)

        # log to file
        if log_file:
            self.file_h = logging.FileHandler(self.log_path)
            formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
            self.file_h.setFormatter(formatter)
            self.logger.addHandler(self.file_h)

        # interactive logging
        if interactive:
            self.interactive_h = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter('%(levelname)s: %(message)s')
            self.interactive_h.setFormatter(formatter)
            self.logger.addHandler(self.interactive_h)

        self.logger.setLevel(log_level)

    def info(self, message):
        """Informative message (normal msec operation)"""
        self.logger.info(message)

    def error(self, message):
        """Error message (security has changed: authentication, passwords, etc)"""
        self.logger.error(message)

    def debug(self, message):
        """Debugging message"""
        self.logger.debug(message)

    def critical(self, message):
        """Critical message (big security risk, e.g., rootkit, etc)"""
        self.logger.critical(message)

    def warn(self, message):
        """Warning message (slight security change, permissions change, etc)"""
        self.logger.warn(message)
# }}}

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
    print """Msec usage:
msec [[-l] security level]
The configuration is stored to /etc/security/msec/msec.conf.
If no configuration file is found on the system, the specified
security level is used to create one. If no security level is specified
on the command line, "default" level is used.

Arguments to msec:
    -h, --help              displays this helpful message.
    -l, --level <level>     displays configuration for specified security
                            level.
    -f                      force new level, overwriting user settings.
    -d                      enable debugging messages.
    -c, --check             check for changes in system configuration.
"""
# }}}

if __name__ == "__main__":
    # default options
    force_level = False
    log_level = logging.INFO
    commit = True

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hl:fdc', ['help', 'list', 'force', 'debug', 'check'])
    except getopt.error:
        usage()
        sys.exit(1)
    for o in opt:
        # help
        if o[0] == '-h' or o[0] == '--option':
            usage()
            sys.exit(0)
        # list
        elif o[0] == '-l' or o[0] == '--list':
            level = o[1]
            params, callbacks = load_defaults(level)
            if not params:
                sys.exit(1)
            print _("Default configuration for '%s' level") % level
            for item in params:
                print "%s: %s" % (item, params[item])
            sys.exit(0)
        # force new level
        elif o[0] == '-f' or o[0] == '--force':
            force_level = True
        # debugging
        elif o[0] == '-d' or o[0] == '--debug':
            log_level = logging.DEBUG
        # check-only mode
        elif o[0] == '-c' or o[0] == '--check':
            commit = False

    # verifying use id
    if os.geteuid() != 0:
        print >>sys.stderr, _("This application must be run by root")
        sys.exit(1)

    # configuring logging
    interactive = sys.stdin.isatty()
    if interactive:
        # logs to file and to terminal
        log = Log(log_path="/tmp/msec.log", interactive=True, log_syslog=False, log_level=log_level)
    else:
        log = Log(log_path="/tmp/msec.log", interactive=False, log_level=log_level)


    # ok, let's if user specified a security level
    if len(args) == 0:
        log.debug(_("No security level specified, using %s") % config.DEFAULT_LEVEL)
        level = config.DEFAULT_LEVEL
    else:
        level = args[0]
        log.debug(_("Using security level %s") % level)

    # loading default configuration
    params, callbacks = load_defaults(level)
    if not params:
        sys.exit(1)

    # loading initial config
    config = MsecConfig(log, config="/tmp/msec.conf")
    if not config.load():
        log.info(_("Unable to load config, using default values"))

    # overriding defined parameters from config file
    for opt in params:
        if force_level:
            # forcing new value as user requested it
            config.set(opt, params[opt])
        else:
            # only forcing new value when undefined
            config.get(opt, params[opt])
    # saving updated config
    if not config.save():
        log.error(_("Unable to save config!"))

    # load the msec library
    msec = MSEC(log)

    # ok, now the main msec functionality begins. For each
    # security action we call the correspondent callback with
    # right parameter (either default, or specified by user)
    for opt in config.list_options():
        log.debug("Processing action %s: %s(%s)" % (opt, callbacks[opt], config.get(opt)))
        msec.run_action(callbacks[opt], config.get(opt))
    # writing back changes
    msec.commit(commit)
    sys.exit(0)
