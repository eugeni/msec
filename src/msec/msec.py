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

# libmsec
from libmsec import MSEC

# logging
import logging
from logging.handlers import SysLogHandler

# configuration variables
APP_NAME="msec"

# security levels
SECURITY_LEVELS = {
            "none": 0,
            "default": 1,
            "secure": 2
        }
DEFAULT_LEVEL="default"

# default parameters
#                                                   security level
#               OPTION                           none   default secure  callback
SETTINGS =    {'CHECK_SECURITY' :               (['yes', 'yes',  'yes'], "check_security"),
               'CHECK_PERMS' :                  (['no',  'yes',  'yes'], "check_perms"),
               'CHECK_SUID_ROOT' :              (['yes', 'yes',  'yes'], "check_suid_root"),
               'CHECK_SUID_MD5' :               (['yes', 'yes',  'yes'], "check_suid_md5"),
               'CHECK_SGID' :                   (['yes', 'yes',  'yes'], "check_sgid"),
               'CHECK_WRITABLE' :               (['yes', 'yes',  'yes'], "check_writable"),
               'CHECK_UNOWNED' :                (['no',  'no',   'yes'], "check_unowned"),
               'CHECK_PROMISC' :                (['no',  'no',   'yes'], "check_promisc"),
               'CHECK_OPEN_PORT' :              (['no',  'yes',  'yes'], "check_open_port"),
               'CHECK_PASSWD' :                 (['no',  'yes',  'yes'], "check_passwd"),
               'CHECK_SHADOW' :                 (['no',  'yes',  'yes'], "check_shadow"),
               'CHECK_CHKROOTKIT' :             (['no',  'yes',  'yes'], "check_chkrootkit"), # was: CHKROOTKIT_CHECK
               'CHECK_RPM' :                    (['no',  'yes',  'yes'], "check_rpm"), # was: RPM_CHECK
               'CHECK_SHOSTS' :                 (['no',  'yes',  'yes'], "check_shosts"),
               'TTY_WARN' :                     (['no',  'no',   'yes'], "tty_warn"),
               'MAIL_WARN' :                    (['no',  'yes',  'yes'], "mail_warn"),
               'MAIL_EMPTY_CONTENT':            (['no',  'no',   'yes'], "mail_empty_content"),
               'SYSLOG_WARN' :                  (['yes', 'yes',  'yes'], "syslog_warn"),
               # security options
               'USER_UMASK':                    (['022', '022',  '077'], "set_user_umask"),
               'ROOT_UMASK':                    (['022', '022',  '077'], "set_root_umask"),
               'WIN_PARTS_UMASK':               (['no',  'no',   '0'  ], "set_win_parts_umask"),
               'ACCEPT_BOGUS_ERROR_RESPONSES':  (['no',  'no',   'no' ], "accept_bogus_error_responses"),
               'ACCEPT_BROADCASTED_ICMP_ECHO':  (['yes', 'yes',  'no' ], "accept_broadcasted_icmp_echo"),
               'ACCEPT_ICMP_ECHO':              (['yes', 'yes',  'yes'], "accept_icmp_echo"),
               'ALLOW_AUTOLOGIN':               (['yes', 'yes',  'no' ], "allow_autologin"),
               'ALLOW_ISSUES':                  (['yes', 'yes',  'yes'], "allow_issues"),
               'ALLOW_REBOOT':                  (['yes', 'yes',  'yes'], "allow_reboot"),
               'ALLOW_REMOTE_ROOT_LOGIN':       (['yes', 'without_password', 'no' ], "allow_remote_root_login"), # was: WITHOUT_PASSWORD
               'ALLOW_ROOT_LOGIN':              (['yes', 'yes',  'no' ], "allow_root_login"),
               'ALLOW_USER_LIST':               (['yes', 'yes',  'no' ], "allow_user_list"),
               'ALLOW_X_CONNECTIONS':           (['yes', 'LOCAL','no' ], "allow_x_connections"),
               'ALLOW_XAUTH_FROM_ROOT':         (['yes', 'yes',  'no' ], "allow_xauth_from_root"),
               'ALLOW_XSERVER_TO_LISTEN':       (['yes', 'no',   'no' ], "allow_xserver_to_listen"),
               'AUTHORIZE_SERVICES':            (['ALL', 'LOCAL','NONE'], "authorize_services"),
               'CREATE_SERVER_LINK':            (['no',  'no',   'yes'], "create_server_link"),
               'ENABLE_AT_CRONTAB':             (['no',  'yes',  'no' ], "enable_at_crontab"),
               'ENABLE_CONSOLE_LOG':            (['yes', 'yes',  'no' ], "enable_console_log"),
               'ENABLE_DNS_SPOOFING_PROTECTION':(['yes', 'yes',  'yes'], "enable_ip_spoofing_protection"),
               'ENABLE_IP_SPOOFING_PROTECTION': (['yes', 'yes',  'yes'], "enable_dns_spoofing_protection"),
               'ENABLE_LOG_STRANGE_PACKETS':    (['no',  'yes',  'yes'], "enable_log_strange_packets"),
               'ENABLE_MSEC_CRON':              (['no',  'yes',  'yes'], "enable_msec_cron"),
               'ENABLE_PAM_ROOT_FROM_WHEEL':    (['no',  'no',   'no' ], "enable_pam_root_from_wheel"),
               'ENABLE_PAM_WHEEL_FOR_SU':       (['no',  'no',   'yes'], "enable_pam_wheel_for_su"),
               'ENABLE_PASSWORD':               (['yes', 'yes',  'yes'], "enable_password"),
               'ENABLE_SULOGIN':                (['no',  'no',   'yes'], "enable_sulogin"),
               'ENABLE_APPARMOR':               (['no',  'no',   'yes'], "enable_apparmor"),
               # password aging - do we need that at all??
               'NO_PASSWORD_AGING_FOR':         (['no',  'no',   'no' ], "no_password_aging_for"),
               'PASSWORD_AGING':                (['99999',  '99999',   '60' ], "password_aging"),
               'PASSWORD_HISTORY':              (['no',  'no',   '2'  ], "password_history"),
               #                                format: min length, num upper, num digits
               'PASSWORD_LENGTH':               (['0,0,0',  '0,0,0', '6,1,1'], "password_length"),
               'SHELL_HISTORY_SIZE':            (['-1',  '-1',   '100'], "set_shell_history_size"),
               'SHELL_TIMEOUT':                 (['0',   '0',    '600'], "set_shell_timeout"),
               }

def load_defaults(levelname):
    """Loads default configuration for given level"""
    if levelname not in SECURITY_LEVELS:
        print >>sys.stderr, _("Error: unknown level '%s'!") % levelname
        return None
    level = SECURITY_LEVELS[levelname]
    params = {}
    callbacks = {}
    for item in SETTINGS:
        levels, callback = SETTINGS[item]
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
        log.debug(_("No security level specified, using %s") % DEFAULT_LEVEL)
        level = DEFAULT_LEVEL
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
