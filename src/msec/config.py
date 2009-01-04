#!/usr/bin/python -O
"""This is the configuration file for msec.
The following variables are defined here:
    SECURITY_LEVELS: list of supported security levels
    SECURITYCONF: location of msec configuration file
    SECURITYLOG: log file for msec messages
    SETTINGS: all security settings, with correspondent options for each
              level, callback functions, and regexp of valid parameters.

A helper function load_defaults parses the SETTINGS variable.

The MsecConfig class processes the main msec configuration file.
"""

import gettext
import sys
import traceback
import re

# security levels
SECURITY_LEVELS = {
            "none": 0,
            "default": 1,
            "secure": 2
        }
DEFAULT_LEVEL="default"

# msec configuration file
SECURITYCONF = '/etc/security/msec/security.conf'
SECURITYLOG = '/var/log/msec.log'

# TODO: more strict checking for numbers and text
# default parameters
#                                                   security level
#               OPTION                           none   default secure   callback         valid values
SETTINGS =    {'CHECK_SECURITY' :               (['no',  'yes',  'yes'], "check_security", ['yes', 'no']),
               'CHECK_PERMS' :                  (['no',  'yes',  'yes'], "check_perms", ['yes', 'no']),
               'CHECK_SUID_ROOT' :              (['no',  'yes',  'yes'], "check_suid_root", ['yes', 'no']),
               'CHECK_SUID_MD5' :               (['no',  'yes',  'yes'], "check_suid_md5", ['yes', 'no']),
               'CHECK_SGID' :                   (['no',  'yes',  'yes'], "check_sgid", ['yes', 'no']),
               'CHECK_WRITABLE' :               (['no',  'yes',  'yes'], "check_writable", ['yes', 'no']),
               'CHECK_UNOWNED' :                (['no',  'no',   'yes'], "check_unowned", ['yes', 'no']),
               'CHECK_PROMISC' :                (['no',  'no',   'yes'], "check_promisc", ['yes', 'no']),
               'CHECK_OPEN_PORT' :              (['no',  'yes',  'yes'], "check_open_port", ['yes', 'no']),
               'CHECK_PASSWD' :                 (['no',  'yes',  'yes'], "check_passwd", ['yes', 'no']),
               'CHECK_SHADOW' :                 (['no',  'yes',  'yes'], "check_shadow", ['yes', 'no']),
               'CHECK_CHKROOTKIT' :             (['no',  'yes',  'yes'], "check_chkrootkit", ['yes', 'no']), # was: CHKROOTKIT_CHECK
               'CHECK_RPM' :                    (['no',  'yes',  'yes'], "check_rpm", ['yes', 'no']), # was: RPM_CHECK
               'CHECK_SHOSTS' :                 (['no',  'yes',  'yes'], "check_shosts", ['yes', 'no']),
               # notifications
               'TTY_WARN' :                     (['no',  'no',   'yes'], "tty_warn", ['yes', 'no']),
               'MAIL_WARN' :                    (['no',  'yes',  'yes'], "mail_warn", ['yes', 'no']),
               'MAIL_USER' :                    (['root','root','root'], "mail_user", ['*']),
               'MAIL_EMPTY_CONTENT':            (['no',  'no',   'yes'], "mail_empty_content", ['yes', 'no']),
               'SYSLOG_WARN' :                  (['no',  'yes',  'yes'], "syslog_warn", ['yes', 'no']),
               'NOTIFY_WARN' :                  (['yes', 'yes',  'no' ], "notify_warn", ['yes', 'no']),
               # security options
               'USER_UMASK':                    (['022', '022',  '077'], "set_user_umask", ['*']),
               'ROOT_UMASK':                    (['022', '022',  '077'], "set_root_umask", ['*']),
               'WIN_PARTS_UMASK':               (['no',  'no',   '0'  ], "set_win_parts_umask", ['no', '*']),
               'ACCEPT_BOGUS_ERROR_RESPONSES':  (['yes', 'no',   'no' ], "accept_bogus_error_responses", ['yes', 'no']),
               'ACCEPT_BROADCASTED_ICMP_ECHO':  (['yes', 'yes',  'no' ], "accept_broadcasted_icmp_echo", ['yes', 'no']),
               'ACCEPT_ICMP_ECHO':              (['yes', 'yes',  'yes'], "accept_icmp_echo", ['yes', 'no']),
               'ALLOW_AUTOLOGIN':               (['yes', 'yes',  'no' ], "allow_autologin", ['yes', 'no']),
               'ALLOW_REBOOT':                  (['yes', 'yes',  'no' ], "allow_reboot", ['yes', 'no']),
               'ALLOW_REMOTE_ROOT_LOGIN':       (['yes', 'without_password', 'no' ], "allow_remote_root_login", ['yes', 'no', 'without_password']),
               'ALLOW_ROOT_LOGIN':              (['yes', 'yes',  'no' ], "allow_root_login", ['yes', 'no']),
               'ALLOW_USER_LIST':               (['yes', 'yes',  'no' ], "allow_user_list", ['yes', 'no']),
               'ALLOW_X_CONNECTIONS':           (['yes', 'local','no' ], "allow_x_connections", ['yes', 'no', 'local']),
               'ALLOW_XAUTH_FROM_ROOT':         (['yes', 'yes',  'no' ], "allow_xauth_from_root", ['yes', 'no']),
               'ALLOW_XSERVER_TO_LISTEN':       (['yes', 'no',   'no' ], "allow_xserver_to_listen", ['yes', 'no']),
               'AUTHORIZE_SERVICES':            (['yes', 'yes','local'], "authorize_services", ['yes', 'no', 'local']),
               'CREATE_SERVER_LINK':            (['no',  'default','secure'], "create_server_link", ['no', 'default', 'secure']),
               'ENABLE_AT_CRONTAB':             (['yes', 'yes',  'no' ], "enable_at_crontab", ['yes', 'no']),
               'ENABLE_CONSOLE_LOG':            (['yes', 'yes',  'no' ], "enable_console_log", ['yes', 'no']),
               'ENABLE_DNS_SPOOFING_PROTECTION':(['yes', 'yes',  'yes'], "enable_ip_spoofing_protection", ['yes', 'no']),
               'ENABLE_IP_SPOOFING_PROTECTION': (['yes', 'yes',  'yes'], "enable_dns_spoofing_protection", ['yes', 'no']),
               'ENABLE_LOG_STRANGE_PACKETS':    (['no',  'yes',  'yes'], "enable_log_strange_packets", ['yes', 'no']),
               'ENABLE_MSEC_CRON':              (['no',  'yes',  'yes'], "enable_msec_cron", ['yes', 'no']),
               'ENABLE_PAM_ROOT_FROM_WHEEL':    (['no',  'no',   'no' ], "enable_pam_root_from_wheel", ['yes', 'no']),
               'ENABLE_SUDO':                   (['yes', 'wheel','no' ], "enable_sudo", ['yes', 'no', 'wheel']),
               'ENABLE_PAM_WHEEL_FOR_SU':       (['no',  'no',   'yes'], "enable_pam_wheel_for_su", ['yes', 'no']),
               'ENABLE_SULOGIN':                (['no',  'no',   'yes'], "enable_sulogin", ['yes', 'no']),
               'ENABLE_APPARMOR':               (['no',  'no',   'yes'], "enable_apparmor", ['yes', 'no']),
               'ENABLE_POLICYKIT':              (['yes', 'yes',  'no' ], "enable_policykit", ['yes', 'no']),
               # password stuff
               'ENABLE_PASSWORD':               (['yes', 'yes',  'yes'], "enable_password", ['yes', 'no']),
               'PASSWORD_HISTORY':              (['0',   '0',    '2'  ], "password_history", ['*']),
               #                                format: min length, num upper, num digits
               'PASSWORD_LENGTH':               (['0,0,0',  '4,0,0', '6,1,1'], "password_length", ['*']),
               'SHELL_HISTORY_SIZE':            (['-1',  '-1',   '100'], "set_shell_history_size", ['*']),
               'SHELL_TIMEOUT':                 (['0',   '0',    '600'], "set_shell_timeout", ['*']),
               }

# localization
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# helper functions
def load_defaults(levelname):
    """Loads default configuration for given level, returning 3 dicts:
        params: list of default options for level
        callbacks: list of callback functions for each option
        values: list of valid option values."""
    if levelname not in SECURITY_LEVELS:
        print >>sys.stderr, _("Error: unknown level '%s'!") % levelname
        return None, None, None
    level = SECURITY_LEVELS[levelname]
    params = {}
    callbacks = {}
    values = {}
    for item in SETTINGS:
        levels, callback, value = SETTINGS[item]
        params[item] = levels[level]
        callbacks[item] = callback
        values[item] = value
    return params, callbacks, values

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

# {{{ PermConfig
class PermConfig(MsecConfig):
    """Msec file permission parser"""
    def __init__(self, log, config="/etc/security/msec/msec.conf"):
        self.config = config
        self.options = {}
        self.comments = []
        self.log = log
        self.regexp = re.compile("^([^\s]*)\s*([a-z]*)\.([a-z]*)\s*([\d]?\d\d\d)$")

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
                res = self.regexp.findall(line)
                if res:
                    file, user, group, perm = res[0]
                    self.options[file] = (user, group, perm)
            except:
                traceback.print_exc()
                self.log.warn(_("Bad config option: %s") % line)
                continue
        fd.close()
        return True

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
            print >>fd, "%s\t%s" % (option, "\t".join(self.options[option]))
        return True
# }}}

