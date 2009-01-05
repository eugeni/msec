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
SECURITY_LEVELS = [ "none", "default", "secure" ]
DEFAULT_LEVEL="default"
SECURITY_LEVEL="/etc/security/msec/level.%s"

# msec configuration file
SECURITYCONF = '/etc/security/msec/security.conf'
SECURITYLOG = '/var/log/msec.log'

# permissions
PERMCONF = '/etc/security/msec/perms.conf'
PERMISSIONS_LEVEL = '/etc/security/msec/perm.%s' # for level

# TODO: more strict checking for numbers and text
# default parameters
#               OPTION                           callback                            valid values
SETTINGS =    {'CHECK_SECURITY' :               ("check_security",                  ['yes', 'no']),
               'CHECK_PERMS' :                  ("check_perms",                     ['yes', 'no']),
               'CHECK_SUID_ROOT' :              ("check_suid_root",                 ['yes', 'no']),
               'CHECK_SUID_MD5' :               ("check_suid_md5",                  ['yes', 'no']),
               'CHECK_SGID' :                   ("check_sgid",                      ['yes', 'no']),
               'CHECK_WRITABLE' :               ("check_writable",                  ['yes', 'no']),
               'CHECK_UNOWNED' :                ("check_unowned",                   ['yes', 'no']),
               'CHECK_PROMISC' :                ("check_promisc",                   ['yes', 'no']),
               'CHECK_OPEN_PORT' :              ("check_open_port",                 ['yes', 'no']),
               'CHECK_PASSWD' :                 ("check_passwd",                    ['yes', 'no']),
               'CHECK_SHADOW' :                 ("check_shadow",                    ['yes', 'no']),
               'CHECK_CHKROOTKIT' :             ("check_chkrootkit",                ['yes', 'no']),
               'CHECK_RPM' :                    ("check_rpm",                       ['yes', 'no']),
               'CHECK_SHOSTS' :                 ("check_shosts",                    ['yes', 'no']),
               # notifications
               'TTY_WARN' :                     ("tty_warn",                        ['yes', 'no']),
               'MAIL_WARN' :                    ("mail_warn",                       ['yes', 'no']),
               'MAIL_USER' :                    ("mail_user",                       ['*']),
               'MAIL_EMPTY_CONTENT':            ("mail_empty_content",              ['yes', 'no']),
               'SYSLOG_WARN' :                  ("syslog_warn",                     ['yes', 'no']),
               'NOTIFY_WARN' :                  ("notify_warn",                     ['yes', 'no']),
               # security options
               'USER_UMASK':                    ("set_user_umask",                  ['*']),
               'ROOT_UMASK':                    ("set_root_umask",                  ['*']),
               'WIN_PARTS_UMASK':               ("set_win_parts_umask",             ['no', '*']),
               'ACCEPT_BOGUS_ERROR_RESPONSES':  ("accept_bogus_error_responses",    ['yes', 'no']),
               'ACCEPT_BROADCASTED_ICMP_ECHO':  ("accept_broadcasted_icmp_echo",    ['yes', 'no']),
               'ACCEPT_ICMP_ECHO':              ("accept_icmp_echo",                ['yes', 'no']),
               'ALLOW_AUTOLOGIN':               ("allow_autologin",                 ['yes', 'no']),
               'ALLOW_REBOOT':                  ("allow_reboot",                    ['yes', 'no']),
               'ALLOW_REMOTE_ROOT_LOGIN':       ("allow_remote_root_login",         ['yes', 'no', 'without_password']),
               'ALLOW_ROOT_LOGIN':              ("allow_root_login",                ['yes', 'no']),
               'ALLOW_USER_LIST':               ("allow_user_list",                 ['yes', 'no']),
               'ALLOW_X_CONNECTIONS':           ("allow_x_connections",             ['yes', 'no', 'local']),
               'ALLOW_XAUTH_FROM_ROOT':         ("allow_xauth_from_root",           ['yes', 'no']),
               'ALLOW_XSERVER_TO_LISTEN':       ("allow_xserver_to_listen",         ['yes', 'no']),
               'AUTHORIZE_SERVICES':            ("authorize_services",              ['yes', 'no', 'local']),
               'CREATE_SERVER_LINK':            ("create_server_link",              ['no', 'default', 'secure']),
               'ENABLE_AT_CRONTAB':             ("enable_at_crontab",               ['yes', 'no']),
               'ENABLE_CONSOLE_LOG':            ("enable_console_log",              ['yes', 'no']),
               'ENABLE_DNS_SPOOFING_PROTECTION':("enable_ip_spoofing_protection",   ['yes', 'no']),
               'ENABLE_IP_SPOOFING_PROTECTION': ("enable_dns_spoofing_protection",  ['yes', 'no']),
               'ENABLE_LOG_STRANGE_PACKETS':    ("enable_log_strange_packets",      ['yes', 'no']),
               'ENABLE_MSEC_CRON':              ("enable_msec_cron",                ['yes', 'no']),
               'ENABLE_PAM_ROOT_FROM_WHEEL':    ("enable_pam_root_from_wheel",      ['yes', 'no']),
               'ENABLE_SUDO':                   ("enable_sudo",                     ['yes', 'no', 'wheel']),
               'ENABLE_PAM_WHEEL_FOR_SU':       ("enable_pam_wheel_for_su",         ['yes', 'no']),
               'ENABLE_SULOGIN':                ("enable_sulogin",                  ['yes', 'no']),
               'ENABLE_APPARMOR':               ("enable_apparmor",                 ['yes', 'no']),
               'ENABLE_POLICYKIT':              ("enable_policykit",                ['yes', 'no']),
               # password stuff
               'ENABLE_PASSWORD':               ("enable_password",                 ['yes', 'no']),
               'PASSWORD_HISTORY':              ("password_history",                ['*']),
               #                                                    format: min length, num upper, num digits
               'PASSWORD_LENGTH':               ("password_length",                 ['*']),
               'SHELL_HISTORY_SIZE':            ("set_shell_history_size",          ['*']),
               'SHELL_TIMEOUT':                 ("set_shell_timeout",               ['*']),
               }

def find_callback(param):
    '''Finds a callback for security option'''
    if param not in SETTINGS:
        return None
    else:
        callback, valid_params = SETTINGS[param]
        return callback

def find_valid_params(param):
    '''Finds valid parameters for security option'''
    if param not in SETTINGS:
        return None
    else:
        callback, valid_params = SETTINGS[param]
        return valid_params

# localization
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# helper functions
def load_defaults(log, level):
    """Loads default configuration for given security level, returning a
        MsecConfig instance.
        """
    config = MsecConfig(log, config=SECURITY_LEVEL % level)
    config.load()
    return config

def load_default_perms(log, level):
    """Loads default permissions for given security level, returning a
        MsecConfig instance.
        """
    config = PermConfig(log, config=PERMISSIONS_LEVEL % level)
    config.load()
    return config

# {{{ MsecConfig
class MsecConfig:
    """Msec configuration parser"""
    def __init__(self, log, config=SECURITYCONF):
        self.config = config
        self.options = {}
        self.comments = []
        self.log = log

    def load(self):
        """Loads and parses configuration file"""
        try:
            fd = open(self.config)
        except:
            self.log.error(_("Unable to load configuration file %s: %s") % (self.config, sys.exc_value[1]))
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
        for option in self.list_options():
            print >>fd, "%s=%s" % (option, self.options[option])
        return True
# }}}

# {{{ PermConfig
class PermConfig(MsecConfig):
    """Msec file permission parser"""
    def __init__(self, log, config=PERMCONF):
        self.config = config
        self.options = {}
        self.options_order = []
        self.comments = []
        self.log = log
        self.regexp = re.compile("^([^\s]*)\s*([a-z]*)\.([a-z]*)\s*([\d]?\d\d\d)\s*(force)?$")

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
                    if len(res[0]) == 5:
                        file, user, group, perm, force = res[0]
                    else:
                        force = None
                        file, user, group, perm = res[0]
                    self.options[file] = (user, group, perm, force)
                    self.options_order.append(file)
            except:
                traceback.print_exc()
                self.log.warn(_("Bad config option: %s") % line)
                continue
        fd.close()
        return True

    def list_options(self):
        """Sorts and returns configuration parameters"""
        return self.options_order

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
        for file in self.options_order:
            user, group, perm, force = self.options[file]
            if force:
                force = "\tforce"
            else:
                force = ""
            print >>fd, "%s\t%s.%s\t%s%s" % (file, user, group, perm, force)
        return True
# }}}

