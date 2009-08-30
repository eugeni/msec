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
import os

# security levels
NONE_LEVEL="none"
STANDARD_LEVEL="standard"
SECURE_LEVEL="secure"
SECURITY_LEVEL="%s/etc/security/msec/level.%s"

# msec configuration file
SECURITYCONF = '/etc/security/msec/security.conf'

# permissions
PERMCONF = '/etc/security/msec/perms.conf'
PERMISSIONS_LEVEL = '%s/etc/security/msec/perm.%s' # for level

# logging
SECURITYLOG = '/var/log/msec.log'

# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

# shared strings
MODIFICATIONS_FOUND = _('Modified system files')
MODIFICATIONS_NOT_FOUND = _('No changes in system files')

# plugins
MSEC_DIR="/usr/share/msec"
MAIN_LIB="libmsec"
PLUGINS_DIR="/usr/share/msec/plugins"

# msec callbacks and valid values
#               OPTION                           callback                            valid values
SETTINGS =    {'BASE_LEVEL':                    ("libmsec.base_level",                      ['*']),
               'CHECK_SECURITY' :               ("libmsec.check_security",                  ['yes', 'no']),
               'CHECK_PERMS' :                  ("libmsec.check_perms",                     ['yes', 'no', 'enforce']),
               'CHECK_USER_FILES' :             ("libmsec.check_user_files",                ['yes', 'no']),
               'CHECK_SUID_ROOT' :              ("libmsec.check_suid_root",                 ['yes', 'no']),
               'CHECK_SUID_MD5' :               ("libmsec.check_suid_md5",                  ['yes', 'no']),
               'CHECK_SGID' :                   ("libmsec.check_sgid",                      ['yes', 'no']),
               'CHECK_WRITABLE' :               ("libmsec.check_writable",                  ['yes', 'no']),
               'CHECK_UNOWNED' :                ("libmsec.check_unowned",                   ['yes', 'no']),
               'FIX_UNOWNED' :                  ("libmsec.fix_unowned",                     ['yes', 'no']),
               'CHECK_PROMISC' :                ("libmsec.check_promisc",                   ['yes', 'no']),
               'CHECK_OPEN_PORT' :              ("libmsec.check_open_port",                 ['yes', 'no']),
               'CHECK_FIREWALL' :               ("libmsec.check_firewall",                  ['yes', 'no']),
               'CHECK_PASSWD' :                 ("libmsec.check_passwd",                    ['yes', 'no']),
               'CHECK_SHADOW' :                 ("libmsec.check_shadow",                    ['yes', 'no']),
               'CHECK_CHKROOTKIT' :             ("libmsec.check_chkrootkit",                ['yes', 'no']),
               'CHECK_RPM_PACKAGES' :           ("libmsec.check_rpm_packages",              ['yes', 'no']),
               'CHECK_RPM_INTEGRITY' :          ("libmsec.check_rpm_integrity",             ['yes', 'no']),
               'CHECK_SHOSTS' :                 ("libmsec.check_shosts",                    ['yes', 'no']),
               'CHECK_USERS' :                  ("libmsec.check_users",                     ['yes', 'no']),
               'CHECK_GROUPS' :                 ("libmsec.check_groups",                    ['yes', 'no']),
               # notifications
               'TTY_WARN' :                     ("libmsec.tty_warn",                        ['yes', 'no']),
               'MAIL_WARN' :                    ("libmsec.mail_warn",                       ['yes', 'no']),
               'MAIL_USER' :                    ("libmsec.mail_user",                       ['*']),
               'MAIL_EMPTY_CONTENT':            ("libmsec.mail_empty_content",              ['yes', 'no']),
               'SYSLOG_WARN' :                  ("libmsec.syslog_warn",                     ['yes', 'no']),
               'NOTIFY_WARN' :                  ("libmsec.notify_warn",                     ['yes', 'no']),
               # security options
               'USER_UMASK':                    ("libmsec.set_user_umask",                  ['*']),
               'ROOT_UMASK':                    ("libmsec.set_root_umask",                  ['*']),
               'ALLOW_CURDIR_IN_PATH':          ("libmsec.allow_curdir_in_path",            ['yes', 'no']),
               'WIN_PARTS_UMASK':               ("libmsec.set_win_parts_umask",             ['*']),
               'ACCEPT_BOGUS_ERROR_RESPONSES':  ("libmsec.accept_bogus_error_responses",    ['yes', 'no']),
               'ACCEPT_BROADCASTED_ICMP_ECHO':  ("libmsec.accept_broadcasted_icmp_echo",    ['yes', 'no']),
               'ACCEPT_ICMP_ECHO':              ("libmsec.accept_icmp_echo",                ['yes', 'no']),
               'ALLOW_AUTOLOGIN':               ("libmsec.allow_autologin",                 ['yes', 'no']),
               'ALLOW_REBOOT':                  ("libmsec.allow_reboot",                    ['yes', 'no']),
               'ALLOW_REMOTE_ROOT_LOGIN':       ("libmsec.allow_remote_root_login",         ['yes', 'no', 'without-password']),
               'ALLOW_ROOT_LOGIN':              ("libmsec.allow_root_login",                ['yes', 'no']),
               'ALLOW_USER_LIST':               ("libmsec.allow_user_list",                 ['yes', 'no']),
               'ALLOW_X_CONNECTIONS':           ("libmsec.allow_x_connections",             ['yes', 'no', 'local']),
               'ALLOW_XAUTH_FROM_ROOT':         ("libmsec.allow_xauth_from_root",           ['yes', 'no']),
               'ALLOW_XSERVER_TO_LISTEN':       ("libmsec.allow_xserver_to_listen",         ['yes', 'no']),
               'AUTHORIZE_SERVICES':            ("libmsec.authorize_services",              ['yes', 'no', 'local']),
               'CREATE_SERVER_LINK':            ("libmsec.create_server_link",              ['no', 'remote', 'local']),
               'ENABLE_AT_CRONTAB':             ("libmsec.enable_at_crontab",               ['yes', 'no']),
               'ENABLE_CONSOLE_LOG':            ("libmsec.enable_console_log",              ['yes', 'no']),
               'ENABLE_DNS_SPOOFING_PROTECTION':("libmsec.enable_dns_spoofing_protection",  ['yes', 'no']),
               'ENABLE_IP_SPOOFING_PROTECTION': ("libmsec.enable_ip_spoofing_protection",   ['yes', 'no']),
               'ENABLE_LOG_STRANGE_PACKETS':    ("libmsec.enable_log_strange_packets",      ['yes', 'no']),
               'ENABLE_MSEC_CRON':              ("libmsec.enable_msec_cron",                ['yes', 'no']),
               'ENABLE_SUDO':                   ("libmsec.enable_sudo",                     ['yes', 'no', 'wheel']),
               'ENABLE_SULOGIN':                ("libmsec.enable_sulogin",                  ['yes', 'no']),
               'SECURE_TMP':                    ("libmsec.secure_tmp",                      ['yes', 'no']),
               'SHELL_HISTORY_SIZE':            ("libmsec.set_shell_history_size",          ['*']),
               'SHELL_TIMEOUT':                 ("libmsec.set_shell_timeout",               ['*']),
               'ENABLE_STARTUP_MSEC':           ("libmsec.enable_startup_msec",             ['yes', 'no']),
               'ENABLE_STARTUP_PERMS':          ("libmsec.enable_startup_perms",            ['yes', 'no', 'enforce']),
               }
# text for disabled options
OPTION_DISABLED=_("System default")

# settings organizes by category
# system security settings
SETTINGS_SYSTEM = ["ENABLE_STARTUP_MSEC", "ENABLE_STARTUP_PERMS", "ENABLE_MSEC_CRON",
                    "ENABLE_SULOGIN", "ENABLE_AT_CRONTAB",
                    "ALLOW_ROOT_LOGIN", "ALLOW_USER_LIST", "ALLOW_AUTOLOGIN",
                    "ENABLE_CONSOLE_LOG", "CREATE_SERVER_LINK", "ALLOW_XAUTH_FROM_ROOT",
                    "ALLOW_REBOOT", "SHELL_HISTORY_SIZE", "SHELL_TIMEOUT", "USER_UMASK", "ROOT_UMASK",
                    "SECURE_TMP", "WIN_PARTS_UMASK", "ALLOW_CURDIR_IN_PATH"
                    ]
# network security settings
SETTINGS_NETWORK = ["ACCEPT_BOGUS_ERROR_RESPONSES", "ACCEPT_BROADCASTED_ICMP_ECHO", "ACCEPT_ICMP_ECHO",
                    "ALLOW_REMOTE_ROOT_LOGIN", "ALLOW_X_CONNECTIONS", "ALLOW_XSERVER_TO_LISTEN",
                    "AUTHORIZE_SERVICES", "ENABLE_DNS_SPOOFING_PROTECTION", "ENABLE_IP_SPOOFING_PROTECTION",
                    "ENABLE_LOG_STRANGE_PACKETS",
                    ]
# periodic checks
SETTINGS_PERIODIC = ["CHECK_PERMS", "CHECK_USER_FILES", "CHECK_SUID_ROOT", "CHECK_SUID_MD5", "CHECK_SGID",
                    "CHECK_WRITABLE", "CHECK_UNOWNED", "FIX_UNOWNED", "CHECK_PROMISC", "CHECK_OPEN_PORT", "CHECK_FIREWALL",
                    "CHECK_PASSWD", "CHECK_SHADOW", "CHECK_CHKROOTKIT", "CHECK_RPM_PACKAGES", "CHECK_RPM_INTEGRITY",
                    "CHECK_SHOSTS", "CHECK_USERS", "CHECK_GROUPS",
                    "TTY_WARN", "SYSLOG_WARN", "MAIL_EMPTY_CONTENT",
                    ]

# localized help
try:
    from help import HELP
except:
    HELP = {}

# helper function to find documentation for an option
def find_doc(msec, option, cached=None):
    """Helper function to find documentation for an option."""
    if option not in SETTINGS:
        # invalid option ?
        return None
    callback, values = SETTINGS[option]
    # is it already cached?
    if option in cached:
        return cached[option]
    if option in HELP:
        doc = HELP[option]
    else:
        # option not found in HELP, lets look in docstring
        # get description from function comments
        func = msec.get_action(callback)
        if func.__doc__:
            doc = func.__doc__.strip()
        else:
            # well, no luck. Just use the callback then
            doc = callback
    # updated cached values
    if cached:
        cached[option] = doc
    return doc


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

# helper functions
def load_defaults(log, level, root=''):
    """Loads default configuration for given security level, returning a
        MsecConfig instance.
        """
    config = MsecConfig(log, config=SECURITY_LEVEL % (root, level))
    config.load()
    return config

def load_default_perms(log, level, root=''):
    """Loads default permissions for given security level, returning a
        MsecConfig instance.
        """
    config = PermConfig(log, config=PERMISSIONS_LEVEL % (root, level))
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

    def merge(self, newconfig, overwrite=False):
        """Merges parameters from newconfig to current config"""
        for opt in newconfig.list_options():
            if overwrite:
                self.set(opt, newconfig.get(opt))
            else:
                self.get(opt, newconfig.get(opt))

    def reset(self):
        """Resets all configuration"""
        del self.options
        self.options = {}
        del self.comments
        self.comments = []

    def load(self):
        """Loads and parses configuration file"""
        if not self.config:
            # No associated file
            return True
        try:
            fd = open(self.config)
        except:
            self.log.error(_("Unable to load configuration file %s: %s") % (self.config, sys.exc_value[1]))
            return False
        for line in fd.readlines():
            line = line.strip()
            if not line:
                continue
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
        if not self.config:
            # No associated file
            return True
        try:
            fd = open(self.config, "w")
        except:
            self.log.error(_("Unable to save %s: %s") % (self.config, sys.exc_value))
            return False
        for comment in self.comments:
            print >>fd, comment
        # sorting keys
        for option in self.list_options():
            value = self.options[option]
            # prevent saving empty options
            # TODO: integrate with remove()
            if value == None or value == OPTION_DISABLED:
                self.log.debug("Skipping %s" % option)
            else:
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
        self.regexp = re.compile("^([^\s]*)\s*([a-z]*)\.([a-z]*)\s*([\d]?\d\d\d|current)\s*(force)?$")

    def reset(self):
        MsecConfig.reset(self)
        del self.options_order
        self.options_order = []

    def remove(self, option):
        """Removes a configuration option."""
        MsecConfig.remove(self, option)
        if option in self.options_order:
            pos = self.options_order.index(option)
            del self.options_order[pos]

    def load(self):
        """Loads and parses configuration file"""
        try:
            fd = open(self.config)
        except:
            self.log.error(_("Unable to load configuration file %s: %s") % (self.config, sys.exc_value))
            return False
        for line in fd.readlines():
            line = line.strip()
            if not line:
                continue
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

    def set(self, option, value):
        """Sets a configuration option"""
        self.options[option] = value
        if option not in self.options_order:
            self.options_order.append(option)

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
