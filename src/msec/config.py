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
DEFAULT_LEVEL="default"
SECURE_LEVEL="secure"
SECURITY_LEVEL="/etc/security/msec/level.%s"

# msec configuration file
SECURITYCONF = '/etc/security/msec/security.conf'

# permissions
PERMCONF = '/etc/security/msec/perms.conf'
PERMISSIONS_LEVEL = '/etc/security/msec/perm.%s' # for level

# logging
SECURITYLOG = '/var/log/msec.log'

# localization
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# shared strings
MODIFICATIONS_FOUND = _('Modified system files')
MODIFICATIONS_NOT_FOUND = _('No changes in system files')

# msec callbacks and valid values
#               OPTION                           callback                            valid values
SETTINGS =    {'BASE_LEVEL':                    ("base_level",                      ['*']),
               'CHECK_SECURITY' :               ("check_security",                  ['yes', 'no']),
               'CHECK_PERMS' :                  ("check_perms",                     ['yes', 'no']),
               'CHECK_USER_FILES' :             ("check_user_files",                ['yes', 'no']),
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

# mandriva security tools
AUTH_NO_PASSWD = _("No password")
AUTH_ROOT_PASSWD = _("Root password")
AUTH_USER_PASSWD = _("User password")

# mandriva drakx tools
MANDRIVA_TOOLS = {
            "rpmdrake":  _("Software Management"),
            "mandrivaupdate":  _("Mandriva Update"),
            "drakrpm-edit-media":  _("Software Media Manager"),
            "drak3d":  _("Configure 3D Desktop effects"),
            "xfdrake":  _("Graphical Server Configuration"),
            "drakmouse":  _("Mouse Configuration"),
            "drakkeyboard":  _("Keyboard Configuration"),
            "drakups":  _("UPS Configuration"),
            "drakconnect":  _("Network Configuration"),
            "drakhosts":  _("Hosts definitions"),
            "draknetcenter":  _("Network Center"),
            "drakvpn":  _("VPN"),
            "drakproxy":  _("Proxy Configuration"),
            "drakgw":  _("Connection Sharing"),
            "drakauth":  _("Authentication"),
            "drakbackup":  _("Backups"),
            "drakfont":  _("Import fonts"),
            "draklog":  _("Logs"),
            "drakxservices":  _("Services"),
            "userdrake":  _("Users"),
            "drakclock":  _("Date, Clock & Time Zone Settings"),
            "drakboot":  _("Boot Configuration"),
    }

# drakx tool groups
MANDRIVA_TOOL_GROUPS = [
            ( _("Software Management"), ['rpmdrake', 'mandrivaupdate', 'drakrpm-edit-media'] ),
            ( _("Hardware"), ['drak3d', 'xfdrake', 'drakmouse', 'drakkeyboard', 'drakups'] ),
            ( _("Network"), ['drakconnect', 'drakhosts', 'draknetcenter', 'drakvpn', 'drakproxy', 'drakgw'] ),
            ( _("System"), ['drakauth', 'drakbackup', 'drakfont', 'draklog', 'drakxservices', 'userdrake', 'drakclock'] ),
            ( _("Boot"), ['drakboot'] ),
        ]

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
            if value == None:
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

# {{{ AuthConfig
class AuthConfig(MsecConfig):
    """Msec auth configuration config"""
    def __init__(self, log, config=MANDRIVA_TOOLS):
        self.config = config
        self.options = {}
        self.log = log
        self.user_r = re.compile("USER=(.*)")
        self.auth_root = "USER=root"
        self.auth_user = "USER=<user>"

    def load(self):
        """Loads Mandriva auth configuration"""
        # TODO: this should probably go to libmsec..
        for app in self.config:
            # first, lets see if file exists
            try:
                link = os.readlink("/etc/pam.d/%s" % app)
            except:
                self.log.error(_("Unable to access /etc/pam.d/%s: %s") % (app, sys.exc_value))
                self.set(app, None)
                continue

            auth = None
            # checking auth
            if link.find("mandriva-console-auth") != -1:
                auth = AUTH_NO_PASSWD
            elif link.find("mandriva-simple-auth") != -1:
                try:
                    # read console.apps data
                    fd = open("/etc/security/console.apps/%s" % app)
                    data = fd.read()
                    fd.close()
                    # locate correspondent user
                    res = self.user_r.findall(data)
                    if res:
                        user = res[0]
                        if user == "root":
                            auth = AUTH_ROOT_PASSWD
                        elif user == "<user>":
                            auth = AUTH_USER_PASSWD
                        else:
                            # unknown authentication
                            self.log.error(_("Unknown authentication scheme for %s: %s") % (app, link))
                except:
                    self.log.error(_("Error parsing /etc/security/console.apps/%s: %s") % (app, sys.exc_value))
            else:
                # unknown pam parameter?
                self.log.error(_("Unknown authentication scheme for %s: %s") % (app, link))
            self.set(app, auth)
        return True

    def list_options(self):
        """Sorts and returns configuration parameters"""
        sortedparams = self.options.keys()
        if sortedparams:
            sortedparams.sort()
        return sortedparams


    def symlinkf(self, src, target, create=True):
        """Check if correct symlink exists and creates when necessary."""
        try:
            link = os.readlink(target)
        except:
            self.log.error(_("Unable to handle symlink from %s to %s: %s") % (src, target, sys.exc_value))
            link = ""
        if link == target:
            return True
        else:
            if create:
                os.unlink(target)
                os.symlink(src, target)
            return False

    def replace_auth(self, file, auth):
        """Replaces PAM authentication in file"""
        try:
            lines = []
            changed = False
            fd = open(file)
            for line in fd.readlines():
                line = line.strip()
                res = self.user_r.search(line)
                if res:
                    if line.find(auth) == -1:
                        self.log.debug("Changing <%s> to <%s> in %s" % (line, auth, file))
                        changed = True
                        line = auth
                lines.append(line)
            fd.close()
            if changed:
                fd = open(file, "w")
                print >>fd, "\n".join(lines)
                fd.close()
        except:
            traceback.print_exc()

    def save(self):
        """Saves configuration. Comments go on top"""
        # TODO: this should probably go to libmsec..
        link_console_auth = "/etc/pam.d/mandriva-console-auth"
        link_simple_auth = "/etc/pam.d/mandriva-simple-auth"
        for app in self.config:
            auth = self.get(app)
            file_pam = "/etc/pam.d/%s" % app
            file_console = "/etc/security/console.apps/%s" % app
            # well, let's rock
            if auth == AUTH_NO_PASSWD:
                self.symlinkf(link_console_auth, file_pam)
            elif auth == AUTH_ROOT_PASSWD:
                self.symlinkf(link_simple_auth, file_pam)
                self.replace_auth(file_console, self.auth_root)
            elif auth == AUTH_USER_PASSWD:
                self.symlinkf(link_simple_auth, file_pam)
                self.replace_auth(file_console, self.auth_user)
            else:
                self.log.error(_("Invalid authentication %s for %s!") % (auth, app))
# }}}

