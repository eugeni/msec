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
               'PASSWORD_AGING':                (['no',  'no',   'no' ], "password_aging"),
               'PASSWORD_HISTORY':              (['no',  'no',   '2'  ], "password_history"),
               'PASSWORD_LENGTH':               (['no',  'no', '6,1,1'], "password_length"),
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

        self.logger.setLevel(logging.INFO)

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
"""
# }}}

if __name__ == "__main__":
    # configuring logging
    interactive = sys.stdin.isatty()
    if interactive:
        # logs to file and to terminal
        log = Log(log_path="/tmp/msec.log", interactive=True, log_syslog=False)
    else:
        log = Log(log_path="/tmp/msec.log", interactive=False)

    # configurable options
    force_level = False

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hl:f', ['help', 'list', 'force'])
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
        print "%s: -> %s(%s)" % (opt, callbacks[opt], config.get(opt))
        msec.run_action(callbacks[opt], config.get(opt))
    sys.exit(0)

############


sys.argv[0] = os.path.basename(sys.argv[0])

try:
    (opt, args) = getopt.getopt(sys.argv[1:], 'o:',
                                ['option'])
except getopt.error:
    error(_('Invalid option. Use %s (-o var=<val>...) ([0-5])') % APP_NAME)
    sys.exit(1)


for o in opt:
    if o[0] == '-o' or o[0] == '--option':
        pair = string.split(o[1], '=')
        if len(pair) != 2:
            error(_('Invalid option format %s %s: use -o var=<val>') % (o[0], o[1]))
            sys.exit(1)
        else:
            Config.set_config(pair[0], pair[1])

set_interactive(interactive)

if len(args) == 0:
    level = get_secure_level()
    if level == None:
        error(_('Secure level not set. Use %s <secure level> to set it.') % APP_NAME)
        sys.exit(1)
else:
    level = args[0]
    changing_level()
    
try:
    level = int(level)
except ValueError:
    error(_('Invalid secure level %s.  Use %s [0-5] to set it.') % (level, APP_NAME))
    sys.exit(1)

if level < 0 or level > 5:
    error(_('Invalid secure level %s.  Use %s [0-5] to set it.') % (level, APP_NAME))
    sys.exit(1)

interactive and log(_('### Program is starting ###'))

set_secure_level(level)

server=(level in range(3, 6))

# process options
server_level = Config.get_config('server_level')
if server_level:
    set_server_level(server_level)

create_server_link()

# for all levels: min length = 2 * (level - 1) and for level 4,5 makes mandatory
# to have at least one upper case character and one digit.
if level > 1:
    plength = (level - 1) * 2
else:
    plength = 0
    
password_length(plength, level / 4, level / 4)

enable_ip_spoofing_protection(server)
enable_dns_spoofing_protection(server)

# differences between level 5 and others
if level == 5:
    set_root_umask('077')
    set_shell_timeout(900)
    authorize_services(NONE)
    enable_pam_wheel_for_su(yes)
    password_history(5)
else:
    set_root_umask('022')
    if level == 4:
        set_shell_timeout(3600)
        authorize_services(LOCAL)
    else:
        set_shell_timeout(0)
        authorize_services(ALL)
    enable_pam_wheel_for_su(no)
    password_history(0)
    
# differences between level 4,5 and others
if level >= 4:
    set_user_umask('077')
    set_shell_history_size(10)
    allow_root_login(no)
    enable_sulogin(yes)
    allow_user_list(no)
    enable_promisc_check(yes)
    accept_icmp_echo(no)
    accept_broadcasted_icmp_echo(no)
    accept_bogus_error_responses(no)
    allow_reboot(no)
    enable_at_crontab(no)
    if level == 4:
        password_aging(60, 30)
    else:
        password_aging(30, 15)
    allow_xauth_from_root(no)
    set_win_parts_umask(None)
else:
    set_user_umask('022')
    set_shell_history_size(-1)
    allow_root_login(yes)
    enable_sulogin(no)
    allow_user_list(yes)
    enable_promisc_check(no)
    accept_icmp_echo(yes)
    accept_broadcasted_icmp_echo(yes)
    accept_bogus_error_responses(yes)
    allow_reboot(yes)
    enable_at_crontab(yes)
    password_aging(99999)
    allow_xauth_from_root(yes)

# special exception for ssh; if level == 3, set
# PermitRootLogin to without_password, otherwise set to no
# see https://qa.mandriva.com/show_bug.cgi?id=19726
if level >= 3:
    if level == 3:
        allow_remote_root_login(without_password)
    else:
        allow_remote_root_login(no)
else:
    allow_remote_root_login(yes)

# differences between level 3,4,5 and others
if server:
    allow_autologin(no)
    enable_console_log(yes)
    if level == 5:
        allow_issues(NONE)
    else:
        allow_issues(LOCAL)
    enable_log_strange_packets(yes)
    enable_pam_root_from_wheel(no)
else:
    allow_autologin(yes)
    enable_console_log(no)
    allow_issues(ALL)
    enable_log_strange_packets(no)
    enable_pam_root_from_wheel(yes)
    set_win_parts_umask('0')

# differences between level 0 and others
if level != 0:
    enable_security_check(yes)
    enable_password(yes)
    if level < 3:
        allow_x_connections(LOCAL)
        allow_xserver_to_listen(yes)
    else:
        if level == 3:
            allow_x_connections(NONE)
            allow_xserver_to_listen(yes)
        else:
            allow_x_connections(NONE)
            allow_xserver_to_listen(no)            
else:
    enable_security_check(no)
    enable_password(no)
    allow_x_connections(ALL, 1)
    allow_xserver_to_listen(yes)

# msec cron
enable_msec_cron(1)

#                                     0      1      2      3       4       5
FILE_CHECKS = {'CHECK_SECURITY' :   ('no',  'yes', 'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_PERMS' :      ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'CHECK_SUID_ROOT' :  ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_SUID_MD5' :   ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_SGID' :       ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_WRITABLE' :   ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_UNOWNED' :    ('no',  'no',  'no',  'no',   'yes',  'yes',  ),
               'CHECK_PROMISC' :    ('no',  'no',  'no',  'no',   'yes',  'yes',  ),
               'CHECK_OPEN_PORT' :  ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'CHECK_PASSWD' :     ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'CHECK_SHADOW' :     ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'TTY_WARN' :         ('no',  'no',  'no',  'no',   'yes',  'yes',  ),
               'MAIL_WARN' :        ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'MAIL_EMPTY_CONTENT':('no',  'no',  'no',  'no',   'yes',  'yes',  ),
               'SYSLOG_WARN' :      ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'RPM_CHECK' :        ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'CHKROOTKIT_CHECK' : ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               }

for k in FILE_CHECKS.keys():
    set_security_conf(k, FILE_CHECKS[k][level])

if Config.get_config('nolocal', '0') == '0':
    # load local customizations
    CONFIG='/etc/security/msec/level.local'
    if os.path.exists(CONFIG):
        interactive and log(_('Reading local rules from %s') % CONFIG)
        local_config(1)
        try:
            eval_file(CONFIG)
        except:
            log(_('Error loading %s: %s') % (CONFIG, str(sys.exc_value)))
        local_config(0)

if Config.get_config('print', '0') == '1':
    print_changes()
else:
    commit_changes()

interactive and log(_('Writing config files and then taking needed actions'))
ConfigFile.write_files()

closelog()

# msec.py ends here
