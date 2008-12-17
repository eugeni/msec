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

#from mseclib import *
#from Log import *
#from Log import _name
#import Config
#import ConfigFile

import sys
import os
import string
import getopt
import gettext
import imp

# logging
import logging
from logging.handlers import SysLogHandler

# configuration variables
APP_NAME="msec"
interactive = sys.stdin.isatty()

# localization
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# default parameters
#                                       security level
#               OPTION               none   default secure
SETTINGS =    {'CHECK_SECURITY' :               ('yes', 'yes',  'yes'),
               'CHECK_PERMS' :                  ('no',  'yes',  'yes'),
               'CHECK_SUID_ROOT' :              ('yes', 'yes',  'yes'),
               'CHECK_SUID_MD5' :               ('yes', 'yes',  'yes'),
               'CHECK_SGID' :                   ('yes', 'yes',  'yes'),
               'CHECK_WRITABLE' :               ('yes', 'yes',  'yes'),
               'CHECK_UNOWNED' :                ('no',  'no',   'yes'),
               'CHECK_PROMISC' :                ('no',  'no',   'yes'),
               'CHECK_OPEN_PORT' :              ('no',  'yes',  'yes'),
               'CHECK_PASSWD' :                 ('no',  'yes',  'yes'),
               'CHECK_SHADOW' :                 ('no',  'yes',  'yes'),
               'CHECK_CHKROOTKIT' :             ('no',  'yes',  'yes'), # was: CHKROOTKIT_CHECK
               'CHECK_RPM' :                    ('no',  'yes',  'yes'), # was: RPM_CHECK
               'TTY_WARN' :                     ('no',  'no',   'yes'),
               'MAIL_WARN' :                    ('no',  'yes',  'yes'),
               'MAIL_EMPTY_CONTENT':            ('no',  'no',   'yes'),
               'SYSLOG_WARN' :                  ('yes', 'yes',  'yes'),
               # security options
               'USER_UMASK':                    ('022', '022',  '077'),
               'ROOT_UMASK':                    ('022', '022',  '077'),
               'WIN_PARTS_UMASK':               ('no',  'no',   '0'  ),
               'ACCEPT_BOGUS_ERROR_RESPONSES':  ('no',  'no',   'no' ),
               'ACCEPT_BROADCASTED_ICMP_ECHO':  ('yes', 'yes',  'no' ),
               'ACCEPT_ICMP_ECHO':              ('yes', 'yes',  'yes'),
               'ALLOW_AUTOLOGIN':               ('yes', 'yes',  'no' ),
               'ALLOW_ISSUES':                  ('yes', 'yes',  'yes'),
               'ALLOW_REBOOT':                  ('yes', 'yes',  'yes'),
               'ALLOW_REMOTE_ROOT_LOGIN':       ('yes', 'WITHOUT_PASSWORD', 'no' ),
               'ALLOW_ROOT_LOGIN':              ('yes', 'yes',  'no' ),
               'ALLOW_USER_LIST':               ('yes', 'yes',  'no' ),
               'ALLOW_X_CONNECTIONS':           ('yes', 'LOCAL','no' ),
               'ALLOW_XAUTH_FROM_ROOT':         ('yes', 'yes',  'no' ),
               'ALLOW_XSERVER_TO_LISTEN':       ('yes', 'no',   'no' ),
               'AUTHORIZE_SERVICES':            ('ALL', 'LOCAL','NONE'),
               'CREATE_SERVER_LINK':            ('no',  'no',   'yes'),
               'ENABLE_AT_CRONTAB':             ('no',  'yes',  'no' ),
               'ENABLE_CONSOLE_LOG':            ('yes', 'yes',  'no' ),
               'ENABLE_DNS_SPOOFING_PROTECTION':('yes', 'yes',  'yes'),
               'ENABLE_IP_SPOOFING_PROTECTION': ('yes', 'yes',  'yes'),
               'ENABLE_LOG_STRANGE_PACKETS':    ('no',  'yes',  'yes'),
               'ENABLE_MSEC_CRON':              ('no',  'yes',  'yes'),
               'ENABLE_PAM_ROOT_FROM_WHEEL':    ('no',  'no',   'no' ),
               'ENABLE_PAM_WHEEL_FOR_SU':       ('no',  'no',   'yes'),
               'ENABLE_PASSWORD':               ('yes', 'yes',  'yes'),
               'ENABLE_SULOGIN':                ('no',  'no',   'yes'),
               # password aging - do we need that at all??
               'NO_PASSWORD_AGING_FOR':         ('no',  'no',   'no' ),
               'PASSWORD_AGING':                ('no',  'no',   'no' ),
               'PASSWORD_HISTORY':              ('no',  'no',   '2'  ),
               #                                length, ndigits, nupper
               'PASSWORD_LENGTH':               ('no',  'no',   '6,1,1'  ),
               'SHELL_HISTORY_SIZE':            ('-1',  '-1',   '100'),
               'SHELL_TIMEOUT':                 ('0',   '0',    '600'),
               }

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
        """Gets a configuration option"""
        return self.options.get(option, default)

    def set(self, option, value):
        """Sets a configuration option"""
        self.options[option] = value

    def save(self):
        """Saves configuration. Comments go on top"""
        try:
            fd = open(self.config, "w")
        except:
            self.log.error(_("Unable to save %s: %s") % (self.config, sys.exc_value))
            return False
        for comment in self.comments:
            print >>fd, comment
        for option in self.options:
            print >>fd, "%s=%s" % (option, self.options[option])
        return True


if __name__ == "__main__":
    log = Log(log_path="/tmp/msec.log")
    config = MsecConfig(log, config="/tmp/msec.conf")
    if not config.load():
        log.info(_("Unable to load config, using default values"))
    CHECK_SUID_ROOT = config.get("CHECK_SUID_ROOT")
    if not CHECK_SUID_ROOT:
        config.set("CHECK_SUID_ROOT", "yes")
    if not config.save():
        log.error(_("Unable to save config!"))
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
        allow_remote_root_login(without_password)
    else:
        password_aging(30, 15)
        allow_remote_root_login(no)
    allow_xauth_from_root(no)
    set_win_parts_umask(None)
else:
    set_user_umask('022')
    set_shell_history_size(-1)
    allow_root_login(yes)
    allow_remote_root_login(yes)
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
