#!/usr/bin/python -O
#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : msec/share
# File            : msec.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Wed Dec  5 20:20:21 2001
#---------------------------------------------------------------

from libmsec import *
from Log import *
from Log import _name
import Config
import sys
import os
import string
import getopt
import gettext

try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# program
_name = 'msec'

sys.argv[0] = os.path.basename(sys.argv[0])

try:
    (opt, args) = getopt.getopt(sys.argv[1:], 'o:',
                                ['option'])
except getopt.error:
    error(_('Invalid option. Use %s (-o var=<val>...) ([0-5])') % sys.argv[0])
    sys.exit(1)


for o in opt:
    if o[0] == '-o' or o[0] == '--option':
        pair = string.split(o[1], '=')
        if len(pair) != 2:
            error(_('Invalid option format %s %s: use -o var=<val>') % (o[0], o[1]))
            sys.exit(1)
        else:
            Config.set_config(pair[0], pair[1])

interactive = sys.stdin.isatty()
set_interactive(interactive)

# initlog must be done after processing the option because we can change
# the way to report log with options...
if interactive:
    import syslog
    
    initlog('msec', syslog.LOG_LOCAL1)
else:
    initlog('msec')
    
if len(args) == 0:
    level = get_secure_level()
    if level == None:
        error(_('Secure level not set. Use %s <secure level> to set it.') % sys.argv[0])
        sys.exit(1)
else:
    level = args[0]

try:
    level = int(level)
except ValueError:
    error(_('Invalid secure level %s.  Use %s [0-5] to set it.') % (level, sys.argv[0]))
    sys.exit(1)

if level < 0 or level > 5:
    error(_('Invalid secure level %s.  Use %s [0-5] to set it.') % (level, sys.argv[0]))
    sys.exit(1)

interactive and log(_('### Program is starting ###'))

set_secure_level(level)

server=(level in range(3, 6))

# for all levels: min length = 2 * (level - 1) and for level 4,5 makes mandatory
# to have at least one upper case character and one digit.
if level > 1:
    plength = (level - 1) * 2
else:
    plength = 0
    
password_length(plength, level / 4, level / 4)

enable_ip_spoofing_protection(server)

# differences between level 5 and others
if level == 5:
    set_root_umask('077')
    set_shell_timeout(900)
    deny_all_services()
    enable_pam_wheel_for_su()
else:
    set_root_umask('022')
    if level == 4:
        set_shell_timeout(3600)
        deny_non_local_services()
    else:
        set_shell_timeout(0)
        authorize_all_services()
    disable_pam_wheel_for_su()
        
# differences between level 4,5 and others
if level >= 4:
    set_user_umask('077')
    set_shell_history_size(10)
    forbid_root_login()
    enable_sulogin()
    forbid_user_list()
    enable_promisc_check()
    ignore_icmp_echo()
    ignore_bogus_error_responses()
    enable_libsafe()
    forbid_reboot()
    disable_at_crontab()
    if level == 4:
        password_aging(60)
    else:
        password_aging(30)
else:
    set_user_umask('022')
    set_shell_history_size(-1)
    allow_root_login()
    disable_sulogin()
    allow_user_list()
    disable_promisc_check()
    accept_icmp_echo()
    accept_bogus_error_responses()
    disable_libsafe()
    allow_reboot()
    enable_at_crontab()
    password_aging(99999)
    
# differences between level 3,4,5 and others
if server:
    forbid_autologin()
    enable_console_log()
    forbid_issues((level != 5))
    enable_log_strange_packets()
else:
    allow_autologin()
    disable_console_log()
    allow_issues()
    disable_log_strange_packets()

# differences between level 0 and others
if level != 0:
    enable_security_check()
    if level < 3:
        allow_local_x_connections()
    else:
        restrict_x_connections()
else:
    disable_security_check()
    allow_x_connections()

# msec cron
enable_msec_cron()

#                                     0      1      2      3       4       5
FILE_CHECKS = {'CHECK_SECURITY' :   ('no',  'yes', 'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_PERMS' :      ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'CHECK_SUID_ROOT' :  ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_SUID_MD5' :   ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_SUID_GROUP' : ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_WRITEABLE' :  ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'CHECK_UNOWNED' :    ('no',  'no',  'no',  'no',   'yes',  'yes',  ),
               'CHECK_PROMISC' :    ('no',  'no',  'no',  'no',   'yes',  'yes',  ),
               'CHECK_OPEN_PORT' :  ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'CHECK_PASSWD' :     ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'CHECK_SHADOW' :     ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'TTY_WARN' :         ('no',  'no',  'no',  'no',   'yes',  'yes',  ),
               'MAIL_WARN' :        ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               'SYSLOG_WARN' :      ('no',  'no',  'yes', 'yes',  'yes',  'yes',  ),
               'RPM_CHECK' :        ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               }

interactive and log(_('Configuring periodic files checks'))
securityconf = ConfigFile.get_config_file('/etc/security/msec/security.conf')
for k in FILE_CHECKS.keys():
    securityconf.set_shell_variable(k, FILE_CHECKS[k][level])
    
interactive and log(_('Writing config files and then taking needed actions'))
ConfigFile.write_files()

closelog()

# msec.py ends here
