#!/usr/bin/python -O
#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : msec/share
# File            : msec.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Wed Dec  5 20:20:21 2001
#---------------------------------------------------------------

from mseclib import *
from Log import *
from Log import _name
import Config
import ConfigFile

import sys
import os
import string
import getopt
import gettext
import imp

try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# Eval a file
def eval_file(name):
    file = os.fdopen(os.open(os.path.expanduser(name), os.O_RDONLY))
    imp.load_source('', name, file)
    file.close()

# program
_name = 'msec'

sys.argv[0] = os.path.basename(sys.argv[0])

try:
    (opt, args) = getopt.getopt(sys.argv[1:], 'o:',
                                ['option'])
except getopt.error:
    error(_('Invalid option. Use %s (-o var=<val>...) ([0-5])') % _name)
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
        error(_('Secure level not set. Use %s <secure level> to set it.') % _msec)
        sys.exit(1)
else:
    level = args[0]

try:
    level = int(level)
except ValueError:
    error(_('Invalid secure level %s.  Use %s [0-5] to set it.') % (level, _msec))
    sys.exit(1)

if level < 0 or level > 5:
    error(_('Invalid secure level %s.  Use %s [0-5] to set it.') % (level, _msec))
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
    authorize_services(NONE)
    enable_pam_wheel_for_su(1)
else:
    set_root_umask('022')
    if level == 4:
        set_shell_timeout(3600)
        authorize_services(LOCAL)
    else:
        set_shell_timeout(0)
        authorize_services(ALL)
    enable_pam_wheel_for_su(0)
    
# differences between level 4,5 and others
if level >= 4:
    set_user_umask('077')
    set_shell_history_size(10)
    allow_root_login(0)
    enable_sulogin(1)
    allow_user_list(0)
    enable_promisc_check(1)
    accept_icmp_echo(0)
    accept_bogus_error_responses(0)
    enable_libsafe(1)
    allow_reboot(0)
    enable_at_crontab(0)
    if level == 4:
        password_aging(60)
    else:
        password_aging(30)
else:
    set_user_umask('022')
    set_shell_history_size(-1)
    allow_root_login(1)
    enable_sulogin(0)
    allow_user_list(1)
    enable_promisc_check(0)
    accept_icmp_echo(1)
    accept_bogus_error_responses(1)
    enable_libsafe(0)
    allow_reboot(1)
    enable_at_crontab(1)
    password_aging(99999)
    
# differences between level 3,4,5 and others
if server:
    allow_autologin(0)
    enable_console_log(1)
    if level == 5:
        allow_issues(NONE)
    else:
        allow_issues(LOCAL)
    enable_log_strange_packets(1)
else:
    allow_autologin(1)
    enable_console_log(0)
    allow_issues(ALL)
    enable_log_strange_packets(0)

# differences between level 0 and others
if level != 0:
    enable_security_check(1)
    if level < 3:
        allow_x_connections(LOCAL)
    else:
        allow_x_connections(NONE)
else:
    enable_security_check(0)
    allow_x_connections(ALL)

# msec cron
enable_msec_cron(1)

# TODO: need to be rewritten because we need to use fakelibmsec instead
# of calling directly the low level functions
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
               'CHKROOTKIT_CHECK' : ('no',  'no',  'no',  'yes',  'yes',  'yes',  ),
               }

for k in FILE_CHECKS.keys():
    set_security_conf(k, FILE_CHECKS[k][level])

# load local customizations
CONFIG='/etc/security/msec/level.local'
if os.path.exists(CONFIG):
    try:
        eval_file(CONFIG)
    except:
        log(_('Error loading %s: %s') % (CONFIG, sys.exc_value[0]))

commit_changes()

interactive and log(_('Writing config files and then taking needed actions'))
ConfigFile.write_files()

closelog()

# msec.py ends here
