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
import mseclib
def import_only_mseclib(name, globals = None, locals = None, fromlist = None):
    """ Import hook to allow only the mseclib module to be imported. """

    if name == 'mseclib':
        return mseclib
    else:
        raise ImportError, '%s cannot be imported' % name
    
def eval_file(name):
    """ Eval level.local file.  Only allow mseclib to be imported for
    backward compatibility. """
    
    globals = {}
    locals = {}
    builtins = {}

    # Insert symbols from mseclib into globals
    non_exported_names = ['FAKE', 'indirect', 'commit_changes', 'print_changes', 'get_translation']
    for attrib_name in dir(mseclib):
        if attrib_name[0] != '_' and attrib_name not in non_exported_names:
            globals[attrib_name] = getattr(mseclib, attrib_name)
            
    # Set import hook -- it needs to be in globals['__builtins'] so we make
    # a copy of builtins to put there
    builtins.update(__builtins__.__dict__)
    builtins['__import__'] = import_only_mseclib
    globals['__builtins__'] = builtins

    # Exec file
    execfile(os.path.expanduser(name), globals, locals)

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
        error(_('Secure level not set. Use %s <secure level> to set it.') % _name)
        sys.exit(1)
else:
    level = args[0]
    changing_level()
    
try:
    level = int(level)
except ValueError:
    error(_('Invalid secure level %s.  Use %s [0-5] to set it.') % (level, _name))
    sys.exit(1)

if level < 0 or level > 5:
    error(_('Invalid secure level %s.  Use %s [0-5] to set it.') % (level, _name))
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
    
# differences between level 3,4,5 and others
if server:
    allow_autologin(no)
    enable_console_log(yes)
    if level == 5:
        allow_issues(NONE)
    else:
        allow_issues(LOCAL)
    enable_log_strange_packets(yes)
else:
    allow_autologin(yes)
    enable_console_log(no)
    allow_issues(ALL)
    enable_log_strange_packets(no)

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
