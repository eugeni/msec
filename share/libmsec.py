#---------------------------------------------------------------
# Project         : Mandrakelinux
# Module          : msec
# File            : libmsec.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Mon Dec 10 22:52:17 2001
# Purpose         : all access points of the msec utility.
#---------------------------------------------------------------

import ConfigFile
import Config
from Log import *

import os
import grp
import Perms
import gettext
import pwd
import re
import string
import commands
import time
import traceback

try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

SUFFIX='.msec'
_interactive=0
_same_level=1
FORCED = {}

# list of config files

ATALLOW = '/etc/at.allow'
AUTOLOGIN = '/etc/sysconfig/autologin'
BASTILLENOLOGIN = '/etc/bastille-no-login'
CRON = '/etc/cron.d/msec'
CRONALLOW = '/etc/cron.allow'
GDM = '/etc/pam.d/gdm'
GDMCONF = '/etc/X11/gdm/gdm.conf'
HALT = '/usr/bin/halt'
HOSTCONF = '/etc/host.conf'
HOSTSDENY = '/etc/hosts.deny'
INITTAB = '/etc/inittab'
ISSUE = '/etc/issue'
ISSUENET = '/etc/issue.net'
KDE = '/etc/pam.d/kde'
KDMRC = '/usr/share/config/kdm/kdmrc'
LDSOPRELOAD = '/etc/ld.so.preload'
LILOCONF = '/etc/lilo.conf'
LOGINDEFS = '/etc/login.defs'
MENULST = '/boot/grub/menu.lst'
MSEC = '/etc/sysconfig/msec'
MSECBIN = '/usr/sbin/msec'
MSECCRON = '/etc/cron.hourly/msec'
MSEC_XINIT = '/etc/X11/xinit.d/msec'
OPASSWD = '/etc/security/opasswd'
PASSWD = '/etc/pam.d/passwd'
POWEROFF = '/usr/bin/poweroff'
REBOOT = '/usr/bin/reboot'
SECURETTY = '/etc/securetty'
SECURITYCONF = '/var/lib/msec/security.conf'
SECURITYCRON = '/etc/cron.daily/msec'
SECURITYSH = '/usr/share/msec/security.sh'
SERVER = '/etc/security/msec/server'
SHADOW = '/etc/shadow'
SHUTDOWN = '/usr/bin/shutdown'
SHUTDOWNALLOW = '/etc/shutdown.allow'
SSHDCONFIG = '/etc/ssh/sshd_config'
STARTX = '/usr/X11R6/bin/startx'
SU = '/etc/pam.d/su'
SYSCTLCONF = '/etc/sysctl.conf'
SYSLOGCONF = '/etc/syslog.conf'
SYSTEM_AUTH = '/etc/pam.d/system-auth'
XDM = '/etc/pam.d/xdm'
XSERVERS = '/etc/X11/xdm/Xservers'
EXPORT = '/root/.xauth/export'

# constants to keep in sync with shadow.py
NONE=0
ALL=1
LOCAL=2

no=0
yes=1
without_password=2

ALL_LOCAL_NONE_TRANS = {ALL : 'ALL', NONE: 'NONE', LOCAL : 'LOCAL'}
YES_NO_TRANS = {yes : 'yes', no : 'no'}
ALLOW_ROOT_LOGIN_TRANS = {no : 'no', yes : 'yes', without_password : 'without_password'}

# config files => actions

ConfigFile.add_config_assoc(INITTAB, '/sbin/telinit q')
ConfigFile.add_config_assoc('/etc(?:/rc.d)?/init.d/(.+)', '[ -f /var/lock/subsys/@1 ] && @0 reload')
ConfigFile.add_config_assoc(SYSCTLCONF, '/sbin/sysctl -e -p /etc/sysctl.conf')
ConfigFile.add_config_assoc(SSHDCONFIG, '[ -f /var/lock/subsys/sshd ] && /etc/rc.d/init.d/sshd restart')
ConfigFile.add_config_assoc(LILOCONF, '[ `/usr/sbin/detectloader` = LILO ] && /sbin/lilo')
ConfigFile.add_config_assoc(SYSLOGCONF, '[ -f /var/lock/subsys/syslog ] && service syslog reload')
ConfigFile.add_config_assoc('^/etc/issue$', '/usr/bin/killall mingetty')

# functions

################################################################################

# The same_level function inspects the call stack in the 2 previous
# levels to see if a function is used that has been registered by
# force_val and if this is the case we act as if we were changing the
# security level to force the value to be used.
def same_level():
    'D'
    tb = traceback.extract_stack()
    if FORCED.has_key(tb[-2][2]) or FORCED.has_key(tb[-3][2]):
        return 0
    else:
        return _same_level

def changing_level():
    'D'
    global _same_level
    _same_level=0

def force_val(name):
    'D'
    global FORCED
    FORCED[name] = 1

# configuration rules

################################################################################

def set_secure_level(level):
    msec = ConfigFile.get_config_file(MSEC)

    val = msec.get_shell_variable('SECURE_LEVEL')

    if not val or int(val) != level:
        _interactive and log(_('Setting secure level to %s') % level)
        msec.set_shell_variable('SECURE_LEVEL', level)

################################################################################

def get_secure_level():
    'D'
    msec = ConfigFile.get_config_file(MSEC)
    return msec.get_shell_variable('SECURE_LEVEL')

################################################################################

def set_server_level(level):
    _interactive and log(_('Setting server level to %s') % level)
    securityconf = ConfigFile.get_config_file(SECURITYCONF)
    securityconf.set_shell_variable('SERVER_LEVEL', level)

################################################################################

def get_server_level():
    'D'
    securityconf = ConfigFile.get_config_file(SECURITYCONF)
    level = securityconf.get_shell_variable('SERVER_LEVEL')
    if level: return level
    msec = ConfigFile.get_config_file(MSEC)
    return msec.get_shell_variable('SECURE_LEVEL')

################################################################################

def create_server_link():
    '''  If SERVER_LEVEL (or SECURE_LEVEL if absent) is greater than 3
in /etc/security/msec/security.conf, creates the symlink /etc/security/msec/server
to point to /etc/security/msec/server.<SERVER_LEVEL>. The /etc/security/msec/server
is used by chkconfig --add to decide to add a service if it is present in the file
during the installation of packages.'''
    level = get_server_level()
    server = ConfigFile.get_config_file(SERVER)
    if level in ('0', '1', '2', '3'):
        _interactive and log(_('Allowing chkconfig --add from rpm'))
        server.exists() and server.unlink()
    else:
        _interactive and log(_('Restricting chkconfig --add from rpm'))
        server.symlink(SERVER + '.' + str(level))

create_server_link.arg_trans = YES_NO_TRANS

################################################################################

STRING_TYPE = type('')

# helper function for set_root_umask and set_user_umask
def set_umask(variable, umask, msg):
    'D'
    msec = ConfigFile.get_config_file(MSEC)

    if type(umask) == STRING_TYPE:
        umask = int(umask, 8)

    if msec.exists():
        val = msec.get_shell_variable(variable)
    else:
        val = None

    # don't lower security when not changing security level
    if same_level():
        if val:
            octal = umask | int(val, 8)
            umask = '0%o' % octal

    if type(umask) != STRING_TYPE:
        umask = '0%o' % umask
        
    if val != umask:
        _interactive and log(_('Setting %s umask to %s') % (msg, umask))
        msec.set_shell_variable(variable, umask)
    
def set_root_umask(umask):
    '''  Set the root umask.'''
    set_umask('UMASK_ROOT', umask, 'root')

def set_user_umask(umask):
    '''  Set the user umask.'''
    set_umask('UMASK_USER', umask, 'users')

################################################################################

# the listen_tcp argument is kept for backward compatibility
def allow_x_connections(arg, listen_tcp=None):
    '''  Allow/Forbid X connections. First arg specifies what is done
on the client side: ALL (all connections are allowed), LOCAL (only
local connection) and NONE (no connection).'''
    
    msec = ConfigFile.get_config_file(MSEC_XINIT)

    val = msec.exists() and msec.get_match('/usr/X11R6/bin/xhost\s*\+\s*([^#]*)')

    if val:
        if val == '':
            val = ALL
        elif val == 'localhost':
            val = LOCAL
        else:
            val = NONE
    else:
        val = NONE
        
    # don't lower security when not changing security level
    if same_level():
        if val == NONE or (val == LOCAL and arg == ALL):
            return
        
    if arg == ALL:
        if val != arg:
            _interactive and log(_('Allowing users to connect X server from everywhere'))
            msec.exists() and msec.replace_line_matching('/usr/X11R6/bin/xhost', '/usr/X11R6/bin/xhost +', 1)

    elif arg == LOCAL:
        if val != arg:
            _interactive and log(_('Allowing users to connect X server from localhost'))
            msec.exists() and msec.replace_line_matching('/usr/X11R6/bin/xhost', '/usr/X11R6/bin/xhost + localhost', 1)
        
    elif arg == NONE:
        if val != arg:
            _interactive and log(_('Restricting X server connection to the console user'))
            msec.exists() and msec.remove_line_matching('/usr/X11R6/bin/xhost', 1)
        
    else:
        error(_('invalid allow_x_connections arg: %s') % arg)
        return

allow_x_connections.arg_trans=ALL_LOCAL_NONE_TRANS
allow_x_connections.one_arg = 1

################################################################################

STARTX_REGEXP = '(\s*serverargs=".*) -nolisten tcp(.*")'
XSERVERS_REGEXP = '(\s*[^#]+/usr/X11R6/bin/X .*) -nolisten tcp(.*)'
GDMCONF_REGEXP = '(\s*command=.*/X.*?) -nolisten tcp(.*)$'
def allow_xserver_to_listen(arg):
    '''  The argument specifies if clients are authorized to connect
to the X server on the tcp port 6000 or not.'''
    
    startx = ConfigFile.get_config_file(STARTX)
    xservers = ConfigFile.get_config_file(XSERVERS)
    gdmconf = ConfigFile.get_config_file(GDMCONF)

    val_startx = startx.exists() and startx.get_match(STARTX_REGEXP)
    val_xservers = xservers.exists() and xservers.get_match(XSERVERS_REGEXP)
    val_gdmconf = gdmconf.exists() and gdmconf.get_match(GDMCONF_REGEXP)
    
    # don't lower security when not changing security level
    if same_level():
        if val_startx and val_xservers and val_gdmconf:
            return
        
    if arg:
        if val_startx or val_xservers or val_gdmconf:
            _interactive and log(_('Allowing the X server to listen to tcp connections'))
            if not (same_level() and val_startx):
                startx.exists() and startx.replace_line_matching(STARTX_REGEXP, '@1@2')
            if not (same_level() and val_xservers):
                xservers.exists() and xservers.replace_line_matching(XSERVERS_REGEXP, '@1@2', 0, 1)
            if not (same_level() and val_gdmconf):
                gdmconf.exists() and gdmconf. replace_line_matching(GDMCONF_REGEXP, '@1@2', 0, 1)
    else:
        if not val_startx or not val_xservers or not val_gdmconf:
            _interactive and log(_('Forbidding the X server to listen to tcp connection'))
            startx.exists() and startx.replace_line_matching('serverargs="(.*?)( -nolisten tcp)?"', 'serverargs="@1 -nolisten tcp"')
            xservers.exists() and xservers.replace_line_matching('(\s*[^#]+/usr/X11R6/bin/X .*?)( -nolisten tcp)?$', '@1 -nolisten tcp', 0, 1)
            gdmconf.exists() and gdmconf. replace_line_matching('(\s*command=.*/X.*?)( -nolisten tcp)?$', '@1 -nolisten tcp', 0, 1)

allow_xserver_to_listen.arg_trans = YES_NO_TRANS

################################################################################

def set_shell_timeout(val):
    '''  Set the shell timeout. A value of zero means no timeout.'''

    msec = ConfigFile.get_config_file(MSEC)

    if msec.exists():
        old = msec.get_shell_variable('TMOUT')
        if old != None:
            old = int(old)
    else:
        old = None
        
    # don't lower security when not changing security level
    if same_level():
        if old != None and old > val:
            return

    if old != val:
        _interactive and log(_('Setting shell timeout to %s') % val)
        msec.set_shell_variable('TMOUT', val)

################################################################################

def set_shell_history_size(size):
    '''  Set shell commands history size. A value of -1 means unlimited.'''
    msec = ConfigFile.get_config_file(MSEC)

    if msec.exists():
        val = msec.get_shell_variable('HISTFILESIZE')
    else:
        val = None
        
    # don't lower security when not changing security level
    if same_level():
        if val != None:
            val = int(val)
            if size == -1 or val < size:
                return
            
    if size >= 0:
        if val != size:
            _interactive and log(_('Setting shell history size to %s') % size)
            msec.set_shell_variable('HISTFILESIZE', size)
    else:
        if val != None:
            _interactive and log(_('Removing limit on shell history size'))
            msec.remove_line_matching('^HISTFILESIZE=')
        
################################################################################

def get_index(val, array):
    for loop in range(0, len(array)):
        if val == array[loop]:
            return loop
    return -1

################################################################################
ALLOW_SHUTDOWN_VALUES = ('All', 'Root', 'None')
CTRALTDEL_REGEXP = '^ca::ctrlaltdel:/sbin/shutdown.*'
CONSOLE_HELPER = 'consolehelper'

def allow_reboot(arg):
    '''  Allow/Forbid reboot by the console user.'''
    shutdownallow = ConfigFile.get_config_file(SHUTDOWNALLOW)
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    kdmrc = ConfigFile.get_config_file(KDMRC)
    gdmconf = ConfigFile.get_config_file(GDMCONF)
    inittab = ConfigFile.get_config_file(INITTAB)
    
    val_shutdownallow = shutdownallow.exists()
    val_sysctlconf = sysctlconf.exists() and sysctlconf.get_shell_variable('kernel.sysrq')
    val_inittab = inittab.exists() and inittab.get_match(CTRALTDEL_REGEXP)
    num = 0
    val = {}
    for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
        val[f] = ConfigFile.get_config_file(f).exists()
        if val[f]:
            num = num + 1
    val_gdmconf = gdmconf.exists() and gdmconf.get_shell_variable('SystemMenu')
    oldval_kdmrc = kdmrc.exists() and kdmrc.get_shell_variable('AllowShutdown', 'X-:\*-Core', '^\s*$')
    if oldval_kdmrc:
        oldval_kdmrc = get_index(oldval_kdmrc, ALLOW_SHUTDOWN_VALUES)
    if arg:
        val_kdmrc = 0
    else:
        val_kdmrc = 2
        
    # don't lower security when not changing security level
    if same_level():
        if val_shutdownallow and val_sysctlconf == '0' and num == 0 and oldval_kdmrc >= val_kdmrc and val_gdmconf == 'false' and not val_inittab:
            return
        if oldval_kdmrc > val_kdmrc:
            val_kdmrc = oldval_kdmrc
            
    if arg:
        _interactive and log(_('Allowing reboot to the console user'))
        if not (same_level() and val_shutdownallow):
            shutdownallow.exists() and shutdownallow.move(SUFFIX)
        for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
            cfg = ConfigFile.get_config_file(f)
            if not (same_level() and not val[f]):
                cfg.exists() or cfg.symlink(CONSOLE_HELPER)
        if not (same_level() and val_sysctlconf == '0'):
            sysctlconf.set_shell_variable('kernel.sysrq', 1)
        if not (same_level() and val_gdmconf == 'false'):
            gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'true', '\[greeter\]', '^\s*$')
        if not (same_level() and not val_inittab):
            inittab.replace_line_matching(CTRALTDEL_REGEXP, 'ca::ctrlaltdel:/sbin/shutdown -t3 -r now', 1)
    else:
        _interactive and log(_('Forbidding reboot to the console user'))
        ConfigFile.get_config_file(SHUTDOWNALLOW, SUFFIX).touch()
        for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
            ConfigFile.get_config_file(f).unlink()
        sysctlconf.set_shell_variable('kernel.sysrq', 0)
        gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'false', '\[greeter\]', '^\s*$')
        inittab.remove_line_matching(CTRALTDEL_REGEXP)

    kdmrc.exists() and kdmrc.set_shell_variable('AllowShutdown', ALLOW_SHUTDOWN_VALUES[val_kdmrc], 'X-:\*-Core', '^\s*$')

allow_reboot.arg_trans = YES_NO_TRANS

################################################################################
SHOW_USERS_VALUES = ('All', 'Selected', 'None')

def allow_user_list(arg):
    '''  Allow/Forbid the list of users on the system on display managers (kdm and gdm).'''
    kdmrc = ConfigFile.get_config_file(KDMRC)
    gdmconf = ConfigFile.get_config_file(GDMCONF)
    
    oldval_gdmconf = gdmconf.exists() and gdmconf.get_shell_variable('Browser')
    oldval_kdmrc = kdmrc.exists() and kdmrc.get_shell_variable('ShowUsers', 'X-\*-Greeter', '^\s*$')
    if oldval_kdmrc:
        oldval_kdmrc = get_index(oldval_kdmrc, SHOW_USERS_VALUES)

    if arg:
        msg = 'Allowing the listing of users in display managers'
        val_kdmrc = 0
        val_gdmconf = 'true'
    else:
        msg = 'Disabling the listing of users in display managers'
        val_kdmrc = 2
        val_gdmconf = 'false'

    # don't lower security when not changing security level
    if same_level():
        if oldval_kdmrc >= val_kdmrc  and oldval_gdmconf == 'false':
            return
        if oldval_kdmrc > val_kdmrc:
            val_kdmrc = oldval_kdmrc
        if oldval_gdmconf == 'false':
            val_gdmconf = 'false'
    
    if (gdmconf.exists() and oldval_gdmconf != val_gdmconf) or (kdmrc.exists() and oldval_kdmrc != val_kdmrc):
        _interactive and log(_(msg))
        oldval_kdmrc != val_gdmconf and kdmrc.exists() and kdmrc.set_shell_variable('ShowUsers', SHOW_USERS_VALUES[val_kdmrc], 'X-\*-Greeter', '^\s*$')
        oldval_gdmconf != val_gdmconf and gdmconf.exists() and gdmconf.set_shell_variable('Browser', val_gdmconf)

allow_user_list.arg_trans = YES_NO_TRANS

################################################################################

def allow_root_login(arg):
    '''  Allow/Forbid direct root login.'''
    securetty = ConfigFile.get_config_file(SECURETTY)
    kde = ConfigFile.get_config_file(KDE)
    gdm = ConfigFile.get_config_file(GDM)
    xdm = ConfigFile.get_config_file(XDM)

    val = {}
    val[kde] = kde.exists() and kde.get_match('auth required (?:/lib/security/)?pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login')
    val[gdm] = gdm.exists() and gdm.get_match('auth required (?:/lib/security/)?pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login')
    val[xdm] = xdm.exists() and xdm.get_match('auth required (?:/lib/security/)?pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login')
    num = 0
    for n in range(1, 7):
        s = 'tty' + str(n)
        if securetty.get_match(s):
            num = num + 1
            val[s] = 1
        else:
            val[s] = 0
        s = 'vc/' + str(n)
        if securetty.get_match(s):
            num = num + 1
            val[s] = 1
        else:
            val[s] = 0
    
    # don't lower security when not changing security level
    if same_level():
        if (not kde.exists() or val[kde]) and (not gdm.exists() or val[gdm]) and (not xdm.exists() or val[xdm]) and num == 12:
            return

    if arg:
        if val[kde] or val[gdm] or val[xdm] or num != 12:
            _interactive and log(_('Allowing direct root login'))
        
            for cnf in (kde, gdm, xdm):
                if not (same_level() and val[cnf]):
                    cnf.exists() and cnf.remove_line_matching('^auth\s*required\s*(?:/lib/security/)?pam_listfile.so.*bastille-no-login', 1)
        
            for n in range(1, 7):
                s = 'tty' + str(n)
                if not (same_level() and not val[s]):
                    securetty.replace_line_matching(s, s, 1)
                s = 'vc/' + str(n)
                if not (same_level() and not val[s]):
                    securetty.replace_line_matching(s, s, 1)
    else:
        if (kde.exists() and not val[kde]) or (gdm.exists() and not val[gdm]) or (xdm.exists() and not val[xdm]) or num > 0:
            _interactive and log(_('Forbidding direct root login'))
        
            bastillenologin = ConfigFile.get_config_file(BASTILLENOLOGIN)
            bastillenologin.replace_line_matching('^\s*root', 'root', 1)
        
            for cnf in (kde, gdm, xdm):
                cnf.exists() and (cnf.replace_line_matching('^auth\s*required\s*(?:/lib/security/)?pam_listfile.so.*bastille-no-login', 'auth required pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login') or \
                                  cnf.insert_at(0, 'auth required pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login'))
        
            securetty.remove_line_matching('.+', 1)

allow_root_login.arg_trans = YES_NO_TRANS

PERMIT_ROOT_LOGIN_REGEXP = '^\s*PermitRootLogin\s+(no|yes|without-password|forced-commands-only)'

################################################################################

def allow_remote_root_login(arg):
    '''  Allow/Forbid remote root login via sshd. You can specify
yes, no and without-password. See sshd_config(5) man page for more
information.'''
    sshd_config = ConfigFile.get_config_file(SSHDCONFIG)

    if sshd_config.exists():
        val = sshd_config.get_match(PERMIT_ROOT_LOGIN_REGEXP, '@1')
    else:
        val = None

    # don't lower security when not changing security level
    if same_level():
        if val == 'no':
            return
        if val == 'forced-commands-only':
            return

    if val == 'yes':
        val = yes
    elif val == 'no':
        val = no
    elif val == 'without-password':
        val = without_password
    else:
        val = yes
        
    if val != arg:
        if arg == yes:
            _interactive and log(_('Allowing remote root login'))
            sshd_config.exists() and sshd_config.replace_line_matching(PERMIT_ROOT_LOGIN_REGEXP,
                                                                       'PermitRootLogin yes', 1)
        elif arg == no:
            _interactive and log(_('Forbidding remote root login'))
            sshd_config.exists() and sshd_config.replace_line_matching(PERMIT_ROOT_LOGIN_REGEXP,
                                                                       'PermitRootLogin no', 1)
        elif arg == without_password:
            _interactive and log(_('Allowing remote root login only by passphrase'))
            sshd_config.exists() and sshd_config.replace_line_matching(PERMIT_ROOT_LOGIN_REGEXP,
                                                                       'PermitRootLogin without-password', 1)

allow_remote_root_login.arg_trans = ALLOW_ROOT_LOGIN_TRANS

################################################################################

def enable_pam_wheel_for_su(arg):
    '''   Enabling su only from members of the wheel group or allow su from any user.'''
    su = ConfigFile.get_config_file(SU)

    val = su.exists() and su.get_match('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$')
    
    # don't lower security when not changing security level
    if same_level():
        if val:
            return

    if arg:
        if not val:
            _interactive and log(_('Allowing su only from wheel group members'))
            try:
                ent = grp.getgrnam('wheel')
            except KeyError:
                error(_('no wheel group'))
                return
            members = ent[3]
            if members == [] or members == ['root']:
                _interactive and error(_('wheel group is empty'))
                return
            su.exists() and (su.replace_line_matching('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$',
                                                      'auth       required     pam_wheel.so use_uid') or \
                             su.insert_after('^auth\s+required',
                                             'auth       required     pam_wheel.so use_uid'))
    else:
        if val:
            _interactive and log(_('Allowing su for all'))
            su.exists() and su.remove_line_matching('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$')

enable_pam_wheel_for_su.arg_trans = YES_NO_TRANS

################################################################################

def allow_issues(arg):
    '''  If \\fIarg\\fP = ALL allow /etc/issue and /etc/issue.net to exist. If \\fIarg\\fP = NONE no issues are
allowed else only /etc/issue is allowed.'''
    issue = ConfigFile.get_config_file(ISSUE, SUFFIX)
    issuenet = ConfigFile.get_config_file(ISSUENET, SUFFIX)

    val = issue.exists(1)
    valnet = issuenet.exists(1)

    # don't lower security when not changing security level
    if same_level():
        if not val and not valnet:
            return
        if arg == ALL and not valnet:
            return

    if arg == ALL:
        if not (val and valnet):
            _interactive and log(_('Allowing network pre-login messages'))    
            issue.exists() and issue.get_lines()
            issuenet.exists() and issuenet.get_lines()
    else:
        if arg == NONE:
            if val:
                _interactive and log(_('Disabling pre-login message'))
                issue.exists(1) and issue.move(SUFFIX) and issue.modified()
        else:
            if not val:
                _interactive and log(_('Allowing pre-login message'))
                issue.exists() and issue.get_lines()
        if valnet:
            _interactive and log(_('Disabling network pre-login message'))
            issuenet.exists(1) and issuenet.move(SUFFIX)

allow_issues.arg_trans = ALL_LOCAL_NONE_TRANS

################################################################################

def allow_autologin(arg):
    '''  Allow/Forbid autologin.'''
    autologin = ConfigFile.get_config_file(AUTOLOGIN)

    if autologin.exists():
        val = autologin.get_shell_variable('AUTOLOGIN')
    else:
        val = None
        
    # don't lower security when not changing security level
    if same_level():
        if val == 'no':
            return

    if arg:
        if val != 'yes':
            _interactive and log(_('Allowing autologin'))
            autologin.exists() and autologin.set_shell_variable('AUTOLOGIN', 'yes')
    else:
        if val != 'no':
            _interactive and log(_('Forbidding autologin'))
            autologin.exists() and autologin.set_shell_variable('AUTOLOGIN', 'no')

allow_autologin.arg_trans = YES_NO_TRANS

################################################################################

def password_loader(value):
    'D'
    _interactive and log(_('Activating password in boot loader'))
    liloconf = ConfigFile.get_config_file(LILOCONF)
    liloconf.exists() and (liloconf.replace_line_matching('^password=', 'password="' + value + '"', 0, 1) or \
                           liloconf.insert_after('^boot=', 'password="' + value + '"')) and \
                           Perms.chmod(liloconf.path, 0600)
    # TODO encrypt password in grub
    menulst = ConfigFile.get_config_file(MENULST)
    menulst.exists() and (menulst.replace_line_matching('^password\s', 'password "' + value + '"') or \
                          menulst.insert_at(0, 'password "' + value + '"')) and \
                          Perms.chmod(menulst.path, 0600)
    # TODO add yaboot support
        
################################################################################

def nopassword_loader():
    'D'
    _interactive and log(_('Removing password in boot loader'))
    liloconf = ConfigFile.get_config_file(LILOCONF)
    liloconf.exists() and liloconf.remove_line_matching('^password=', 1)
    menulst = ConfigFile.get_config_file(MENULST)
    menulst.exists() and menulst.remove_line_matching('^password\s')

################################################################################

def enable_console_log(arg, expr='*.*', dev='tty12'):
    '''  Enable/Disable syslog reports to console 12. \\fIexpr\\fP is the
expression describing what to log (see syslog.conf(5) for more details) and
dev the device to report the log.'''
    
    syslogconf = ConfigFile.get_config_file(SYSLOGCONF)

    if syslogconf.exists():
        val = syslogconf.get_match('\s*[^#]+/dev/([^ ]+)', '@1')
    else:
        val = None

    # don't lower security when not changing security level
    if same_level():
        if val:
            return
        
    if arg:
        if dev != val:
            _interactive and log(_('Enabling log on console'))
            syslogconf.exists() and syslogconf.replace_line_matching('\s*[^#]+/dev/', expr + ' /dev/' + dev, 1)
    else:
        if val != None:
            _interactive and log(_('Disabling log on console'))
            syslogconf.exists() and syslogconf.remove_line_matching('\s*[^#]+/dev/')

enable_console_log.arg_trans = YES_NO_TRANS

CRON_ENTRY = '*/1 * * * *    root    /usr/share/msec/promisc_check.sh'
CRON_REGEX = '[^#]+/usr/share/msec/promisc_check.sh'

################################################################################

def enable_promisc_check(arg):
    '''  Activate/Disable ethernet cards promiscuity check.'''
    cron = ConfigFile.get_config_file(CRON)
    
    val = cron.exists() and cron.get_match(CRON_REGEX)
    
    # don't lower security when not changing security level
    if same_level():
        if val == CRON_ENTRY:
            return
        
    if arg:
        if val != CRON_ENTRY:
            _interactive and log(_('Activating periodic promiscuity check'))
            cron.replace_line_matching(CRON_REGEX, CRON_ENTRY, 1)
    else:
        if val:
            _interactive and log(_('Disabling periodic promiscuity check'))
            cron.remove_line_matching('[^#]+/usr/share/msec/promisc_check.sh')

enable_promisc_check.arg_trans = YES_NO_TRANS

################################################################################

def enable_security_check(arg):
    '''   Activate/Disable daily security check.'''
    cron = ConfigFile.get_config_file(CRON)
    cron.remove_line_matching('[^#]+/usr/share/msec/security.sh')

    securitycron = ConfigFile.get_config_file(SECURITYCRON)

    val = securitycron.exists()
    
    # don't lower security when not changing security level
    if same_level():
        if val:
            return
        
    if arg:
        if not val:
            _interactive and log(_('Activating daily security check'))
            securitycron.symlink(SECURITYSH)
    else:
        if val:
            _interactive and log(_('Disabling daily security check'))
            securitycron.unlink()

enable_security_check.arg_trans = YES_NO_TRANS

################################################################################

ALL_REGEXP = '^ALL:ALL:DENY'
ALL_LOCAL_REGEXP = '^ALL:ALL EXCEPT 127\.0\.0\.1:DENY'
def authorize_services(arg):
    '''  Authorize all services controlled by tcp_wrappers (see hosts.deny(5)) if \\fIarg\\fP = ALL. Only local ones
if \\fIarg\\fP = LOCAL and none if \\fIarg\\fP = NONE. To authorize the services you need, use /etc/hosts.allow
(see hosts.allow(5)).'''
    hostsdeny = ConfigFile.get_config_file(HOSTSDENY)
    
    if hostsdeny.exists():
        if hostsdeny.get_match(ALL_REGEXP):
            val = NONE
        elif hostsdeny.get_match(ALL_LOCAL_REGEXP):
            val = LOCAL
        else:
            val = ALL
    else:
        val = ALL
        
    # don't lower security when not changing security level
    if same_level():
        if val == NONE or (val == LOCAL and arg == ALL):
            return
        
    if arg == ALL:
        if arg != val:
            _interactive and log(_('Authorizing all services'))
            hostsdeny.remove_line_matching(ALL_REGEXP, 1)
            hostsdeny.remove_line_matching(ALL_LOCAL_REGEXP, 1)
    elif arg == NONE:
        if arg != val:
            _interactive and log(_('Disabling all services'))
            hostsdeny.remove_line_matching('^ALL:ALL EXCEPT 127\.0\.0\.1:DENY', 1)
            hostsdeny.replace_line_matching('^ALL:ALL:DENY', 'ALL:ALL:DENY', 1)
    elif arg == LOCAL:
        if arg != val:
            _interactive and log(_('Disabling non local services'))
            hostsdeny.remove_line_matching(ALL_REGEXP, 1)
            hostsdeny.replace_line_matching(ALL_LOCAL_REGEXP, 'ALL:ALL EXCEPT 127.0.0.1:DENY', 1)
    else:
        error(_('authorize_services invalid argument: %s') % arg)

authorize_services.arg_trans = ALL_LOCAL_NONE_TRANS

################################################################################

def boolean2bit(bool):
    if bool:
        return 1
    else:
        return 0
    
# helper function for enable_ip_spoofing_protection, accept_icmp_echo, accept_broadcasted_icmp_echo,
# accept_bogus_error_responses and enable_log_strange_packets.
def set_zero_one_variable(file, variable, value, secure_value, one_msg, zero_msg):
    'D'
    f = ConfigFile.get_config_file(file)

    if f.exists():
        val = f.get_shell_variable(variable)
        if val:
            val = int(val)
    else:
        val = None
        
    # don't lower security when not changing security level
    if same_level():
        if val == secure_value:
            return
    
    if value != val:
        if value:
            msg = _(one_msg)
        else:
            msg = _(zero_msg)
        
        _interactive and log(msg)
        f.set_shell_variable(variable, boolean2bit(value))

################################################################################

# the alert argument is kept for backward compatibility
def enable_ip_spoofing_protection(arg, alert=1):
    '''  Enable/Disable IP spoofing protection.'''
    set_zero_one_variable(SYSCTLCONF, 'net.ipv4.conf.all.rp_filter', arg, 1, 'Enabling ip spoofing protection', 'Disabling ip spoofing protection')

enable_ip_spoofing_protection.arg_trans = YES_NO_TRANS
enable_ip_spoofing_protection.one_arg = 1

################################################################################

def enable_dns_spoofing_protection(arg, alert=1):
    '''  Enable/Disable name resolution spoofing protection.  If
\\fIalert\\fP is true, also reports to syslog.'''
    hostconf = ConfigFile.get_config_file(HOSTCONF)

    val = hostconf.exists() and hostconf.get_match('nospoof\s+on')
    
    # don't lower security when not changing security level
    if same_level():
        if val:
            return
        
    if arg:
        if not val:
            _interactive and log(_('Enabling name resolution spoofing protection'))
            hostconf.replace_line_matching('nospoof', 'nospoof on', 1)
            hostconf.replace_line_matching('spoofalert', 'spoofalert on', (alert != 0))
    else:
        if val:
            _interactive and log(_('Disabling name resolution spoofing protection'))
            hostconf.remove_line_matching('nospoof')
            hostconf.remove_line_matching('spoofalert')

enable_dns_spoofing_protection.arg_trans = YES_NO_TRANS

################################################################################

def accept_icmp_echo(arg):
    '''   Accept/Refuse icmp echo.'''
    set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_echo_ignore_all', not arg, 1, 'Ignoring icmp echo', 'Accepting icmp echo')

accept_icmp_echo.arg_trans = YES_NO_TRANS

################################################################################

def accept_broadcasted_icmp_echo(arg):
    '''   Accept/Refuse broadcasted icmp echo.'''
    set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_echo_ignore_broadcasts', not arg, 1, 'Ignoring broadcasted icmp echo', 'Accepting broadcasted icmp echo')

accept_broadcasted_icmp_echo.arg_trans = YES_NO_TRANS

################################################################################

def accept_bogus_error_responses(arg):
    '''  Accept/Refuse bogus IPv4 error messages.'''
    set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_ignore_bogus_error_responses', not arg, 1, 'Ignoring bogus icmp error responses', 'Accepting bogus icmp error responses')

accept_bogus_error_responses.arg_trans = YES_NO_TRANS

################################################################################

def enable_log_strange_packets(arg):
    '''  Enable/Disable the logging of IPv4 strange packets.'''
    set_zero_one_variable(SYSCTLCONF, 'net.ipv4.conf.all.log_martians', arg, 1, 'Enabling logging of strange packets', 'Disabling logging of strange packets')

enable_log_strange_packets.arg_trans = YES_NO_TRANS

################################################################################

def enable_libsafe(arg):
    '''  Enable/Disable libsafe if libsafe is found on the system.'''

    ldsopreload = ConfigFile.get_config_file(LDSOPRELOAD)

    val = ldsopreload.exists() and ldsopreload.get_match('/lib/libsafe.so.2')

    # don't lower security when not changing security level
    if same_level():
        if val:
            return
    
    if arg:
        if not val:
            if os.path.exists(Config.get_config('root', '') + '/lib/libsafe.so.2'):
                _interactive and log(_('Enabling libsafe'))
                ldsopreload.replace_line_matching('[^#]*libsafe', '/lib/libsafe.so.2', 1)
    else:
        if val:
            _interactive and log(_('Disabling libsafe'))
            ldsopreload.remove_line_matching('[^#]*libsafe')        

enable_libsafe.arg_trans = YES_NO_TRANS

################################################################################

LENGTH_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sminlen=([0-9]+)\s(.*)')
NDIGITS_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sdcredit=([0-9]+)\s(.*)')
UCREDIT_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sucredit=([0-9]+)\s(.*)')

def password_length(length, ndigits=0, nupper=0):
    '''  Set the password minimum length and minimum number of digit and minimum number of capitalized letters.'''

    passwd = ConfigFile.get_config_file(SYSTEM_AUTH)

    val_length = val_ndigits = val_ucredit = 999999
    
    if passwd.exists():
        val_length  = passwd.get_match(LENGTH_REGEXP, '@2')
        if val_length:
            val_length = int(val_length)
        
        val_ndigits = passwd.get_match(NDIGITS_REGEXP, '@2')
        if val_ndigits:
            val_ndigits = int(val_ndigits)

        val_ucredit = passwd.get_match(UCREDIT_REGEXP, '@2')
        if val_ucredit:
            val_ucredit = int(val_ucredit)
            
    # don't lower security when not changing security level
    if same_level():
        if val_length > length and val_ndigits > ndigits and val_ucredit > nupper:
            return
        
        if val_length > length:
            length = val_length
            
        if val_ndigits > ndigits:
            ndigits = val_ndigits

        if val_ucredit > nupper:
            nupper = val_ucredit

    if passwd.exists() and (val_length != length or val_ndigits != ndigits or val_ucredit != nupper):
        _interactive and log(_('Setting minimum password length %d') % length)
        (passwd.replace_line_matching(LENGTH_REGEXP,
                                      '@1 minlen=%s @3' % length) or \
         passwd.replace_line_matching('^password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*',
                                      '@0 minlen=%s ' % length))
    
        (passwd.replace_line_matching(NDIGITS_REGEXP,
                                      '@1 dcredit=%s @3' % ndigits) or \
         passwd.replace_line_matching('^password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*',
                                      '@0 dcredit=%s ' % ndigits))
    
        (passwd.replace_line_matching(UCREDIT_REGEXP,
                                      '@1 ucredit=%s @3' % nupper) or \
         passwd.replace_line_matching('^password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*',
                                      '@0 ucredit=%s ' % nupper))

################################################################################

PASSWORD_REGEXP = '^\s*auth\s+sufficient\s+(?:/lib/security/)?pam_permit.so'
def enable_password(arg):
    '''  Use password to authenticate users.'''
    system_auth = ConfigFile.get_config_file(SYSTEM_AUTH)

    val = system_auth.exists() and system_auth.get_match(PASSWORD_REGEXP)
    
    # don't lower security when not changing security level
    if same_level():
        if not val:
            return
        
    if arg:
        if val:
            _interactive and log(_('Using password to authenticate users'))
            system_auth.remove_line_matching(PASSWORD_REGEXP)
    else:
        if not val:
            _interactive and log(_('Don\'t use password to authenticate users'))
            system_auth.replace_line_matching(PASSWORD_REGEXP, 'auth        sufficient    pam_permit.so') or \
            system_auth.insert_before('auth\s+sufficient', 'auth        sufficient    pam_permit.so')

enable_password.arg_trans = YES_NO_TRANS

################################################################################

UNIX_REGEXP = re.compile('(^\s*password\s+sufficient\s+(?:/lib/security/)?pam_unix.so.*)\sremember=([0-9]+)(.*)')

def password_history(arg):
    '''  Set the password history length to prevent password reuse.'''
    system_auth = ConfigFile.get_config_file(SYSTEM_AUTH)

    if system_auth.exists():
        val = system_auth.get_match(UNIX_REGEXP, '@2')

        if val and val != '':
            val = int(val)
        else:
            val = 0
    else:
        val = 0

    # don't lower security when not changing security level
    if same_level():
        if val >= arg:
            return
    
    if arg != val:
        if arg > 0:
            _interactive and log(_('Setting password history to %d.') % arg)
            system_auth.replace_line_matching(UNIX_REGEXP, '@1 remember=%d@3' % arg) or \
            system_auth.replace_line_matching('(^\s*password\s+sufficient\s+(?:/lib/security/)?pam_unix.so.*)', '@1 remember=%d' % arg)
            opasswd = ConfigFile.get_config_file(OPASSWD)
            opasswd.exists() or opasswd.touch()
        else:
            _interactive and log(_('Disabling password history'))
            system_auth.replace_line_matching(UNIX_REGEXP, '@1@3')

################################################################################

SULOGIN_REGEXP = '~~:S:wait:/sbin/sulogin'
def enable_sulogin(arg):
    '''   Enable/Disable sulogin(8) in single user level.'''
    inittab = ConfigFile.get_config_file(INITTAB)

    val = inittab.exists() and inittab.get_match(SULOGIN_REGEXP)
    
    # don't lower security when not changing security level
    if same_level():
        if val:
            return
        
    if arg:
        if not val:
            _interactive and log(_('Enabling sulogin in single user runlevel'))
            inittab.replace_line_matching('[^#]+:S:', '~~:S:wait:/sbin/sulogin', 1)
    else:
        if val:
            _interactive and log(_('Disabling sulogin in single user runlevel'))
            inittab.remove_line_matching('~~:S:wait:/sbin/sulogin')

enable_sulogin.arg_trans = YES_NO_TRANS

################################################################################

def enable_msec_cron(arg):
    '''  Enable/Disable msec hourly security check.'''
    mseccron = ConfigFile.get_config_file(MSECCRON)

    val = mseccron.exists()
    
    # don't lower security when not changing security level
    if same_level():
        if val:
            return
        
    if arg:
        if arg != val:
            _interactive and log(_('Enabling msec periodic runs'))
            mseccron.symlink(MSECBIN)
    else:
        if arg != val:
            _interactive and log(_('Disabling msec periodic runs'))
            mseccron.unlink()

enable_msec_cron.arg_trans = YES_NO_TRANS

################################################################################

def enable_at_crontab(arg):
    '''  Enable/Disable crontab and at for users. Put allowed users in /etc/cron.allow and /etc/at.allow
(see man at(1) and crontab(1)).'''
    cronallow = ConfigFile.get_config_file(CRONALLOW)
    atallow = ConfigFile.get_config_file(ATALLOW)

    val_cronallow = cronallow.exists() and cronallow.get_match('root')
    val_atallow = atallow.exists() and atallow.get_match('root')
    
    # don't lower security when not changing security level
    if same_level():
        if val_cronallow and val_atallow:
            return

    if arg:
        if val_cronallow or val_atallow:
            _interactive and log(_('Enabling crontab and at'))
            if not (same_level() and val_cronallow):
                cronallow.exists() and cronallow.move(SUFFIX)
            if not (same_level() and val_atallow):
                atallow.exists() and atallow.move(SUFFIX)
    else:
        if not val_cronallow or not val_atallow:
            _interactive and log(_('Disabling crontab and at'))
            cronallow.replace_line_matching('root', 'root', 1)
            atallow.replace_line_matching('root', 'root', 1)

enable_at_crontab.arg_trans = YES_NO_TRANS

################################################################################

maximum_regex = re.compile('^Maximum:\s*([0-9]+|-1)', re.MULTILINE)
inactive_regex = re.compile('^Inactive:\s*(-?[0-9]+)', re.MULTILINE)
no_aging_list = []

def no_password_aging_for(name):
    '''D Add the name as an exception to the handling of password aging by msec.
Name must be put between '. Msec will then no more manage password aging for
name so you have to use chage(1) to manage it by hand.'''
    no_aging_list.append(name)
    
# TODO FL Sat Dec 29 20:18:20 2001
# replace chage calls and /etc/shadow parsing by a python API to the shadow functions.
def password_aging(max, inactive=-1):
    '''  Set password aging to \\fImax\\fP days and delay to change to \\fIinactive\\fP.'''
    uid_min = 500
    _interactive and log(_('Setting password maximum aging for new user to %d') % max)
    logindefs = ConfigFile.get_config_file(LOGINDEFS)
    if logindefs.exists():
        logindefs.replace_line_matching('^\s*PASS_MAX_DAYS', 'PASS_MAX_DAYS ' + str(max), 1)
        uid_min = logindefs.get_match('^\s*UID_MIN\s+([0-9]+)', '@1')
        if uid_min:
            uid_min = int(uid_min)
    shadow = ConfigFile.get_config_file(SHADOW)
    if shadow.exists():
        _interactive and log(_('Setting password maximum aging for root and users with id greater than %d to %d and delay to %d days') % (uid_min, max, inactive))
        for line in shadow.get_lines():
            field = string.split(line, ':')
            if len(field) < 2:
                continue
            name = field[0]
            password = field[1]
            if name in no_aging_list:
                _interactive and log(_('User %s in password aging exception list') % (name,))
                continue
            try:
                entry = pwd.getpwnam(name)
            except KeyError:
                error(_('User %s in shadow but not in passwd file') % name)
                continue
            if (len(password) > 0 and password[0] != '!') and password != '*' and password != 'x' and (entry[2] >= uid_min or entry[2] == 0):
                cmd = 'LC_ALL=C /usr/bin/chage -l %s' % entry[0]
                ret = commands.getstatusoutput(cmd)
                _interactive and log(_('got current maximum password aging for user %s with command \'%s\'') % (entry[0], cmd))
                if ret[0] == 0:
                    res = maximum_regex.search(ret[1])
                    res2 = inactive_regex.search(ret[1])
                    if res and res2:
                        current_max = int(res.group(1))
                        current_inactive = int(res2.group(1))
                        new_max = max
                        new_inactive = inactive
                        # don't lower security when not changing security level
                        if same_level():
                            if current_max < max and current_inactive < inactive:
                                continue
                            if current_max < max:
                                new_max = current_max
                            if current_inactive < inactive:
                                new_inactive = current_inactive
                        if new_max != current_max or current_inactive != new_inactive:
                            cmd = 'LC_ALL=C /usr/bin/chage -M %d -I %d -d %s %s' % (new_max, new_inactive, time.strftime('%Y-%m-%d'), entry[0])
                            ret = commands.getstatusoutput(cmd)
                            log(_('changed maximum password aging for user %s with command %s') % (entry[0], cmd))
                            if ret[0] != 0:
                                error(ret[1])
                    else:
                        error(_('unable to parse chage output'))
                else:
                    error(_('unable to run chage: %s') % ret[1])

################################################################################

def allow_xauth_from_root(arg):
    ''' Allow/forbid to export display when passing from the root account
to the other users. See pam_xauth(8) for more details.'''
    export = ConfigFile.get_config_file(EXPORT)

    allow = export.exists() and export.get_match('^\*$')

    # don't lower security when not changing security level
    if same_level():
        if not allow:
            return

    if arg:
        if not allow:
            _interactive and log(_('Allowing export display from root'))
            export.insert_at(0, '*')
    else:
        if allow:
            _interactive and log(_('Forbidding export display from root'))
            export.remove_line_matching('^\*$')

################################################################################

def set_security_conf(var, value):
    '''1 Set the variable \\fIvar\\fP to the value \\fIvalue\\fP in /var/lib/msec/security.conf.
The best way to override the default setting is to use create /etc/security/msec/security.conf
with the value you want. These settings are used to configure the daily check run each night.

The following variables are currentrly recognized by msec:

CHECK_UNOWNED if set to yes, report unowned files.

CHECK_SHADOW if set to yes, check empty password in /etc/shadow.

CHECK_SUID_MD5 if set to yes, verify checksum of the suid/sgid files.

CHECK_SECURITY if set to yes, run the daily security checks.

CHECK_PASSWD if set to yes, check for empty passwords, for no password in /etc/shadow and for users with the 0 id other than root.

SYSLOG_WARN if set to yes, report check result to syslog.

CHECK_SUID_ROOT if set to yes, check additions/removals of suid root files.

CHECK_PERMS if set to yes, check permissions of files in the users' home.

CHKROOTKIT_CHECK if set to yes, run chkrootkit checks.

CHECK_PROMISC if set to yes, check if the network devices are in promiscuous mode.

RPM_CHECK if set to yes, run some checks against the rpm database.

TTY_WARN if set to yes, reports check result to tty.

CHECK_WRITABLE if set to yes, check files/directories writable by everybody.

MAIL_WARN if set to yes, report check result by mail.

MAIL_USER if set, send the mail report to this email address else send it to root.

CHECK_OPEN_PORT if set to yes, check open ports.

CHECK_SGID if set to yes, check additions/removals of sgid files.
'''
    securityconf = ConfigFile.get_config_file(SECURITYCONF)
    securityconf.set_shell_variable(var, value)

# various

def set_interactive(v):
    "D"
    
    global _interactive
    
    _interactive = v

# libmsec.py ends here

