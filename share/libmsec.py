#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : share
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

try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

SUFFIX='.msec'
_interactive=0

# list of config files

ATALLOW = '/etc/at.allow'
AUTOLOGIN = '/etc/sysconfig/autologin'
BASTILLENOLOGIN = '/etc/bastille-no-login'
CRON = '/etc/cron.d/msec'
CRONALLOW = '/etc/cron.allow'
GDM = '/etc/pam.d/gdm'
GDMCONF = '/etc/X11/gdm/gdm.conf'
HALT = '/etc/security/console.apps/halt'
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
PASSWD = '/etc/pam.d/passwd'
POWEROFF = '/etc/security/console.apps/poweroff'
REBOOT = '/etc/security/console.apps/reboot'
SECURETTY = '/etc/securetty'
SECURITYCONF = '/etc/security/msec/security.conf'
SECURITYCRON = '/etc/cron.daily/msec'
SECURITYSH = '/usr/share/msec/security.sh'
SERVER = '/etc/security/msec/server'
SHADOW = '/etc/shadow'
SHUTDOWN = '/etc/security/console.apps/shutdown'
SHUTDOWNALLOW = '/etc/shutdown.allow'
SSHDCONFIG = '/etc/ssh/sshd_config'
SU = '/etc/pam.d/su'
SYSCTLCONF = '/etc/sysctl.conf'
SYSLOGCONF = '/etc/syslog.conf'
XDM = '/etc/pam.d/xdm'

# constants to keep in sync with shadow.py
NONE=0
ALL=1
LOCAL=2

# config files => actions

ConfigFile.add_config_assoc(INITTAB, '/sbin/telinit q')
ConfigFile.add_config_assoc('/etc(?:/rc.d)?/init.d/(.+)', '[ -f /var/lock/subsys/@1 ] && @0 reload')
ConfigFile.add_config_assoc(SYSCTLCONF, '/sbin/sysctl -e -p /etc/sysctl.conf; service network restart')
ConfigFile.add_config_assoc(SSHDCONFIG, '[ -f /var/lock/subsys/sshd ] && /etc/rc.d/init.d/sshd restart')
ConfigFile.add_config_assoc(LILOCONF, '[ `/usr/sbin/detectloader` = LILO ] && /sbin/lilo')
ConfigFile.add_config_assoc(SYSLOGCONF, '[ -f /var/lock/subsys/syslog ] && service syslog reload')
ConfigFile.add_config_assoc('^/etc/issue$', '/usr/bin/killall mingetty')

# configuration rules

def set_secure_level(level):
    _interactive and log(_('Setting secure level to %s') % level)
    msec = ConfigFile.get_config_file(MSEC)
    msec.set_shell_variable('SECURE_LEVEL', level)

def get_secure_level():
    "D"
    msec = ConfigFile.get_config_file(MSEC)
    return msec.get_shell_variable('SECURE_LEVEL')

def set_server_level(level):
    _interactive and log(_('Setting server level to %s') % level)
    securityconf = ConfigFile.get_config_file(SECURITYCONF)
    securityconf.set_shell_variable('SERVER_LEVEL', level)

def get_server_level():
    "D"
    securityconf = ConfigFile.get_config_file(SECURITYCONF)
    level = securityconf.get_shell_variable('SERVER_LEVEL')
    if level: return level
    msec = ConfigFile.get_config_file(MSEC)
    return msec.get_shell_variable('SECURE_LEVEL')

def create_server_link():
    level = get_server_level()
    server = ConfigFile.get_config_file(SERVER)
    if level in ('0', '1', '2', '3'):
        _interactive and log(_('Allowing chkconfig --add from rpm'))
        server.exists() and server.unlink()
    else:
        _interactive and log(_('Restricting chkconfig --add from rpm'))
        server.symlink(SERVER + '.' + str(level))

def set_root_umask(umask):
    _interactive and log(_('Setting root umask to %s') % umask)
    msec = ConfigFile.get_config_file(MSEC)
    msec.set_shell_variable('UMASK_ROOT', umask)

def set_user_umask(umask):
    _interactive and log(_('Setting users umask to %s') % umask)
    msec = ConfigFile.get_config_file(MSEC)
    msec.set_shell_variable('UMASK_USER', umask)

def allow_x_connections(arg):
    msec = ConfigFile.get_config_file(MSEC_XINIT)
    
    if arg == ALL:
        _interactive and log(_('Allowing users to connect X server from everywhere'))
        msec.replace_line_matching('/usr/X11R6/bin/xhost', '/usr/X11R6/bin/xhost +', 1)
        
    elif arg == LOCAL:
        _interactive and log(_('Allowing users to connect X server from localhost'))
        msec.replace_line_matching('/usr/X11R6/bin/xhost', '/usr/X11R6/bin/xhost + localhost', 1)

    elif arg == NONE:
        _interactive and log(_('Restricting X server connection to the console user'))
        msec.remove_line_matching('/usr/X11R6/bin/xhost', 1)
        
    else:
        error(_('invalid allow_x_connections arg: %s') % arg)
        
def set_shell_timeout(val):
    _interactive and log(_('Setting shell timeout to %s') % val)
    msec = ConfigFile.get_config_file(MSEC)
    msec.set_shell_variable('TMOUT', val)

def set_shell_history_size(size):
    msec = ConfigFile.get_config_file(MSEC)

    if size >= 0:
        _interactive and log(_('Setting shell history size to %s') % size)
        msec.set_shell_variable('HISTFILESIZE', size)
    else:
        _interactive and log(_('Removing limit on shell history size'))
        msec. remove_line_matching('^HISTFILESIZE=')
        
def allow_reboot(arg):
    shutdownallow = ConfigFile.get_config_file(SHUTDOWNALLOW)
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    kdmrc = ConfigFile.get_config_file(KDMRC)
    gdmconf = ConfigFile.get_config_file(GDMCONF)
    
    if arg:
        _interactive and log(_('Allowing reboot to the console user'))
        shutdownallow.exists() and shutdownallow.move(SUFFIX)
        for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
            ConfigFile.get_config_file(f).touch()
        sysctlconf.set_shell_variable('kernel.sysrq', 1)
        kdmrc.exists() and kdmrc.set_shell_variable('AllowShutdown', 'All', 'X-:\*-Greeter', '^\s*$')
        gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'true', '\[greeter\]', '^\s*$')
    else:
        _interactive and log(_('Forbidding reboot to the console user'))
        ConfigFile.get_config_file(SHUTDOWNALLOW, SUFFIX).touch()
        for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
            ConfigFile.get_config_file(f).unlink()
        sysctlconf.set_shell_variable('kernel.sysrq', 0)
        kdmrc.exists() and kdmrc.set_shell_variable('AllowShutdown', 'None', 'X-:\*-Greeter', '^\s*$')
        gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'false', '\[greeter\]', '^\s*$')
    
def allow_user_list(arg):
    kdmrc = ConfigFile.get_config_file(KDMRC)
    gdmconf = ConfigFile.get_config_file(GDMCONF)

    if arg:
        _interactive and log(_('Allowing the listing of users in display managers'))
        kdmrc.exists() and kdmrc.set_shell_variable('ShowUsers', 'All')
        gdmconf.exists() and gdmconf.set_shell_variable('Browser', '1')
    else:
        _interactive and log(_('Disabling the listing of users in display managers'))
        kdmrc.exists() and kdmrc.set_shell_variable('ShowUsers', 'None')
        gdmconf.exists() and gdmconf.set_shell_variable('Browser', '0')

def allow_root_login(arg):
    sshd_config = ConfigFile.get_config_file(SSHDCONFIG)
    securetty = ConfigFile.get_config_file(SECURETTY)
    
    if arg:
        _interactive and log(_('Allowing root login'))
        sshd_config.exists() and sshd_config.replace_line_matching('^\s*PermitRootLogin\s+no',
                                                                   'PermitRootLogin yes')
        
        kde = ConfigFile.get_config_file(KDE)
        gdm = ConfigFile.get_config_file(GDM)
        xdm = ConfigFile.get_config_file(XDM)
        
        for cnf in (kde, gdm, xdm):
            cnf.exists() and cnf.remove_line_matching('^auth\s*required\s*/lib/security/pam_listfile.so.*bastille-no-login', 1)
        
        for n in range(1, 7):
            s = 'tty' + str(n)
            securetty.replace_line_matching(s, s, 1)
            s = 'vc/' + str(n)
            securetty.replace_line_matching(s, s, 1)
    else:
        _interactive and log(_('Forbidding root login'))
        sshd_config.exists() and sshd_config.replace_line_matching('^\s*PermitRootLogin\s+yes',
                                                                   'PermitRootLogin no')
        
        bastillenologin = ConfigFile.get_config_file(BASTILLENOLOGIN)
        bastillenologin.replace_line_matching('^\s*root', 'root', 1)
        
        kde = ConfigFile.get_config_file(KDE)
        gdm = ConfigFile.get_config_file(GDM)
        xdm = ConfigFile.get_config_file(XDM)
        
        for cnf in (kde, gdm, xdm):
            cnf.exists() and (cnf.replace_line_matching('^auth\s*required\s*/lib/security/pam_listfile.so.*bastille-no-login', 'auth required /lib/security/pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login') or \
                              cnf.insert_at(0, 'auth required /lib/security/pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login'))
        
        securetty.remove_line_matching('.+', 1)

def enable_pam_wheel_for_su(arg):
    su = ConfigFile.get_config_file(SU)
    
    if arg:
        _interactive and log(_('Allowing su only from wheel group members'))
        try:
            ent = grp.getgrnam('wheel')
        except KeyError:
            error(_('no wheel group'))
            return
        members = ent[3]
        if members == [] or members == ['root']:
            error(_('wheel group is empty'))
            return
        su.exists() and (su.replace_line_matching('^auth\s+required\s+/lib/security/pam_wheel.so\s+use_uid\s*$',
                                                  'auth       required     /lib/security/pam_wheel.so use_uid') or \
                         su.insert_after('^auth\s+required',
                                         'auth       required     /lib/security/pam_wheel.so use_uid'))
    else:
        _interactive and log(_('Allowing su for all'))
        su.exists() and su.remove_line_matching('^auth\s+required\s+/lib/security/pam_wheel.so\s+use_uid\s*$')
    
def allow_issues(arg):
    issue = ConfigFile.get_config_file(ISSUE, SUFFIX)
    issuenet = ConfigFile.get_config_file(ISSUENET, SUFFIX)

    if arg == ALL:
        _interactive and log(_('Allowing RemoteRoot pre-login messages'))    
        issue.exists() and issue.get_lines()
        issuenet.exists() and issuenet.get_lines()
    else:
        if arg == NONE:
            _interactive and log(_('Disabling pre-login message'))
            issue.exists() and issue.move(SUFFIX) and issue.modified()
        else:
            _interactive and log(_('Allowing pre-login message'))
            issue.exists() and issue.get_lines()
        _interactive and log(_('Disabling network pre-login message'))
        issuenet.exists() and issuenet.move(SUFFIX)

def allow_autologin(arg):
    autologin = ConfigFile.get_config_file(AUTOLOGIN)
    
    if arg:
        _interactive and log(_('Allowing autologin'))
        autologin.exists() and autologin.set_shell_variable('AUTOLOGIN', 'yes')
    else:
        _interactive and log(_('Forbidding autologin'))
        autologin.exists() and autologin.set_shell_variable('AUTOLOGIN', 'no')

def password_loader(value):
    "D"
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
        
def nopassword_loader():
    "D"
    _interactive and log(_('Removing password in boot loader'))
    liloconf = ConfigFile.get_config_file(LILOCONF)
    liloconf.exists() and liloconf.remove_line_matching('^password=', 1)
    menulst = ConfigFile.get_config_file(MENULST)
    menulst.exists() and menulst.remove_line_matching('^password\s')

def enable_console_log(arg):
    syslogconf = ConfigFile.get_config_file(SYSLOGCONF)

    if arg:
        _interactive and log(_('Enabling log on console 12'))
        syslogconf.exists() and syslogconf.replace_line_matching('\s*[^#]+/dev/tty12', '*.* /dev/tty12', 1)
    else:
        _interactive and log(_('Disabling log on console 12'))
        syslogconf.exists() and syslogconf.remove_line_matching('\*\.\*\s*/dev/tty12')

def enable_promisc_check(arg):
    cron = ConfigFile.get_config_file(CRON)

    if arg:
        _interactive and log(_('Activating periodic promiscuity check'))
        cron.replace_line_matching('[^#]+/usr/share/msec/promisc_check.sh', '*/1 * * * *    root    /usr/share/msec/promisc_check.sh', 1)
    else:
        _interactive and log(_('Disabling periodic promiscuity check'))
        cron.remove_line_matching('[^#]+/usr/share/msec/promisc_check.sh')

def enable_security_check(arg):
    cron = ConfigFile.get_config_file(CRON)
    cron.remove_line_matching('[^#]+/usr/share/msec/security.sh')

    securitycron = ConfigFile.get_config_file(SECURITYCRON)
    
    if arg:
        _interactive and log(_('Activating daily security check'))
        securitycron.symlink(SECURITYSH)
    else:
        _interactive and log(_('Disabling daily security check'))
        securitycron.unlink()
        
def authorize_services(arg):
    hostsdeny = ConfigFile.get_config_file(HOSTSDENY)

    if arg == ALL:
        _interactive and log(_('Authorizing all services'))
        hostsdeny.remove_line_matching('^ALL:ALL:DENY', 1)
        hostsdeny.remove_line_matching('^ALL:ALL EXCEPT localhost:DENY', 1)
    elif arg == NONE:
        _interactive and log(_('Disabling all services'))
        hostsdeny.remove_line_matching('^ALL:ALL EXCEPT localhost:DENY', 1)
        hostsdeny.replace_line_matching('^ALL:ALL:DENY$', 'ALL:ALL:DENY', 1)
    elif arg == LOCAL:
        _interactive and log(_('Disabling non local services'))
        hostsdeny.remove_line_matching('^ALL:ALL:DENY', 1)
        hostsdeny.replace_line_matching('^ALL:ALL EXCEPT localhost:DENY$', 'ALL:ALL EXCEPT localhost:DENY', 1)
    else:
        error(_('authorize_services invalid argument: %s') % arg)
    
def enable_ip_spoofing_protection(arg, alert=1):
    hostconf = ConfigFile.get_config_file(HOSTCONF)

    if arg:
        _interactive and log(_('Enabling ip spoofing protection'))
        hostconf.replace_line_matching('nospoof', 'nospoof on', 1)
        hostconf.replace_line_matching('spoofalert', 'spoofalert on', (alert != 0))
        sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
        sysctlconf.set_shell_variable('net.ipv4.conf.all.rp_filter', 1)
    else:
        _interactive and log(_('Disabling ip spoofing protection'))
        hostconf.remove_line_matching('nospoof')
        hostconf.remove_line_matching('spoofalert')

def accept_icmp_echo(arg):
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)

    if arg:
        _interactive and log(_('Accepting icmp echo'))
        sysctlconf.set_shell_variable('net.ipv4.icmp_echo_ignore_all', 0)
        sysctlconf.set_shell_variable('net.ipv4.icmp_echo_ignore_broadcasts', 0)
    else:
        _interactive and log(_('Ignoring icmp echo'))
        sysctlconf.set_shell_variable('net.ipv4.icmp_echo_ignore_all', 1)
        sysctlconf.set_shell_variable('net.ipv4.icmp_echo_ignore_broadcasts', 1)
    
def accept_bogus_error_responses(arg):
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)

    if arg:
        _interactive and log(_('Accepting bogus icmp error responses'))
        sysctlconf.set_shell_variable('net.ipv4.icmp_ignore_bogus_error_responses', 0)
    else:
        _interactive and log(_('Ignoring bogus icmp error responses'))
        sysctlconf.set_shell_variable('net.ipv4.icmp_ignore_bogus_error_responses', 1)
    
def enable_log_strange_packets(arg):
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)

    if arg:
        _interactive and log(_('Enabling logging of strange packets'))
        sysctlconf.set_shell_variable('net.ipv4.conf.all.log_martians', 1)
    else:
        _interactive and log(_('Disabling logging of strange packets'))
        sysctlconf.set_shell_variable('net.ipv4.conf.all.log_martians', 0)

def enable_libsafe(arg):
    if arg:
        if os.path.exists(Config.get_config('root', '') + '/lib/libsafe.so.2'):
            _interactive and log(_('Enabling libsafe'))
            ldsopreload = ConfigFile.get_config_file(LDSOPRELOAD)
            ldsopreload.replace_line_matching('[^#]*libsafe', '/lib/libsafe.so.2', 1)
    else:
        _interactive and log(_('Disabling libsafe'))
        ldsopreload = ConfigFile.get_config_file(LDSOPRELOAD)
        ldsopreload.remove_line_matching('[^#]*libsafe')        

def password_length(length, ndigits=0, nupper=0):
    _interactive and log(_('Setting minimum password length %d') % length)
    passwd = ConfigFile.get_config_file(PASSWD)
    passwd.exists() and (passwd.replace_line_matching('^(password\s+required\s+/lib/security/pam_cracklib.so.*?)(\sminlen=[0-9]+\s)(.*)',
                                                      '@1 minlen=%s @3' % length) or \
                         passwd.replace_line_matching('^password\s+required\s+/lib/security/pam_cracklib.so.*',
                                                      '@0 minlen=%s ' % length))
    
    passwd.exists() and (passwd.replace_line_matching('^(password\s+required\s+/lib/security/pam_cracklib.so.*?)(\sdcredit=[0-9]+\s)(.*)',
                                                     '@1 dcredit=%s @3' % ndigits) or \
                         passwd.replace_line_matching('^password\s+required\s+/lib/security/pam_cracklib.so.*',
                                                      '@0 dcredit=%s ' % ndigits))
    
    passwd.exists() and (passwd.replace_line_matching('^(password\s+required\s+/lib/security/pam_cracklib.so.*?)(\sucredit=[0-9]+\s)(.*)',
                                                     '@1 ucredit=%s @3' % nupper) or \
                         passwd.replace_line_matching('^password\s+required\s+/lib/security/pam_cracklib.so.*',
                                                      '@0 ucredit=%s ' % nupper))

def enable_sulogin(arg):
    inittab = ConfigFile.get_config_file(INITTAB)

    if arg:
        _interactive and log(_('Enabling sulogin in single user runlevel'))
        inittab.replace_line_matching('[^#]+:S:', '~~:S:wait:/sbin/sulogin', 1)
    else:
        _interactive and log(_('Disabling sulogin in single user runlevel'))
        inittab.remove_line_matching('~~:S:wait:/sbin/sulogin')

def enable_msec_cron(arg):
    mseccron = ConfigFile.get_config_file(MSECCRON)

    if arg:
        _interactive and log(_('Enabling msec periodic runs'))
        mseccron.symlink(MSECBIN)
    else:
        _interactive and log(_('Disabling msec periodic runs'))
        mseccron.unlink()

def enable_at_crontab(arg):
    cronallow = ConfigFile.get_config_file(CRONALLOW)
    atallow = ConfigFile.get_config_file(ATALLOW)

    if arg:
        _interactive and log(_('Enabling crontab and at'))
        cronallow.exists() and cronallow.move(SUFFIX)
        atallow.exists() and atallow.move(SUFFIX)
    else:
        _interactive and log(_('Disabling crontab and at'))
        cronallow.replace_line_matching('root', 'root', 1)
        atallow.replace_line_matching('root', 'root', 1)

maximum_regex = re.compile('^Maximum:\s*([0-9]+)', re.MULTILINE)

# TODO FL Sat Dec 29 20:18:20 2001
# replace chage calls and /etc/shadow parsing by a python API to the shadow functions.
def password_aging(max):
    uid_min = 500
    _interactive and log(_('Setting password maximum aging for new user to %d') % max)
    logindefs = ConfigFile.get_config_file(LOGINDEFS)
    if logindefs.exists():
        logindefs.replace_line_matching('^\s*PASS_MAX_DAYS', 'PASS_MAX_DAYS ' + str(max))
        uid_min = logindefs.get_match('^\s*UID_MIN\s+([0-9]+)', '@1')
        if uid_min:
            uid_min = int(uid_min)
    shadow = ConfigFile.get_config_file(SHADOW)
    if shadow.exists():
        _interactive and log(_('Setting password maximum aging for users with id greater than %d to %d') % (uid_min, max))
        for line in shadow.get_lines():
            field = string.split(line, ':')
            if len(field) < 2:
                continue
            name = field[0]
            password = field[1]
            entry = pwd.getpwnam(name)
            if (len(password) > 0 and password[0] != '!') and password != '*' and password != 'x' and entry[2] >= uid_min:
                cmd = '/usr/bin/chage -l %s' % entry[0]
                ret = commands.getstatusoutput(cmd)
                _interactive and log(_('got current maximum password aging for user %s with command \'%s\'') % (entry[0], cmd))
                if ret[0] == 0:
                    res = maximum_regex.search(ret[1])
                    if res:
                        current_max = int(res.group(1))
                        if max != current_max:
                            cmd = '/usr/bin/chage -M %d %s' % (max, entry[0])
                            ret = commands.getstatusoutput(cmd)
                            log(_('changed maximum password aging for user %s with command %s') % (entry[0], cmd))
                            if ret[0] != 0:
                                error(ret[1])
                    else:
                        error(_('unable to parse chage output'))
                else:
                    error(_('unable to run chage: %s') % ret[1])

def set_security_conf(var, value):
    "1"
    securityconf = ConfigFile.get_config_file(SECURITYCONF)
    securityconf.set_shell_variable(var, value)

# various

def set_interactive(v):
    "D"
    
    global _interactive
    
    _interactive = v

# libmsec.py ends here
