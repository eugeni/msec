#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : share
# File            : libmsec.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Mon Dec 10 22:52:17 2001
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
SHADOW = '/etc/shadow'
SHUTDOWN = '/etc/security/console.apps/shutdown'
SHUTDOWNALLOW = '/etc/shutdown.allow'
SSHDCONFIG = '/etc/ssh/sshd_config'
SU = '/etc/pam.d/su'
SYSCTLCONF = '/etc/sysctl.conf'
SYSLOGCONF = '/etc/syslog.conf'
XDM = '/etc/pam.d/xdm'

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
    msec = ConfigFile.get_config_file(MSEC)
    return msec.get_shell_variable('SECURE_LEVEL')

def set_root_umask(umask):
    _interactive and log(_('Setting root umask to %s') % umask)
    msec = ConfigFile.get_config_file(MSEC)
    msec.set_shell_variable('UMASK_ROOT', umask)

def set_user_umask(umask):
    _interactive and log(_('Setting users umask to %s') % umask)
    msec = ConfigFile.get_config_file(MSEC)
    msec.set_shell_variable('UMASK_USER', umask)

def allow_x_connections():
    _interactive and log(_('Allowing users to connect X server from everywhere'))
    msec = ConfigFile.get_config_file(MSEC_XINIT)
    msec.replace_line_matching('/usr/X11R6/bin/xhost', '/usr/X11R6/bin/xhost +', 1)

def allow_local_x_connections():
    _interactive and log(_('Allowing users to connect X server from localhost'))
    msec = ConfigFile.get_config_file(MSEC_XINIT)
    msec.replace_line_matching('/usr/X11R6/bin/xhost', '/usr/X11R6/bin/xhost + localhost', 1)

def restrict_x_connections():
    _interactive and log(_('Restricting X server connection to the console user'))
    msec = ConfigFile.get_config_file(MSEC_XINIT)
    msec.remove_line_matching('/usr/X11R6/bin/xhost', 1)

def set_shell_timeout(val):
    _interactive and log(_('Setting shell timeout to %s') % val)
    msec = ConfigFile.get_config_file(MSEC)
    msec.set_shell_variable('TMOUT', val)

def set_shell_history_size(size):
    if size >= 0:
        _interactive and log(_('Setting shell history size to %s') % size)
        msec = ConfigFile.get_config_file(MSEC)
        msec.set_shell_variable('HISTFILESIZE', size)
    else:
        _interactive and log(_('Removing limit on shell history size'))
        msec = ConfigFile.get_config_file(MSEC)
        msec. remove_line_matching('^HISTFILESIZE=')
        
def allow_reboot():
    _interactive and log(_('Allowing reboot to the console user'))
    shutdownallow = ConfigFile.get_config_file(SHUTDOWNALLOW)
    shutdownallow.exists() and shutdownallow.move(SUFFIX)
    for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
        ConfigFile.get_config_file(f).touch()
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('kernel.sysrq', 1)
    kdmrc = ConfigFile.get_config_file(KDMRC)
    kdmrc.exists() and kdmrc.set_shell_variable('AllowShutdown', 'All', 'X-:\*-Greeter', '^\s*$')
    gdmconf = ConfigFile.get_config_file(GDMCONF)
    gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'true', '\[greeter\]', '^\s*$')

def forbid_reboot():
    _interactive and log(_('Forbidding reboot to the console user'))
    ConfigFile.get_config_file(SHUTDOWNALLOW, SUFFIX).touch()
    for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
        ConfigFile.get_config_file(f).unlink()
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('kernel.sysrq', 0)
    kdmrc = ConfigFile.get_config_file(KDMRC)
    kdmrc.exists() and kdmrc.set_shell_variable('AllowShutdown', 'None', 'X-:\*-Greeter', '^\s*$')
    gdmconf = ConfigFile.get_config_file(GDMCONF)
    gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'false', '\[greeter\]', '^\s*$')
    
def allow_user_list():
    _interactive and log(_('Allowing the listing of users in display managers'))
    kdmrc = ConfigFile.get_config_file(KDMRC)
    kdmrc.exists() and kdmrc.set_shell_variable('ShowUsers', 'All')
    gdmconf = ConfigFile.get_config_file(GDMCONF)
    gdmconf.exists() and gdmconf.set_shell_variable('Browser', '1')

def forbid_user_list():
    _interactive and log(_('Disabling the listing of users in display managers'))
    kdmrc = ConfigFile.get_config_file(KDMRC)
    kdmrc.exists() and kdmrc.set_shell_variable('ShowUsers', 'None')
    gdmconf = ConfigFile.get_config_file(GDMCONF)
    gdmconf.exists() and gdmconf.set_shell_variable('Browser', '0')

def allow_root_login():
    _interactive and log(_('Allowing root login'))
    sshd_config = ConfigFile.get_config_file(SSHDCONFIG)
    sshd_config.exists() and sshd_config.replace_line_matching('^\s*PermitRootLogin\s+no',
                                                               'PermitRootLogin yes')

    kde = ConfigFile.get_config_file(KDE)
    gdm = ConfigFile.get_config_file(GDM)
    xdm = ConfigFile.get_config_file(XDM)

    for cnf in (kde, gdm, xdm):
        cnf.exists() and cnf.remove_line_matching('^auth\s*required\s*/lib/security/pam_listfile.so.*bastille-no-login', 1)

    securetty = ConfigFile.get_config_file(SECURETTY)
    for n in range(1, 7):
        s = 'tty' + str(n)
        securetty.replace_line_matching(s, s, 1)
        s = 'vc/' + str(n)
        securetty.replace_line_matching(s, s, 1)

def forbid_root_login():
    _interactive and log(_('Forbidding root login'))
    sshd_config = ConfigFile.get_config_file(SSHDCONFIG)
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

    # TODO xdm support
    securetty = ConfigFile.get_config_file(SECURETTY)
    securetty.remove_line_matching('.+', 1)

def enable_pam_wheel_for_su():
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
    su = ConfigFile.get_config_file(SU)
    su.exists() and (su.replace_line_matching('^auth\s+required\s+/lib/security/pam_wheel.so\s+use_uid\s*$',
                                              'auth       required     /lib/security/pam_wheel.so use_uid') or \
                     su.insert_after('^auth\s+required',
                                     'auth       required     /lib/security/pam_wheel.so use_uid'))

def disable_pam_wheel_for_su():
    _interactive and log(_('Allowing su for all'))
    su = ConfigFile.get_config_file(SU)
    su.exists() and su.remove_line_matching('^auth\s+required\s+/lib/security/pam_wheel.so\s+use_uid\s*$')
    
def forbid_issues(allow_local=0):
    if not allow_local:
        _interactive and log(_('Disabling pre-login message'))
        issue = ConfigFile.get_config_file(ISSUE)
        issue.exists() and issue.move(SUFFIX) and issue.modified()
    else:
        _interactive and log(_('Allowing pre-login message'))
        issue = ConfigFile.get_config_file(ISSUE, SUFFIX)
        issue.exists() and issue.get_lines()
    _interactive and log(_('Disabling network pre-login message'))
    issuenet = ConfigFile.get_config_file(ISSUENET)
    issuenet.exists() and issuenet.move(SUFFIX)

def allow_issues():
    _interactive and log(_('Allowing RemoteRoot pre-login messages'))    
    issue = ConfigFile.get_config_file(ISSUE, SUFFIX)
    issue.exists() and issue.get_lines()
    issuenet = ConfigFile.get_config_file(ISSUENET, SUFFIX)
    issuenet.exists() and issuenet.get_lines()

def allow_autologin():
    _interactive and log(_('Allowing autologin'))
    autologin = ConfigFile.get_config_file(AUTOLOGIN)
    autologin.exists() and autologin.set_shell_variable('AUTOLOGIN', 'yes')

def forbid_autologin():
    _interactive and log(_('Forbidding autologin'))
    autologin = ConfigFile.get_config_file(AUTOLOGIN)
    autologin.exists() and autologin.set_shell_variable('AUTOLOGIN', 'no')

def password_loader(value):
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
    _interactive and log(_('Removing password in boot loader'))
    liloconf = ConfigFile.get_config_file(LILOCONF)
    liloconf.exists() and liloconf.remove_line_matching('^password=', 1)
    menulst = ConfigFile.get_config_file(MENULST)
    menulst.exists() and menulst.remove_line_matching('^password\s')

def enable_console_log():
    _interactive and log(_('Enabling log on console 12'))
    syslogconf = ConfigFile.get_config_file(SYSLOGCONF)
    syslogconf.exists() and syslogconf.replace_line_matching('\s*[^#]+/dev/tty12', '*.* /dev/tty12', 1)

def disable_console_log():
    _interactive and log(_('Disabling log on console 12'))
    syslogconf = ConfigFile.get_config_file(SYSLOGCONF)
    syslogconf.exists() and syslogconf.remove_line_matching('\*\.\*\s*/dev/tty12')

def enable_promisc_check():
    _interactive and log(_('Activating periodic promiscuity check'))
    cron = ConfigFile.get_config_file(CRON)
    cron.replace_line_matching('[^#]+/usr/share/msec/promisc_check.sh', '*/1 * * * *    root    /usr/share/msec/promisc_check.sh', 1)

def disable_promisc_check():
    _interactive and log(_('Disabling periodic promiscuity check'))
    cron = ConfigFile.get_config_file(CRON)
    cron.remove_line_matching('[^#]+/usr/share/msec/promisc_check.sh')

def enable_security_check():
    _interactive and log(_('Activating daily security check'))
    cron = ConfigFile.get_config_file(CRON)
    cron.replace_line_matching('[^#]+/usr/share/msec/security.sh', '0 4 * * *    root    /usr/share/msec/security.sh', 1)

def disable_security_check():
    _interactive and log(_('Disabling daily security check'))
    cron = ConfigFile.get_config_file(CRON)
    cron.remove_line_matching('[^#]+/usr/share/msec/security.sh')

def deny_all_services():
    _interactive and log(_('Disabling all services'))
    hostsdeny = ConfigFile.get_config_file(HOSTSDENY)
    hostsdeny.remove_line_matching('^ALL:ALL EXCEPT localhost:DENY', 1)
    hostsdeny.replace_line_matching('^ALL:ALL:DENY$', 'ALL:ALL:DENY', 1)

def deny_non_local_services():
    _interactive and log(_('Disabling non local services'))
    hostsdeny = ConfigFile.get_config_file(HOSTSDENY)
    hostsdeny.remove_line_matching('^ALL:ALL:DENY', 1)
    hostsdeny.replace_line_matching('^ALL:ALL EXCEPT localhost:DENY$', 'ALL:ALL EXCEPT localhost:DENY', 1)

def authorize_all_services():
    _interactive and log(_('Authorizing all services'))
    hostsdeny = ConfigFile.get_config_file(HOSTSDENY)
    hostsdeny.remove_line_matching('^ALL:ALL:DENY', 1)
    hostsdeny.remove_line_matching('^ALL:ALL EXCEPT localhost:DENY', 1)
    
def enable_ip_spoofing_protection(alert):
    _interactive and log(_('Enabling ip spoofing protection'))
    hostconf = ConfigFile.get_config_file(HOSTCONF)
    hostconf.replace_line_matching('nospoof', 'nospoof on', 1)
    hostconf.replace_line_matching('spoofalert', 'spoofalert on', (alert != 0))
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('net.ipv4.conf.all.rp_filter', 1)

def disable_ip_spoofing_protection():
    _interactive and log(_('Disabling ip spoofing protection'))
    hostconf = ConfigFile.get_config_file(HOSTCONF)
    hostconf.remove_line_matching('nospoof')
    hostconf.remove_line_matching('spoofalert')

def ignore_icmp_echo():
    _interactive and log(_('Ignoring icmp echo'))
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('net.ipv4.icmp_echo_ignore_all', 1)
    sysctlconf.set_shell_variable('net.ipv4.icmp_echo_ignore_broadcasts', 1)
    
def accept_icmp_echo():
    _interactive and log(_('Accepting icmp echo'))
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('net.ipv4.icmp_echo_ignore_all', 0)
    sysctlconf.set_shell_variable('net.ipv4.icmp_echo_ignore_broadcasts', 0)

def ignore_bogus_error_responses():
    _interactive and log(_('Ignoring bogus icmp error responses'))
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('net.ipv4.icmp_ignore_bogus_error_responses', 1)
    
def accept_bogus_error_responses():
    _interactive and log(_('Accepting bogus icmp error responses'))
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('net.ipv4.icmp_ignore_bogus_error_responses', 0)
    
def enable_log_strange_packets():
    _interactive and log(_('Enabling logging of strange packets'))
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('net.ipv4.conf.all.log_martians', 1)

def disable_log_strange_packets():
    _interactive and log(_('Disabling logging of strange packets'))
    sysctlconf = ConfigFile.get_config_file(SYSCTLCONF)
    sysctlconf.set_shell_variable('net.ipv4.conf.all.log_martians', 0)

def enable_libsafe():
    if os.path.exists(Config.get_config('root', '') + '/lib/libsafe.so.2'):
        _interactive and log(_('Enabling libsafe'))
        ldsopreload = ConfigFile.get_config_file(LDSOPRELOAD)
        ldsopreload.replace_line_matching('[^#]*libsafe', '/lib/libsafe.so.2', 1)
    
def disable_libsafe():
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

def enable_sulogin():
    _interactive and log(_('Enabling sulogin in single user runlevel'))
    inittab = ConfigFile.get_config_file(INITTAB)
    inittab.replace_line_matching('[^#]+:S:', '~~:S:wait:/sbin/sulogin', 1)

def disable_sulogin():
    _interactive and log(_('Disabling sulogin in single user runlevel'))
    inittab = ConfigFile.get_config_file(INITTAB)
    inittab.remove_line_matching('~~:S:wait:/sbin/sulogin')

def enable_msec_cron():
    _interactive and log(_('Enabling msec periodic runs'))
    mseccron = ConfigFile.get_config_file(MSECCRON)
    mseccron.symlink(MSECBIN)

def disable_msec_cron():
    _interactive and log(_('Disabling msec periodic runs'))
    mseccron = ConfigFile.get_config_file(MSECCRON)
    mseccron.unlink()

def disable_at_crontab():
    _interactive and log(_('Disabling crontab and at'))
    cronallow = ConfigFile.get_config_file(CRONALLOW, SUFFIX)
    cronallow.replace_line_matching('root', 'root', 1)
    atallow = ConfigFile.get_config_file(ATALLOW, SUFFIX)
    atallow.replace_line_matching('root', 'root', 1)

def enable_at_crontab():
    _interactive and log(_('Enabling crontab and at'))
    cronallow = ConfigFile.get_config_file(CRONALLOW)
    cronallow.exists() and cronallow.move(SUFFIX)
    atallow = ConfigFile.get_config_file(ATALLOW)
    atallow.exists() and atallow.move(SUFFIX)

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

# various

def set_interactive(v):
    global _interactive
    
    _interactive = v

# libmsec.py ends here
