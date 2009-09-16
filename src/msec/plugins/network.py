#!/usr/bin/plugin
"""Msec plugin for enforcing network security settings"""

# main plugin class name
PLUGIN = "network"

# configuration

import os
import re
import string
import stat
import sys

import config

import gettext
# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

# list of config files

ATALLOW = '/etc/at.allow'
AUTOLOGIN = '/etc/sysconfig/autologin'
BASTILLENOLOGIN = '/etc/bastille-no-login'
CRON = '/etc/cron.d/msec'
CRONALLOW = '/etc/cron.allow'
FSTAB = '/etc/fstab'
GDM = '/etc/pam.d/gdm'
GDMCONF = '/etc/X11/gdm/custom.conf'
HALT = '/usr/bin/halt'
HOSTCONF = '/etc/host.conf'
HOSTSDENY = '/etc/hosts.deny'
INITTAB = '/etc/inittab'
ISSUE = '/etc/issue'
ISSUENET = '/etc/issue.net'
KDE = '/etc/pam.d/kde'
KDMRC = '/usr/share/config/kdm/kdmrc'
LILOCONF = '/etc/lilo.conf'
LOGINDEFS = '/etc/login.defs'
MENULST = '/boot/grub/menu.lst'
SHELLCONF = '/etc/security/shell'
MSECBIN = '/usr/sbin/msec'
MSECCRON = '/etc/cron.hourly/msec'
MSEC_XINIT = '/etc/X11/xinit.d/msec'
OPASSWD = '/etc/security/opasswd'
PASSWD = '/etc/pam.d/passwd'
POWEROFF = '/usr/bin/poweroff'
REBOOT = '/usr/bin/reboot'
SECURITYSH = '/usr/share/msec/security.sh'
SERVER = '/etc/security/msec/server'
SHADOW = '/etc/shadow'
SHUTDOWN = '/usr/bin/shutdown'
SHUTDOWNALLOW = '/etc/shutdown.allow'
SSHDCONFIG = '/etc/ssh/sshd_config'
STARTX = '/usr/bin/startx'
SYSCTLCONF = '/etc/sysctl.conf'
SYSLOGCONF = '/etc/syslog.conf'
XDM = '/etc/pam.d/xdm'
XSERVERS = '/etc/X11/xdm/Xservers'
EXPORT = '/root/.xauth/export'

# regexps
# X server
SECURETTY = '/etc/securetty'
STARTX_REGEXP = '(\s*serverargs=".*) -nolisten tcp(.*")'
XSERVERS_REGEXP = '(\s*[^#]+/usr/bin/X .*) -nolisten tcp(.*)'
GDMCONF_REGEXP = '(\s*command=.*/X.*?) -nolisten tcp(.*)$'
KDMRC_REGEXP = re.compile('(.*?)-nolisten tcp(.*)$')
# ctrl-alt-del
CTRALTDEL_REGEXP = '^ca::ctrlaltdel:/sbin/shutdown.*'
# consolehelper
CONSOLE_HELPER = 'consolehelper'
# ssh PermitRootLogin
PERMIT_ROOT_LOGIN_REGEXP = '^\s*PermitRootLogin\s+(no|yes|without-password|forced-commands-only)'
# tcp_wrappers
ALL_REGEXP = '^ALL:ALL:DENY'
ALL_LOCAL_REGEXP = '^ALL:ALL EXCEPT 127\.0\.0\.1:DENY'
# sulogin
SULOGIN_REGEXP = '~~:S:wait:/sbin/sulogin'

def invert(param):
    """Returns inverse value for param. E.g., yes becomes no, and no becomes yes."""
    if param == "yes":
        return "no"
    else:
        return "yes"
class network:
    def __init__(self, log=None, configfiles=None, root=None):
        """This plugin is responsible for enforcing network security settings on the machine."""
        self.log = log
        self.configfiles = configfiles
        self.root = root

        # associate helper commands with files
        self.configfiles.add_config_assoc(INITTAB, '/sbin/telinit q')
        self.configfiles.add_config_assoc('/etc(?:/rc.d)?/init.d/(.+)', '[ -f /var/lock/subsys/@1 ] && @0 reload')
        self.configfiles.add_config_assoc(SYSCTLCONF, '/sbin/sysctl -e -p /etc/sysctl.conf')
        self.configfiles.add_config_assoc(SSHDCONFIG, '[ -f /var/lock/subsys/sshd ] && /etc/rc.d/init.d/sshd restart')
        self.configfiles.add_config_assoc(LILOCONF, '[ `/usr/sbin/detectloader` = LILO ] && /sbin/lilo')
        self.configfiles.add_config_assoc(SYSLOGCONF, '[ -f /var/lock/subsys/syslog ] && service syslog reload')
        self.configfiles.add_config_assoc('^/etc/issue$', '/usr/bin/killall mingetty')

        # security options
        config.SETTINGS['ACCEPT_BOGUS_ERROR_RESPONSES'] = ("network.accept_bogus_error_responses", ['yes', 'no'])
        config.SETTINGS['ACCEPT_BROADCASTED_ICMP_ECHO'] = ("network.accept_broadcasted_icmp_echo", ['yes', 'no'])
        config.SETTINGS['ACCEPT_ICMP_ECHO'] = ("network.accept_icmp_echo", ['yes', 'no'])
        config.SETTINGS['ALLOW_REMOTE_ROOT_LOGIN'] = ("network.allow_remote_root_login", ['yes', 'no', 'without-password'])
        config.SETTINGS['ENABLE_DNS_SPOOFING_PROTECTION'] = ("network.enable_dns_spoofing_protection", ['yes', 'no'])
        config.SETTINGS['ENABLE_IP_SPOOFING_PROTECTION'] = ("network.enable_ip_spoofing_protection", ['yes', 'no'])
        config.SETTINGS['ENABLE_LOG_STRANGE_PACKETS'] = ("network.enable_log_strange_packets", ['yes', 'no'])

        # network settings
        for check in ["ACCEPT_BOGUS_ERROR_RESPONSES", "ACCEPT_BROADCASTED_ICMP_ECHO", "ACCEPT_ICMP_ECHO",
                    "ALLOW_REMOTE_ROOT_LOGIN", "ALLOW_X_CONNECTIONS", "ALLOW_XSERVER_TO_LISTEN",
                    "AUTHORIZE_SERVICES", "ENABLE_DNS_SPOOFING_PROTECTION", "ENABLE_IP_SPOOFING_PROTECTION",
                    "ENABLE_LOG_STRANGE_PACKETS"]:
            config.SETTINGS_NETWORK.append(check)

    def allow_remote_root_login(self, arg):
        '''  Allow remote root login via sshd. If yes, login is allowed. If without-password, only public-key authentication logins are allowed. See sshd_config(5) man page for more information.'''
        sshd_config = self.configfiles.get_config_file(SSHDCONFIG)

        if not sshd_config.exists():
            return

        val = sshd_config.get_match(PERMIT_ROOT_LOGIN_REGEXP, '@1')

        if val != arg:
            if arg == "yes":
                self.log.info(_('Allowing remote root login'))
                sshd_config.exists() and sshd_config.replace_line_matching(PERMIT_ROOT_LOGIN_REGEXP,
                                                                           'PermitRootLogin yes', 1)
            elif arg == "no":
                self.log.info(_('Forbidding remote root login'))
                sshd_config.exists() and sshd_config.replace_line_matching(PERMIT_ROOT_LOGIN_REGEXP,
                                                                           'PermitRootLogin no', 1)
            elif arg == "without-password":
                self.log.info(_('Allowing remote root login only by passphrase'))
                sshd_config.exists() and sshd_config.replace_line_matching(PERMIT_ROOT_LOGIN_REGEXP,
                                                                           'PermitRootLogin without-password', 1)

    def set_zero_one_variable(self, file, variable, value, one_msg, zero_msg):
        ''' Helper function for enable_ip_spoofing_protection, accept_icmp_echo, accept_broadcasted_icmp_echo,
        # accept_bogus_error_responses and enable_log_strange_packets.'''
        f = self.configfiles.get_config_file(file)
        curvalue = f.get_shell_variable(variable)
        if value == "yes":
            value = "1"
        else:
            value = "0"
        if value != curvalue:
            if value == "1":
                self.log.info(one_msg)
                f.set_shell_variable(variable, 1)
            else:
                self.log.info(zero_msg)
                f.set_shell_variable(variable, 0)

    def enable_ip_spoofing_protection(self, arg, alert=1):
        '''  Enable IP spoofing protection.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.conf.all.rp_filter', arg, 'Enabling ip spoofing protection', 'Disabling ip spoofing protection')

    def enable_dns_spoofing_protection(self, arg, alert=1):
        '''  Enable name resolution spoofing protection.'''
        hostconf = self.configfiles.get_config_file(HOSTCONF)

        val = hostconf.get_match('nospoof\s+on')

        if arg:
            if not val:
                self.log.info(_('Enabling name resolution spoofing protection'))
                hostconf.replace_line_matching('nospoof', 'nospoof on', 1)
                hostconf.replace_line_matching('spoofalert', 'spoofalert on', (alert != 0))
        else:
            if val:
                self.log.info(_('Disabling name resolution spoofing protection'))
                hostconf.remove_line_matching('nospoof')
                hostconf.remove_line_matching('spoofalert')

    def accept_icmp_echo(self, arg):
        ''' Accept ICMP echo.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_echo_ignore_all', invert(arg), 'Ignoring icmp echo', 'Accepting icmp echo')

    def accept_broadcasted_icmp_echo(self, arg):
        ''' Accept broadcasted ICMP echo.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_echo_ignore_broadcasts', invert(arg), 'Ignoring broadcasted icmp echo', 'Accepting broadcasted icmp echo')

    def accept_bogus_error_responses(self, arg):
        '''  Accept bogus IPv4 error messages.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_ignore_bogus_error_responses', invert(arg), 'Ignoring bogus icmp error responses', 'Accepting bogus icmp error responses')

    def enable_log_strange_packets(self, arg):
        '''  Enable logging of strange network packets.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.conf.all.log_martians', arg, 'Enabling logging of strange packets', 'Disabling logging of strange packets')
