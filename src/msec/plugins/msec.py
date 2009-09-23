#!/usr/bin/python
"""Msec plugin for enforcing local security settings"""

# main plugin class name
PLUGIN = "msec"

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
class msec:
    def __init__(self, log=None, configfiles=None, root=None):
        """This plugin is responsible for enforcing security settings on the machine."""
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
        config.SETTINGS['USER_UMASK'] = ("msec.set_user_umask", ['*'])
        config.SETTINGS['ROOT_UMASK'] = ("msec.set_root_umask", ['*'])
        config.SETTINGS['ALLOW_CURDIR_IN_PATH'] = ("msec.allow_curdir_in_path", ['yes', 'no'])
        config.SETTINGS['WIN_PARTS_UMASK'] = ("msec.set_win_parts_umask", ['*'])
        config.SETTINGS['ALLOW_AUTOLOGIN'] = ("msec.allow_autologin", ['yes', 'no'])
        config.SETTINGS['ALLOW_REBOOT'] = ("msec.allow_reboot", ['yes', 'no'])
        config.SETTINGS['ALLOW_ROOT_LOGIN'] = ("msec.allow_root_login", ['yes', 'no'])
        config.SETTINGS['ALLOW_USER_LIST'] = ("msec.allow_user_list", ['yes', 'no'])
        config.SETTINGS['ALLOW_X_CONNECTIONS'] = ("msec.allow_x_connections", ['yes', 'no', 'local'])
        config.SETTINGS['ALLOW_XAUTH_FROM_ROOT'] = ("msec.allow_xauth_from_root", ['yes', 'no'])
        config.SETTINGS['ALLOW_XSERVER_TO_LISTEN'] = ("msec.allow_xserver_to_listen", ['yes', 'no'])
        config.SETTINGS['AUTHORIZE_SERVICES'] = ("msec.authorize_services", ['yes', 'no', 'local'])
        config.SETTINGS['CREATE_SERVER_LINK'] = ("msec.create_server_link", ['no', 'remote', 'local'])
        config.SETTINGS['ENABLE_AT_CRONTAB'] = ("msec.enable_at_crontab", ['yes', 'no'])
        config.SETTINGS['ENABLE_CONSOLE_LOG'] = ("msec.enable_console_log", ['yes', 'no'])
        config.SETTINGS['ENABLE_MSEC_CRON'] = ("msec.enable_msec_cron", ['yes', 'no'])
        config.SETTINGS['ENABLE_SULOGIN'] = ("msec.enable_sulogin", ['yes', 'no'])
        config.SETTINGS['SECURE_TMP'] = ("msec.secure_tmp", ['yes', 'no'])
        config.SETTINGS['SHELL_HISTORY_SIZE'] = ("msec.set_shell_history_size", ['*'])
        config.SETTINGS['SHELL_TIMEOUT'] = ("msec.set_shell_timeout", ['*'])
        config.SETTINGS['ENABLE_STARTUP_MSEC'] = ("msec.enable_startup_msec", ['yes', 'no'])
        config.SETTINGS['ENABLE_STARTUP_PERMS'] = ("msec.enable_startup_perms", ['yes', 'no', 'enforce'])

        # system settings
        for check in ["ENABLE_STARTUP_MSEC", "ENABLE_STARTUP_PERMS", "ENABLE_MSEC_CRON",
                    "ENABLE_SULOGIN", "ENABLE_AT_CRONTAB", "ALLOW_XSERVER_TO_LISTEN",
                    "ALLOW_ROOT_LOGIN", "ALLOW_USER_LIST", "ALLOW_AUTOLOGIN",
                    "ENABLE_CONSOLE_LOG", "CREATE_SERVER_LINK", "ALLOW_XAUTH_FROM_ROOT",
                    "ALLOW_REBOOT", "SHELL_HISTORY_SIZE", "SHELL_TIMEOUT", "USER_UMASK", "ROOT_UMASK",
                    "SECURE_TMP", "WIN_PARTS_UMASK", "ALLOW_CURDIR_IN_PATH"
                    ]:
            config.SETTINGS_SYSTEM.append(check)

    def create_server_link(self, param):
        '''  Creates the symlink /etc/security/msec/server to point to /etc/security/msec/server.SERVER_LEVEL. The /etc/security/msec/server is used by chkconfig --add to decide to add a service if it is present in the file during the installation of packages. By default, two presets are provided: local (which only enables local services) and remote (which also enables some remote services considered safe). Note that the allowed services must be placed manually into the server.SERVER_LEVEL files when necessary.'''
        server = self.configfiles.get_config_file(SERVER)

        if param == "no":
            if server.exists():
                self.log.info(_('Allowing unrestricted chkconfig for packages'))
                server.unlink()
        else:
            newpath = "%s.%s" % (SERVER, param)
            if server.realpath() != newpath:
                self.log.info(_('Restricting chkconfig for packages according to "%s" profile') % param)
                server.symlink(newpath)

    def set_root_umask(self, umask):
        '''  Set the root umask.'''
        msec = self.configfiles.get_config_file(SHELLCONF)

        val = msec.get_shell_variable('UMASK_ROOT')

        if val != umask:
            self.log.info(_('Setting root umask to %s') % (umask))
            msec.set_shell_variable('UMASK_ROOT', umask)

    def set_user_umask(self, umask):
        '''  Set the user umask.'''
        msec = self.configfiles.get_config_file(SHELLCONF)

        val = msec.get_shell_variable('UMASK_USER')

        if val != umask:
            self.log.info(_('Setting users umask to %s') % (umask))
            msec.set_shell_variable('UMASK_USER', umask)

    def allow_x_connections(self, arg):
        '''  Allow local users to connect to X server. Accepted arguments: yes (all connections are allowed), local (only local connection), no (no connection).'''

        xinit = self.configfiles.get_config_file(MSEC_XINIT)
        val = xinit.get_match('/usr/bin/xhost\s*(\+\s*[^#]*)', '@1')

        if val:
            if val == '+':
                val = "yes"
            elif val == "+ localhost":
                val = "local"
            else:
                val = "no"
        else:
            val = "no"

        if val != arg:
            if arg == "yes":
                self.log.info(_('Allowing users to connect X server from everywhere'))
                xinit.replace_line_matching('/usr/bin/xhost', '/usr/bin/xhost +', 1)
            elif arg == "local":
                self.log.info(_('Allowing users to connect X server from localhost'))
                xinit.replace_line_matching('/usr/bin/xhost', '/usr/bin/xhost + localhost', 1)
            elif arg == "no":
                self.log.info(_('Restricting X server connection to the console user'))
                xinit.remove_line_matching('/usr/bin/xhost', 1)
            else:
                self.log.error(_('invalid allow_x_connections arg: %s') % arg)

    def allow_xserver_to_listen(self, arg):
        '''  Allow X server to accept connections from network on tcp port 6000.'''

        startx = self.configfiles.get_config_file(STARTX)
        xservers = self.configfiles.get_config_file(XSERVERS)
        gdmconf = self.configfiles.get_config_file(GDMCONF)
        kdmrc = self.configfiles.get_config_file(KDMRC)

        val_startx = startx.get_match(STARTX_REGEXP)
        val_xservers = xservers.get_match(XSERVERS_REGEXP)
        val_gdmconf = gdmconf.get_shell_variable('DisallowTCP')
        str = kdmrc.get_shell_variable('ServerArgsLocal', 'X-\*-Core', '^\s*$')
        if str:
            val_kdmrc = KDMRC_REGEXP.search(str)
        else:
            val_kdmrc = None

        # TODO: better check for file existance

        if arg == "yes":
            if val_startx or val_xservers or val_kdmrc or val_gdmconf != 'false':
                self.log.info(_('Allowing the X server to listen to tcp connections'))
                if startx.exists():
                    startx.replace_line_matching(STARTX_REGEXP, '@1@2')
                if xservers.exists():
                    xservers.replace_line_matching(XSERVERS_REGEXP, '@1@2', 0, 1)
                if gdmconf.exists():
                    gdmconf.set_shell_variable('DisallowTCP', 'false', '\[security\]', '^\s*$')
                if kdmrc.exists():
                    kdmrc.replace_line_matching('^(ServerArgsLocal=.*?)-nolisten tcp(.*)$', '@1@2', 0, 0, 'X-\*-Core', '^\s*$')
        else:
            if not val_startx or not val_xservers or not val_kdmrc or val_gdmconf != 'true':
                self.log.info(_('Forbidding the X server to listen to tcp connection'))
                if not val_startx:
                    startx.exists() and startx.replace_line_matching('serverargs="(.*?)( -nolisten tcp)?"', 'serverargs="@1 -nolisten tcp"')
                if not val_xservers:
                    xservers.exists() and xservers.replace_line_matching('(\s*[^#]+/usr/bin/X .*?)( -nolisten tcp)?$', '@1 -nolisten tcp', 0, 1)
                if val_gdmconf != 'true':
                    gdmconf.exists() and gdmconf.set_shell_variable('DisallowTCP', 'true', '\[security\]', '^\s*$')
                if not val_kdmrc:
                    kdmrc.exists() and kdmrc.replace_line_matching('^(ServerArgsLocal=.*)$', '@1 -nolisten tcp', 'ServerArgsLocal=-nolisten tcp', 0, 'X-\*-Core', '^\s*$')

    def set_shell_timeout(self, val):
        '''  Set the shell timeout. A value of zero means no timeout.'''
        msec = self.configfiles.get_config_file(SHELLCONF)
        try:
            timeout = int(val)
        except:
            self.log.error(_('Invalid shell timeout "%s"') % val)
            return

        old = msec.get_shell_variable('TMOUT')
        if old:
            old = int(old)

        if old != timeout:
            self.log.info(_('Setting shell timeout to %s') % timeout)
            msec.set_shell_variable('TMOUT', timeout)

    def set_shell_history_size(self, size):
        '''  Set shell commands history size. A value of -1 means unlimited.'''
        try:
            size = int(size)
        except:
            self.log.error(_('Invalid shell history size "%s"') % size)
            return

        msec = self.configfiles.get_config_file(SHELLCONF)

        val = msec.get_shell_variable('HISTFILESIZE')
        if val:
            val = int(val)

        if size >= 0:
            if val != size:
                self.log.info(_('Setting shell history size to %s') % size)
                msec.set_shell_variable('HISTFILESIZE', size)
        else:
            if val != None:
                self.log.info(_('Removing limit on shell history size'))
                msec.remove_line_matching('^HISTFILESIZE=')

    def set_win_parts_umask(self, umask):
        ''' Set umask option for mounting vfat and ntfs partitions. If umask is '-1', default system umask is used.'''
        fstab = self.configfiles.get_config_file(FSTAB)
        try:
            test_umask = int(umask)
        except:
            self.log.error(_('Invalid file system umask "%s"') % umask)
            return
        if umask == "-1":
            fstab.replace_line_matching("(.*\s(vfat|ntfs|ntfs-3g)\s+)umask=\d+(\s.*)", "@1defaults@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs|ntfs-3g)\s+)umask=\d+,(.*)", "@1@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs|ntfs-3g)\s+\S+),umask=\d+(.*)", "@1@3", 0, 1)
        else:
            fstab.replace_line_matching("(.*\s(vfat|ntfs|ntfs-3g)\s+\S*)umask=\d+(.*)", "@1umask="+umask+"@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs|ntfs-3g)\s+)(?!.*umask=)(\S+)(.*)", "@1@3,umask="+umask+"@4", 0, 1)

    def allow_reboot(self, arg):
        '''  Allow system reboot and shutdown to local users.'''
        shutdownallow = self.configfiles.get_config_file(SHUTDOWNALLOW)
        sysctlconf = self.configfiles.get_config_file(SYSCTLCONF)
        kdmrc = self.configfiles.get_config_file(KDMRC)
        gdmconf = self.configfiles.get_config_file(GDMCONF)
        inittab = self.configfiles.get_config_file(INITTAB)
        shutdown = self.configfiles.get_config_file(SHUTDOWN)
        poweroff = self.configfiles.get_config_file(POWEROFF)
        reboot = self.configfiles.get_config_file(REBOOT)
        halt = self.configfiles.get_config_file(HALT)

        val_shutdownallow = shutdownallow.exists()
        val_shutdown = shutdown.exists()
        val_poweroff = poweroff.exists()
        val_reboot = reboot.exists()
        val_halt = halt.exists()
        val_sysctlconf = sysctlconf.get_shell_variable('kernel.sysrq')
        val_inittab = inittab.get_match(CTRALTDEL_REGEXP)
        val_gdmconf = gdmconf.get_shell_variable('SystemMenu')
        oldval_kdmrc = kdmrc.get_shell_variable('AllowShutdown', 'X-:\*-Core', '^\s*$')

        if arg == "yes":
            if val_shutdownallow or not val_shutdown or not val_poweroff or not val_reboot or not val_halt:
                self.log.info(_('Allowing reboot and shutdown to the console user'))
                shutdownallow.exists() and shutdownallow.move(SUFFIX)
                shutdown.exists() or shutdown.symlink(CONSOLE_HELPER)
                poweroff.exists() or poweroff.symlink(CONSOLE_HELPER)
                reboot.exists() or reboot.symlink(CONSOLE_HELPER)
                halt.exists() or halt.symlink(CONSOLE_HELPER)
            if val_sysctlconf == '0':
                self.log.info(_('Allowing SysRq key to the console user'))
                sysctlconf.set_shell_variable('kernel.sysrq', 1)
            if val_gdmconf == 'false':
                self.log.info(_('Allowing Shutdown/Reboot in GDM'))
                gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'true', '\[greeter\]', '^\s*$')
            if kdmrc.exists():
                if oldval_kdmrc != 'All':
                    self.log.info(_('Allowing Shutdown/Reboot in KDM'))
                    kdmrc.set_shell_variable('AllowShutdown', 'All', 'X-:\*-Core', '^\s*$')
            if not val_inittab:
                self.log.info(_('Allowing Ctrl-Alt-Del from console'))
                inittab.exists() and inittab.replace_line_matching(CTRALTDEL_REGEXP, 'ca::ctrlaltdel:/sbin/shutdown -t3 -r now', 1)
        else:
            if not val_shutdownallow or val_shutdown or val_poweroff or val_reboot or val_halt:
                self.log.info(_('Forbidding reboot and shutdown to the console user'))
                if not shutdownallow.exists():
                    self.configfiles.get_config_file(SHUTDOWNALLOW, SUFFIX).touch()
                shutdown.exists() and shutdown.unlink()
                poweroff.exists() and poweroff.unlink()
                reboot.exists() and reboot.unlink()
                halt.exists() and halt.unlink()
            if val_sysctlconf != '0':
                self.log.info(_('Forbidding SysRq key to the console user'))
                sysctlconf.set_shell_variable('kernel.sysrq', 0)
            if val_gdmconf != 'false':
                self.log.info(_('Forbidding Shutdown/Reboot in GDM'))
                gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'false', '\[greeter\]', '^\s*$')
            if kdmrc.exists():
                if oldval_kdmrc != 'None':
                    self.log.info(_('Forbidding Shutdown/Reboot in KDM'))
                    kdmrc.set_shell_variable('AllowShutdown', 'None', 'X-:\*-Core', '^\s*$')
            if val_inittab:
                self.log.info(_('Forbidding Ctrl-Alt-Del from console'))
                inittab.exists() and inittab.remove_line_matching(CTRALTDEL_REGEXP)

    def allow_user_list(self, arg):
        '''  Allow display managers (kdm and gdm) to display list of local users.'''
        kdmrc = self.configfiles.get_config_file(KDMRC)
        gdmconf = self.configfiles.get_config_file(GDMCONF)

        oldval_gdmconf = gdmconf.get_shell_variable('Browser')
        oldval_kdmrc = kdmrc.get_shell_variable('ShowUsers', 'X-\*-Greeter', '^\s*$')

        if arg == "yes":
            if kdmrc.exists():
                if oldval_kdmrc != 'NotHidden':
                    self.log.info(_("Allowing list of users in KDM"))
                    kdmrc.set_shell_variable('ShowUsers', 'NotHidden', 'X-\*-Greeter', '^\s*$')
            if gdmconf.exists():
                if oldval_gdmconf != 'true':
                    self.log.info(_("Allowing list of users in GDM"))
                    gdmconf.set_shell_variable('Browser', 'true')
        else:
            if kdmrc.exists():
                if oldval_kdmrc != 'Selected':
                    self.log.info(_("Forbidding list of users in KDM"))
                    kdmrc.set_shell_variable('ShowUsers', 'Selected', 'X-\*-Greeter', '^\s*$')
            if gdmconf.exists():
                if oldval_gdmconf != 'false':
                    self.log.info(_("Forbidding list of users in GDM"))
                    gdmconf.set_shell_variable('Browser', 'false')

    def allow_autologin(self, arg):
        '''  Allow autologin.'''
        autologin = self.configfiles.get_config_file(AUTOLOGIN)

        val = autologin.get_shell_variable('AUTOLOGIN')

        if val != arg:
            if arg == "yes":
                self.log.info(_('Allowing autologin'))
                autologin.set_shell_variable('AUTOLOGIN', 'yes')
            else:
                self.log.info(_('Forbidding autologin'))
                autologin.set_shell_variable('AUTOLOGIN', 'no')

    def password_loader(self, value):
        '''Unused'''
        self.log.info(_('Activating password in boot loader'))
        liloconf = self.configfiles.get_config_file(LILOCONF)
        liloconf.exists() and (liloconf.replace_line_matching('^password=', 'password="' + value + '"', 0, 1) or \
                               liloconf.insert_after('^boot=', 'password="' + value + '"')) and \
                               Perms.chmod(liloconf.path, 0600)
        # TODO encrypt password in grub
        menulst = self.configfiles.get_config_file(MENULST)
        menulst.exists() and (menulst.replace_line_matching('^password\s', 'password "' + value + '"') or \
                              menulst.insert_at(0, 'password "' + value + '"')) and \
                              Perms.chmod(menulst.path, 0600)
        # TODO add yaboot support

    def nopassword_loader(self):
        '''Unused'''
        self.log.info(_('Removing password in boot loader'))
        liloconf = self.configfiles.get_config_file(LILOCONF)
        liloconf.exists() and liloconf.remove_line_matching('^password=', 1)
        menulst = self.configfiles.get_config_file(MENULST)
        menulst.exists() and menulst.remove_line_matching('^password\s')

    def enable_console_log(self, arg, expr='*.*', dev='tty12'):
        ''' Log syslog messages on console terminal 12.'''

        syslogconf = self.configfiles.get_config_file(SYSLOGCONF)

        val = syslogconf.get_match('\s*[^#]+/dev/([^ ]+)', '@1')

        if arg == "yes":
            if dev != val:
                self.log.info(_('Enabling log on console'))
                syslogconf.exists() and syslogconf.replace_line_matching('\s*[^#]+/dev/', expr + ' /dev/' + dev, 1)
        else:
            if val != None:
                self.log.info(_('Disabling log on console'))
                syslogconf.exists() and syslogconf.remove_line_matching('\s*[^#]+/dev/')

    def authorize_services(self, arg):
        ''' Allow full access to network services controlled by tcp_wrapper (see hosts.deny(5)). If yes, all services are allowed. If local, only connections to local services are authorized. If no, the services must be authorized manually in /etc/hosts.allow (see hosts.allow(5)).'''

        hostsdeny = self.configfiles.get_config_file(HOSTSDENY)

        if hostsdeny.get_match(ALL_REGEXP):
            val = "no"
        elif hostsdeny.get_match(ALL_LOCAL_REGEXP):
            val = "local"
        else:
            val = "yes"

        if val != arg:
            if arg == "yes":
                self.log.info(_('Authorizing all services'))
                hostsdeny.remove_line_matching(ALL_REGEXP, 1)
                hostsdeny.remove_line_matching(ALL_LOCAL_REGEXP, 1)
            elif arg == "no":
                self.log.info(_('Disabling all services'))
                hostsdeny.remove_line_matching(ALL_LOCAL_REGEXP, 1)
                hostsdeny.replace_line_matching(ALL_REGEXP, 'ALL:ALL:DENY', 1)
            elif arg == "local":
                self.log.info(_('Disabling non local services'))
                hostsdeny.remove_line_matching(ALL_REGEXP, 1)
                hostsdeny.replace_line_matching(ALL_LOCAL_REGEXP, 'ALL:ALL EXCEPT 127.0.0.1:DENY', 1)

    def enable_sulogin(self, arg):
        ''' Ask for root password when going to single user level (man sulogin(8)).'''
        inittab = self.configfiles.get_config_file(INITTAB)

        val = inittab.get_match(SULOGIN_REGEXP)

        if arg == "yes":
            if not val:
                self.log.info(_('Enabling sulogin in single user runlevel'))
                inittab.replace_line_matching('[^#]+:S:', '~~:S:wait:/sbin/sulogin', 1)
        else:
            if val:
                self.log.info(_('Disabling sulogin in single user runlevel'))
                inittab.remove_line_matching('~~:S:wait:/sbin/sulogin')

    def enable_msec_cron(self, arg):
        '''  Perform hourly security check for changes in system configuration.'''
        mseccron = self.configfiles.get_config_file(MSECCRON)

        val = mseccron.exists()

        if arg == "yes":
            if not val:
                self.log.info(_('Enabling msec periodic runs'))
                mseccron.symlink(MSECBIN)
        else:
            if val:
                self.log.info(_('Disabling msec periodic runs'))
                mseccron.unlink()

    def enable_at_crontab(self, arg):
        ''' Enable crontab and at for users. Put allowed users in /etc/cron.allow and /etc/at.allow (see man at(1) and crontab(1)).'''
        cronallow = self.configfiles.get_config_file(CRONALLOW)
        atallow = self.configfiles.get_config_file(ATALLOW)

        val_cronallow = cronallow.get_match('root')
        val_atallow = atallow.get_match('root')

        if arg == "yes":
            if val_cronallow or val_atallow:
                self.log.info(_('Enabling crontab and at'))
                if val_cronallow:
                    cronallow.exists() and cronallow.move(SUFFIX)
                if val_atallow:
                    atallow.exists() and atallow.move(SUFFIX)
        else:
            if not val_cronallow or not val_atallow:
                self.log.info(_('Disabling crontab and at'))
                cronallow.replace_line_matching('root', 'root', 1)
                atallow.replace_line_matching('root', 'root', 1)

    def allow_xauth_from_root(self, arg):
        ''' Allow to export display when passing from the root account to the other users. See pam_xauth(8) for more details.'''
        export = self.configfiles.get_config_file(EXPORT)

        allow = export.get_match('^\*$')

        if arg == 'yes':
            if not allow:
                self.log.info(_('Allowing export display from root'))
                export.insert_at(0, '*')
        else:
            if allow:
                self.log.info(_('Forbidding export display from root'))
                export.remove_line_matching('^\*$')

    def allow_root_login(self, arg):
        '''  Allow direct root login on terminal.'''
        securetty = self.configfiles.get_config_file(SECURETTY)
        kde = self.configfiles.get_config_file(KDE)
        gdm = self.configfiles.get_config_file(GDM)
        gdmconf = self.configfiles.get_config_file(GDMCONF)
        xdm = self.configfiles.get_config_file(XDM)

        val = {}
        val_kde = kde.get_match('auth required (?:/lib/security/)?pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login')
        val_gdm = gdm.get_match('auth required (?:/lib/security/)?pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login')
        val_xdm = xdm.get_match('auth required (?:/lib/security/)?pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login')
        num = 0
        for n in range(1, 7):
            s = 'tty' + str(n)
            if securetty.get_match(s):
                num = num + 1
            s = 'vc/' + str(n)
            if securetty.get_match(s):
                num = num + 1

        if arg == "yes":
            if val_kde or val_gdm or val_xdm or num != 12:
                self.log.info(_('Allowing direct root login'))
                if gdmconf.exists():
                    gdmconf.set_shell_variable('ConfigAvailable', 'true', '\[greeter\]', '^\s*$')

                for cnf in [kde, gdm, xdm]:
                    if cnf.exists():
                        cnf.remove_line_matching('^auth\s*required\s*(?:/lib/security/)?pam_listfile.so.*bastille-no-login', 1)

                for n in range(1, 7):
                    s = 'tty' + str(n)
                    securetty.replace_line_matching(s, s, 1)
                    s = 'vc/' + str(n)
                    securetty.replace_line_matching(s, s, 1)
        else:
            if gdmconf.exists():
                gdmconf.set_shell_variable('ConfigAvailable', 'false', '\[greeter\]', '^\s*$')
            if (kde.exists() and not val_kde) or (gdm.exists() and not val_gdm) or (xdm.exists() and not val_xdm) or num > 0:
                self.log.info(_('Forbidding direct root login'))

                bastillenologin = self.configfiles.get_config_file(BASTILLENOLOGIN)
                bastillenologin.replace_line_matching('^\s*root', 'root', 1)

                # TODO: simplify this
                for cnf in [kde, gdm, xdm]:
                    if cnf.exists():
                        (cnf.replace_line_matching('^auth\s*required\s*(?:/lib/security/)?pam_listfile.so.*bastille-no-login',
                            'auth required pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login') or
                          cnf.insert_at(0, 'auth required pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login'))
                securetty.remove_line_matching('.+', 1)

    # bogus functions
    def secure_tmp(self, param):
        """Use secure location for temporary files. If this parameter is set to 'yes', user home directory will be used for temporary files. Otherwise, /tmp will be used."""
        shell = self.configfiles.get_config_file(SHELLCONF)

        val = shell.get_shell_variable('SECURE_TMP')

        if val != param:
            if param == 'yes':
                self.log.info(_('Using secure location for temporary files'))
            else:
                self.log.info(_('Not using secure location for temporary files'))
            shell.set_shell_variable('SECURE_TMP', param)
        pass

    def enable_startup_msec(self, param):
        """Enforce MSEC settings on system startup"""
        pass

    def enable_startup_perms(self, param):
        """Enforce MSEC file directory permissions on system startup. If this parameter is set to 'enforce', system permissions will be enforced automatically, according to system security settings."""
        pass

    def allow_curdir_in_path(self, param):
        """Include current directory into user PATH by default"""
        msec = self.configfiles.get_config_file(SHELLCONF)

        val = msec.get_shell_variable('ALLOW_CURDIR_IN_PATH')

        if val != param:
            if param == 'yes':
                self.log.info(_('Allowing including current directory in path'))
                msec.set_shell_variable('ALLOW_CURDIR_IN_PATH', param)
            else:
                self.log.info(_('Not allowing including current directory in path'))
                msec.set_shell_variable('ALLOW_CURDIR_IN_PATH', param)

