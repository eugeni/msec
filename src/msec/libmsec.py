#!/usr/bin/python -O
#---------------------------------------------------------------
# Project         : Mandriva Linux
# Module          : mseclib
# File            : libmsec.py
# Version         : $Id$
# Author          : Eugeni Dodonov
# Original Author : Frederic Lepied
# Created On      : Mon Dec 10 22:52:17 2001
# Purpose         : low-level msec functions
#---------------------------------------------------------------

import os
import grp
import gettext
import pwd
import re
import string
import commands
import time
import stat
import traceback
import sys

# localization
try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

# backup file suffix
SUFFIX = '.msec'

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
LDSOPRELOAD = '/etc/ld.so.preload'
LILOCONF = '/etc/lilo.conf'
LOGINDEFS = '/etc/login.defs'
MENULST = '/boot/grub/menu.lst'
SHELLCONF = '/etc/sysconfig/shell'
MSECBIN = '/usr/sbin/msec'
MSECCRON = '/etc/cron.hourly/msec'
MSEC_XINIT = '/etc/X11/xinit.d/msec'
OPASSWD = '/etc/security/opasswd'
PASSWD = '/etc/pam.d/passwd'
POWEROFF = '/usr/bin/poweroff'
REBOOT = '/usr/bin/reboot'
SECURETTY = '/etc/securetty'
SECURITYCONF = '/var/lib/msec/security.conf'
SECURITYCONF2 = '/etc/security/msec/security.conf'
SECURITYCRON = '/etc/cron.daily/msec'
SECURITYSH = '/usr/share/msec/security.sh'
SERVER = '/etc/security/msec/server'
SHADOW = '/etc/shadow'
SHUTDOWN = '/usr/bin/shutdown'
SHUTDOWNALLOW = '/etc/shutdown.allow'
SIMPLE_ROOT_AUTHEN = '/etc/pam.d/simple_root_authen'
SSHDCONFIG = '/etc/ssh/sshd_config'
STARTX = '/usr/bin/startx'
SU = '/etc/pam.d/su'
SYSCTLCONF = '/etc/sysctl.conf'
SYSLOGCONF = '/etc/syslog.conf'
SYSTEM_AUTH = '/etc/pam.d/system-auth'
XDM = '/etc/pam.d/xdm'
XSERVERS = '/etc/X11/xdm/Xservers'
EXPORT = '/root/.xauth/export'

# ConfigFile constants
STRING_TYPE = type('')

BEFORE=0
INSIDE=1
AFTER=2

# constants
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

ALLOW_SHUTDOWN_VALUES = ('All', 'Root', 'None')
SHOW_USERS_VALUES = ('NotHidden', 'Selected')

# regexps
space = re.compile('\s')
# X server
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
# pam
SUCCEED_MATCH = '^auth\s+sufficient\s+pam_succeed_if.so\s+use_uid\s+user\s+ingroup\s+wheel\s*$'
SUCCEED_LINE = 'auth       sufficient   pam_succeed_if.so use_uid user ingroup wheel'
# cron
CRON_ENTRY = '*/1 * * * *    root    /usr/share/msec/promisc_check.sh'
CRON_REGEX = '[^#]+/usr/share/msec/promisc_check.sh'
# tcp_wrappers
ALL_REGEXP = '^ALL:ALL:DENY'
ALL_LOCAL_REGEXP = '^ALL:ALL EXCEPT 127\.0\.0\.1:DENY'
# password stuff
LENGTH_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sminlen=([0-9]+)\s(.*)')
NDIGITS_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sdcredit=([0-9]+)\s(.*)')
UCREDIT_REGEXP = re.compile('^(password\s+required\s+(?:/lib/security/)?pam_cracklib.so.*?)\sucredit=([0-9]+)\s(.*)')
PASSWORD_REGEXP = '^\s*auth\s+sufficient\s+(?:/lib/security/)?pam_permit.so'
UNIX_REGEXP = re.compile('(^\s*password\s+sufficient\s+(?:/lib/security/)?pam_unix.so.*)\sremember=([0-9]+)(.*)')
# sulogin
SULOGIN_REGEXP = '~~:S:wait:/sbin/sulogin'
# password aging
maximum_regex = re.compile('^Maximum.*:\s*([0-9]+|-1)', re.MULTILINE)
inactive_regex = re.compile('^(Inactive|Password inactive\s*):\s*(-?[0-9]+|never)', re.MULTILINE)


# {{{  helper functions
def get_index(val, array):
    # works with python 2.6
    #return array.index(val) if val in array else -1
    for loop in range(0, len(array)):
        if val == array[loop]:
            return loop
    return -1


def boolean2bit(bool):
    if bool == "yes":
        return 1
    else:
        return 0

def move(old, new):
    try:
        os.unlink(new)
    except OSError:
        pass
    try:
        os.rename(old, new)
    except:
        error('rename %s %s: %s' % (old, new, str(sys.exc_value)))

def substitute_re_result(res, s):
    for idx in range(0, (res.lastindex or 0) + 1):
        subst = res.group(idx) or ''
        s = string.replace(s, '@' + str(idx), subst)
    return s

def mkdir_p(path):
    if not os.path.exists(path):
        os.makedirs(path)
# }}}

# {{{ ConfigFiles - stores references to all configuration files
class ConfigFiles:
    """This class is responsible to store references to all configuration files,
        mark them as changed, and update on disk when necessary"""
    def __init__(self, log):
        """Initializes list of ConfigFiles"""
        self.files = {}
        self.modified_files = []
        self.action_assoc = []
        self.log = log

    def add(self, file, path):
        """Appends a path to list of files"""
        self.files[path] = file

    def modified(self, path):
        """Marks a file as modified"""
        if not path in self.modified_files:
            self.modified_files.append(path)

    def get_config_file(self, path, suffix=None):
        """Retreives corresponding config file"""
        try:
            return self.files[path]
        except KeyError:
            return ConfigFile(path, self, self.log, suffix=suffix)

    def add_config_assoc(self, regex, action):
        """Adds association between a file and an action"""
        self.log.debug("Adding custom command '%s' for '%s'" % (action, regex))
        self.action_assoc.append((re.compile(regex), action))

    def write_files(self, commit=True):
        """Writes all files back to disk"""
        for f in self.files.values():
            self.log.debug("Attempting to write %s" % f.path)
            if commit:
                f.write()

        if len(self.modified_files) > 0:
            self.log.info("Modified files: %s" % " ".join(self.modified_files))
        else:
            self.log.info(_("No changes in configuration."))

        for f in self.modified_files:
            for a in self.action_assoc:
                res = a[0].search(f)
                if res:
                    s = substitute_re_result(res, a[1])
                    if commit:
                        self.log.info(_('%s modified so launched command: %s') % (f, s))
                        cmd = commands.getstatusoutput(s)
                        cmd = [0, '']
                        if cmd[0] == 0:
                            if cmd[1]:
                                self.log.info(cmd[1])
                        else:
                            self.log.error(cmd[1])
                    else:
                        self.log.info(_('%s modified so should have run command: %s') % (f, s))

# }}}

# {{{ ConfigFile - an individual config file
class ConfigFile:
    """This class represents an individual config file.
       All config files are stored in meta (which is ConfigFiles).
       All operations are performed in memory, and written when required"""
    def __init__(self, path, meta, log, root='', suffix=None):
        """Initializes a config file, and put reference to meta (ConfigFiles)"""
        self.meta=meta
        self.path = root + path
        self.is_modified = 0
        self.is_touched = 0
        self.is_deleted = 0
        self.is_moved = 0
        self.suffix = suffix
        self.lines = None
        self.sym_link = None
        self.log = log
        self.meta.add(self, path)

    def get_lines(self):
        if self.lines == None:
            file=None
            try:
                file = open(self.path, 'r')
            except IOError:
                if self.suffix:
                    try:
                        moved = self.path + self.suffix
                        file = open(moved, 'r')
                        move(moved, self.path)
                        self.meta.modified(self.path)
                    except IOError:
                        self.lines = []
                else:
                    self.lines = []
            if file:
                self.lines = string.split(file.read(), "\n")
                file.close()
        return self.lines

    def append(self, value):
        lines = self.lines
        l = len(lines)
        if l > 0 and lines[l - 1] == '':
            lines.insert(l - 1,  value)
        else:
            lines.append(value)
            lines.append('')

    def modified(self):
        self.is_modified = 1
        self.meta.modified(self.path)
        return self

    def touch(self):
        self.is_touched = 1
        return self

    def symlink(self, link):
        self.sym_link = link
        return self

    def exists(self):
        return os.path.lexists(self.path)
        #return os.path.exists(self.path) or (self.suffix and os.path.exists(self.path + self.suffix))

    def realpath(self):
        return os.path.realpath(self.path)

    def move(self, suffix):
        self.suffix = suffix
        self.is_moved = 1

    def unlink(self):
        self.is_deleted = 1
        self.lines=[]
        return self

    def write(self):
        if self.is_deleted:
            if self.exists():
                try:
                    os.unlink(self.path)
                except:
                    error('unlink %s: %s' % (self.path, str(sys.exc_value)))
                self.log.info(_('deleted %s') % (self.path,))
        elif self.is_modified:
            content = string.join(self.lines, "\n")
            mkdir_p(os.path.dirname(self.path))
            file = open(self.path, 'w')
            file.write(content)
            file.close()
            self.meta.modified(self.path)
        elif self.is_touched:
            if os.path.exists(self.path):
                try:
                    os.utime(self.path, None)
                except:
                    self.log.error('utime %s: %s' % (self.path, str(sys.exc_value)))
            elif self.suffix and os.path.exists(self.path + self.suffix):
                move(self.path + self.suffix, self.path)
                try:
                    os.utime(self.path, None)
                except:
                    self.log.error('utime %s: %s' % (self.path, str(sys.exc_value)))
            else:
                self.lines = []
                self.is_modified = 1
                file = open(self.path, 'w')
                file.close()
                self.log.info(_('touched file %s') % (self.path,))
        elif self.sym_link:
            done = 0
            if self.exists():
               full = os.lstat(self.path)
               if stat.S_ISLNK(full[stat.ST_MODE]):
                   link = os.readlink(self.path)
                   # to be fixed: resolv relative symlink
                   done = (link == self.sym_link)
               if not done:
                   try:
                       os.unlink(self.path)
                   except:
                       self.log.error('unlink %s: %s' % (self.path, str(sys.exc_value)))
                   self.log.info(_('deleted %s') % (self.path,))
            if not done:
                try:
                    os.symlink(self.sym_link, self.path)
                except:
                    self.log.error('symlink %s %s: %s' % (self.sym_link, self.path, str(sys.exc_value)))
                self.log.info(_('made symbolic link from %s to %s') % (self.sym_link, self.path))

        if self.is_moved:
            move(self.path, self.path + self.suffix)
            self.log.info(_('moved file %s to %s') % (self.path, self.path + self.suffix))
            self.meta.modified(self.path)
        self.is_touched = 0
        self.is_modified = 0
        self.is_deleted = 0
        self.is_moved = 0

    def set_shell_variable(self, var, value, start=None, end=None):
        regex = re.compile('^' + var + '="?([^#"]+)"?(.*)')
        lines = self.get_lines()
        idx=0
        value=str(value)
        start_regexp = start

        if start:
            status = BEFORE
            start = re.compile(start)
        else:
            status = INSIDE

        if end:
            end = re.compile(end)

        idx = None
        for idx in range(0, len(lines)):
            line = lines[idx]
            if status == BEFORE:
                if start.search(line):
                    status = INSIDE
                else:
                    continue
            elif end and end.search(line):
                break
            res = regex.search(line)
            if res:
                if res.group(1) != value:
                    if space.search(value):
                        lines[idx] = var + '="' + value + '"' + res.group(2)
                    else:
                        lines[idx] = var + '=' + value + res.group(2)
                    self.modified()
                    self.log.debug(_('set variable %s to %s in %s') % (var, value, self.path,))
                return self
        if status == BEFORE:
            # never found the start delimiter
            self.log.warning(_('WARNING: never found regexp %s in %s, not writing changes') % (start_regexp, self.path))
            return self
        if space.search(value):
            s = var + '="' + value + '"'
        else:
            s = var + '=' + value
        if idx == None or idx == len(lines):
            self.append(s)
        else:
            lines.insert(idx, s)

        self.modified()
        self.log.info(_('set variable %s to %s in %s') % (var, value, self.path,))
        return self

    def get_shell_variable(self, var, start=None, end=None):
        # if file does not exists, fail quickly
        if not self.exists():
            return None
        if end:
            end=re.compile(end)
        if start:
            start=re.compile(start)
        regex = re.compile('^' + var + '="?([^#"]+)"?(.*)')
        lines = self.get_lines()
        llen = len(lines)
        start_idx = 0
        end_idx = llen
        if start:
            found = 0
            for idx in range(0, llen):
                if start.search(lines[idx]):
                    start_idx = idx
                    found = 1
                    break
            if found:
                for idx in range(start_idx, llen):
                    if end.search(lines[idx]):
                        end_idx = idx
                        break
        else:
            start_idx = 0
        for idx in range(end_idx - 1, start_idx - 1, -1):
            res = regex.search(lines[idx])
            if res:
                return res.group(1)
        return None

    def get_match(self, regex, replace=None):
        # if file does not exists, fail quickly
        if not self.exists():
            return None
        r=re.compile(regex)
        lines = self.get_lines()
        for idx in range(0, len(lines)):
            res = r.search(lines[idx])
            if res:
                if replace:
                    s = substitute_re_result(res, replace)
                    return s
                else:
                    return lines[idx]
        return None

    def replace_line_matching(self, regex, value, at_end_if_not_found=0, all=0, start=None, end=None):
        # if at_end_if_not_found is a string its value will be used as the string to inster
        r=re.compile(regex)
        lines = self.get_lines()
        matches = 0

        if start:
            status = BEFORE
            start = re.compile(start)
        else:
            status = INSIDE

        if end:
            end = re.compile(end)

        idx = None
        for idx in range(0, len(lines)):
            line = lines[idx]
            if status == BEFORE:
                if start.search(line):
                    status = INSIDE
                else:
                    continue
            elif end and end.search(line):
                break
            res = r.search(line)
            if res:
                s = substitute_re_result(res, value)
                matches = matches + 1
                if s != line:
                    self.log.debug(_("replaced in %s the line %d:\n%s\nwith the line:\n%s") % (self.path, idx, line, s))
                    lines[idx] = s
                    self.modified()
                if not all:
                    return matches
        if matches == 0 and at_end_if_not_found:
            if type(at_end_if_not_found) == STRING_TYPE:
                value = at_end_if_not_found
            self.log.debug(_("appended in %s the line:\n%s") % (self.path, value))
            if idx == None or idx == len(lines):
                self.append(value)
            else:
                lines.insert(idx, value)
            self.modified()
            matches = matches + 1
        return matches

    def insert_after(self, regex, value, at_end_if_not_found=0, all=0):
        matches = 0
        r=re.compile(regex)
        lines = self.get_lines()
        for idx in range(0, len(lines)):
            res = r.search(lines[idx])
            if res:
                s = substitute_re_result(res, value)
                self.log.debug(_("inserted in %s after the line %d:\n%s\nthe line:\n%s") % (self.path, idx, lines[idx], s))
                lines.insert(idx+1, s)
                self.modified()
                matches = matches + 1
                if not all:
                    return matches
        if matches == 0 and at_end_if_not_found:
            self.log.debug(_("appended in %s the line:\n%s") % (self.path, value))
            self.append(value)
            self.modified()
            matches = matches + 1
        return matches

    def insert_before(self, regex, value, at_top_if_not_found=0, all=0):
        matches = 0
        r=re.compile(regex)
        lines = self.get_lines()
        for idx in range(0, len(lines)):
            res = r.search(lines[idx])
            if res:
                s = substitute_re_result(res, value)
                self.log.debug(_("inserted in %s before the line %d:\n%s\nthe line:\n%s") % (self.path, idx, lines[idx], s))
                lines.insert(idx, s)
                self.modified()
                matches = matches + 1
                if not all:
                    return matches
        if matches == 0 and at_top_if_not_found:
            self.log.debug(_("inserted at the top of %s the line:\n%s") % (self.path, value))
            lines.insert(0, value)
            self.modified()
            matches = matches + 1
        return matches

    def insert_at(self, idx, value):
        lines = self.get_lines()
        try:
            lines.insert(idx, value)
            self.log.debug(_("inserted in %s at the line %d:\n%s") % (self.path, idx, value))
            self.modified()
            return 1
        except KeyError:
            return 0

    def remove_line_matching(self, regex, all=0):
        matches = 0
        r=re.compile(regex)
        lines = self.get_lines()
        for idx in range(len(lines) - 1, -1, -1):
            res = r.search(lines[idx])
            if res:
                self.log.debug(_("removing in %s the line %d:\n%s") % (self.path, idx, lines[idx]))
                lines.pop(idx)
                self.modified()
                matches = matches + 1
                if not all:
                    return matches
        return matches
# }}}

# {{{ MSEC - main class
class MSEC:
    """Main msec class. Contains all functions and performs the actions"""
    def __init__(self, log):
        """Initializes config files and associations"""
        # all config files
        self.log = log
        self.configfiles = ConfigFiles(log)

        # associate helper commands with files
        self.configfiles.add_config_assoc(INITTAB, '/sbin/telinit q')
        self.configfiles.add_config_assoc('/etc(?:/rc.d)?/init.d/(.+)', '[ -f /var/lock/subsys/@1 ] && @0 reload')
        self.configfiles.add_config_assoc(SYSCTLCONF, '/sbin/sysctl -e -p /etc/sysctl.conf')
        self.configfiles.add_config_assoc(SSHDCONFIG, '[ -f /var/lock/subsys/sshd ] && /etc/rc.d/init.d/sshd restart')
        self.configfiles.add_config_assoc(LILOCONF, '[ `/usr/sbin/detectloader` = LILO ] && /sbin/lilo')
        self.configfiles.add_config_assoc(SYSLOGCONF, '[ -f /var/lock/subsys/syslog ] && service syslog reload')
        self.configfiles.add_config_assoc('^/etc/issue$', '/usr/bin/killall mingetty')

        # TODO: add a common function to check parameters

    def get_action(self, name):
        """Determines correspondent function for requested action."""
        try:
            func = getattr(self, name)
            return func
        except:
            return None

    def commit(self, really_commit=True):
        """Commits changes"""
        if not really_commit:
            self.log.info(_("In check-only mode, nothing is written back to disk."))
        self.configfiles.write_files(really_commit)

    def create_server_link(self, param):
        '''  Creates the symlink /etc/security/msec/server to point to
        /etc/security/msec/server.<SERVER_LEVEL>. The /etc/security/msec/server
        is used by chkconfig --add to decide to add a service if it is present
        in the file during the installation of packages.'''

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
        '''  Allow/Forbid X connections. Accepted arguments: yes (all
        connections are allowed), local (only local connection), no (no
        connection).'''

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
        '''  The argument specifies if clients are authorized to connect
    to the X server on the tcp port 6000 or not.'''

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
                if startx.exists():
                    startx.replace_line_matching('serverargs="(.*?)( -nolisten tcp)?"', 'serverargs="@1 -nolisten tcp"')
                if xservers.exists():
                    xservers.replace_line_matching('(\s*[^#]+/usr/bin/X .*?)( -nolisten tcp)?$', '@1 -nolisten tcp', 0, 1)
                if gdmconf.exists():
                    gdmconf.set_shell_variable('DisallowTCP', 'true', '\[security\]', '^\s*$')
                if kdmrc.exists():
                    if not kdmrc.get_match('^ServerArgsLocal=.* -nolisten tcp'):
                        kdmrc.replace_line_matching('^(ServerArgsLocal=.*)$', '@1 -nolisten tcp', 'ServerArgsLocal=-nolisten tcp', 0, 'X-\*-Core', '^\s*$')

    def set_shell_timeout(self, val):
        '''  Set the shell timeout. A value of zero means no timeout.'''
        msec = self.configfiles.get_config_file(SHELLCONF)
        try:
            timeout = int(val)
        except:
            self.log.error(_('Invalid shell timeout "%s"') % size)
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
        '''  Set umask option for mounting vfat and ntfs partitions. A value of None means default umask.'''
        fstab = self.configfiles.get_config_file(FSTAB)

        if umask == "no":
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+)umask=\d+(\s.*)", "@1defaults@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+)umask=\d+,(.*)", "@1@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+\S+),umask=\d+(.*)", "@1@3", 0, 1)
        else:
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+\S*)umask=\d+(.*)", "@1umask=0@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+)(?!.*umask=)(\S+)(.*)", "@1@3,umask=0@4", 0, 1)

    def allow_reboot(self, arg):
        '''  Allow/Forbid system reboot and shutdown to local users.'''
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
                inittab.replace_line_matching(CTRALTDEL_REGEXP, 'ca::ctrlaltdel:/sbin/shutdown -t3 -r now', 1)
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
                inittab.remove_line_matching(CTRALTDEL_REGEXP)

    def allow_user_list(self, arg):
        '''  Allow/Forbid the list of users on the system on display managers (kdm and gdm).'''
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

    def allow_root_login(self, arg):
        '''  Allow/Forbid direct root login.'''
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

    def allow_remote_root_login(self, arg):
        '''  Allow/Forbid remote root login via sshd. You can specify
    yes, no and without-password. See sshd_config(5) man page for more
    information.'''
        sshd_config = self.configfiles.get_config_file(SSHDCONFIG)

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
            elif arg == "without_password":
                self.log.info(_('Allowing remote root login only by passphrase'))
                sshd_config.exists() and sshd_config.replace_line_matching(PERMIT_ROOT_LOGIN_REGEXP,
                                                                           'PermitRootLogin without-password', 1)

    def enable_pam_wheel_for_su(self, arg):
        '''   Enabling su only from members of the wheel group or allow su from any user.'''
        su = self.configfiles.get_config_file(SU)

        val = su.get_match('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$')

        if arg == "yes":
            if not val:
                self.log.info(_('Allowing su only from wheel group members'))
                try:
                    ent = grp.getgrnam('wheel')
                except KeyError:
                    error(_('no wheel group'))
                    return
                members = ent[3]
                if members == [] or members == ['root']:
                    self.log.error(_('wheel group is empty'))
                    return
                if su.exists():
                    (su.replace_line_matching('^[#\s]*auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$',
                                                          'auth       required     pam_wheel.so use_uid') or \
                                 su.insert_after('^auth\s+required', 'auth       required     pam_wheel.so use_uid'))
        else:
            if val:
                self.log.info(_('Allowing su for all'))
                if su.exists():
                    su.replace_line_matching('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$',
                                                          '# auth       required     pam_wheel.so use_uid')

    def enable_pam_root_from_wheel(self, arg):
        '''   Allow root access without password for the members of the wheel group.'''
        su = self.configfiles.get_config_file(SU)
        simple = self.configfiles.get_config_file(SIMPLE_ROOT_AUTHEN)

        if not su.exists():
            return

        val = su.get_match(SUCCEED_MATCH)

        val_simple = simple.get_match(SUCCEED_MATCH)

        if arg == "yes":
            if not val or not val_simple:
                self.log.info(_('Allowing transparent root access for wheel group members'))
                if not val:
                    print "here2"
                    su.insert_before('^auth\s+sufficient', SUCCEED_LINE)
                if simple.exists() and not val_simple:
                    simple.insert_before('^auth\s+sufficient', SUCCEED_LINE)
        else:
            if val or val_simple:
                self.log.info(_('Disabling transparent root access for wheel group members'))
                if val:
                    su.remove_line_matching(SUCCEED_MATCH)
                if simple.exists() and val_simple:
                    simple.remove_line_matching(SUCCEED_MATCH)

    def allow_autologin(self, arg):
        '''  Allow/Forbid autologin.'''
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
        '''  Enable/Disable syslog reports to console 12. \\fIexpr\\fP is the
    expression describing what to log (see syslog.conf(5) for more details) and
    dev the device to report the log.'''

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

    def enable_security_check(self, arg):
        '''   Activate/Disable daily security check.'''
        cron = self.configfiles.get_config_file(CRON)
        cron.remove_line_matching('[^#]+/usr/share/msec/security.sh')

        securitycron = self.configfiles.get_config_file(SECURITYCRON)

        if arg == "yes":
            if not securitycron.exists():
                self.log.info(_('Activating daily security check'))
                securitycron.symlink(SECURITYSH)
        else:
            if securitycron.exists():
                self.log.info(_('Disabling daily security check'))
                securitycron.unlink()

    def authorize_services(self, arg):
        ''' Configure access to tcp_wrappers services (see hosts.deny(5)).  If
        arg = yes, all services are authorized. If arg = local, only local ones
        are, and if arg = no, no services are authorized. In this case, To
        authorize the services you need, use /etc/hosts.allow (see
        hosts.allow(5)).'''

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
        '''  Enable/Disable IP spoofing protection.'''
        # the alert argument is kept for backward compatibility
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.conf.all.rp_filter', arg, 'Enabling ip spoofing protection', 'Disabling ip spoofing protection')

    def enable_dns_spoofing_protection(self, arg, alert=1):
        '''  Enable/Disable name resolution spoofing protection.  If
    \\fIalert\\fP is true, also reports to syslog.'''
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
        '''   Accept/Refuse icmp echo.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_echo_ignore_all', arg, 'Ignoring icmp echo', 'Accepting icmp echo')

    def accept_broadcasted_icmp_echo(self, arg):
        '''   Accept/Refuse broadcasted icmp echo.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_echo_ignore_broadcasts', arg, 'Ignoring broadcasted icmp echo', 'Accepting broadcasted icmp echo')

    def accept_bogus_error_responses(self, arg):
        '''  Accept/Refuse bogus IPv4 error messages.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_ignore_bogus_error_responses', arg, 'Ignoring bogus icmp error responses', 'Accepting bogus icmp error responses')

    def enable_log_strange_packets(self, arg):
        '''  Enable/Disable the logging of IPv4 strange packets.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.conf.all.log_martians', arg, 'Enabling logging of strange packets', 'Disabling logging of strange packets')

    def password_length(self, arg):
        '''  Set the password minimum length and minimum number of digit and minimum number of capitalized letters.'''

        try:
            length, ndigits, nupper = arg.split(",")
            length = int(length)
            ndigits = int(ndigits)
            nupper = int(nupper)
        except:
            self.log.error(_('Invalid password length "%s". Use "length,ndigits,nupper" as parameter') % arg)
            return

        passwd = self.configfiles.get_config_file(SYSTEM_AUTH)

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

        if passwd.exists() and (val_length != length or val_ndigits != ndigits or val_ucredit != nupper):
            self.log.info(_('Setting minimum password length %d') % length)
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

    def enable_password(self, arg):
        '''  Use password to authenticate users. Take EXTREMELY care when
        disabling passwords, as it will leave the machine COMPLETELY vulnerable.
        '''
        system_auth = self.configfiles.get_config_file(SYSTEM_AUTH)

        val = system_auth.get_match(PASSWORD_REGEXP)

        if arg == "yes":
            if val:
                self.log.info(_('Using password to authenticate users'))
                system_auth.remove_line_matching(PASSWORD_REGEXP)
        else:
            if not val:
                self.log.info(_('Don\'t use password to authenticate users'))
                system_auth.replace_line_matching(PASSWORD_REGEXP, 'auth        sufficient    pam_permit.so') or \
                system_auth.insert_before('auth\s+sufficient', 'auth        sufficient    pam_permit.so')

    def password_history(self, arg):
        '''  Set the password history length to prevent password reuse.'''
        system_auth = self.configfiles.get_config_file(SYSTEM_AUTH)

        # verify parameter validity
        # max
        try:
            history = int(arg)
        except:
            self.log.error(_('Invalid maximum password history length: "%s"') % arg)
            return

        if system_auth.exists():
            val = system_auth.get_match(UNIX_REGEXP, '@2')

            if val and val != '':
                val = int(val)
            else:
                val = 0
        else:
            val = 0

        if history != val:
            if history > 0:
                self.log.info(_('Setting password history to %d.') % history)
                system_auth.replace_line_matching(UNIX_REGEXP, '@1 remember=%d@3' % history) or \
                system_auth.replace_line_matching('(^\s*password\s+sufficient\s+(?:/lib/security/)?pam_unix.so.*)', '@1 remember=%d' % history)
                opasswd = self.configfiles.get_config_file(OPASSWD)
                opasswd.exists() or opasswd.touch()
            else:
                self.log.info(_('Disabling password history'))
                system_auth.replace_line_matching(UNIX_REGEXP, '@1@3')

    def enable_sulogin(self, arg):
        '''   Enable/Disable sulogin(8) in single user level.'''
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

    # Do we need this?
    def enable_msec_cron(self, arg):
        '''  Enable/Disable msec hourly security check.'''
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
        '''  Enable/Disable crontab and at for users. Put allowed users in /etc/cron.allow and /etc/at.allow
    (see man at(1) and crontab(1)).'''
        cronallow = self.configfiles.get_config_file(CRONALLOW)
        atallow = self.configfiles.get_config_file(ATALLOW)

        val_cronallow = cronallow.get_match('root')
        val_atallow = atallow.get_match('root')

        if arg == "yes":
            if val_cronallow or val_atallow:
                self.log.info(_('Enabling crontab and at'))
                if not val_cronallow:
                    cronallow.exists() and cronallow.move(SUFFIX)
                if not val_atallow:
                    atallow.exists() and atallow.move(SUFFIX)
        else:
            if not val_cronallow or not val_atallow:
                self.log.info(_('Disabling crontab and at'))
                cronallow.replace_line_matching('root', 'root', 1)
                atallow.replace_line_matching('root', 'root', 1)

    def allow_xauth_from_root(self, arg):
        ''' Allow/forbid to export display when passing from the root account
    to the other users. See pam_xauth(8) for more details.'''
        export = self.configfiles.get_config_file(EXPORT)

        allow = export.get_match('^\*$')

        if arg:
            if not allow:
                self.log.info(_('Allowing export display from root'))
                export.insert_at(0, '*')
        else:
            if allow:
                self.log.info(_('Forbidding export display from root'))
                export.remove_line_matching('^\*$')

    def set_security_conf(self, var, value):
        '''1 Set the variable \\fIvar\\fP to the value \\fIvalue\\fP in /var/lib/msec/security.conf.
    The best way to override the default setting is to create /etc/security/msec/security.conf
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
        securityconf = self.configfiles.get_config_file(SECURITYCONF)
        securityconf.set_shell_variable(var, value)

    def check_security(self, param):
        pass

    def check_perms(self, param):
        pass

    def check_suid_root(self, param):
        pass

    def check_suid_md5(self, param):
        pass

    def check_sgid(self, param):
        pass

    def check_writable(self, param):
        pass

    def check_unowned(self, param):
        pass

    def check_promisc(self, param):
        '''  Activate/Disable ethernet cards promiscuity check.'''
        cron = self.configfiles.get_config_file(CRON)

        val = cron.get_match(CRON_REGEX)

        if param == "yes":
            if val != CRON_ENTRY:
                self.log.info(_('Activating periodic promiscuity check'))
                cron.replace_line_matching(CRON_REGEX, CRON_ENTRY, 1)
        else:
            if val:
                self.log.info(_('Disabling periodic promiscuity check'))
                cron.remove_line_matching('[^#]+/usr/share/msec/promisc_check.sh')

    def check_open_port(self, param):
        pass

    def check_passwd(self, param):
        pass

    def check_shadow(self, param):
        pass

    def check_chkrootkit(self, param):
        pass

    def check_rpm(self, param):
        pass

    def tty_warn(self, param):
        pass

    def mail_warn(self, param):
        pass

    def mail_empty_content(self, param):
        pass

    def syslog_warn(self, param):
        pass
# }}}

if __name__ == "__main__":
    # this should never ever be run directly
    print >>sys.stderr, """This file should not be run directly."""

