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
#import Perms
import gettext
import pwd
import re
import string
import commands
import time
import stat
import traceback
import sys

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


# helper functions
def get_index(val, array):
    return array.index(val) if val in array else -1

def boolean2bit(bool):
    return 1 if bool else 0

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


# {{{ ConfigFiles - stores references to all configuration files
class ConfigFiles:
    """This class is responsible to store references to all configuration files,
        mark them as changed, and update on disk when necessary"""
    def __init__(self):
        """Initializes list of ConfigFiles"""
        self.files = {}
        self.modified_files = []
        self.action_assoc = []

    def add(self, file, path):
        """Appends a path to list of files"""
        self.files[path] = file

    def modified(self, path):
        """Marks a file as modified"""
        if not path in self.modified_files:
            self.modified_files.append(path)

    def get_config_file(self, path, suffix):
        """Retreives corresponding config file"""
        try:
            return self.files[path]
        except KeyError:
            return ConfigFile(path, suffix, self)

    def add_config_assoc(self, regex, action):
        """Adds association between a file and an action"""
        self.action_assoc.append((re.compile(regex), action))

    def write_files(all_files, run_commands=True):
        """Writes all files back to disk"""
        for f in self.files.values():
            f.write()

        for f in all_files.modified_files:
            for a in all_files.action_assoc:
                res = a[0].search(f)
                if res:
                    s = substitute_re_result(res, a[1])
                    if run_commands != '0':
                        log(_('%s modified so launched command: %s') % (f, s))
                        cmd = commands.getstatusoutput(s)
                        if cmd[0] == 0:
                            log(cmd[1])
                        else:
                            error(cmd[1])
                    else:
                        log(_('%s modified so should have run command: %s') % (f, s))

# }}}

#all_files=ConfigFiles()

# {{{ ConfigFile - an individual config file
class ConfigFile:
    """This class represents an individual config file.
       All config files are stored in meta (which is ConfigFiles).
       All operations are performed in memory, and written when required"""
    def __init__(self, path, meta, root='', suffix=None):
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
        return self

    def touch(self):
        self.is_touched = 1
        return self

    def symlink(self, link):
        self.sym_link = link
        return self

    def exists(self, really=0):
        return os.path.exists(self.path) or (not really and self.suffix and os.path.exists(self.path + self.suffix))

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
                log(_('deleted %s') % (self.path,))
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
                    error('utime %s: %s' % (self.path, str(sys.exc_value)))
            elif self.suffix and os.path.exists(self.path + self.suffix):
                move(self.path + self.suffix, self.path)
                try:
                    os.utime(self.path, None)
                except:
                    error('utime %s: %s' % (self.path, str(sys.exc_value)))
            else:
                self.lines = []
                self.is_modified = 1
                file = open(self.path, 'w')
                file.close()
                log(_('touched file %s') % (self.path,))
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
                       error('unlink %s: %s' % (self.path, str(sys.exc_value)))
                   log(_('deleted %s') % (self.path,))
            if not done:
                try:
                    os.symlink(self.sym_link, self.path)
                except:
                    error('symlink %s %s: %s' % (self.sym_link, self.path, str(sys.exc_value)))
                log(_('made symbolic link from %s to %s') % (self.sym_link, self.path))

        if self.is_moved:
            move(self.path, self.path + self.suffix)
            log(_('moved file %s to %s') % (self.path, self.path + self.suffix))
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
                    log(_('set variable %s to %s in %s') % (var, value, self.path,))
                return self
        if status == BEFORE:
            # never found the start delimiter
            log(_('WARNING: never found regexp %s in %s, not writing changes') % (start_regexp, self.path))
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
        log(_('set variable %s to %s in %s') % (var, value, self.path,))
        return self

    def get_shell_variable(self, var, start=None, end=None):
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
                    log(_("replaced in %s the line %d:\n%s\nwith the line:\n%s") % (self.path, idx, line, s))
                    lines[idx] = s
                    self.modified()
                if not all:
                    return matches
        if matches == 0 and at_end_if_not_found:
            if type(at_end_if_not_found) == STRING_TYPE:
                value = at_end_if_not_found
            log(_("appended in %s the line:\n%s") % (self.path, value))
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
                log(_("inserted in %s after the line %d:\n%s\nthe line:\n%s") % (self.path, idx, lines[idx], s))
                lines.insert(idx+1, s)
                self.modified()
                matches = matches + 1
                if not all:
                    return matches
        if matches == 0 and at_end_if_not_found:
            log(_("appended in %s the line:\n%s") % (self.path, value))
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
                log(_("inserted in %s before the line %d:\n%s\nthe line:\n%s") % (self.path, idx, lines[idx], s))
                lines.insert(idx, s)
                self.modified()
                matches = matches + 1
                if not all:
                    return matches
        if matches == 0 and at_top_if_not_found:
            log(_("inserted at the top of %s the line:\n%s") % (self.path, value))
            lines.insert(0, value)
            self.modified()
            matches = matches + 1
        return matches

    def insert_at(self, idx, value):
        lines = self.get_lines()
        try:
            lines.insert(idx, value)
            log(_("inserted in %s at the line %d:\n%s") % (self.path, idx, value))
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
                log(_("removing in %s the line %d:\n%s") % (self.path, idx, lines[idx]))
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
        self.configfiles = ConfigFiles()
        self.no_aging_list = []

        # associate helper commands with files
        self.configfiles.add_config_assoc(INITTAB, '/sbin/telinit q')
        self.configfiles.add_config_assoc('/etc(?:/rc.d)?/init.d/(.+)', '[ -f /var/lock/subsys/@1 ] && @0 reload')
        self.configfiles.add_config_assoc(SYSCTLCONF, '/sbin/sysctl -e -p /etc/sysctl.conf')
        self.configfiles.add_config_assoc(SSHDCONFIG, '[ -f /var/lock/subsys/sshd ] && /etc/rc.d/init.d/sshd restart')
        self.configfiles.add_config_assoc(LILOCONF, '[ `/usr/sbin/detectloader` = LILO ] && /sbin/lilo')
        self.configfiles.add_config_assoc(SYSLOGCONF, '[ -f /var/lock/subsys/syslog ] && service syslog reload')
        self.configfiles.add_config_assoc('^/etc/issue$', '/usr/bin/killall mingetty')

    def create_server_link(self):
        '''  If SERVER_LEVEL (or SECURE_LEVEL if absent) is greater than 3
    in /etc/security/msec/security.conf, creates the symlink /etc/security/msec/server
    to point to /etc/security/msec/server.<SERVER_LEVEL>. The /etc/security/msec/server
    is used by chkconfig --add to decide to add a service if it is present in the file
    during the installation of packages.'''
        level = get_server_level()
        server = self.configfiles.get_config_file(SERVER)
        if level in ('0', '1', '2', '3'):
            self.log.info(_('Allowing chkconfig --add from rpm'))
            server.exists() and server.unlink()
        else:
            self.log.info(_('Restricting chkconfig --add from rpm'))
            server.symlink(SERVER + '.' + str(level))

    #create_server_link.arg_trans = YES_NO_TRANS

    # helper function for set_root_umask and set_user_umask
    def set_umask(self, variable, umask, msg):
        'D'
        msec = self.configfiles.get_config_file(MSEC)

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
            self.log.info(_('Setting %s umask to %s') % (msg, umask))
            msec.set_shell_variable(variable, umask)

    def set_root_umask(self, umask):
        '''  Set the root umask.'''
        self.set_umask('UMASK_ROOT', umask, 'root')

    def set_user_umask(self, umask):
        '''  Set the user umask.'''
        self.set_umask('UMASK_USER', umask, 'users')

    ################################################################################

    # the listen_tcp argument is kept for backward compatibility
    def allow_x_connections(self, arg, listen_tcp=None):
        '''  Allow/Forbid X connections. First arg specifies what is done
    on the client side: ALL (all connections are allowed), LOCAL (only
    local connection) and NONE (no connection).'''

        msec = self.configfiles.get_config_file(MSEC_XINIT)

        val = msec.exists() and msec.get_match('/usr/bin/xhost\s*\+\s*([^#]*)')

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
                self.log.info(_('Allowing users to connect X server from everywhere'))
                msec.exists() and msec.replace_line_matching('/usr/bin/xhost', '/usr/bin/xhost +', 1)
        elif arg == LOCAL:
            if val != arg:
                self.log.info(_('Allowing users to connect X server from localhost'))
                msec.exists() and msec.replace_line_matching('/usr/bin/xhost', '/usr/bin/xhost + localhost', 1)
        elif arg == NONE:
            if val != arg:
                self.log.info(_('Restricting X server connection to the console user'))
                msec.exists() and msec.remove_line_matching('/usr/bin/xhost', 1)
        else:
            error(_('invalid allow_x_connections arg: %s') % arg)
            return

    #allow_x_connections.arg_trans=ALL_LOCAL_NONE_TRANS
    #allow_x_connections.one_arg = 1

    ################################################################################

    def allow_xserver_to_listen(self, arg):
        '''  The argument specifies if clients are authorized to connect
    to the X server on the tcp port 6000 or not.'''

        startx = self.configfiles.get_config_file(STARTX)
        xservers = self.configfiles.get_config_file(XSERVERS)
        gdmconf = self.configfiles.get_config_file(GDMCONF)
        kdmrc = self.configfiles.get_config_file(KDMRC)

        val_startx = startx.exists() and startx.get_match(STARTX_REGEXP)
        val_xservers = xservers.exists() and xservers.get_match(XSERVERS_REGEXP)
        val_gdmconf = gdmconf.exists() and gdmconf.get_match(GDMCONF_REGEXP)
        str = kdmrc.exists() and kdmrc.get_shell_variable('ServerArgsLocal', 'X-\*-Core', '^\s*$')

        if str:
            val_kdmrc = KDMRC_REGEXP.search(str)
        else:
            val_kdmrc = None

        # don't lower security when not changing security level
        if same_level():
            if val_startx and val_xservers and val_gdmconf and val_kdmrc:
                return

        if arg:
            if val_startx or val_xservers or val_gdmconf or val_kdmrc:
                self.log.info(_('Allowing the X server to listen to tcp connections'))
                if not (same_level() and val_startx):
                    startx.exists() and startx.replace_line_matching(STARTX_REGEXP, '@1@2')
                if not (same_level() and val_xservers):
                    xservers.exists() and xservers.replace_line_matching(XSERVERS_REGEXP, '@1@2', 0, 1)
                if not (same_level() and val_gdmconf):
                    gdmconf.exists() and gdmconf.replace_line_matching(GDMCONF_REGEXP, '@1@2', 0, 1)
                if not (same_level() and val_kdmrc):
                    kdmrc.exists() and kdmrc.replace_line_matching('^(ServerArgsLocal=.*?)-nolisten tcp(.*)$', '@1@2', 0, 0, 'X-\*-Core', '^\s*$')
        else:
            if not val_startx or not val_xservers or not val_gdmconf or not val_kdmrc:
                self.log.info(_('Forbidding the X server to listen to tcp connection'))
                startx.exists() and not val_startx and startx.replace_line_matching('serverargs="(.*?)( -nolisten tcp)?"', 'serverargs="@1 -nolisten tcp"')
                xservers.exists() and not val_xservers and xservers.replace_line_matching('(\s*[^#]+/usr/bin/X .*?)( -nolisten tcp)?$', '@1 -nolisten tcp', 0, 1)
                gdmconf.exists() and not val_gdmconf and gdmconf.replace_line_matching('(\s*command=.*/X.*?)( -nolisten tcp)?$', '@1 -nolisten tcp', 0, 1)
                kdmrc.exists() and not val_kdmrc and kdmrc.replace_line_matching('^(ServerArgsLocal=.*)( -nolisten tcp)?$', '@1 -nolisten tcp', 'ServerArgsLocal=-nolisten tcp', 0, 'X-\*-Core', '^\s*$')

    #allow_xserver_to_listen.arg_trans = YES_NO_TRANS

    def set_shell_timeout(self, val):
        '''  Set the shell timeout. A value of zero means no timeout.'''

        msec = self.configfiles.get_config_file(MSEC)

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
            self.log.info(_('Setting shell timeout to %s') % val)
            msec.set_shell_variable('TMOUT', val)

    def set_shell_history_size(self, size):
        '''  Set shell commands history size. A value of -1 means unlimited.'''
        msec = self.configfiles.get_config_file(MSEC)

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
                self.log.info(_('Setting shell history size to %s') % size)
                msec.set_shell_variable('HISTFILESIZE', size)
        else:
            if val != None:
                self.log.info(_('Removing limit on shell history size'))
                msec.remove_line_matching('^HISTFILESIZE=')

    def set_win_parts_umask(self, umask):
        '''  Set umask option for mounting vfat and ntfs partitions. A value of None means default umask.'''
        fstab = self.configfiles.get_config_file(FSTAB)

        # don't lower security when not changing security level
        if same_level():
            if umask != None:
                return

        if umask == None:
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+)umask=\d+(\s.*)", "@1defaults@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+)umask=\d+,(.*)", "@1@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+\S+),umask=\d+(.*)", "@1@3", 0, 1)
        else:
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+\S*)umask=\d+(.*)", "@1umask=0@3", 0, 1)
            fstab.replace_line_matching("(.*\s(vfat|ntfs)\s+)(?!.*umask=)(\S+)(.*)", "@1@3,umask=0@4", 0, 1)

    def allow_reboot(self, arg):
        '''  Allow/Forbid reboot by the console user.'''
        shutdownallow = self.configfiles.get_config_file(SHUTDOWNALLOW)
        sysctlconf = self.configfiles.get_config_file(SYSCTLCONF)
        kdmrc = self.configfiles.get_config_file(KDMRC)
        gdmconf = self.configfiles.get_config_file(GDMCONF)
        inittab = self.configfiles.get_config_file(INITTAB)

        val_shutdownallow = shutdownallow.exists()
        val_sysctlconf = sysctlconf.exists() and sysctlconf.get_shell_variable('kernel.sysrq')
        val_inittab = inittab.exists() and inittab.get_match(CTRALTDEL_REGEXP)
        num = 0
        val = {}
        for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
            val[f] = self.configfiles.get_config_file(f).exists()
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
            self.log.info(_('Allowing reboot to the console user'))
            if not (same_level() and val_shutdownallow):
                shutdownallow.exists() and shutdownallow.move(SUFFIX)
            for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
                cfg = self.configfiles.get_config_file(f)
                if not (same_level() and not val[f]):
                    cfg.exists() or cfg.symlink(CONSOLE_HELPER)
            if not (same_level() and val_sysctlconf == '0'):
                sysctlconf.set_shell_variable('kernel.sysrq', 1)
            if not same_level() and val_gdmconf == 'false':
                gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'true', '\[greeter\]', '^\s*$')
            if not (same_level() and not val_inittab):
                inittab.replace_line_matching(CTRALTDEL_REGEXP, 'ca::ctrlaltdel:/sbin/shutdown -t3 -r now', 1)
        else:
            self.log.info(_('Forbidding reboot to the console user'))
            self.configfiles.get_config_file(SHUTDOWNALLOW, SUFFIX).touch()
            for f in [SHUTDOWN, POWEROFF, REBOOT, HALT]:
                self.configfiles.get_config_file(f).unlink()
            sysctlconf.set_shell_variable('kernel.sysrq', 0)
            gdmconf.exists() and gdmconf.set_shell_variable('SystemMenu', 'false', '\[greeter\]', '^\s*$')
            inittab.remove_line_matching(CTRALTDEL_REGEXP)

        kdmrc.exists() and kdmrc.set_shell_variable('AllowShutdown', ALLOW_SHUTDOWN_VALUES[val_kdmrc], 'X-:\*-Core', '^\s*$')

    #allow_reboot.arg_trans = YES_NO_TRANS

    def allow_user_list(self, arg):
        '''  Allow/Forbid the list of users on the system on display managers (kdm and gdm).'''
        kdmrc = self.configfiles.get_config_file(KDMRC)
        gdmconf = self.configfiles.get_config_file(GDMCONF)

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
            val_kdmrc = 1
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
            self.log.info(_(msg))
            oldval_kdmrc != val_gdmconf and kdmrc.exists() and kdmrc.set_shell_variable('ShowUsers', SHOW_USERS_VALUES[val_kdmrc], 'X-\*-Greeter', '^\s*$')
            oldval_gdmconf != val_gdmconf and gdmconf.exists() and gdmconf.set_shell_variable('Browser', val_gdmconf)

    #allow_user_list.arg_trans = YES_NO_TRANS

    def allow_root_login(self, arg):
        '''  Allow/Forbid direct root login.'''
        securetty = self.configfiles.get_config_file(SECURETTY)
        kde = self.configfiles.get_config_file(KDE)
        gdm = self.configfiles.get_config_file(GDM)
        gdmconf = self.configfiles.get_config_file(GDMCONF)
        xdm = self.configfiles.get_config_file(XDM)

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
                self.log.info(_('Allowing direct root login'))
                gdmconf.exists() and gdmconf.set_shell_variable('ConfigAvailable', 'true', '\[greeter\]', '^\s*')

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
            gdmconf.exists() and gdmconf.set_shell_variable('ConfigAvailable', 'false', '\[greeter\]', '^\s*')
            if (kde.exists() and not val[kde]) or (gdm.exists() and not val[gdm]) or (xdm.exists() and not val[xdm]) or num > 0:
                self.log.info(_('Forbidding direct root login'))

                bastillenologin = self.configfiles.get_config_file(BASTILLENOLOGIN)
                bastillenologin.replace_line_matching('^\s*root', 'root', 1)

                for cnf in (kde, gdm, xdm):
                    cnf.exists() and (cnf.replace_line_matching('^auth\s*required\s*(?:/lib/security/)?pam_listfile.so.*bastille-no-login', 'auth required pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login') or \
                                      cnf.insert_at(0, 'auth required pam_listfile.so onerr=succeed item=user sense=deny file=/etc/bastille-no-login'))
                securetty.remove_line_matching('.+', 1)

    #allow_root_login.arg_trans = YES_NO_TRANS

    def allow_remote_root_login(self, arg):
        '''  Allow/Forbid remote root login via sshd. You can specify
    yes, no and without-password. See sshd_config(5) man page for more
    information.'''
        sshd_config = self.configfiles.get_config_file(SSHDCONFIG)

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

    #allow_remote_root_login.arg_trans = ALLOW_ROOT_LOGIN_TRANS

    def enable_pam_wheel_for_su(self, arg):
        '''   Enabling su only from members of the wheel group or allow su from any user.'''
        su = self.configfiles.get_config_file(SU)

        val = su.exists() and su.get_match('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$')

        # don't lower security when not changing security level
        if same_level():
            if val:
                return

        if arg:
            if not val:
                self.log.info(_('Allowing su only from wheel group members'))
                try:
                    ent = grp.getgrnam('wheel')
                except KeyError:
                    error(_('no wheel group'))
                    return
                members = ent[3]
                if members == [] or members == ['root']:
                    _interactive and error(_('wheel group is empty'))
                    return
                # TODO: fix
                su.exists() and (su.replace_line_matching('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$',
                                                          'auth       required     pam_wheel.so use_uid') or \
                                 su.insert_after('^auth\s+required',
                                                 'auth       required     pam_wheel.so use_uid'))
        else:
            if val:
                self.log.info(_('Allowing su for all'))
                su.exists() and su.remove_line_matching('^auth\s+required\s+(?:/lib/security/)?pam_wheel.so\s+use_uid\s*$')

    #enable_pam_wheel_for_su.arg_trans = YES_NO_TRANS

    def enable_pam_root_from_wheel(self, arg):
        '''   Allow root access without password for the members of the wheel group.'''
        su = self.configfiles.get_config_file(SU)
        simple = self.configfiles.get_config_file(SIMPLE_ROOT_AUTHEN)

        if not su.exists():
            return

        val = su.get_match(SUCCEED_MATCH)

        if simple.exists():
            val_simple = simple.get_match(SUCCEED_MATCH)
        else:
            val_simple = False

        # don't lower security when not changing security level
        if same_level():
            if not val and not val_simple:
                return

        if arg:
            if not val or (simple.exists() and not val_simple):
                self.log.info(_('Allowing transparent root access for wheel group members'))
                if not val:
                    su.insert_before('^auth\s+required', SUCCEED_LINE)
                if simple.exists() and not val_simple:
                    simple.insert_before('^auth\s+required', SUCCEED_LINE)
        else:
            if val or (simple.exists() and val_simple):
                self.log.info(_('Disabling transparent root access for wheel group members'))
                if val:
                    su.remove_line_matching(SUCCEED_MATCH)
                if simple.exists() and val_simple:
                    simple.remove_line_matching(SUCCEED_MATCH)

    # enable_pam_root_from_wheel.arg_trans = YES_NO_TRANS

    def allow_issues(self, arg):
        '''  If \\fIarg\\fP = ALL allow /etc/issue and /etc/issue.net to exist. If \\fIarg\\fP = NONE no issues are
    allowed else only /etc/issue is allowed.'''
        issue = self.configfiles.get_config_file(ISSUE, SUFFIX)
        issuenet = self.configfiles.get_config_file(ISSUENET, SUFFIX)

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
                self.log.info(_('Allowing network pre-login messages'))
                issue.exists() and issue.get_lines()
                issuenet.exists() and issuenet.get_lines()
        else:
            if arg == NONE:
                if val:
                    self.log.info(_('Disabling pre-login message'))
                    issue.exists(1) and issue.move(SUFFIX) and issue.modified()
            else:
                if not val:
                    self.log.info(_('Allowing pre-login message'))
                    issue.exists() and issue.get_lines()
            if valnet:
                self.log.info(_('Disabling network pre-login message'))
                issuenet.exists(1) and issuenet.move(SUFFIX)

    # allow_issues.arg_trans = ALL_LOCAL_NONE_TRANS

    def allow_autologin(self, arg):
        '''  Allow/Forbid autologin.'''
        autologin = self.configfiles.get_config_file(AUTOLOGIN)

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
                self.log.info(_('Allowing autologin'))
                autologin.exists() and autologin.set_shell_variable('AUTOLOGIN', 'yes')
        else:
            if val != 'no':
                self.log.info(_('Forbidding autologin'))
                autologin.exists() and autologin.set_shell_variable('AUTOLOGIN', 'no')

    # allow_autologin.arg_trans = YES_NO_TRANS

    def password_loader(self, value):
        'D'
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
        'D'
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
                self.log.info(_('Enabling log on console'))
                syslogconf.exists() and syslogconf.replace_line_matching('\s*[^#]+/dev/', expr + ' /dev/' + dev, 1)
        else:
            if val != None:
                self.log.info(_('Disabling log on console'))
                syslogconf.exists() and syslogconf.remove_line_matching('\s*[^#]+/dev/')

    enable_console_log.arg_trans = YES_NO_TRANS

    def enable_promisc_check(self, arg):
        '''  Activate/Disable ethernet cards promiscuity check.'''
        cron = self.configfiles.get_config_file(CRON)

        val = cron.exists() and cron.get_match(CRON_REGEX)

        # don't lower security when not changing security level
        if same_level():
            if val == CRON_ENTRY:
                return

        if arg:
            if val != CRON_ENTRY:
                self.log.info(_('Activating periodic promiscuity check'))
                cron.replace_line_matching(CRON_REGEX, CRON_ENTRY, 1)
        else:
            if val:
                self.log.info(_('Disabling periodic promiscuity check'))
                cron.remove_line_matching('[^#]+/usr/share/msec/promisc_check.sh')

    #enable_promisc_check.arg_trans = YES_NO_TRANS

    def enable_security_check(self, arg):
        '''   Activate/Disable daily security check.'''
        cron = self.configfiles.get_config_file(CRON)
        cron.remove_line_matching('[^#]+/usr/share/msec/security.sh')

        securitycron = self.configfiles.get_config_file(SECURITYCRON)

        val = securitycron.exists()

        # don't lower security when not changing security level
        if same_level():
            if val:
                return

        if arg:
            if not val:
                self.log.info(_('Activating daily security check'))
                securitycron.symlink(SECURITYSH)
        else:
            if val:
                self.log.info(_('Disabling daily security check'))
                securitycron.unlink()

    #enable_security_check.arg_trans = YES_NO_TRANS

    def authorize_services(self, arg):
        '''  Authorize all services controlled by tcp_wrappers (see hosts.deny(5)) if \\fIarg\\fP = ALL. Only local ones
    if \\fIarg\\fP = LOCAL and none if \\fIarg\\fP = NONE. To authorize the services you need, use /etc/hosts.allow
    (see hosts.allow(5)).'''
        hostsdeny = self.configfiles.get_config_file(HOSTSDENY)

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
                self.log.info(_('Authorizing all services'))
                hostsdeny.remove_line_matching(ALL_REGEXP, 1)
                hostsdeny.remove_line_matching(ALL_LOCAL_REGEXP, 1)
        elif arg == NONE:
            if arg != val:
                self.log.info(_('Disabling all services'))
                hostsdeny.remove_line_matching('^ALL:ALL EXCEPT 127\.0\.0\.1:DENY', 1)
                hostsdeny.replace_line_matching('^ALL:ALL:DENY', 'ALL:ALL:DENY', 1)
        elif arg == LOCAL:
            if arg != val:
                self.log.info(_('Disabling non local services'))
                hostsdeny.remove_line_matching(ALL_REGEXP, 1)
                hostsdeny.replace_line_matching(ALL_LOCAL_REGEXP, 'ALL:ALL EXCEPT 127.0.0.1:DENY', 1)
        else:
            error(_('authorize_services invalid argument: %s') % arg)

    # authorize_services.arg_trans = ALL_LOCAL_NONE_TRANS

    def set_zero_one_variable(self, file, variable, value, secure_value, one_msg, zero_msg):
        # helper function for enable_ip_spoofing_protection, accept_icmp_echo, accept_broadcasted_icmp_echo,
        # accept_bogus_error_responses and enable_log_strange_packets.
        'D'
        f = self.configfiles.get_config_file(file)

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

            self.log.info(msg)
            f.set_shell_variable(variable, boolean2bit(value))

    def enable_ip_spoofing_protection(self, arg, alert=1):
        '''  Enable/Disable IP spoofing protection.'''
        # the alert argument is kept for backward compatibility
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.conf.all.rp_filter', arg, 1, 'Enabling ip spoofing protection', 'Disabling ip spoofing protection')

    #enable_ip_spoofing_protection.arg_trans = YES_NO_TRANS
    #enable_ip_spoofing_protection.one_arg = 1

    def enable_dns_spoofing_protection(self, arg, alert=1):
        '''  Enable/Disable name resolution spoofing protection.  If
    \\fIalert\\fP is true, also reports to syslog.'''
        hostconf = self.configfiles.get_config_file(HOSTCONF)

        val = hostconf.exists() and hostconf.get_match('nospoof\s+on')

        # don't lower security when not changing security level
        if same_level():
            if val:
                return

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

    #enable_dns_spoofing_protection.arg_trans = YES_NO_TRANS

    def accept_icmp_echo(self, arg):
        '''   Accept/Refuse icmp echo.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_echo_ignore_all', not arg, 1, 'Ignoring icmp echo', 'Accepting icmp echo')

    #accept_icmp_echo.arg_trans = YES_NO_TRANS

    def accept_broadcasted_icmp_echo(self, arg):
        '''   Accept/Refuse broadcasted icmp echo.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_echo_ignore_broadcasts', not arg, 1, 'Ignoring broadcasted icmp echo', 'Accepting broadcasted icmp echo')

    #accept_broadcasted_icmp_echo.arg_trans = YES_NO_TRANS

    def accept_bogus_error_responses(self, arg):
        '''  Accept/Refuse bogus IPv4 error messages.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.icmp_ignore_bogus_error_responses', not arg, 1, 'Ignoring bogus icmp error responses', 'Accepting bogus icmp error responses')

    #accept_bogus_error_responses.arg_trans = YES_NO_TRANS

    def enable_log_strange_packets(self, arg):
        '''  Enable/Disable the logging of IPv4 strange packets.'''
        self.set_zero_one_variable(SYSCTLCONF, 'net.ipv4.conf.all.log_martians', arg, 1, 'Enabling logging of strange packets', 'Disabling logging of strange packets')

    #enable_log_strange_packets.arg_trans = YES_NO_TRANS

    def password_length(self, length, ndigits=0, nupper=0):
        '''  Set the password minimum length and minimum number of digit and minimum number of capitalized letters.'''

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

    # TODO: remove this, too dangerous
    def enable_password(self, arg):
        '''  Use password to authenticate users.'''
        system_auth = self.configfiles.get_config_file(SYSTEM_AUTH)

        val = system_auth.exists() and system_auth.get_match(PASSWORD_REGEXP)

        # don't lower security when not changing security level
        if same_level():
            if not val:
                return

        if arg:
            if val:
                self.log.info(_('Using password to authenticate users'))
                system_auth.remove_line_matching(PASSWORD_REGEXP)
        else:
            if not val:
                self.log.info(_('Don\'t use password to authenticate users'))
                system_auth.replace_line_matching(PASSWORD_REGEXP, 'auth        sufficient    pam_permit.so') or \
                system_auth.insert_before('auth\s+sufficient', 'auth        sufficient    pam_permit.so')

    #enable_password.arg_trans = YES_NO_TRANS

    def password_history(self, arg):
        '''  Set the password history length to prevent password reuse.'''
        system_auth = self.configfiles.get_config_file(SYSTEM_AUTH)

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
                self.log.info(_('Setting password history to %d.') % arg)
                system_auth.replace_line_matching(UNIX_REGEXP, '@1 remember=%d@3' % arg) or \
                system_auth.replace_line_matching('(^\s*password\s+sufficient\s+(?:/lib/security/)?pam_unix.so.*)', '@1 remember=%d' % arg)
                opasswd = self.configfiles.get_config_file(OPASSWD)
                opasswd.exists() or opasswd.touch()
            else:
                self.log.info(_('Disabling password history'))
                system_auth.replace_line_matching(UNIX_REGEXP, '@1@3')

    def enable_sulogin(self, arg):
        '''   Enable/Disable sulogin(8) in single user level.'''
        inittab = self.configfiles.get_config_file(INITTAB)

        val = inittab.exists() and inittab.get_match(SULOGIN_REGEXP)

        # don't lower security when not changing security level
        if same_level():
            if val:
                return

        if arg:
            if not val:
                self.log.info(_('Enabling sulogin in single user runlevel'))
                inittab.replace_line_matching('[^#]+:S:', '~~:S:wait:/sbin/sulogin', 1)
        else:
            if val:
                self.log.info(_('Disabling sulogin in single user runlevel'))
                inittab.remove_line_matching('~~:S:wait:/sbin/sulogin')

    # enable_sulogin.arg_trans = YES_NO_TRANS

    def enable_msec_cron(self, arg):
        '''  Enable/Disable msec hourly security check.'''
        mseccron = self.configfiles.get_config_file(MSECCRON)

        val = mseccron.exists()

        # don't lower security when not changing security level
        if same_level():
            if val:
                return

        if arg:
            if arg != val:
                self.log.info(_('Enabling msec periodic runs'))
                mseccron.symlink(MSECBIN)
        else:
            if arg != val:
                self.log.info(_('Disabling msec periodic runs'))
                mseccron.unlink()

    # enable_msec_cron.arg_trans = YES_NO_TRANS

    def enable_at_crontab(self, arg):
        '''  Enable/Disable crontab and at for users. Put allowed users in /etc/cron.allow and /etc/at.allow
    (see man at(1) and crontab(1)).'''
        cronallow = self.configfiles.get_config_file(CRONALLOW)
        atallow = self.configfiles.get_config_file(ATALLOW)

        val_cronallow = cronallow.exists() and cronallow.get_match('root')
        val_atallow = atallow.exists() and atallow.get_match('root')

        # don't lower security when not changing security level
        if same_level():
            if val_cronallow and val_atallow:
                return

        if arg:
            if val_cronallow or val_atallow:
                self.log.info(_('Enabling crontab and at'))
                if not (same_level() and val_cronallow):
                    cronallow.exists() and cronallow.move(SUFFIX)
                if not (same_level() and val_atallow):
                    atallow.exists() and atallow.move(SUFFIX)
        else:
            if not val_cronallow or not val_atallow:
                self.log.info(_('Disabling crontab and at'))
                cronallow.replace_line_matching('root', 'root', 1)
                atallow.replace_line_matching('root', 'root', 1)

    #enable_at_crontab.arg_trans = YES_NO_TRANS

    def no_password_aging_for(self, name):
        '''D Add the name as an exception to the handling of password aging by msec.
    Name must be put between '. Msec will then no more manage password aging for
    name so you have to use chage(1) to manage it by hand.'''
        self.no_aging_list.append(name)

    def password_aging(self, max, inactive=-1):
        '''  Set password aging to \\fImax\\fP days and delay to change to \\fIinactive\\fP.'''
        uid_min = 500
        self.log.info(_('Setting password maximum aging for new user to %d') % max)
        logindefs = self.configfiles.get_config_file(LOGINDEFS)
        if logindefs.exists():
            logindefs.replace_line_matching('^\s*PASS_MAX_DAYS', 'PASS_MAX_DAYS ' + str(max), 1)
            uid_min = logindefs.get_match('^\s*UID_MIN\s+([0-9]+)', '@1')
            if uid_min:
                uid_min = int(uid_min)
        shadow = self.configfiles.get_config_file(SHADOW)
        if shadow.exists():
            self.log.info(_('Setting password maximum aging for root and users with id greater than %d to %d and delay to %d days') % (uid_min, max, inactive))
            for line in shadow.get_lines():
                field = string.split(line, ':')
                if len(field) < 2:
                    continue
                name = field[0]
                password = field[1]
                if name in self.no_aging_list:
                    self.log.info(_('User %s in password aging exception list') % (name,))
                    continue
                try:
                    entry = pwd.getpwnam(name)
                except KeyError:
                    error(_('User %s in shadow but not in passwd file') % name)
                    continue
                if (len(password) > 0 and password[0] != '!') and password != '*' and password != 'x' and (entry[2] >= uid_min or entry[2] == 0):
                    if field[4] == '':
                        current_max = 99999
                    else:
                        current_max = int(field[4])
                    if field[6] == '':
                        current_inactive = -1
                    else:
                        current_inactive = int(field[6])
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
                        cmd = 'LC_ALL=C /usr/bin/chage -M %d -I %d -d %s \'%s\'' % (new_max, new_inactive, time.strftime('%Y-%m-%d'), entry[0])
                        ret = commands.getstatusoutput(cmd)
                        log(_('changed maximum password aging for user \'%s\' with command %s') % (entry[0], cmd))

    def allow_xauth_from_root(self, arg):
        ''' Allow/forbid to export display when passing from the root account
    to the other users. See pam_xauth(8) for more details.'''
        export = self.configfiles.get_config_file(EXPORT)

        allow = export.exists() and export.get_match('^\*$')

        # don't lower security when not changing security level
        if same_level():
            if not allow:
                return

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

    def check_security(self):
        pass

    def check_perms(self):
        pass

    def check_suid_root(self):
        pass

    def check_suid_md5(self):
        pass

    def check_sgid(self):
        pass

    def check_writable(self):
        pass

    def check_unowned(self):
        pass

    def check_promisc(self):
        pass

    def check_open_port(self):
        pass

    def check_passwd(self):
        pass

    def check_shadow(self):
        pass

    def check_chkrootkit(self):
        pass

    def check_rpm(self):
        pass

    def tty_warn(self):
        pass

    def mail_warn(self):
        pass

    def mail_empty_content(self):
        pass

    def syslog_warn(self):
        pass
# }}}

if __name__ == "__main__":
    # this should never ever be run directly
    print >>sys.stderr, """This file should not be run directly."""

