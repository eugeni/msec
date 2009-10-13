#!/usr/bin/python -O
"""This is the main msec module, responsible for all msec operations.

The following classes are defined here:

    ConfigFile: an individual config file. This class is responsible for
            configuration modification, variable searching and replacing,
            and so on.

    ConfigFiles: this file contains the entire set of modifications performed
            by msec, stored in list of ConfigFile instances. When required, all
            changes are commited back to physical files. This way, no real
            change occurs on the system until the msec app explicitly tells
            to do so.

    Log: logging class, that supports logging to terminal, a fixed log file,
            and syslog. A single log instance can be shared by all other
            classes.

    MSEC: main msec class. It contains the callback functions for all msec
            operations.

All configuration variables, and config file names are defined here as well.
"""

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
import glob

# logging
import logging
from logging.handlers import SysLogHandler

# configuration
import config

# localization
try:
    gettext.install('msec')
except IOError:
    _ = str

# ConfigFile constants
STRING_TYPE = type('')

BEFORE=0
INSIDE=1
AFTER=2

# regexps
space = re.compile('\s')

# {{{  helper functions
def move(old, new):
    """Renames files, deleting existent ones when necessary."""
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

# }}}

# {{{ Log
class Log:
    """Logging class. Logs to both syslog and log file"""
    def __init__(self,
                app_name="msec",
                log_syslog=True,
                log_file=True,
                log_level = logging.INFO,
                log_facility=SysLogHandler.LOG_AUTHPRIV,
                syslog_address="/dev/log",
                log_path="/var/log/msec.log",
                interactive=True,
                quiet=False):
        self.log_facility = log_facility
        self.log_path = log_path

        # buffer
        self.buffer = None

        # common logging stuff
        self.logger = logging.getLogger(app_name)

        self.quiet = quiet

        # syslog
        if log_syslog:
            try:
                self.syslog_h = SysLogHandler(facility=log_facility, address=syslog_address)
                formatter = logging.Formatter('%(name)s: %(levelname)s: %(message)s')
                self.syslog_h.setFormatter(formatter)
                self.logger.addHandler(self.syslog_h)
            except:
                print >>sys.stderr, "Logging to syslog not available: %s" % (sys.exc_value[1])
                interactive = True

        # log to file
        if log_file:
            try:
                self.file_h = logging.FileHandler(self.log_path)
                formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
                self.file_h.setFormatter(formatter)
                self.logger.addHandler(self.file_h)
            except:
                print >>sys.stderr, "Logging to '%s' not available: %s" % (self.log_path, sys.exc_value[1])
                interactive = True

        # interactive logging
        if interactive:
            self.interactive_h = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter('%(levelname)s: %(message)s')
            self.interactive_h.setFormatter(formatter)
            self.logger.addHandler(self.interactive_h)

        self.logger.setLevel(log_level)

    def trydecode(self, message):
        """Attempts to decode a unicode message"""
        try:
            msg = message.decode('UTF-*')
        except:
            msg = message
        return msg

    def info(self, message):
        """Informative message (normal msec operation)"""
        if self.quiet:
            # skip informative messages in quiet mode
            return
        message = self.trydecode(message)
        if self.buffer:
            self.buffer["info"].append(message)
        else:
            self.logger.info(message)

    def error(self, message):
        """Error message (security has changed: authentication, passwords, etc)"""
        message = self.trydecode(message)
        if self.buffer:
            self.buffer["error"].append(message)
        else:
            self.logger.error(message)

    def debug(self, message):
        """Debugging message"""
        message = self.trydecode(message)
        if self.buffer:
            self.buffer["debug"].append(message)
        else:
            self.logger.debug(message)

    def critical(self, message):
        """Critical message (big security risk, e.g., rootkit, etc)"""
        message = self.trydecode(message)
        if self.buffer:
            self.buffer["critical"].append(message)
        else:
            self.logger.critical(message)

    def warn(self, message):
        """Warning message (slight security change, permissions change, etc)"""
        if self.quiet:
            # skip warning messages in quiet mode
            return
        message = self.trydecode(message)
        if self.buffer:
            self.buffer["warn"].append(message)
        else:
            self.logger.warn(message)

    def start_buffer(self):
        """Beginns message buffering"""
        self.buffer = {"info": [], "error": [], "debug": [], "critical": [], "warn": []}

    def get_buffer(self):
        """Returns buffered messages"""
        messages = self.buffer.copy()
        del self.buffer
        self.buffer = None
        return messages

# }}}

# {{{ ConfigFiles - stores references to all configuration files
class ConfigFiles:
    """This class is responsible to store references to all configuration files,
        mark them as changed, and update on disk when necessary"""
    def __init__(self, log, root=''):
        """Initializes list of ConfigFiles"""
        self.files = {}
        self.modified_files = []
        self.action_assoc = []
        self.log = log
        self.root = root

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
            return ConfigFile(path, self, self.log, suffix=suffix, root=self.root)

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
            self.log.info("%s: %s" % (config.MODIFICATIONS_FOUND, " ".join(self.modified_files)))
        else:
            self.log.info(config.MODIFICATIONS_NOT_FOUND)

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
        self.modified()
        return self

    def symlink(self, link):
        self.sym_link = link
        self.modified()
        return self

    def exists(self):
        return os.path.lexists(self.path)
        #return os.path.exists(self.path) or (self.suffix and os.path.exists(self.path + self.suffix))

    def realpath(self):
        return os.path.realpath(self.path)

    def move(self, suffix):
        self.suffix = suffix
        self.is_moved = 1
        self.modified()

    def unlink(self):
        self.is_deleted = 1
        self.lines=[]
        self.modified()
        return self

    def is_link(self):
        '''Checks if file is a symlink and, if yes, returns the real path'''
        full = os.stat(self.path)
        if stat.S_ISLNK(full[stat.ST_MODE]):
            link = os.readlink(self.path)
        else:
            link = None
        return link

    def write(self):
        if self.is_deleted:
            if self.exists():
                try:
                    os.unlink(self.path)
                except:
                    error('unlink %s: %s' % (self.path, str(sys.exc_value)))
                self.log.info(_('deleted %s') % (self.path,))
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
        elif self.is_moved:
            move(self.path, self.path + self.suffix)
            self.log.info(_('moved file %s to %s') % (self.path, self.path + self.suffix))
            self.meta.modified(self.path)
        elif self.is_modified:
            content = string.join(self.lines, "\n")
            dirname = os.path.dirname(self.path)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            file = open(self.path, 'w')
            file.write(content)
            file.close()
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
            self.log.debug('WARNING: never found regexp %s in %s, not writing changes' % (start_regexp, self.path))
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
        self.log.debug(_('set variable %s to %s in %s') % (var, value, self.path,))
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
                    self.log.debug("replaced in %s the line %d:\n%s\nwith the line:\n%s" % (self.path, idx, line, s))
                    lines[idx] = s
                    self.modified()
                if not all:
                    return matches
        if matches == 0 and at_end_if_not_found:
            if type(at_end_if_not_found) == STRING_TYPE:
                value = at_end_if_not_found
            self.log.debug("appended in %s the line:\n%s" % (self.path, value))
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
                self.log.debug("inserted in %s after the line %d:\n%s\nthe line:\n%s" % (self.path, idx, lines[idx], s))
                lines.insert(idx+1, s)
                self.modified()
                matches = matches + 1
                if not all:
                    return matches
        if matches == 0 and at_end_if_not_found:
            self.log.debug("appended in %s the line:\n%s" % (self.path, value))
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
                self.log.debug("inserted in %s before the line %d:\n%s\nthe line:\n%s" % (self.path, idx, lines[idx], s))
                lines.insert(idx, s)
                self.modified()
                matches = matches + 1
                if not all:
                    return matches
        if matches == 0 and at_top_if_not_found:
            self.log.debug("inserted at the top of %s the line:\n%s" % (self.path, value))
            lines.insert(0, value)
            self.modified()
            matches = matches + 1
        return matches

    def insert_at(self, idx, value):
        lines = self.get_lines()
        try:
            lines.insert(idx, value)
            self.log.debug("inserted in %s at the line %d:\n%s" % (self.path, idx, value))
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
                self.log.debug("removing in %s the line %d:\n%s" % (self.path, idx, lines[idx]))
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
    def __init__(self, log, root='', plugins=config.PLUGINS_DIR):
        """Initializes config files and associations"""
        # all config files
        self.log = log
        self.root = root
        self.configfiles = ConfigFiles(log, root=root)

        # plugins
        self.init_plugins(plugins)

    def init_plugins(self, path=config.PLUGINS_DIR):
        """Loads msec plugins from path"""
        self.plugins = {}
        plugin_files = glob.glob("%s/*.py" % path)
        plugin_r = re.compile("plugins/(.*).py")
        sys.path.insert(0, path)
        for file in plugin_files:
            f = plugin_r.findall(file)
            if f:
                plugin_f = f[0]
                try:
                    plugin = __import__(plugin_f, fromlist=[path])
                    if not hasattr(plugin, "PLUGIN"):
                        # not a valid plugin
                        continue
                    self.log.debug("Loading plugin %s" % file)
                    plugin_name = getattr(plugin, "PLUGIN")
                    plugin_class = getattr(plugin, plugin_name)
                    plugin = plugin_class(log=self.log, configfiles=self.configfiles, root=self.root)
                    self.plugins[plugin_name] = plugin
                    self.log.debug("Loaded plugin '%s'" % plugin_f)
                except:
                    self.log.error(_("Error loading plugin '%s' from %s: %s") % (plugin_f, file, sys.exc_value))

    def reset(self):
        """Resets the configuration"""
        self.log.debug("Resetting msec data.")
        self.configfiles = ConfigFiles(self.log, root=self.root)
        # updating plugins
        for plugin in self.plugins:
            self.plugins[plugin].configfiles = self.configfiles

    def get_action(self, name):
        """Determines correspondent function for requested action."""
        # finding out what function to call
        try:
            plugin_, callback = name.split(".", 1)
        except:
            # bad format?
            self.log.error(_("Invalid callback: %s") % (name))
            return None
        # is it a main function or a plugin?
        if plugin_ == config.MAIN_LIB:
            plugin = self
        else:
            if plugin_ in self.plugins:
                plugin = self.plugins[plugin_]
            else:
                self.log.info(_("Plugin %s not found") % plugin_)
                return self.log.info
                return None
        try:
            func = getattr(plugin, callback)
            return func
        except:
            self.log.info(_("Not supported function '%s' in '%s'") % (callback, plugin))
            traceback.print_exc()
            return None

    def commit(self, really_commit=True):
        """Commits changes"""
        if not really_commit:
            self.log.info(_("In check-only mode, nothing is written back to disk."))
        self.configfiles.write_files(really_commit)

    def apply(self, curconfig):
        '''Applies configuration from a MsecConfig instance'''
        # first, reset previous msec data
        self.reset()
        # process all options
        for opt in curconfig.list_options():
            # Determines correspondent function
            action = None
            callback = config.find_callback(opt)
            valid_params = config.find_valid_params(opt)
            if callback:
                action = self.get_action(callback)
            if not action:
                # The required functionality is not supported
                self.log.debug("'%s' is not available in this version" % opt)
                continue
            self.log.debug("Processing action %s: %s(%s)" % (opt, callback, curconfig.get(opt)))
            # validating parameters
            param = curconfig.get(opt)
            # if param is None, this option is to be skipped
            if param == None:
                self.log.debug("Skipping %s" % opt)
                continue
            if param not in valid_params and '*' not in valid_params:
                self.log.error(_("Invalid parameter for %s: '%s'. Valid parameters: '%s'.") % (opt,
                            param, valid_params))
                continue
            action(curconfig.get(opt))

    def base_level(self, param):
        """Defines the base security level, on top of which the current configuration is based."""
        pass

# }}}

# {{{ PERMS - permissions handling
class PERMS:
    """Permission checking/enforcing."""
    def __init__(self, log, root=''):
        """Initializes internal variables"""
        self.log = log
        self.root = root
        self.USER = {}
        self.GROUP = {}
        self.USERID = {}
        self.GROUPID = {}
        self.files = {}
        self.fs_regexp = self.build_non_localfs_regexp()

    def get_user_id(self, name):
        '''Caches and retreives user id correspondent to name'''
        try:
            return self.USER[name]
        except KeyError:
            try:
                self.USER[name] = pwd.getpwnam(name)[2]
            except KeyError:
                error(_('user name %s not found') % name)
                self.USER[name] = -1
        return self.USER[name]

    def get_user_name(self, id):
        '''Caches and retreives user name correspondent to id'''
        try:
            return self.USERID[id]
        except KeyError:
            try:
                self.USERID[id] = pwd.getpwuid(id)[0]
            except KeyError:
                error(_('user name not found for id %d') % id)
                self.USERID[id] = str(id)
        return self.USERID[id]

    def get_group_id(self, name):
        '''Caches and retreives group id correspondent to name'''
        try:
            return self.GROUP[name]
        except KeyError:
            try:
                self.GROUP[name] = grp.getgrnam(name)[2]
            except KeyError:
                error(_('group name %s not found') % name)
                self.GROUP[name] = -1
        return self.GROUP[name]

    def get_group_name(self, id):
        '''Caches and retreives group name correspondent to id'''
        try:
            return self.GROUPID[id]
        except KeyError:
            try:
                self.GROUPID[id] = grp.getgrgid(id)[0]
            except KeyError:
                error(_('group name not found for id %d') % id)
                self.GROUPID[id] = str(id)
        return self.GROUPID[id]

    def build_non_localfs_regexp(self,
            non_localfs = ['nfs', 'codafs', 'smbfs', 'cifs', 'autofs']):
        """Build a regexp that matches all the non local filesystems"""
        try:
            file = open('/proc/mounts', 'r')
        except IOError:
            self.log.error(_('Unable to check /proc/mounts. Assuming all file systems are local.'))
            return None

        regexp = None

        for line in file.readlines():
            fields = string.split(line)
            if fields[2] in non_localfs:
                if regexp:
                    regexp = regexp + '|' + fields[1]
                else:
                    regexp = '^(' + fields[1]

        file.close()

        if not regexp:
            return None
        else:
            return re.compile(regexp + ')')

    def commit(self, really_commit=True, enforce=False):
        """Commits changes.
        If enforce is True, the permissions on all files are enforced."""
        if not really_commit:
            self.log.info(_("In check-only mode, nothing is written back to disk."))

        if len(self.files) > 0:
            self.log.info("%s: %s" % (config.MODIFICATIONS_FOUND, " ".join(self.files)))
        else:
            self.log.info(config.MODIFICATIONS_NOT_FOUND)

        for file in self.files:
            newperm, newuser, newgroup, force = self.files[file]
            # are we in enforcing mode?
            if enforce:
                force = True

            if newuser != None:
                if force and really_commit:
                    self.log.warn(_("Forcing ownership of %s to %s") % (file, self.get_user_name(newuser)))
                    try:
                        os.chown(file, newuser, -1)
                    except:
                        self.log.error(_("Error changing user on %s: %s") % (file, sys.exc_value))
                else:
                    self.log.warn(_("Wrong owner of %s: should be %s") % (file, self.get_user_name(newuser)))
            if newgroup != None:
                if force and really_commit:
                    self.log.warn(_("Enforcing group on %s to %s") % (file, self.get_group_name(newgroup)))
                    try:
                        os.chown(file, -1, newgroup)
                    except:
                        self.log.error(_("Error changing group on %s: %s") % (file, sys.exc_value))
                else:
                    self.log.warn(_("Wrong group of %s: should be %s") % (file, self.get_group_name(newgroup)))
            # permissions should be last, as chown resets them
            # on suid files
            if newperm != None:
                if force and really_commit:
                    self.log.warn(_("Enforcing permissions on %s to %o") % (file, newperm))
                    try:
                        os.chmod(file, newperm)
                    except:
                        self.log.error(_("Error changing permissions on %s: %s") % (file, sys.exc_value))
                else:
                    self.log.warn(_("Wrong permissions of %s: should be %o") % (file, newperm))


    def check_perms(self, perms, files_to_check=[]):
        '''Checks permissions for all entries in perms (PermConfig).
        If files_to_check is specified, only the specified files are checked.'''

        for file in perms.list_options():
            user_s, group_s, perm_s, force = perms.get(file)

            # permission
            if perm_s == 'current':
                perm = -1
            else:
                try:
                    perm = int(perm_s, 8)
                except ValueError:
                    self.log.error(_("bad permissions for '%s': '%s'") % (file, perm_s))
                    continue

            # user
            if user_s == 'current':
                user = -1
            else:
                user = self.get_user_id(user_s)

            # group
            if group_s == 'current':
                group = -1
            else:
                group = self.get_group_id(group_s)

            # now check the permissions
            for f in glob.glob('%s%s' % (self.root, file)):
                # get file properties
                f = os.path.realpath(f)
                try:
                    full = os.lstat(f)
                except OSError:
                    continue

                if self.fs_regexp and self.fs_regexp.search(f):
                    self.log.info(_('Non local file: "%s". Nothing changed.') % fields[0])
                    continue

                curperm = perm
                mode = stat.S_IMODE(full[stat.ST_MODE])

                if perm != -1 and stat.S_ISDIR(full[stat.ST_MODE]):
                    if curperm & 0400:
                        curperm = curperm | 0100
                    if curperm & 0040:
                        curperm = curperm | 0010
                    if curperm & 0004:
                        curperm = curperm | 0001

                curuser = full[stat.ST_UID]
                curgroup = full[stat.ST_GID]
                curperm = mode
                # checking for subdirectory permissions
                if f != '/' and f[-1] == '/':
                    f = f[:-1]
                if f[-2:] == '/.':
                    f = f[:-2]
                # check for changes
                newperm = None
                newuser = None
                newgroup = None
                if perm != -1 and perm != curperm:
                    newperm = perm
                if user != -1 and user != curuser:
                    newuser = user
                if group != -1 and group != curgroup:
                    newgroup = group
                if newperm != None or newuser != None or newgroup != None:
                    self.files[f] = (newperm, newuser, newgroup, force)
                    self.log.debug("Updating %s (matched by '%s')" % (f, file))
                else:
                    # see if any other rule put this file into the list
                    if f in self.files:
                        self.log.debug("Removing previously selected %s (matched by '%s')" % (f, file))
                        del self.files[f]
        # do we have to check for any specific paths?
        if files_to_check:
            self.log.info(_("Checking paths: %s") % ", ".join(files_to_check))
            paths_to_check = []
            for f in files_to_check:
                paths_to_check.extend(glob.glob(f))
            paths_to_check = set(paths_to_check)
            # remove unneeded entries from self.files
            for f in self.files.keys():
                if f not in paths_to_check:
                    del self.files[f]
        return self.files
# }}}

if __name__ == "__main__":
    # this should never ever be run directly
    print >>sys.stderr, """This file should not be run directly."""

