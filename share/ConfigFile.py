#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : msec
# File            : ConfigFile.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Wed Dec  5 21:42:49 2001
# Purpose         : class abstraction to handle configuration
#                   files.
#---------------------------------------------------------------

import re
import string
import os
import stat
import Config
import commands
from Log import *
import gettext

try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

BEFORE=0
INSIDE=1
AFTER=2

space = re.compile('\s')

class ConfigFiles:
    def __init__(self):
        self.files = {}
        self.modified_files = []
        self.action_assoc = []

    def add(self, file, path):
        self.files[path] = file

    def modified(self, path):
        if not path in self.modified_files:
            self.modified_files.append(path)

    def get_config_file(self, path, suffix):
        try:
            return self.files[path]
        except KeyError:
            return ConfigFile(path, suffix, self)

    def add_config_assoc(self, regex, action):
        self.action_assoc.append((re.compile(regex), action))

all_files=ConfigFiles()

def move(old, new):
    try:
        os.unlink(new)
    except OSError:
        pass
    try:
        os.rename(old, new)
    except:
        error('rename %s %s: %s' % (old, new, str(sys.exc_value)))

class ConfigFile:
    def __init__(self, path, suffix=None, meta=all_files):
        self.meta=meta
        self.path = Config.get_config('root', '') + path
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
            mkdir_p(self.path)
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
    
# utility funtions

def substitute_re_result(res, s):
    for idx in range(0, (res.lastindex or 0) + 1):
        subst = res.group(idx) or ''
        s = string.replace(s, '@' + str(idx), subst)
    return s

def write_files():
    global all_files

    run_commands = Config.get_config('run_commands', 0)
    for f in all_files.files.values():
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
                    
def get_config_file(path, suffix=None):
    global all_files

    return all_files.get_config_file(path, suffix)

def add_config_assoc(regex, action):
    global all_files

    return all_files.add_config_assoc(regex, action)

def mkdir_p(path):
    s = os.stat(path)
    if not s:
        os.makedirs(os.path.dirname(path))
    
# ConfigFile.py ends here
