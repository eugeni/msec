#!/usr/bin/python -O
#---------------------------------------------------------------
# Project         : Mandrake Linux
# Module          : msec
# File            : Perms.py
# Version         : $Id$
# Author          : Frederic Lepied
# Created On      : Fri Dec  7 23:33:49 2001
# Purpose         : fix permissions and owner/group of files
#                   and directories.
#---------------------------------------------------------------

import glob
import re
import string
import os
import stat
import pwd
import grp
import Config
import sys
from Log import *
import gettext

try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

comment_regex = re.compile('^\s*#|^\s*$')

USER = {}
GROUP = {}
USERID = {}
GROUPID = {}

def get_user_id(name):
    try:
        return USER[name]
    except KeyError:
        try:
            USER[name] = pwd.getpwnam(name)[2]
        except KeyError:
            error(_('user name %s not found') % name)
            USER[name] = -1
    return USER[name]

def get_user_name(id):
    try:
        return USERID[id]
    except KeyError:
        try:
            USERID[id] = pwd.getpwuid(id)[0]
        except KeyError:
            error(_('user name not found for id %d') % id)
            USERID[id] = str(id)
    return USERID[id]

def get_group_id(name):
    try:
        return GROUP[name]
    except KeyError:
        try:
            GROUP[name] = grp.getgrnam(name)[2]
        except KeyError:
            error(_('group name %s not found') % name)
            GROUP[name] = -1
    return GROUP[name]

def get_group_name(id):
    try:
        return GROUPID[id]
    except KeyError:
        try:
            GROUPID[id] = grp.getgrgid(id)[0]
        except KeyError:
            error(_('group name not found for id %d') % id)
            GROUPID[id] = str(id)
    return GROUPID[id]

assoc = {}

def fix_perms(path):
    try:
        file = open(path, 'r')
    except IOError:
        return
    root = Config.get_config('root', '')
    lineno = 0
    for line in file.readlines():
        lineno = lineno + 1
        
        if comment_regex.search(line):
            continue

        fields = re.split('\s*', line)
        mode_str = fields[2]
        
        if mode_str == 'current':
            newmode = -1
        else:
            newmode = int(mode_str, 8)
        
        if fields[1] == 'current':
            user = group = -1
            user_str = group_str = ''
        else:
            (user_str, group_str) = string.split(fields[1], '.')
            user = get_user_id(user_str)
            group = get_group_id(group_str)
        
        if len(fields) == 4:
            for f in glob.glob(fields[0]):
                try:
                    full = os.stat(f)
                except OSError:
                    continue
                mode = stat.S_IMODE(full[stat.ST_MODE])
                newperm = newmode
                if stat.S_ISDIR(full[stat.ST_MODE]):
                    if newperm & 0400:
                        newperm = newperm | 0100
                    if newperm & 0040:
                        newperm = newperm | 0010
                    if newperm & 0004:
                        newperm = newperm | 0001
                uid = full[stat.ST_UID]
                gid = full[stat.ST_GID]
                if f != '/' and f[-1] == '/':
                    f = f[:-1]
                if f[-2:] == '/.':
                    f = f[:-2]
                assoc[f] = (mode, uid, gid, newperm, user, group, user_str, group_str)
        else:
            error(_('invalid syntax in %s line %d') % (path, lineno))
    file.close()

def act(change):
    for f in assoc.keys():
        (mode, uid, gid, newperm, user, group, user_str, group_str) = assoc[f]
        # if we don't change the security level, try not to lower the security
        # if the user has changed it manually
        if not change:
            newperm = newperm & mode
        #print f, (mode, uid, gid, newperm, user, group)
        if newperm != -1 and mode != newperm:
            log(_('changed mode of %s from %o to %o') % (f, mode, newperm))
            try:
                os.chmod(f, newperm)
            except:
                error('chmod %s %o: %s' % (f, newperm, str(sys.exc_value)))
        if user != -1 and user != uid:
            log(_('changed owner of %s from %s to %s') % (f, get_user_name(uid), user_str))
            try:
                os.chown(f, user, -1)
            except:
                error('chown %s %s: %s' % (f, user, str(sys.exc_value)))
        if group != -1 and group != gid:
            log(_('changed group of %s from %s to %s') % (f, get_group_name(gid), group_str))
            try:
                os.chown(f, -1, group)
            except:
                error('chgrp %s %s: %s' % (f, group, str(sys.exc_value)))

def chmod(f, newperm):
    try:
        full = os.stat(f)
    except OSError:
        return 0
    mode = stat.S_IMODE(full[stat.ST_MODE])
    if stat.S_ISDIR(full[stat.ST_MODE]):
        if newperm & 0400:
            newperm = newperm | 0100
        if newperm & 0040:
            newperm = newperm | 0010
        if newperm & 0004:
            newperm = newperm | 0001
    if mode != newperm:
        log(_('changed mode of %s from %o to %o') % (f, mode, newperm))
        try:
            os.chmod(f, newperm)
        except:
            error('chmod %s %o: %s' % (f, newperm, str(sys.exc_value)))
    return 1

if __name__ == '__main__':
    import getopt
    
    _interactive = sys.stdin.isatty()
    change = 0
    
    # process the options
    try:
        (opt, args) = getopt.getopt(sys.argv[1:], 'co:',
                                    ['change', 'option'])
    except getopt.error:
        error(_('Invalid option. Use %s (-o var=<val>...) ([0-5])') % sys.argv[0])
        sys.exit(1)

    for o in opt:
        if o[0] == '-o' or o[0] == '--option':
            pair = string.split(o[1], '=')
            if len(pair) != 2:
                error(_('Invalid option format %s %s: use -o var=<val>') % (o[0], o[1]))
                sys.exit(1)
            else:
                Config.set_config(pair[0], pair[1])
        elif o[0] == '-c' or o[0] == '--change':
            change = 1
            
    # initlog must be done after processing the option because we can change
    # the way to report log with options...
    if _interactive:
        import syslog
        
        initlog('msec', syslog.LOG_LOCAL1)
    else:
        initlog('msec')
        
    _interactive and log(_('Fixing owners and permissions of files and directories'))
    
    # process the files
    for p in args:
        _interactive and log(_('Reading data from %s') % p)
        fix_perms(p)

    # do the modifications
    act(change)
    
# Perms.py ends here
