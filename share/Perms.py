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
from Log import *
import gettext

try:
    cat = gettext.Catalog('msec')
    _ = cat.gettext
except IOError:
    _ = str

comment_regex = re.compile('^\s*#|^\s*$')

user = {}
group = {}
userid = {}
groupid = {}

def get_user_id(name):
    try:
        return user[name]
    except KeyError:
        try:
            user[name] = pwd.getpwnam(name)[2]
        except KeyError:
            error(_('user name %s not found') % name)
            user[name] = -1
    return user[name]

def get_user_name(id):
    try:
        return userid[id]
    except KeyError:
        try:
            userid[id] = pwd.getpwuid(id)[0]
        except KeyError:
            error(_('user name not found for id %d') % id)
            userid[id] = str(id)
    return userid[id]

def get_group_id(name):
    try:
        return group[name]
    except KeyError:
        try:
            group[name] = grp.getgrnam(name)[2]
        except KeyError:
            error(_('group name %s not found') % name)
            group[name] = -1
    return group[name]

def get_group_name(id):
    try:
        return groupid[id]
    except KeyError:
        try:
            groupid[id] = grp.getgrgid(id)[0]
        except KeyError:
            error(_('group name not found for id %d') % id)
            groupid[id] = str(id)
    return groupid[id]

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
        newmode = int(fields[2], 8)
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

def act():
    for f in assoc.keys():
        (mode, uid, gid, newperm, user, group, user_str, group_str) = assoc[f]
        #print f, (mode, uid, gid, newperm, user, group)
        if mode != newperm:
            log(_('changed mode of %s from %o to %o') % (f, mode, newperm))
            os.chmod(f, newperm)
        if user != -1:
            if user != uid:
                log(_('changed owner of %s from %s to %s') % (f, get_user_name(uid), user_str))
                os.chown(f, user, -1)
        if group != -1:
            if group != gid:
                log(_('changed group of %s from %s to %s') % (f, get_group_name(gid), group_str))
                os.chown(f, -1, group)

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
        os.chmod(f, newperm)
    return 1

if __name__ == '__main__':
    import sys

    initlog('msec')
    
    for p in sys.argv[1:]:
        fix_perms(p)

    act()
    
# Perms.py ends here
