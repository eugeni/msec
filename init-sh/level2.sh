#!/bin/bash

#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

if [ -f /etc/security/msec/init-sh/lib.sh ]; then
    . /etc/security/msec/init-sh/lib.sh
else
    exit 1
fi

# login as root on console granted...
AddRules "tty1" /etc/securetty
AddRules "tty2" /etc/securetty
AddRules "tty3" /etc/securetty
AddRules "tty4" /etc/securetty
AddRules "tty5" /etc/securetty
AddRules "tty6" /etc/securetty

# Suid Check
AddRules "CHECK_SUID=yes" /etc/security/msec/security.conf
AddRules "CHECK_PROMISC=no" /etc/security/msec/security.conf
AddRules "TTY_WARN=no" /etc/security/msec/security.conf
AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf

# Permissions
AddRules "umask 002" /etc/profile
AddRules "SECURE_LEVEL=2" /etc/profile
# Group
usermod -G audio ${USERNAME} >& /dev/null

# For X auth :
xhost + localhost 2>&1 >& /dev/null

# lilo update
/sbin/lilo

# Path
AddRules "PATH=\$PATH:/usr/X11R6/bin" /etc/profile












