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

# All events logged on tty12
AddRules "*.* /dev/tty12" /etc/syslog.conf

# login as root from the console allowed
AddRules "tty1" /etc/securetty
AddRules "tty2" /etc/securetty
AddRules "tty3" /etc/securetty
AddRules "tty4" /etc/securetty
AddRules "tty5" /etc/securetty
AddRules "tty6" /etc/securetty

# Suid Check
AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf
AddRules "CHECK_SUID_GROUP=yes" /etc/security/msec/security.conf
AddRules "CHECK_WRITABLE=yes" /etc/security/msec/security.conf
AddRules "CHECK_UNOWNED=yes" /etc/security/msec/security.conf
AddRules "CHECK_PROMISC=no" /etc/security/msec/security.conf
AddRules "TTY_WARN=no" /etc/security/msec/security.conf
AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf

# Crontab
AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab


# Permissions
AddRules "umask 022" /etc/profile

/sbin/lilo


# Path
if [ ${HAVE_X}==1 ]; then
    AddRules "PATH=$PATH:/usr/X11R6/bin" /etc/profile
fi













