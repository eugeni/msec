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

# Log in append only mode
chattr +a /var/log/*

# All events logged on tty12
AddRules "*.* /dev/tty12" /etc/syslog.conf

# Prevent all kind of connection except from localhost
AddRules "ALL:ALL EXCEPT localhost:DENY" /etc/hosts.deny

# Login as root on the console allowed :
AddRules "tty1" /etc/securetty
AddRules "tty2" /etc/securetty
AddRules "tty3" /etc/securetty
AddRules "tty4" /etc/securetty
AddRules "tty5" /etc/securetty
AddRules "tty6" /etc/securetty

# Suid check
AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf
AddRules "CHECK_SUID_GROUP=yes" /etc/security/msec/security.conf
AddRules "CHECK_WRITABLE=yes" /etc/security/msec/security.conf
AddRules "CHECK_UNOWNED=yes" /etc/security/msec/security.conf
AddRules "CHECK_PROMISC=yes" /etc/security/msec/security.conf
AddRules "TTY_WARN=yes" /etc/security/msec/security.conf
AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf

# Check every 1 minutes for promisc problem
AddRules "*/1 * * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/promisc_check.sh" /etc/crontab
AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab

# Do you want a password ?
LiloUpdate;
/sbin/lilo

# Permissions 
AddRules "umask 022" /etc/profile

# Path

if [ ${HAVE_X}==1 ]; then
    AddRules "PATH=$PATH:/usr/X11R6/bin" /etc/profile
fi










