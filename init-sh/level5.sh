#!/bin/bash

#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

if [ -f /etc/security/msec/init-sh/lib.sh ]; then
    . /etc/security/msec/init-sh/lib.sh
fi

chattr +a /var/log/*

# All events logged on tty12
AddRules "*.* /dev/tty12" /etc/syslog.conf

# Prevent all kind of connection
AddRules "ALL:ALL:DENY" /etc/hosts.deny

# No login as root
AddRules "" /etc/securetty

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


# Wanna a password ?
LiloUpdate;
/sbin/lilo

# Disable all server :
AddRules "SECURE_LEVEL=5" /etc/profile
IFS="
"

export SECURE_LEVEL=5
for service in `chkconfig --list | awk '{print $1}'`; do
    chkconfig --del "${service}"
	chkconfig --msec --add "${service}"
done

# Permissions
AddRules "umask 077" /etc/profile 

# Path
AddRules "PATH=\$PATH:/usr/X11R6/bin" /etc/profile

echo
echo "You are now running your system in security level 5,"
echo "All services are disabled : try the chkconfig to enable one..."
echo "If you're on a senssible machine, ( which is probably the case )"
echo "you should compile the server from the sources".
echo
echo "Good luck. :-)"
echo



















