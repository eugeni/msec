#!/bin/bash

#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

if [ -f /etc/security/msec/init-sh/lib.sh ]; then
    . /etc/security/msec/init-sh/lib.sh
fi


clear

###
echo "Do you want your log file to be in append mode only ?"
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    find /var/log/ -type f -exec chattr +a {} \;
fi
###
echo "Do you want all system events to be logged on tty12 ?"
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    AddRules "*.* /dev/tty12" /etc/syslog.conf
fi
###
echo "Do you want to deny any machine to connect to yours ?"
WaitAnswer
if [ ${answer} == "yes" ]; then
    echo "Do you want only localhost to be allowed ?"
    WaitAnswer; clear
    if [ "${answer}" == "yes" ]; then
	AddRules "ALL:ALL EXCEPT localhost:DENY" /etc/hosts.deny
    else
	AddRules "ALL:ALL:DENY" /etc/hosts.deny
    fi
fi
###
echo "Do you want root console login to be allowed ?" 
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    AddRules "tty1" /etc/securetty quiet
    AddRules "tty2" /etc/securetty quiet
    AddRules "tty3" /etc/securetty quiet
    AddRules "tty4" /etc/securetty quiet
    AddRules "tty5" /etc/securetty quiet
    AddRules "tty6" /etc/securetty 
fi
###
echo "Do you want your system to daily check SUID Root file change ?"
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab
fi
###
echo "Do you want your system to daily check SUID Group file change ?"
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    AddRules "CHECK_SUID_GROUP=yes" /etc/security/msec/security.conf
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab
fi
###
echo "Do you want your system to daily check Writable file change ?"
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    AddRules "CHECK_WRITABLE=yes" /etc/security/msec/security.conf
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab
fi
###
echo "Do you want your system to daily check Unowned file change ?"
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    AddRules "CHECK_UNOWNED=yes" /etc/security/msec/security.conf
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab
fi
###
echo "Do you want your system to verify every minutes if a network interface"
echo "is in promiscuous state (which mean someone is probably running a sniffer on your machine ) ?"
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    AddRules "CHECK_PROMISC=yes" /etc/security/msec/security.conf
    AddRules "*/1 * * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/promisc_check.sh" /etc/crontab
fi
###
LiloUpdate;
/sbin/lilo >& /dev/null
###
echo "Do you want a "." in your PATH variable ?"
echo "This permit you to not use ./progname & to just type progname"
echo "However this is a *high* security risk."
WaitAnswer; clear
if [ ${answer} == "yes" ]; then
    AddRules "PATH=\$PATH:/usr/X11R6/bin" /etc/profile
fi
###
AddRules "SECURE_LEVEL=\"custom\"" /etc/profile
export SECURE_LEVEL="custom"
###
AddRules "umask 077" /etc/profile









