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
echo "Loging all messages on tty12 : "
AddRules "*.* /dev/tty12" /etc/syslog.conf

# login as root from the console allowed
echo "Login as root is allowed (on the console) : "
AddRules "tty1" /etc/securetty
AddRules "tty2" /etc/securetty quiet
AddRules "tty3" /etc/securetty quiet
AddRules "tty4" /etc/securetty quiet
AddRules "tty5" /etc/securetty quiet
AddRules "tty6" /etc/securetty quiet

# /
echo "Updating file check variable : "
echo -e "\t- Check suid root file : yes."
AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf quiet
echo -e "\t- Check suid goup file : yes."
AddRules "CHECK_SUID_GROUP=yes" /etc/security/msec/security.conf quiet
echo -e "\t- Check world writable file : yes."
AddRules "CHECK_WRITABLE=yes" /etc/security/msec/security.conf quiet
echo -e "\t- Check unowned file : yes."
AddRules "CHECK_UNOWNED=yes" /etc/security/msec/security.conf quiet
echo -e "\t- Check promiscuous mode : \"no\" :"
AddRules "CHECK_PROMISC=no" /etc/security/msec/security.conf quiet
echo -e "\t- Security warning on tty : \"no\" :"
AddRules "TTY_WARN=no" /etc/security/msec/security.conf quiet
echo -e "\t- Security warning on syslog : \"yes\" :"
AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf

# Crontab
echo "Adding permission check in crontab (scheduled every midnight) :"
AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab

echo -n "Running lilo to record new config : "
/sbin/lilo >& /dev/null
echo -e "done.\n"

# /etc/profile
echo "Setting secure level variable to 3 :"
AddRules "SECURE_LEVEL=3" /etc/profile
echo "Setting umask to 022 (user = rw, group = r, o = r) :"
AddRules "umask 022" /etc/profile
echo "Adding a \"normal\" PATH variable : "
AddRules "PATH=\$PATH:/usr/X11R6/bin" /etc/profile

