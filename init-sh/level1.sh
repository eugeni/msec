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
echo "Login as root is granted :"
AddRules "tty1" /etc/securetty quiet
AddRules "tty2" /etc/securetty quiet
AddRules "tty3" /etc/securetty quiet
AddRules "tty4" /etc/securetty quiet
AddRules "tty5" /etc/securetty quiet
AddRules "tty6" /etc/securetty

# Suid Check
echo "Updating file check variable :"
echo -e "\t- Check suid root file : no."
AddRules "CHECK_SUID_ROOT=no" /etc/security/msec/security.conf quiet
echo -e "\t- Check suid goup file : no."
AddRules "CHECK_SUID_GROUP=no" /etc/security/msec/security.conf quiet
echo -e "\t- Check world writable file : no."
AddRules "CHECK_WRITABLE=no" /etc/security/msec/security.conf quiet
echo -e "\t- Check unowned file : no."
AddRules "CHECK_UNOWNED=no" /etc/security/msec/security.conf quiet
echo -e "\t- Check promiscuous mode : no."
AddRules "CHECK_PROMISC=no" /etc/security/msec/security.conf quiet
echo -e "\t- Security warning on tty : no."
AddRules "TTY_WARN=no" /etc/security/msec/security.conf quiet
echo -e "\t- Security warning in syslog : yes."
AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf

# lilo update
echo -n "Running lilo to record new config : "
/sbin/lilo >& /dev/null
echo -e "done.\n"

# /etc/profile
echo "Setting secure level variable to 1 :"
AddRules "SECURE_LEVEL=1" /etc/profile
echo "Setting umask to 002 (user = rw, group = rw, o = r) :"
AddRules "umask 002" /etc/profile
echo "Adding \"non secure\" PATH variable :"
AddRules "PATH=\$PATH:/usr/X11R6/bin:." /etc/profile

# Group
echo "Adding \"${USERNAME} to audio group :"
usermod -G audio "${USERNAME}"
