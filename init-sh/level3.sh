#!/bin/bash

#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

if [[ -f /etc/security/msec/init-sh/lib.sh ]]; then
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

# Security check
echo "Updating file check variable : "
echo -e "\t- Check security : yes."
    AddRules "CHECK_SECURITY=yes" /etc/security/msec/security.conf      quiet
echo -e "\t- Check important permissions : yes."
    AddRules "CHECK_PERMS=yes" /etc/security/msec/security.conf         quiet          
echo -e "\t- Check suid root file : yes."
    AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf 	quiet
echo -e "\t- Check suid root file integrity (backdoor check) : yes."
    AddRules "CHECK_SUID_MD5=yes" /etc/security/msec/security.conf 	quiet
echo -e "\t- Check suid group file : yes."
    AddRules "CHECK_SUID_GROUP=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check world writable file : yes."
    AddRules "CHECK_WRITEABLE=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check unowned file : no."
    AddRules "CHECK_UNOWNED=no" /etc/security/msec/security.conf	quiet
echo -e "\t- Check promiscuous mode : no."
    AddRules "CHECK_PROMISC=no" /etc/security/msec/security.conf       quiet
echo -e "\t- Check listening port : yes."                               
    AddRules "CHECK_OPEN_PORT=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check passwd file integrity : yes."
    AddRules "CHECK_PASSWD=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check shadow file integrity : yes."
    AddRules "CHECK_SHADOW=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Security warning on tty : yes."
    AddRules "TTY_WARN=no" /etc/security/msec/security.conf	        quiet
echo -e "\t- Security warning by mail : yes."
    AddRules "MAIL_WARN=yes" /etc/security/msec/security.conf       quiet
    AddRules "MAIL_USER=root" /etc/security/msec/security.conf      quiet
echo -e "\t- Security warning in syslog : yes."			
    AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf		
# end security check

# Crontab
echo "Adding permission check in crontab (scheduled every midnight) :"
AddRules "0 0 * * *    root    /etc/security/msec/cron-sh/security.sh" /etc/crontab

# lilo update
echo -n "Running lilo to record new config : "
/sbin/lilo >& /dev/null
echo -e "done.\n"

# /etc/profile
export SECURE_LEVEL=3
echo "Setting secure level variable to 3 :"
AddRules "SECURE_LEVEL=3" /etc/profile
echo "Setting umask to 022 (u=rw,g=r,o=r) :"
AddRules "umask 022" /etc/profile
echo "Adding a \"normal\" PATH variable : "
AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games" /etc/profile quiet
AddRules "export PATH SECURE_LEVEL" /etc/profile

# Do not boot on a shell
echo -n "Setting up inittab to authorize any user to issue ctrl-alt-del : "
tmpfile=`mktemp /tmp/secure.XXXXXX`
cp /etc/inittab ${tmpfile}
cat ${tmpfile} | \
    sed s'/\/bin\/bash --login/\/sbin\/mingetty tty1/' | \
    sed s'/ca::ctrlaltdel:\/sbin\/shutdown -a -t3 -r now/ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now/' > /etc/inittab
rm -f ${tmpfile}
echo "done."


# Group were modified in lib.sh...
grpconv
