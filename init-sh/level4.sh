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
echo -e "Changing attribute of /var/log/* to append only...\n"
chattr +a /var/log/*

# All events logged on tty12
echo "Loging all messages on tty12 : "
AddRules "*.* /dev/tty12" /etc/syslog.conf

# Prevent all kind of connection except from localhost
echo "Denying all kind of connection except localhost : "
AddRules "ALL:ALL EXCEPT localhost:DENY" /etc/hosts.deny

# Login as root on the console allowed :
echo "Denying login as root (except on the console) :"
AddRules "tty1" /etc/securetty quiet
AddRules "tty2" /etc/securetty quiet
AddRules "tty3" /etc/securetty quiet
AddRules "tty4" /etc/securetty quiet
AddRules "tty5" /etc/securetty quiet
AddRules "tty6" /etc/securetty 

# Security check
echo "Updating file check variable : "
echo -e "\t- Check suid root file : yes."
    AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf 	quiet
echo -e "\t- Check suid root file integrity (backdoor check) : yes."
    AddRules "CHECK_SUID_MD5=yes" /etc/security/msec/security.conf 	quiet
echo -e "\t- Check suid group file : yes."
    AddRules "CHECK_SUID_GROUP=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check world writable file : yes."
    AddRules "CHECK_WRITABLE=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check unowned file : yes."
    AddRules "CHECK_UNOWNED=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check promiscuous mode : yes."
    AddRules "CHECK_PROMISC=yes" /etc/security/msec/security.conf       quiet
echo -e "\t- Check listening port : yes."                               
    AddRules "CHECK_OPEN_PORT=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check for dangerous .[sr]hosts file : yes."                               
    AddRules "CHECK_RHOST=yes" /etc/security/msec/security.conf	        quiet
echo -e "\t- Check passwd file integrity : yes."
    AddRules "CHECK_PASSWD=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check shadow file integrity : yes."
    AddRules "CHECK_SHADOW=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Security warning on tty : \"yes\" :"
    AddRules "TTY_WARN=yes" /etc/security/msec/security.conf	        quiet
echo -e "\t- Security warning in syslog : \"yes\" :"			
    AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf		
# end security check

# Check every 1 minutes for promisc problem
echo "Adding promisc check in crontab (scheduled every minutes) :"
AddRules "*/1 * * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/promisc_check.sh" /etc/crontab

echo "Adding permission check in crontab (scheduled every midnight) :"
AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab

# Do you want a password ?
LiloUpdate;
echo -n "Running lilo to record new config : "
/sbin/lilo >& /dev/null
echo -e "done.\n"

# Server update
echo "Setting secure level variable to 4 :"
AddRules "SECURE_LEVEL=4" /etc/profile
export SECURE_LEVEL=4

echo -n "Disabling all service, except : {"
for service in `chkconfig --list | awk '{print $1}'`; do
    if grep -qx ${service} /etc/security/msec/init-sh/server.4; then
        echo -n " ${service}"
    fi
done
echo " } : "

for service in `chkconfig --list | awk '{print $1}'`; do
    chkconfig --del "${service}"
    if ! chkconfig --msec --add "${service}"; then
        echo -e "\t- Services ${service} is now disabled."
    fi
done
echo -e "done.\n";

# /etc/profile
echo "Setting umask to 022 (u=rw,g=rx) for root, 077 (u=rw) for user :"
AddRules "if [ ${UID} == 0 ]; then umask 022; else umask 077; fi" /etc/profile
echo "Adding \"normal\" PATH variable :"
AddRules "PATH=\$PATH:/usr/X11R6/bin" /etc/profile quiet
AddRules "export PATH SECURE_LEVEL" /etc/profile