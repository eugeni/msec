#!/bin/bash

#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

if [[ -f /usr/share/msec/lib.sh ]]; then
    . /usr/share/msec/lib.sh
else
    echo "Can't find /usr/share/msec/lib.sh, exiting."
    exit 1
fi

echo -e "Changing attribute of /var/log/* to append only...\n"

# All events logged on tty12
echo "Loging all messages on tty12 : "
AddRules "*.* /dev/tty12" /etc/syslog.conf

# Prevent all kind of connection
echo "Denying all kind of connection : "
AddRules "ALL:ALL:DENY" /etc/hosts.deny

# No login as root
echo "Login as root is denied : "
echo "Modified file : /etc/securetty..."
echo -e "done.\n\n"

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
echo -e "\t- Check unowned file : yes."
    AddRules "CHECK_UNOWNED=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check promiscuous mode : yes."
    AddRules "CHECK_PROMISC=yes" /etc/security/msec/security.conf       quiet
echo -e "\t- Check listening port : yes."                               
    AddRules "CHECK_OPEN_PORT=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check passwd file integrity : yes."
    AddRules "CHECK_PASSWD=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check shadow file integrity : yes."
    AddRules "CHECK_SHADOW=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Security warning on tty : yes."
    AddRules "TTY_WARN=yes" /etc/security/msec/security.conf	        quiet
echo -e "\t- Security warning by mail : yes."
    AddRules "MAIL_WARN=yes" /etc/security/msec/security.conf       quiet
	AddRules "MAIL_USER=root" /etc/security/msec/security.conf		quiet
echo -e "\t- Security warning in syslog : yes."			
    AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf		
# end security check

################ Crontab things ###################
# Check every 1 minutes for promisc problem 
echo "Adding promisc check in crontab (scheduled every minutes) :"
AddRules "*/1 * * * *    root    /usr/share/msec/promisc_check.sh" /etc/crontab

echo "Adding \"diff\" & \"global\" security check in crontab (scheduled every midnight) :"
AddRules "0 4 * * *    root    /usr/share/msec/security.sh" /etc/crontab

###################################################

# setup BSD accounting.

echo "Setting up BSD process accounting..." 
if [[ -f /sbin/accton ]]; then
    AddRules "touch /var/log/security/pacct.log" /etc/rc.d/rc.local
    AddRules "/sbin/accton /var/log/security/pacct.log" /etc/rc.d/rc.local
    AddRules "/var/log/security/pacct.log {" /etc/logrotate.conf
    AddRules "    postrotate" /etc/logrotate.conf
    AddRules "    /sbin/accton /var/log/security/pacct.log" /etc/logrotate.conf
    AddRules "   }" /etc/logrotate.conf
    touch /var/log/security/pacct.log
    chown root.root /var/log/security/pacct.log
    chmod 600 /var/log/security/pacct.log
    /sbin/accton /var/log/security/pacct.log
fi

# Wanna password ?
LoaderUpdate;

# Disable all server :
echo "Setting secure level variable to 5 :"
AddRules "export SECURE_LEVEL=5" /etc/profile.d/msec.sh
AddRules "setenv SECURE_LEVEL 5" /etc/profile.d/msec.csh


IFS="
"

export SECURE_LEVEL=5
echo -n "Disabling all service, except : {"
for service in `chkconfig --list | awk '{print $1}'`; do
	if grep -qx ${service} /etc/security/msec/server.5; then
		echo -n " ${service}"
	fi
done
echo " } : "

for service in `chkconfig --list | awk '{print $1}'`; do
    chkconfig --del "${service}"
	if ! chkconfig --msec --add "${service}"; then
		echo -e "\t- Services ${service} scheduled to be disabled at next boot."
	fi
done
echo -e "done.\n";

# /etc/profile.d/msec.{sh,csh}
echo "Setting umask to 077 (u=rw) :"
AddRules "UMASK_ROOT=077" /etc/sysconfig/msec
AddRules "UMASK_USER=077" /etc/sysconfig/msec

if [[ -f /lib/libsafe.so.2]]; then
    echo "Enabling stack overflow protection :"
    AddRules "/lib/libsafe.so.2" /etc/ld.so.preload
fi

# Do not boot on a shell
ForbidReboot
ForbidAutologin

echo
echo "You are now running your system in security level 5,"
echo "All services are disabled : try the chkconfig to enable one..."
echo "If you're on a senssible machine, ( which is probably the case )"
echo "you should compile the server from the sources".
echo
echo "In order to launch X in this security level,"
echo "you need to add your user to the \"xgrp\" group..." 
echo "Use : usermod -G xgrp username"
echo

# Group were modified in lib.sh...
grpconv

ForbidUserList
RootSshLogin 5
