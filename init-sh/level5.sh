#!/bin/bash

#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

if [ -f /etc/security/msec/init-sh/lib.sh ]; then
    . /etc/security/msec/init-sh/lib.sh
fi

echo -e "Changing attribute of /var/log/* to append only...\n"
chattr +a /var/log/*

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

################ Crontab things ###################
# Check every 1 minutes for promisc problem 
echo "Adding promisc check in crontab (scheduled every minutes) :"
AddRules "*/1 * * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/promisc_check.sh" /etc/crontab

echo "Adding permission check in crontab (schedued every midnight) :"
AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/file_check.sh" /etc/crontab
###################################################

# Wanna a password ?
LiloUpdate;

echo -n "Running lilo to record new config : "
/sbin/lilo >& /dev/null
echo -e "done.\n"

# Disable all server :
echo "Setting secure level variable to 5 :"
AddRules "SECURE_LEVEL=5" /etc/profile
IFS="
"

export SECURE_LEVEL=5
echo -n "Disabling all service, except : {"
for service in `chkconfig --list | awk '{print $1}'`; do
	if grep -qx ${service} /etc/security/msec/init-sh/server.5; then
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
echo "Setting umask to 077 (u=rw) :"
AddRules "umask 077" /etc/profile 
echo "Adding \"normal\" PATH variable :"
AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games" /etc/profile quiet
AddRules "export PATH SECURE_LEVEL" /etc/profile

echo
echo "You are now running your system in security level 5,"
echo "All services are disabled : try the chkconfig to enable one..."
echo "If you're on a senssible machine, ( which is probably the case )"
echo "you should compile the server from the sources".
echo
echo "Good luck. :-)"
echo



















