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

# login as root on console granted...
echo "Login as root is granted :"
AddRules "tty1" /etc/securetty quiet
AddRules "tty2" /etc/securetty quiet
AddRules "tty3" /etc/securetty quiet
AddRules "tty4" /etc/securetty quiet
AddRules "tty5" /etc/securetty quiet
AddRules "tty6" /etc/securetty 

# Security check
echo "Updating file check variable : "
echo -e "\t- Check security : yes."
    AddRules "CHECK_SECURITY=yes" /etc/security/msec/security.conf      quiet
echo -e "\t- Check important permissions : no."
    AddRules "CHECK_PERMS=no" /etc/security/msec/security.conf          quiet          
echo -e "\t- Check suid root file : yes."
    AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf 	quiet
echo -e "\t- Check suid root file integrity (backdoor check) : yes."
    AddRules "CHECK_SUID_MD5=yes" /etc/security/msec/security.conf 	quiet
echo -e "\t- Check suid group file : yes."
    AddRules "CHECK_SUID_GROUP=no" /etc/security/msec/security.conf	quiet
echo -e "\t- Check world writable file : yes."
    AddRules "CHECK_WRITEABLE=yes" /etc/security/msec/security.conf	quiet
echo -e "\t- Check unowned file : no."
    AddRules "CHECK_UNOWNED=no" /etc/security/msec/security.conf	quiet
echo -e "\t- Check promiscuous mode : no."
    AddRules "CHECK_PROMISC=no" /etc/security/msec/security.conf        quiet
echo -e "\t- Check listening port : no."                               
    AddRules "CHECK_OPEN_PORT=no" /etc/security/msec/security.conf	quiet
echo -e "\t- Check passwd file integrity : no."
    AddRules "CHECK_PASSWD=no" /etc/security/msec/security.conf	        quiet
echo -e "\t- Check shadow file integrity : no."
    AddRules "CHECK_SHADOW=no" /etc/security/msec/security.conf	        quiet
echo -e "\t- Security warning on tty : no."
    AddRules "TTY_WARN=no" /etc/security/msec/security.conf	        quiet
echo -e "\t- Security warning in syslog : yes."			
    AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf		
# end security check

# lilo update
echo -n "Running lilo to record new config : "
/sbin/lilo
echo -e "done.\n"

# /etc/profile
export SECURE_LEVEL=2
echo "Setting secure level variable to 2 :"
AddRules "SECURE_LEVEL=2" /etc/profile
echo "Setting umask to 022 (u=rw,g=r,o=r) :"
AddRules "umask 022" /etc/profile
echo "Adding \"normal\" PATH variable :"
AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games" /etc/profile quiet
AddRules "export PATH SECURE_LEVEL" /etc/profile

# Xserver
echo "Allowing users to connect X server from localhost :"
AddBegRules "/usr/X11R6/bin/xhost + localhost" /etc/X11/xdm/Xsession quiet
AddBegRules "/usr/X11R6/bin/xhost + localhost" /etc/X11/xinit/xinitrc

# Group
if [[ ! -z ${DRAKX_USERS} ]]; then
    echo -n "Adding \"${DRAKX_USERS}\" to audio group :"
    for user in ${DRAKX_USERS}; do
	usermod -G audio "${user}"
    done
    echo "done."
fi

