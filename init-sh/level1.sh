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

# Security check
echo "Updating file check variable : "
echo -e "\t- Check security : yes."
    AddRules "CHECK_SECURITY=yes" /etc/security/msec/security.conf      quiet
echo -e "\t- Check important permissions : no."
    AddRules "CHECK_PERMS=no" /etc/security/msec/security.conf          quiet             
echo -e "\t- Check suid root file : no."
    AddRules "CHECK_SUID_ROOT=no" /etc/security/msec/security.conf 	quiet
echo -e "\t- Check suid root file integrity (backdoor check) : no."
    AddRules "CHECK_SUID_MD5=no" /etc/security/msec/security.conf 	quiet
echo -e "\t- Check suid group file : no."
    AddRules "CHECK_SUID_GROUP=no" /etc/security/msec/security.conf	quiet
echo -e "\t- Check world writable file : no."
    AddRules "CHECK_WRITEABLE=no" /etc/security/msec/security.conf	quiet
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
echo -e "\t- Security warning on tty : \"no\" :"
    AddRules "TTY_WARN=no" /etc/security/msec/security.conf	        quiet
echo -e "\t- Security warning in syslog : \"no\" :"			
    AddRules "SYSLOG_WARN=no" /etc/security/msec/security.conf		
# end security check

# lilo update
echo -n "Running lilo to record new config : "
/sbin/lilo >& /dev/null
echo -e "done.\n"

# /etc/profile
export SECURE_LEVEL=1
echo "Setting secure level variable to 1 :"
AddRules "SECURE_LEVEL=1" /etc/profile
echo "Setting umask to 002 (u=rw,g=rw,o=r) :"
AddRules "umask 002" /etc/profile
echo "Adding \"non secure\" PATH variable :"
AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games:." /etc/profile quiet
AddRules "export PATH SECURE_LEVEL" /etc/profile

# Group
echo -n "Adding \"${DRAKX_USERS}\" to audio group :"
for user in ${DRAKX_USERS}; do
    usermod -G audio "${user}"
done
echo "done."







