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

# login as root on console granted...
echo "Login as root is granted :"
AddRules "tty1" /etc/securetty quiet
AddRules "tty2" /etc/securetty quiet
AddRules "tty3" /etc/securetty quiet
AddRules "tty4" /etc/securetty quiet
AddRules "tty5" /etc/securetty quiet
AddRules "tty6" /etc/securetty
AddRules "vc/1" /etc/securetty quiet
AddRules "vc/2" /etc/securetty quiet
AddRules "vc/3" /etc/securetty quiet
AddRules "vc/4" /etc/securetty quiet
AddRules "vc/5" /etc/securetty quiet
AddRules "vc/6" /etc/securetty

# Security check
echo "Updating file check variable : "
echo -e "\t- Check security : no."
    AddRules "CHECK_SECURITY=no" /etc/security/msec/security.conf      quiet
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
echo -e "\t- Security warning on tty : no."
    AddRules "TTY_WARN=no" /etc/security/msec/security.conf	        quiet
echo -e "\t- Security warning by mail : no."
    AddRules "MAIL_WARN=no" /etc/security/msec/security.conf       quiet
echo -e "\t- Security warning in syslog : no."			
    AddRules "SYSLOG_WARN=no" /etc/security/msec/security.conf		
# end security check

# /etc/profile.d/msec.{sh,csh}
export SECURE_LEVEL=0
echo "Setting secure level variable to 0 :"
AddRules "export SECURE_LEVEL=0" /etc/profile.d/msec.sh
AddRules "setenv SECURE_LEVEL 0" /etc/profile.d/msec.csh

echo "Setting umask to 022 (u=rw,g=r,o=r) :"
AddRules "umask 022" /etc/profile.d/msec.sh
AddRules "umask 022" /etc/profile.d/msec.csh

echo "Adding \"non secure\" PATH variable :"
if ! echo ${PATH} |grep -q /usr/X11R6/bin ; then
	AddRules "export PATH=\$PATH:/usr/X11R6/bin" /etc/profile.d/msec.sh quiet
	AddRules "setenv PATH \"\${PATH}:/usr/X11R6/bin\"" /etc/profile.d/msec.csh quiet
fi
if ! echo ${PATH} |grep -q /usr/games ; then
        AddRules "export PATH=\$PATH:/usr/games" /etc/profile.d/msec.sh quiet
	AddRules "setenv PATH \"\${PATH}:/usr/games\"" /etc/profile.d/msec.csh quiet
fi

AddRules "export PATH=\$PATH:." /etc/profile.d/msec.sh quiet
AddRules "setenv PATH \"\${PATH}:.\"" /etc/profile.d/msec.csh quiet

# Xserver
echo "Allowing users to connect X server from everywhere :"
AddBegRules "/usr/X11R6/bin/xhost +" /etc/X11/xinit.d/msec quiet

# Group
echo "Adding system users to specific groups :"
/usr/share/msec/grpuser.sh --refresh
echo -e "done.\n"

AllowAutologin

# Boot on a shell / authorize ctrl-alt-del
AllowReboot
AllowUserList
RootSshLogin 0
