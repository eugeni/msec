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
echo -e "\t- Security warning by mail : no."
    AddRules "MAIL_WARN=no" /etc/security/msec/security.conf       quiet
echo -e "\t- Security warning in syslog : yes."			
    AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf		
# end security check

# /etc/profile.d/msec.{sh,csh}
export SECURE_LEVEL=2
echo "Setting secure level variable to 2 :"
AddRules "export SECURE_LEVEL=2" /etc/profile.d/msec.sh
AddRules "setenv SECURE_LEVEL 2" /etc/profile.d/msec.csh

echo "Setting umask to 022 (u=rw,g=r,o=r) :"
AddRules "umask 022" /etc/profile.d/msec.sh
AddRules "umask 022" /etc/profile.d/msec.csh

echo "Adding \"non secure\" PATH variable :"
AddRules "if ! echo \${PATH} |grep -q /usr/X11R6/bin ; then\n\texport PATH=\$PATH:/usr/X11R6/bin\nfi" /etc/profile.d/msec.sh quiet
AddRules "if ! { (echo "\${PATH}" | grep -q /usr/X11R6/bin) } then\n\tsetenv PATH \"\${PATH}:/usr
/X11R6/bin\"\nendif" /etc/profile.d/msec.csh quiet
AddRules "if ! echo \${PATH} |grep -q /usr/games ; then\n\texport PATH=\$PATH:/usr/games\nfi" /etc/profile.d/msec.sh quiet
AddRules "if ! { (echo "\${PATH}" | grep -q /usr/games) } then\n\tsetenv PATH \"\${PATH}:/usr/games\"\nendif" /etc/profile.d/msec.csh quiet

AddRules "if ! echo \${PATH} |grep -q :. ; then\n\texport PATH=\$PATH:.\nfi" /etc/profile.d/msec.
sh quiet
AddRules "if ! { (echo "\${PATH}" | grep -q :.) } then\n\tsetenv PATH \"\${PATH}:.\"\nendif" /etc/profile.d/msec.csh quiet

# Xserver
echo "Allowing users to connect X server from localhost :"
AddBegRules "/usr/X11R6/bin/xhost + localhost" /etc/X11/xinit.d/msec

# group
echo "Adding system users to specifics groups :"
/usr/share/msec/grpuser.sh --refresh
grpconv
echo -e "done.\n"

AllowAutologin

# Do not boot on a shell
AllowReboot
AllowUserList
RootSshLogin 2
