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

echo "Loging all messages on tty12 : "
AddRules "*.* /dev/tty12" /etc/syslog.conf

# login as root from the console allowed
echo "Login as root is allowed (on the console) : "
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
AddRules "0 4 * * *    root    /usr/share/msec/security.sh" /etc/crontab

# /etc/profile.d/msec.{sh,csh}
export SECURE_LEVEL=3
echo "Setting secure level variable to 3 :"
AddRules "export SECURE_LEVEL=3" /etc/profile.d/msec.sh
AddRules "setenv SECURE_LEVEL 3" /etc/profile.d/msec.csh

echo "Setting umask to 022 (u=rw,g=r,o=r) :"
AddRules "umask 022" /etc/profile.d/msec.sh
AddRules "umask 022" /etc/profile.d/msec.csh

echo "Adding \"non secure\" PATH variable :"
AddRules "if ! echo \${PATH} |grep -q /usr/X11R6/bin ; then\n\texport PATH=\$PATH:/usr/X11R6/bin\nfi" /etc/profile.d/msec.sh quiet
AddRules "if ! { (echo "\${PATH}" | grep -q /usr/X11R6/bin) } then\n\tsetenv PATH \"\${PATH}:/usr/X11R6/bin\"\nendif" /etc/profile.d/msec.csh quiet
AddRules "if ! echo \${PATH} |grep -q /usr/games ; then\n\texport PATH=\$PATH:/usr/games\nfi" /et
c/profile.d/msec.sh quiet
AddRules "if ! { (echo "\${PATH}" | grep -q /usr/games) } then\n\tsetenv PATH \"\${PATH}:/usr/games\"\nendif" /etc/profile.d/msec.csh quiet

AddRules "if ! echo \${PATH} |grep -q :. ; then\n\texport PATH=\$PATH:.\nfi" /etc/profile.d/msec.sh quiet
AddRules "if ! { (echo "\${PATH}" | grep -q :.) } then\n\tsetenv PATH \"\${PATH}:.\"\nendif" /etc/profile.d/msec.csh quiet

# Do not boot on a shell
AllowReboot

ForbidAutologin

# Group were modified in lib.sh...
grpconv

AllowUserList
RootSshLogin 3
