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
echo -e "\t- Security warning on tty : no."
    AddRules "TTY_WARN=no" /etc/security/msec/security.conf	        quiet
echo -e "\t- Security warning by mail : no."
    AddRules "MAIL_WARN=no" /etc/security/msec/security.conf       quiet
echo -e "\t- Security warning in syslog : no."			
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
AddRules "SECURE_LEVEL=1" /etc/zprofile

echo "Setting umask to 002 (u=rw,g=rw,o=r) :"
AddRules "umask 002" /etc/profile
AddRules "umask 002" /etc/zprofile

echo "Adding \"non secure\" PATH variable :"
AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games:." /etc/profile quiet
AddRules "export PATH SECURE_LEVEL" /etc/profile
AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games:." /etc/zprofile quiet
AddRules "export PATH SECURE_LEVEL" /etc/zprofile

# Xserver
echo "Allowing users to connect X server from localhost :"
AddBegRules "/usr/X11R6/bin/xhost + localhost" /etc/X11/xdm/Xsession
AddBegRules "/usr/X11R6/bin/xhost + localhost" /etc/X11/xinit/xinitrc

# Group
echo "Adding system users to specific groups :"
/usr/share/msec/grpuser.sh --refresh
grpconv
echo -e "done.\n"

# Do not boot on a shell
echo -n "Setting up inittab to authorize any user to issue ctrl-alt-del : "
tmpfile=`mktemp /tmp/secure.XXXXXX`
cp /etc/inittab ${tmpfile}
cat ${tmpfile} | \
    sed s'/\/bin\/bash --login/\/sbin\/mingetty tty1/' | \
    sed s'/ca::ctrlaltdel:\/sbin\/shutdown -a -t3 -r now/ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now/' > /etc/inittab
rm -f ${tmpfile}
echo "done."
