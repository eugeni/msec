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

# Log in append only mode
echo -e "Changing attribute of /var/log/* to append only...\n"

# All events logged on tty12
echo "Loging all messages on tty12 : "
AddRules "*.* /dev/tty12" /etc/syslog.conf

# Prevent all kind of connection except from localhost
echo "Denying all kind of connection except localhost : "
AddRules "ALL:ALL EXCEPT localhost:DENY" /etc/hosts.deny

# Allow all the ssh connexions from anywhere
echo "Allowing the ssh connexions from everywhere : "
AddRules "ALL:sshd ALL" /etc/hosts.allow

# Login as root on the console allowed :
echo "Denying login as root (except on the console) :"
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
    AddRules "MAIL_USER=root" /etc/security/msec/security.conf      quiet
echo -e "\t- Security warning in syslog : yes."			
    AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf		
# end security check

# Check every 1 minutes for promisc problem
echo "Adding promisc check in crontab (scheduled every minutes) :"
AddRules "*/1 * * * *    root    /usr/share/msec/promisc_check.sh" /etc/crontab

echo "Adding \"diff\" & \"global\" security check in crontab (scheduled every midnight) :"
AddRules "0 4 * * *    root    /usr/share/msec/security.sh" /etc/crontab

# Server update
echo "Setting secure level variable to snf :"
AddRules "SECURE_LEVEL=snf" /etc/sysconfig/msec

# Console timeout
echo "Setting console timeout :"
AddRules "TMOUT=180" /etc/sysconfig/msec

# No history file
echo "No history file :"
AddRules "HISTFILESIZE=0" /etc/sysconfig/msec

# Ip spoofing protection
echo "IP spoofing protection :"
AddRules "nospoof on" /etc/host.conf
AddRules "spoofalert on" /etc/host.conf

# icmp echo
echo "Ignoring icmp echo :"
AddRules "net.ipv4.icmp_echo_ignore_all=1" /etc/sysctl.conf
AddRules "net.ipv4.icmp_echo_ignore_broadcasts=1" /etc/sysctl.conf

# bad error
echo "Enabling bad error message Protection :"
AddRules "net.ipv4.icmp_ignore_bogus_error_responses=1" /etc/sysctl.conf

# log strange packets
echo "Enabling logging Spoofed Packets, Source Routed Packets, Redirect Packets :"
AddRules "net.ipv4.conf.all.log_martians=1" /etc/sysctl.conf

LoadSysctl

# issues
echo "Removing /etc/issue.net :"
RemoveIssueNet

export SECURE_LEVEL=snf

IFS="
"
echo -n "Disabling all service, except : {"
for service in `chkconfig --list | awk '{print $1}'`; do
    if grep -qx ${service} /etc/security/msec/server.snf; then
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

echo "Setting umask to 022 (u=rw,g=rx) for root, 077 (u=rw) for user :" 
AddRules "UMASK_ROOT=022" /etc/sysconfig/msec
AddRules "UMASK_USER=077" /etc/sysconfig/msec

if [[ -f /lib/libsafe.so.2 ]]; then
    echo "Enabling stack overflow protection :"
    AddRules "/lib/libsafe.so.2" /etc/ld.so.preload
fi

# Do not boot on a shell
ForbidReboot

ForbidAutologin

# Group were modified in lib.sh...
grpconv

ForbidUserList
RootSshLogin snf
