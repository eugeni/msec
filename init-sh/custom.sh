#!/bin/bash

#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

if [[ -f /etc/security/msec/init-sh/lib.sh ]]; then
    . /etc/security/msec/init-sh/lib.sh
fi


clear

###
echo "Do you want all system events to be logged on tty12 ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "*.* /dev/tty12" /etc/syslog.conf
fi

###
echo "Do you want to deny any machine to connect to yours ?"
WaitAnswer
if [[ ${answer} == yes ]]; then
    echo "Do you want only localhost to be allowed ?"
    WaitAnswer; clear
    if [[ ${answer} == yes ]]; then
	AddRules "ALL:ALL EXCEPT localhost:DENY" /etc/hosts.deny
    else
	AddRules "ALL:ALL:DENY" /etc/hosts.deny
    fi
fi

###
echo "Do you want root console login to be allowed ?" 
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "tty1" /etc/securetty quiet
    AddRules "tty2" /etc/securetty quiet
    AddRules "tty3" /etc/securetty quiet
    AddRules "tty4" /etc/securetty quiet
    AddRules "tty5" /etc/securetty quiet
    AddRules "tty6" /etc/securetty 
fi
###
echo "Do you want your system to daily check important security problem ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "CHECK_SECURITY=yes" /etc/security/msec/security.conf
	AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/security_check.sh" /etc/crontab
fi

###
echo "Do you want your system to daily check new open port listening ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "CHECK_OPEN_PORT=yes" /etc/security/msec/security.conf
	AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/security_check.sh" /etc/crontab
	AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/diff_check.sh" /etc/crontab
fi

###
echo "Do you want your system to check for grave permission problem on senssibles files ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "CHECK_PERMS=yes" /etc/security/msec/security.conf
	AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/security_check.sh" /etc/crontab
fi

###
echo "Do you want your system to daily check SUID Root file change ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/diff_check.sh" /etc/crontab
fi

###
echo "Do you want your system to daily check suid files md5 checksum changes ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "CHECK_SUID_MD5=yes" /etc/security/msec/security.conf
	AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/diff_check.sh" /etc/crontab
fi

###
echo "Do you want your system to daily check SUID Group file change ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_SUID_GROUP=yes" /etc/security/msec/security.conf
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/diff_check.sh" /etc/crontab
fi

###
echo "Do you want your system to daily check Writeable file change ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_WRITEABLE=yes" /etc/security/msec/security.conf
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/diff_check.sh" /etc/crontab
fi

###
echo "Do you want your system to daily check Unowned file change ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_UNOWNED=yes" /etc/security/msec/security.conf
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/diff_check.sh" /etc/crontab
fi

###
echo "Do you want your system to verify every minutes if a network interface"
echo "is in promiscuous state (which mean someone is probably running a sniffer on your machine ) ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_PROMISC=yes" /etc/security/msec/security.conf
    AddRules "*/1 * * * *    root    nice --adjustment=+19 /etc/security/msec/cron-sh/promisc_check.sh" /etc/crontab
fi
###

LiloUpdate;
/sbin/lilo >& /dev/null

###
echo "Do you want to disable your running server ( except important one )"
echo "This is only valuable for server installed with rpm."
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	echo -n "Disabling all service, except : {"
	chkconfig --list | awk '{print $1}' | while read service; do
   		if grep -qx ${service} /etc/security/msec/init-sh/server.4; then
       		echo -n " ${service}"
   		fi
	done
	echo " } : "

	chkconfig --list | awk '{print $1}' | while read service; do
    	chkconfig --del "${service}"
    	if ! chkconfig --msec --add "${service}"; then
       	 	echo -e "\t- Services ${service} is now disabled."
    	fi
	done
	echo -e "done.\n";
fi

###
echo "Do you want to disallow rpm to automatically enable a new installed server for run on next reboot ?"
echo "yes = you will need to chkconfig (--add ) servername for the server to run on boot."
echo "no  = rpm will do it for you, but you have less control of what is running on your machine."
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	export SECURE_LEVEL="4"
	AddRules "SECURE_LEVEL=\"4\"" /etc/profile
else
	AddRules "SECURE_LEVEL=\"3\"" /etc/profile
fi

###
echo "Do you want an easy, normal, restricted, or paranoid umask ?"
echo "easy ( 002 )   = user = rwx, group = rwx, other = rx"
echo "normal ( 022 ) = user = rwx, group = rx, other = rx"
echo "restricted ( for users ) ( 077 ) = user = rwx, group =, other ="
echo "restricted ( for root ) ( 022 ) = user = rwx, = group = rx, other = rx" 
echo "paranoid ( 077 ) = user = rwx, group = , other ="
answer="nothing"
while [[ "${answer}" != "easy" && "${answer}" != "normal" && "${answer}" != "restricted" && "${answer}" != "paranoid"  ]]; do
	echo -n "easy/normal/restricted/paranoid : "
    read answer
done
case "${answer}" in
	"easy")
	AddRules "umask 002" /etc/profile
	;;
	"normal")
	AddRules "umask 022" /etc/profile
	;;
	"restricted")
	AddRules "if [[ \${UID} == 0 ]]; then umask 022; else umask 077; fi" /etc/profile
	;;
	"paranoid")
	AddRules "umask 077" /etc/profile
	;;
esac

###
echo "Do you want a "." in your PATH variable ?"
echo "This permit you to not use ./progname & to just type progname"
echo "However this is a *high* security risk."
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games:." /etc/profile quiet
else
    AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games" /etc/profile quiet
fi

AddRules "export PATH SECURE_LEVEL" /etc/profile







