#!/bin/bash

#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#
# Thanks to :
#		- Bryan Paxton.
#		- Thomas Poindessous.	
# for their contributions.
#

###
clear
echo  "This script allows you to customize the security on your system."
echo  "If you feel at all you don't know what you're doing abort now!!!"
# can't use ctrl-c, we trap all signal.
echo -n "continue [yes/no] : "
read answer;

if [[ ${answer} != yes ]]; then
    exit 1
fi

if [[ -f /usr/share/msec/lib.sh ]]; then
    . /usr/share/msec/lib.sh
else
    echo "Can't find /usr/share/msec/lib.sh, exiting."
    exit 1
fi

clear

WRITE_CRON="false"

###

echo "Do you want to only allow ctrl-alt-del if root is logged locally ?"
echo "( or if an user present in /etc/shutdown.allow is logged locally )"
WaitAnswer; clear
tmpfile=`mktemp /tmp/secure.XXXXXX`
cp /etc/inittab ${tmpfile}
if [[ ${answer} == yes ]]; then
    cat ${tmpfile} | \
    sed s'/ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now/ca::ctrlaltdel:\/sbin\/shutdown -a -t3 -r now/' > /etc/inittab
else
    cat ${tmpfile} | \
    sed s'/ca::ctrlaltdel:\/sbin\/shutdown -a -t3 -r now/ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now/' > /etc/inittab
fi
rm -f ${tmpfile}

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

if [[ -f /usr/lib/libsafe.so.1.2 ]]; then
echo "Do you want to enable the libsafe stack overflow protection ?"
echo "This stack overflow protection work by catching dangerous function call"
echo "like strcpy, strcat, getwd, gets, [vf]scanf, realpath, [v]sprintf"
echo "and verify the address & the size of the destination buffer in the stack"
echo "this is done by searching in the stack frame the one which contain the"
echo "destination address, and by substracting the frame address to the destination buffer one" 
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "export LD_PRELOAD=/usr/lib/libsafe.so.1.3" /etc/profile
	AddRules "export LD_PRELOAD=/usr/lib/libsafe.so.1.3" /etc/zprofile
fi
fi

###
echo "Do you want your system to daily check important security problem ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "CHECK_SECURITY=yes" /etc/security/msec/security.conf
	WRITE_CRON="true"
fi

###
echo "Do you want your system to daily check new open port listening ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "CHECK_OPEN_PORT=yes" /etc/security/msec/security.conf
	WRITE_CRON="true"
fi

###
echo "Do you want your system to check for grave permission problem on sensibles files ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "CHECK_PERMS=yes" /etc/security/msec/security.conf
        WRITE_CRON="true"
fi

###
echo "Do you want your system to daily check SUID Root file change ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_SUID_ROOT=yes" /etc/security/msec/security.conf
    WRITE_CRON="true"
fi

###
echo "Do you want your system to daily check suid files md5 checksum changes ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	AddRules "CHECK_SUID_MD5=yes" /etc/security/msec/security.conf
	WRITE_CRON="true"
fi

###
echo "Do you want your system to daily check SUID Group file change ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_SUID_GROUP=yes" /etc/security/msec/security.conf
    WRITE_CRON="true"
fi

###
echo "Do you want your system to daily check Writeable file change ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_WRITEABLE=yes" /etc/security/msec/security.conf
    WRITE_CRON="true"
fi

###
echo "Do you want your system to daily check Unowned file change ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_UNOWNED=yes" /etc/security/msec/security.conf
    WRITE_CRON="true"
fi

###
echo "Do you want your system to verify every minutes if a network interface"
echo "is in promiscuous state (which mean someone is probably running a sniffer on your machine ) ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "CHECK_PROMISC=yes" /etc/security/msec/security.conf
    AddRules "*/1 * * * *    root    nice --adjustment=+19 /usr/share/msec/promisc_check.sh" /etc/crontab
fi
###

echo "Do you want security report to be done directly on the console ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "TTY_WARN=yes" /etc/security/msec/security.conf
else
    AddRules "TTY_WARN=no" /etc/security/msec/security.conf
fi
###

echo "Do you want security report to be done in syslog ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "SYSLOG_WARN=yes" /etc/security/msec/security.conf
else
    AddRules "SYSLOG_WARN=no" /etc/security/msec/security.conf
fi
###

echo "Do you want security report to be done by mail ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "MAIL_WARN=yes" /etc/security/msec/security.conf
else
    AddRules "MAIL_WARN=no" /etc/security/msec/security.conf
fi
###

if [[ ${WRITE_CRON} == "true" ]]; then
    AddRules "0 0-23 * * *    root    nice --adjustment=+19 /usr/share/msec/security.sh" /etc/crontab
fi

LiloUpdate;
/sbin/lilo >& /dev/null

###
clear
echo "Do you want to disable your running server ( except those specified in /etc/security/msec/server.4 )"
echo "This is only valuable for server installed with rpm."
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
	echo -n "Disabling all service, except : {"
	chkconfig --list | awk '{print $1}' | while read service; do
   		if grep -qx ${service} /etc/security/msec/server.4; then
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
	AddRules "SECURE_LEVEL=\"4\"" /etc/zprofile
else
	AddRules "SECURE_LEVEL=\"3\"" /etc/profile
	AddRules "SECURE_LEVEL=\"3\"" /etc/zprofile
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
	AddRules "umask 002" /etc/zprofile
	;;
	"normal")
	AddRules "umask 022" /etc/profile
	AddRules "umask 022" /etc/zprofile
	;;
	"restricted")
	AddRules "if [[ \${UID} == 0 ]]; then umask 022; else umask 077; fi" /etc/profile
	AddRules "if [[ \${UID} == 0 ]]; then umask 022; else umask 077; fi" /etc/zprofile
	;;
	"paranoid")
	AddRules "umask 077" /etc/profile
	AddRules "umask 077" /etc/zprofile
	;;
esac

###

echo "Do you want easy, normal, restricted, or paranoid permission ?"
answer="nothing"
while [[ "${answer}" != "easy" && "${answer}" != "normal" && "${answer}" != "restricted" && "${answer}" != "paranoid"  ]]; do
	echo -n "easy/normal/restricted/paranoid : "
	read answer
done
case "${answer}" in
	"easy")
	/usr/share/msec/file_perm.sh /etc/security/msec/perm.2
	;;
	"normal")
	/usr/share/msec/file_perm.sh /etc/security/msec/perm.3
	;;
	"restricted")
	/usr/share/msec/file_perm.sh /etc/security/msec/perm.4
	;;
	"paranoid")
	/usr/share/msec/file_perm.sh /etc/security/msec/perm.5
	;;
esac

#Logging
clear
echo "Would you like set to up additional logging ?"
echo "Logging will still go to its respected places in /var/log as well."
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    echo "Would you like all system events to be logged on a specific tty ?"
    echo "please answer by \"no\" or the tty number."
    echo -n "no/ttynumber :"
    read answer
    if [[ ${answer} != no && ${anwer} != yes ]]; then
	AddRules "*.* /dev/tty${answer}" /etc/syslog.conf
    fi

    echo
    echo "Would you like for auth and warnings to a specific tty ?"
    echo "please answer by \"no\" or the tty number."
    echo -n "no/ttynumber :"
    read answer
    if [[ ${answer} != no && ${anwer} != yes ]]; then
	AddRules "authpriv.* /dev/tty${answer}" /etc/syslog.conf
    fi

    echo
    echo "Would you like kernel logging to go on a specific tty ?"
    echo "please answer by \"no\" or the tty number."
    echo -n "no/ttynumber :"
    read answer
    if [[ ${answer} != no && ${anwer} != yes ]]; then
	AddRules "kern.* /dev/tty${answer}" /etc/syslog.conf
    fi

    echo
    echo "Would you like mail logging to a specific tty ?"
    echo "This is only useful if you're running a mail server."
    echo "please answer by \"no\" or the tty number."
    echo -n "no/ttynumber :"
    read answer
    if [[ ${answer} != no && ${anwer} != yes ]]; then
	AddRules "mail.* /dev/tty${answer}" /etc/syslog.conf
    fi
    
    /etc/rc.d/init.d/syslog restart >& /dev/null
fi

clear

###
clear
echo "We can setup your system to log who does what commands and when..."
echo "May we set up proccess accounting ?"
echo "The log file (/var/log/security/psacct.log) will get filled up VERY quickly..."
echo "You need the psacct package."
WaitAnswer;

if [[ ${answer} == yes ]]; then
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

### Pam
clear

dfsize=40000
echo "We help prevent certain types of DoS attacks through the use of PAM(Pluggable Authentication Modules.)"
echo "By setting a limit on how big user files may get and how many processes a user may run."

echo "Would you like to set up some PAM configuration ?"
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "# Limit user processes" /etc/security/limits.conf
    AddRules "*   soft    nproc   100" /etc/security/limits.conf
    AddRules "*   hard    nproc   150" /etc/security/limits.conf
    
    echo "Would you like to set a maximum file size a user is allowed ?"
    WaitAnswer; clear
    if [[ ${answer} == yes ]]; then
	echo "What shall be the maximum file size(default is $(dfsize))"
	echo -n "Size : "
	read fsize
	if [[ -z ${fsize} ]]; then
	    AddRules "# limits size of any one of users' files" /etc/security/limits.conf
	    AddRules "*     hard    $dfsize" /etc/security/limits.conf
	else
	    AddRules "# limits size of any one of users' files" /etc/security/limits.conf
	    AddRules "*     hard    $fsize" /etc/security/limits.conf
	fi
    fi
fi



###
echo "Do you want a "." in your PATH variable ?"
echo "This permit you to not use ./progname & to just type progname"
echo "However this is a *high* security risk."
WaitAnswer; clear
if [[ ${answer} == yes ]]; then
    AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games:." /etc/profile quiet
    AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games:." /etc/zprofile quiet
else
    AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games" /etc/profile quiet
    AddRules "PATH=\$PATH:/usr/X11R6/bin:/usr/games" /etc/zprofile quiet
fi

AddRules "export PATH SECURE_LEVEL" /etc/profile
AddRules "export PATH SECURE_LEVEL" /etc/zprofile

























