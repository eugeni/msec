#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

# Need root access
if [[ ${UID} != 0 ]]; then
    echo "You need to be root in order to change secure level."
    exit 1
fi

export COMMENT="# Mandrake-Security : if you remove this comment, remove the next line too."

WaitAnswer() {
    answer="nothing"

    while [[ ${answer} != yes && ${answer} != no ]]; do
	echo -n "yes/no : "
	read answer
    done
}

AddRules() {
	string=$1
	file=$2
	quiet=$3

	if [[ -z ${string} ]]; then
		return;
	fi

	if [[ -z ${quiet} ]]; then
		echo "Modifying config in ${file}..."
	fi	
	
	if ! grep -qx "^${string}" ${file}; then
		echo -e "${COMMENT}" >> ${file};
		echo -e "${string}" >> ${file};
	fi

	if [[ -z ${3} ]]; then
		echo -e "done.\n"
	fi
}

AddBegRules() {
    echo "Modifying config in ${2}..."

	if [[ ! -f ${file} ]]; then
		return;
	fi
    
    export VAL=$1
    perl -pi -e '/^#/ or /^$/ or $m++ or print "$ENV{COMMENT}\n$ENV{VAL}\n"' $2

    echo -e "done.\n"
}


OLD_CleanRules() {
    file=$1
    ctrl=0

    if [[ ! -f ${file} ]]; then
	echo "${file} do not exist... can not clean."
	return;
    fi

    echo -en "\t- Cleaning msec appended line in ${file} : "

    tmpfile=`mktemp /tmp/secure.XXXXXX`
    cp ${file} ${tmpfile}

    while read line; do
	if [[ ${ctrl} == 1 ]]; then
	    ctrl=0
	    continue;
	fi

        if echo "${line}" | grep -qx "${COMMENT}"; then
	    ctrl=1
	fi
		
	if [[ ${ctrl} == 0 ]]; then
	    echo "${line}"
	fi
    done < ${tmpfile} > ${file}

    rm -f ${tmpfile}

    echo "done."
}

CleanRules() {
    echo -en "\t- Cleaning msec appended line in $1 : "

    perl -ni -e '$_ eq "$ENV{COMMENT}\n" ... // or print' $1        

    echo "done."
}

CommentUserRules() {
    file=$1

    if [[ ! -f ${file} ]]; then
	return;
    fi

    echo -en "\t- Cleaning user appended line in ${file} : "

    tmpfile=`mktemp /tmp/secure.XXXXXX`
    cp -f ${file} ${tmpfile}
      
    while read line; do
	if ! echo "${line}" | grep -qE "^#"; then
	    echo "# ${line}"
    else
		echo "${line}"
	fi
    done < ${tmpfile} > ${file}
  
    rm -f ${tmpfile}
    
    echo "done."
}

Syslog() {
    if [[ ${SYSLOG_WARN} == yes ]]; then
        /sbin/initlog --string=${1}
    fi
}

Ttylog() {
    if [[ ${TTY_WARN} == yes ]]; then
	w | grep -v "load\|TTY" | awk '{print $2}' | while read line; do
            echo -e ${1} > /dev/$i
        done
    fi
}


LoaderUpdate() {
   
    # Ask only if we're not inside DrakX.
    if [[ ! ${DRAKX_PASSWORD+set} ]]; then
    	echo "Do you want a password authentication at boot time ?"
    	echo "Be very carefull,"
    	echo "this will prevent your server to reboot without an operator to enter password".
	WaitAnswer;
    	if [[ ${answer} == yes ]]; then
        	echo -n "Please enter the password which will be used at boot time : "
        	read password
    	else
        	password=""
    	fi

	if [[ ! -z ${password} ]]; then
	    if [[ -f /etc/lilo.conf ]]; then
		AddBegRules "password=$password" /etc/lilo.conf
		chmod 600 /etc/lilo.conf
	    fi
	    if [[ -f /boot/grub/menu.lst ]]; then
		AddBegRules "password $password" /boot/grub/menu.lst
		chmod 600 /boot/grub/menu.lst
	    fi
	    
	    loader=`/usr/sbin/detectloader`
	    case "${loader}" in
		"LILO")
		    /sbin/lilo
		    ;;
		"GRUB")
		    ;;
	    esac
	fi
    fi
}

# Do something only if DRAKX_PASSWORD set ( we're in DrakX )
LoaderDrakX() {
    if [[ -n "${DRAKX_PASSWORD}" ]]; then
	if [[ -f /etc/lilo.conf ]]; then
	    AddBegRules "password=$DRAKX_PASSWORD" /etc/lilo.conf
	    chmod 600 /etc/lilo.conf
	fi
	if [[ -f /boot/grub/menu.lst ]]; then
	    AddBegRules "password $DRAKX_PASSWORD" /boot/grub/menu.lst
	    chmod 600 /boot/grub/menu.lst
	fi
	  
	loader=`/usr/sbin/detectloader`
	case "${loader}" in
	    "LILO")
		    /sbin/lilo
		    ;;
	    "GRUB")
		    ;;
	esac
    fi
}


CleanLoaderRules() {
	if [[ -f /etc/lilo.conf ]]; then
	    CleanRules /etc/lilo.conf
	    chmod 644 /etc/lilo.conf
	fi
	if [[ -f /boot/grub/menu.lst ]]; then
	    CleanRules /boot/grub/menu.lst
	    chmod 644 /boot/grub/menu.lst
	fi

	if [[ -z ${DRAKX_PASSWORD} ]]; then
	    loader=`/usr/sbin/detectloader`
	    case "${loader}" in
		"LILO")
			/sbin/lilo
			;;
		"GRUB")
			;;
	    esac
	fi
}

AllowAutologin() {
	file=/etc/sysconfig/autologin
	if [[ -f ${file} ]]; then
		grep -v AUTOLOGIN < ${file} > ${file}.new
		echo "AUTOLOGIN=yes" >> ${file}.new
		mv -f ${file}.new ${file}
	fi
}

ForbidAutologin() {
	file=/etc/sysconfig/autologin
	if [[ -f ${file} ]]; then
        cat ${file} | grep -v AUTOLOGIN > ${file}.new
        echo "AUTOLOGIN=no" >> ${file}.new
		mv -f ${file}.new ${file}
    fi
}

ForbidUserList() {
	file=/usr/share/config/kdm/kdmrc
	if [[ -f ${file} ]]; then
		perl -pi -e 's/^ShowUsers=.*$/ShowUsers=None/' ${file}		
	fi

	file=/etc/X11/gdm/gdm.conf
	if [[ -f ${file} ]]; then
		perl -pi -e 's/^Browser=.*$/Browser=0/' ${file}
	fi
}

AllowUserList() {
	file=/usr/share/config/kdm/kdmrc
    if [[ -f ${file} ]]; then
		perl -pi -e 's/^ShowUsers=.*$/ShowUsers=All/' ${file}		
    fi

	file=/etc/X11/gdm/gdm.conf
    if [[ -f ${file} ]]; then
        perl -pi -e 's/^Browser=.*$/Browser=1/' ${file}
    fi
}

ForbidReboot() {
	echo -n "Setting up inittab to deny any user to issue ctrl-alt-del : "
	tmpfile=`mktemp /tmp/secure.XXXXXX`
	cp /etc/inittab ${tmpfile}
	cat ${tmpfile} | \
    	sed s'/\/bin\/bash --login/\/sbin\/mingetty tty1/' | \
    	sed s'/ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now/ca::ctrlaltdel:\/sbin\/shutdown -a -t3 -r now/' > /etc/inittab
	rm -f ${tmpfile}
	[ -z "$DURING_INSTALL" ] && telinit u
	echo "done."
	echo -n "Forbid console users to reboot/shutdown : "
        for pamfile in /etc/security/console.apps/{shutdown,poweroff,reboot,halt} ; do
	  rm -f ${pamfile} 2>&1 > /dev/null
	done
	echo "done."
}

AllowReboot() {
	echo -n "Setting up inittab to authorize any user to issue ctrl-alt-del : "
	tmpfile=`mktemp /tmp/secure.XXXXXX`
	cp /etc/inittab ${tmpfile}
	cat ${tmpfile} | \
    	sed s'/ca::ctrlaltdel:\/sbin\/shutdown -a -t3 -r now/ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now/' > /etc/inittab
	rm -f ${tmpfile}
	[ -z "$DURING_INSTALL" ] && telinit u
	echo "done."
	echo -n "Allow console users to reboot/shutdown : "
	for pamfile in /etc/security/console.apps/{shutdown,poweroff,reboot,halt} ; do
	  touch -f ${pamfile}
        done
	echo "done."
}

RootSshLogin () {
	echo -n "Setting up the root ssh login : "
	if [[ $1 == 4 || $1 == 5 ]]; then
		/bin/sed 's/PermitRootLogin yes/PermitRootLogin no/' < /etc/ssh/sshd_config > /etc/ssh/sshd_config.new
		mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
		chmod 0600 /etc/ssh/sshd_config
	else
		sed 's/PermitRootLogin no/PermitRootLogin yes/' < /etc/ssh/sshd_config > /etc/ssh/sshd_config.new
		mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
		chmod 0600 /etc/ssh/sshd_config
	fi
}

# If we are currently installing our
# system with DrakX, we don't ask anything to the user...
# Instead, DrakX do it and give us a file with some variable.
if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
fi

clear
echo "Preparing to run security script : "
CleanRules /etc/syslog.conf
CleanRules /etc/hosts.deny
CommentUserRules /etc/hosts.deny
CleanRules /etc/hosts.allow
CommentUserRules /etc/hosts.allow
CleanRules /etc/securetty
CommentUserRules /etc/securetty
CleanRules /etc/security/msec/security.conf
CommentUserRules /etc/security/msec/security.conf
CleanRules /etc/ld.so.preload

CleanLoaderRules
LoaderDrakX

CleanRules /etc/logrotate.conf
CleanRules /etc/rc.d/rc.local
CleanRules /etc/rc.d/rc.firewall
CleanRules /etc/crontab
CleanRules /etc/profile
CleanRules /etc/zprofile

if [[ -f /etc/X11/xinit.d/msec ]]; then
	CleanRules /etc/X11/xinit.d/msec
else
	touch /etc/X11/xinit.d/msec 
	chmod 755 /etc/X11/xinit.d/msec
fi


if [[ -f /etc/profile.d/msec.sh && -f /etc/profile.d/msec.csh ]]; then
	CleanRules /etc/profile.d/msec.sh
	CleanRules /etc/profile.d/msec.csh
else
	touch /etc/profile.d/msec.sh
	touch /etc/profile.d/msec.csh
	chmod 755 /etc/profile.d/msec.sh
	chmod 755 /etc/profile.d/msec.csh
fi

echo -e "\nStarting to reconfigure the system : "
# For all secure level
echo "Setting spoofing protection : "
AddRules "echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter" /etc/rc.d/rc.firewall

# default group which must exist on the system
# groupadd already check for their existance...
groupadd nogroup >& /dev/null
groupadd audio >& /dev/null
groupadd xgrp >& /dev/null
groupadd ntools >& /dev/null
groupadd ctools >& /dev/null

usermod -G xgrp xfs

/usr/share/msec/grpuser.sh --clean
echo
