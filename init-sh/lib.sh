#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

# Need root access
if [[ ${UID} != 0 ]]; then
    echo "You need to be root in order to change secure level."
    exit 1
fi


COMMENT="# Mandrake-Security : if you remove this comment, remove the next line too."

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
	
	if ! grep -Eqx "^${string}" ${file}; then
		echo -e "${COMMENT}" >> ${file};
		echo -e "${string}" >> ${file};
	fi
	if [[ -z ${3} ]]; then
		echo -e "done.\n"
	fi
}

AddBegRules() {
    string=$1
    file=$2
    quiet=$3
    ctrl=0

    if [[ -z ${string} ]]; then
	return;
    fi

    if [[ -z ${quiet} ]]; then
	echo "Modifying config in ${file}..."
    fi

    cp -f ${file} /tmp/secure.tmp

    if ! grep -Eqx "^${string}" /tmp/secure.tmp; then
	echo -e "${COMMENT}" > ${file};
	echo -e "${string}" >> ${file};
    fi

    cat /tmp/secure.tmp >> ${file}

    if [[ -z ${3} ]]; then
	echo -e "done.\n"
    fi
}


CleanRules() {
    file=$1
    ctrl=0

    if [[ ! -f ${file} ]]; then
	return;
    fi

    echo -en "\t- Cleaning msec appended line in ${file} : "
    cp -f ${file} /tmp/secure.tmp

    while read line; do
	if [[ ${ctrl} == 1 ]]; then
	    ctrl=0
	    continue;
	fi

        if echo "${line}" | grep -qx "${COMMENT}"; then
	    ctrl=1
	fi
		
	if [[ ${ctrl} == 0 ]]; then
	    echo "${line}" > ${file}
	fi
    done < /tmp/secure.tmp

    rm -f /tmp/secure.tmp

    echo "done."
}

CommentUserRules() {
    file=$1

    if [[ ! -f ${file} ]]; then
	return;
    fi

    echo -en "\t- Cleaning user appended line in ${file} : "

    cp -f ${file} /tmp/secure.tmp
         
    while read line; do 
	if ! echo "${line}" | grep -qE "^#"; then
	    echo "# ${line}" > ${file}
	fi
    done < /tmp/secure.tmp
  
    rm -f /tmp/secure.tmp
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


LiloUpdate() {
    if [[ ! -f /tmp/secure.DrakX ]]; then
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
    else
    	password=${DRAKX_PASSWORD}
    fi

    if [[ ! -z "${password}" ]]; then
    	cp -f /etc/lilo.conf /tmp/secure.tmp
	while read line; do
	    if ! echo "${line}" | grep -q "password"; then
		echo "${line}" > /etc/lilo.conf
	    fi
    	done < /tmp/secure.tmp
	
	rm -f /tmp/secure.tmp
	clear
    	AddRules "password=$password" /etc/lilo.conf
    fi
}

# If we are currently installing our
# system with DrakX, we don't ask anything to the user...
# Instead, DrakX do it and give us a file with some variable.
if [[ -f /tmp/secure.DrakX ]]; then
    . /tmp/secure.DrakX
    AddRules "${DRAKX_USERS}" /etc/security/msec/security.conf
fi

if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
fi

clear
echo "Preparing to run security script : "
CleanRules /etc/inittab
CleanRules /etc/syslog.conf
CleanRules /etc/hosts.deny
CommentUserRules /etc/hosts.deny
CleanRules /etc/hosts.allow
CommentUserRules /etc/hosts.allow
CleanRules /etc/securetty
CommentUserRules /etc/securetty
CleanRules /etc/security/msec/security.conf
CommentUserRules /etc/security/msec/security.conf
CleanRules /etc/profile
CleanRules /etc/lilo.conf
CleanRules /etc/rc.d/rc.firewall
CleanRules /etc/crontab
CleanRules /etc/security/msec/security.users
CleanRules /etc/X11/xdm/Xsession
CleanRules /etc/X11/xinit/xinitrc

echo -e "\nStarting to reconfigure the system : "
# For all secure level
echo "Setting spoofing protection : "
AddRules "echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter" /etc/rc.d/rc.firewall

# default group which must exist on the system
groupadd nogroup >& /dev/null
groupadd audio >& /dev/null
groupadd xgrp >& /dev/null
usermod -G xgrp xfs

# We aren't at install time, 
# so we delete ( temporarily ) audio user.

if [[ ! -f /tmp/secure.DrakX ]]; then
    if [[ ! -z ${DRAKX_USERS} ]]; then
	for user in ${DRAKX_USERS}; do
	    /etc/security/msec/init-sh/grpuser --del audio "${user}"
	done
    fi
else
    if [[ ! -z ${DRAKX_USERS} ]]; then
	AddRules "DRAKX_USERS=${DRAKX_USERS}" /etc/security/msec/security.conf
    fi
fi









