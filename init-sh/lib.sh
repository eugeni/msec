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
	
	if ! grep -Eqx "^${string}" ${file}; then
		echo -e "${COMMENT}" >> ${file};
		echo -e "${string}" >> ${file};
	fi

	if [[ -z ${3} ]]; then
		echo -e "done.\n"
	fi
}

AddBegRules() {
    echo "Modifying config in ${2}..."
    
    export VAL=$1
    perl -pi -e '/^#/ or /^$/ or $m++ or print "$ENV{COMMENT}\n$ENV{VAL}\n\n"' $2

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


LiloUpdate() {
    if [[ -z ${LILO_PASSWORD} ]]; then
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
    	password=${LILO_PASSWORD}
    fi

    if [[ ! -z ${password} ]]; then
	tmpfile=`mktemp /tmp/secure.XXXXXX`

    	cp -f /etc/lilo.conf ${tmpfile}
	while read line; do
	    if ! echo "${line}" | grep -q "password"; then
		echo "${line}" > /etc/lilo.conf
	    fi
    	done < ${tmpfile}
	
	rm -f ${tmpfile}
	clear
    	AddRules "password=$password" /etc/lilo.conf
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
CleanRules /etc/profile
CleanRules /etc/lilo.conf
CleanRules /etc/rc.d/rc.firewall
CleanRules /etc/crontab
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

/etc/security/msec/init-sh/grpuser.sh --clean
echo











































