#
# Security level implementation...
# Writen by Vandoorselaere Yoann <yoann@mandrakesoft.com>
#

# Need root access
if [ $UID != 0 ]; then
    echo "You need to be root in order to change secure level."
    exit 1
fi

# To avoid error, while new initscript package isn't released...
touch /etc/rc.d/rc.firewall

# If we are currently installing our
# system with DrakX, we don't ask anything to the user...
# Instead, DrakX do it and give us a file with some variable.
if [ -f /tmp/secure.DrakX ]; then
    . /tmp/secure.DrakX
fi

if [ -f /etc/security/msec/security.conf ]; then
    . /etc/security/msec/security.conf
fi

USERNAME="blah"
COMMENT="# Mandrake-Security : if you remove this comment, remove the next line too."

AddRules () {
	string=$1
	file=$2

	if [ -z "${string}" ]; then
		return;
	fi

	if [ -z ${3} ]; then
		echo "Modifying config in ${file}..."
	fi	
	
	if ! grep -qx "${string}" ${file}; then
		echo "${COMMENT}" >> ${file};
		echo "${string}" >> ${file};
	fi
	if [ -z ${3} ]; then
		echo -e "done.\n"
	fi
}

CleanRules() {
    file=$1
    ctrl=0

	echo -en "\t- Cleaning msec appended line in ${file} : "
    mv -f ${file} /tmp/secure.tmp
    touch ${file}

    while read line; do
	if [ ${ctrl} == 1 ]; then
	    ctrl=0
	    continue;
	fi

        if echo "${line}" | grep -qx "${COMMENT}"; then
	    ctrl=1
	fi
		
	if [ ${ctrl} == 0 ]; then
	    echo "${line}" >> ${file}
	fi
    done < /tmp/secure.tmp
    
    rm -f /tmp/secure.tmp

	echo "done."
}

CommentUserRules() {
    file=$1

    echo -en "\t- Cleaning user appended line in ${file} : "

    mv -f ${file} /tmp/secure.tmp
    touch ${file}
     
    while read line; do 
	if ! echo "${line}" | grep -qE "^#"; then
	    echo "# ${line}" >> ${file}
	fi
    done < /tmp/secure.tmp
  
    rm -f /tmp/secure.tmp
	echo "done."
}

Syslog() {
    if [ "${SYS_LOG}" == "yes" ]; then
        /sbin/initlog --string=${1}
    fi
}

Ttylog() {
    if [ "${TTY_LOG}" == "yes" ]; then
        for i in `w | grep -v "load\|TTY" | awk '{print $2}'` ; do
            echo -e ${1} > /dev/$i
        done
    fi
}


LiloUpdate() {
    if [ ! -f /tmp/secure.DrakX ]; then
    	echo "Do you want a password authentication at boot time ?"
    	echo "Be very carefull,"
    	echo "this will prevent your server to reboot without an operator to enter password".
    	echo -n "[yes]/no : "
    	read answer
    	if [[ "${answer}" == "yes" || "${answer}" == "" ]]; then
        	echo -n "Please enter the password which will be used at boot time : "
        	read password
    	else
        	password=""
    	fi
    else
    	password=${DRAKX_PASSWORD}
    fi

    if [ ! -z "${password}" ]; then
    	mv /etc/lilo.conf /tmp/secure.tmp
	while read line; do
	    if ! echo "${line}" | grep -q "password"; then
		echo "${line}" >> /etc/lilo.conf
	    fi
    	done < /etc/secure.tmp
	
	rm -f /etc/secure.tmp
    	AddRules "password=$PASSWORD" /etc/lilo.conf
    fi
}

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

echo -e "\nStarting to reconfigure the system : "

# For all secure level
echo "Setting spoofing protection : "
AddRules "echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter" /etc/rc.d/rc.firewall

# default group which must exist on the system
groupadd audio >& /dev/null
groupadd xgrp >& /dev/null
usermod -G xgrp xfs

if ! /etc/security/msec/init-sh/grpuser --del audio "${USERNAME}"; then
    echo "Problem removing user \"${USERNAME}\" from group audio."
fi









