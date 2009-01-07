#
# Security level implementation...
# Writen by Vandoorselaere Yoann
#

# Need root access
if [[ ${UID} != 0 ]]; then
    echo "You need to be root in order to change secure level."
    exit 1
fi

export COMMENT="# Mandrake-Security : if you remove this comment, remove the next line too."

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
	
	if ! grep -qEx "^${string}" ${file}; then
		echo -e "${COMMENT}" >> ${file};
		echo -e "${string}" >> ${file};
	fi

	if [[ -z ${3} ]]; then
		echo -e "done.\n"
	fi
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

RestoreIssues () {
	if [ ! -f /etc/issue.net -a -f /etc/issue.net.msec ]; then
		mv -f /etc/issue.net.msec /etc/issue.net
	fi

	if [ ! -f /etc/issue -a -f /etc/issue.msec ]; then
		mv -f /etc/issue.msec /etc/issue
	fi
}

# If we are currently installing our
# system with DrakX, we don't ask anything to the user...
# Instead, DrakX do it and give us a file with some variable.
if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
fi

CleanRules /etc/syslog.conf
CleanRules /etc/hosts.deny
CleanRules /etc/hosts.allow
CleanRules /etc/securetty
CleanRules /etc/security/msec/security.conf
CleanRules /etc/ld.so.preload
CleanRules /etc/host.conf
CleanRules /etc/sysctl.conf

CleanRules /etc/logrotate.conf
CleanRules /etc/rc.d/rc.local
CleanRules /etc/rc.d/rc.firewall
CleanRules /etc/crontab
CleanRules /etc/profile
CleanRules /etc/zprofile

RestoreIssues

if [[ -f /etc/X11/xinit.d/msec ]]; then
	CleanRules /etc/X11/xinit.d/msec
else
	touch /etc/X11/xinit.d/msec 
	chmod 755 /etc/X11/xinit.d/msec
fi

if [[ -f /etc/sysconfig/msec ]]; then
	        CleanRules /etc/sysconfig/msec
fi

if [[ -f /etc/profile.d/msec.sh && -f /etc/profile.d/msec.csh ]]; then
        CleanRules /etc/profile.d/msec.sh
        CleanRules /etc/profile.d/msec.csh
else
        chmod 755 /etc/profile.d/msec.sh
        chmod 755 /etc/profile.d/msec.csh
fi  
