#!/bin/bash

. /etc/sysconfig/i18n
LCK=/var/run/msec-security.pid

function cleanup() {
    rm -f $LCK
}

if [ -f $LCK ]; then
    if [ -d /proc/`cat $LCK` ]; then
    	exit 0
    else
    	rm -f $LCK
    fi
fi

echo -n $$ > $LCK

trap cleanup 0

if [[ ! -f /var/lib/msec/security.conf ]]; then
    echo "Can't access /var/lib/msec/security.conf."
    exit 1
fi

. /var/lib/msec/security.conf

if [ -r /etc/security/msec/security.conf ]; then
    . /etc/security/msec/security.conf
fi

if [ -r /etc/sysconfig/msec ]; then
    . /etc/sysconfig/msec
fi

umask ${UMASK_ROOT=077}

[[ ${MAIL_WARN} == yes ]] && [ -z ${MAIL_USER} ] && MAIL_USER="root"

export SUID_ROOT_TODAY="/var/log/security/suid_root.today"
SUID_ROOT_YESTERDAY="/var/log/security/suid_root.yesterday"
SUID_ROOT_DIFF="/var/log/security/suid_root.diff"
export SGID_TODAY="/var/log/security/sgid.today"
SGID_YESTERDAY="/var/log/security/sgid.yesterday"
SGID_DIFF="/var/log/security/sgid.diff"
export SUID_MD5_TODAY="/var/log/security/suid_md5.today"
SUID_MD5_YESTERDAY="/var/log/security/suid_md5.yesterday"
SUID_MD5_DIFF="/var/log/security/suid_md5.diff"
export OPEN_PORT_TODAY="/var/log/security/open_port.today"
OPEN_PORT_YESTERDAY="/var/log/security/open_port.yesterday"
OPEN_PORT_DIFF="/var/log/security/open_port.diff"
export WRITABLE_TODAY="/var/log/security/writable.today"
WRITABLE_YESTERDAY="/var/log/security/writable.yesterday"
WRITABLE_DIFF="/var/log/security/writable.diff"
export UNOWNED_USER_TODAY="/var/log/security/unowned_user.today"
UNOWNED_USER_YESTERDAY="/var/log/security/unowned_user.yesterday"
UNOWNED_USER_DIFF="/var/log/security/unowned_user.diff"
export UNOWNED_GROUP_TODAY="/var/log/security/unowned_group.today"
UNOWNED_GROUP_YESTERDAY="/var/log/security/unowned_group.yesterday"
UNOWNED_GROUP_DIFF="/var/log/security/unowned_group.diff"
export RPM_VA_TODAY="/var/log/security/rpm-va.today"
RPM_VA_YESTERDAY="/var/log/security/rpm-va.yesterday"
RPM_VA_DIFF="/var/log/security/rpm-va.diff"
export RPM_VA_CONFIG_TODAY="/var/log/security/rpm-va-config.today"
RPM_VA_CONFIG_YESTERDAY="/var/log/security/rpm-va-config.yesterday"
RPM_VA_CONFIG_DIFF="/var/log/security/rpm-va-config.diff"
export RPM_QA_TODAY="/var/log/security/rpm-qa.today"
RPM_QA_YESTERDAY="/var/log/security/rpm-qa.yesterday"
RPM_QA_DIFF="/var/log/security/rpm-qa.diff"
export CHKROOTKIT_TODAY="/var/log/security/chkrootkit.today"
CHKROOTKIT_YESTERDAY="/var/log/security/chkrootkit.yesterday"
CHKROOTKIT_DIFF="/var/log/security/chkrootkit.diff"
export EXCLUDE_REGEXP

# Modified filters coming from debian security scripts.
# rootfs is not listed among excluded types, because 
# / is mounted twice, and filtering it would mess with excluded dir list
TYPE_FILTER='(devpts|sysfs|usbfs|tmpfs|binfmt_misc|rpc_pipefs|securityfs|auto|proc|msdos|fat|vfat|iso9660|ncpfs|smbfs|hfs|nfs|afs|coda|cifs)'
MOUNTPOINT_FILTER='^\/mnt|^\/media'
DIR=`awk '$3 !~ /'$TYPE_FILTER'/ && $2 !~ /'$MOUNTPOINT_FILTER'/ \
	{print $2}' /proc/mounts | uniq`
PRINT="%h/%f\n"
EXCLUDEDIR=`awk '$3 ~ /'$TYPE_FILTER'/ || $2 ~ /'$MOUNTPOINT_FILTER'/ \
	{print $2}' /proc/mounts | uniq`
export EXCLUDEDIR

if [[ ! -d /var/log/security ]]; then
    mkdir /var/log/security
fi

if [[ -f ${SUID_ROOT_TODAY} ]]; then
    mv ${SUID_ROOT_TODAY} ${SUID_ROOT_YESTERDAY};
fi

if [[ -f ${SGID_TODAY} ]]; then
    mv ${SGID_TODAY} ${SGID_YESTERDAY};
fi

if [[ -f ${WRITABLE_TODAY} ]]; then
    mv ${WRITABLE_TODAY} ${WRITABLE_YESTERDAY};
fi

if [[ -f ${UNOWNED_USER_TODAY} ]]; then
    mv ${UNOWNED_USER_TODAY} ${UNOWNED_USER_YESTERDAY};
fi

if [[ -f ${UNOWNED_GROUP_TODAY} ]]; then
    mv ${UNOWNED_GROUP_TODAY} ${UNOWNED_GROUP_YESTERDAY};
fi

if [[ -f ${OPEN_PORT_TODAY} ]]; then
    mv -f ${OPEN_PORT_TODAY} ${OPEN_PORT_YESTERDAY}
fi

if [[ -f ${SUID_MD5_TODAY} ]]; then
    mv ${SUID_MD5_TODAY} ${SUID_MD5_YESTERDAY};
fi

if [[ -f ${RPM_VA_TODAY} ]]; then
    mv -f ${RPM_VA_TODAY} ${RPM_VA_YESTERDAY}
fi

if [[ -f ${RPM_VA_CONFIG_TODAY} ]]; then
    mv -f ${RPM_VA_CONFIG_TODAY} ${RPM_VA_CONFIG_YESTERDAY}
fi

if [[ -f ${RPM_QA_TODAY} ]]; then
    mv -f ${RPM_QA_TODAY} ${RPM_QA_YESTERDAY}
fi

if [[ -f ${CHKROOTKIT_TODAY} ]]; then
    mv -f ${CHKROOTKIT_TODAY} ${CHKROOTKIT_YESTERDAY}
fi

netstat -pvlA inet,inet6 2> /dev/null > ${OPEN_PORT_TODAY};

ionice -c3 -p $$

# Hard disk related file check; the less priority the better...
nice --adjustment=+19 /usr/bin/msec_find ${DIR}

if [[ -f ${SUID_ROOT_TODAY} ]]; then
    sort < ${SUID_ROOT_TODAY} > ${SUID_ROOT_TODAY}.tmp
    mv -f ${SUID_ROOT_TODAY}.tmp ${SUID_ROOT_TODAY}
fi

if [[ -f ${SGID_TODAY} ]]; then
    sort < ${SGID_TODAY} > ${SGID_TODAY}.tmp
    mv -f ${SGID_TODAY}.tmp ${SGID_TODAY}
fi

if [[ -f ${WRITABLE_TODAY} ]]; then
    sort < ${WRITABLE_TODAY} | egrep -v '^(/var)?/tmp$' > ${WRITABLE_TODAY}.tmp
    mv -f ${WRITABLE_TODAY}.tmp ${WRITABLE_TODAY}    
fi

if [[ -f ${UNOWNED_USER_TODAY} ]]; then
    sort < ${UNOWNED_USER_TODAY} > ${UNOWNED_USER_TODAY}.tmp
    mv -f ${UNOWNED_USER_TODAY}.tmp ${UNOWNED_USER_TODAY}
fi

if [[ -f ${UNOWNED_GROUP_TODAY} ]]; then
    sort < ${UNOWNED_GROUP_TODAY} > ${UNOWNED_GROUP_TODAY}.tmp
    mv -f ${UNOWNED_GROUP_TODAY}.tmp ${UNOWNED_GROUP_TODAY}
fi

if [[ -f ${SUID_ROOT_TODAY} ]]; then
    while read line; do 
	md5sum ${line}
    done < ${SUID_ROOT_TODAY} > ${SUID_MD5_TODAY}
fi

### rpm database check

if [[ ${RPM_CHECK} == yes ]]; then
    rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\n" | sort > ${RPM_QA_TODAY}

    rm -f ${RPM_VA_TODAY}.tmp
    cut -f 1 < ${RPM_QA_TODAY} | grep -v '^dev-[0-9]' | xargs -s 1024 nice --adjustment=+19 rpm -V | grep '^..5' | sort > ${RPM_VA_TODAY}.tmp
    grep -v '^..........c.'  ${RPM_VA_TODAY}.tmp | sed 's/^............//' | sort > ${RPM_VA_TODAY}
    grep '^..........c.'  ${RPM_VA_TODAY}.tmp | sed 's/^............//' | sort > ${RPM_VA_CONFIG_TODAY}
    rm -f ${RPM_VA_TODAY}.tmp
fi

### chkrootkit checks
if [[ ${CHKROOTKIT_CHECK} == yes ]]; then
    if [ -x /usr/sbin/chkrootkit ]; then
	/usr/sbin/chkrootkit ${CHKROOTKIT_OPTION} > ${CHKROOTKIT_TODAY}
    fi
fi

### Functions ###

Syslog() {
    if [[ ${SYSLOG_WARN} == yes ]]; then
    while read line; do
        logger -- "${line}"
    done < ${1}
    fi
}

Ttylog() {
    if [[ ${TTY_WARN} == yes ]]; then
    for i in `w | grep -v "load\|TTY" | grep '^root' | awk '{print $2}'` ; do
        cat ${1} > /dev/$i
    done
    fi
}

Maillog() {
    subject=${1}
    text=${2}
    SOMETHING_TO_SEND=
    
    if [[ ${MAIL_WARN} == yes ]]; then
	if [[ -z ${MAIL_USER} ]]; then 
	    MAIL_USER="root"
	fi
	if [[ -x /bin/mail ]]; then
	    for f in ${text}; do
		if [[ -s $f ]]; then
		    SOMETHING_TO_SEND=1
		    break
		fi
	    done
	    if [[ -z ${SOMETHING_TO_SEND} ]]; then
		if [[ ${MAIL_EMPTY_CONTENT} != no ]]; then
		    /bin/mail -s "${subject}" "${MAIL_USER}" <<EOF
Nothing has changed since the last run.
EOF
                fi
            else
		# remove non-printable characters,
                # see http://qa.mandriva.com/show_bug.cgi?id=36848 and https://qa.mandriva.com/show_bug.cgi?id=26773
                cat ${text} | sed -e "s,[[:cntrl:]],,g" | LC_CTYPE=$LC_CTYPE /bin/mail -s "${subject}" "${MAIL_USER}"
	    fi
	fi
    fi
}

##################

. /usr/share/msec/diff_check.sh
. /usr/share/msec/security_check.sh

