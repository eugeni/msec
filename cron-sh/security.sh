#!/bin/bash

if [[ ! -f /etc/security/msec/security.conf ]]; then
    echo "Can't access /etc/security/msec/security.conf."
    exit 1
fi

. /etc/security/msec/security.conf

SUID_ROOT_TODAY="/var/log/security/suid_root.today"
SUID_ROOT_YESTERDAY="/var/log/security/suid_root.yesterday"
SUID_ROOT_DIFF="/var/log/security/suid_root.diff"
SUID_GROUP_TODAY="/var/log/security/suid_group.today"
SUID_GROUP_YESTERDAY="/var/log/security/suid_group.yesterday"
SUID_GROUP_DIFF="/var/log/security/suid_group.diff"
SUID_MD5_TODAY="/var/log/security/suid_md5.today"
SUID_MD5_YESTERDAY="/var/log/security/suid_md5.yesterday"
SUID_MD5_DIFF="/var/log/security/suid_md5.diff"
OPEN_PORT_TODAY="/var/log/security/open_port.today"
OPEN_PORT_YESTERDAY="/var/log/security/open_port.yesterday"
OPEN_PORT_DIFF="/var/log/security/open_port.diff"
WRITEABLE_TODAY="/var/log/security/writeable.today"
WRITEABLE_YESTERDAY="/var/log/security/writeable.yesterday"
WRITEABLE_DIFF="/var/log/security/writeable.diff"
UNOWNED_USER_TODAY="/var/log/security/unowned_user.today"
UNOWNED_USER_YESTERDAY="/var/log/security/unowned_user.yesterday"
UNOWNED_USER_DIFF="/var/log/security/unowned_user.diff"
UNOWNED_GROUP_TODAY="/var/log/security/unowned_group.today"
UNOWNED_GROUP_YESTERDAY="/var/log/security/unowned_group.yesterday"
UNOWNED_GROUP_DIFF="/var/log/security/unowned_group.diff"

# Modified filters coming from debian security scripts.
CS_NFSAFS='(nfs|afs|xfs|coda)'
CS_TYPES=' type (devpts|auto|proc|msdos|fat|vfat|iso9660|ncpfs|smbfs|'$CS_NFSAFS')'
CS_DEVS='^/dev/fd'
CS_DIRS='on /mnt'
FILTERS="$CS_TYPES|$CS_DEVS|$CS_DIRS"
DIR=`mount | grep -vE "$FILTERS" | cut -d ' ' -f3`
PRINT="%h/%f\n"

if [[ ! -d /var/log/security ]]; then
    mkdir /var/log/security
fi

if [[ -f ${SUID_ROOT_TODAY} ]]; then
    mv ${SUID_ROOT_TODAY} ${SUID_ROOT_YESTERDAY};
fi

if [[ -f ${SUID_GROUP_TODAY} ]]; then
    mv ${SUID_GROUP_TODAY} ${SUID_GROUP_YESTERDAY};
fi

if [[ -f ${WRITEABLE_TODAY} ]]; then
    mv ${WRITEABLE_TODAY} ${WRITEABLE_YESTERDAY};
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


netstat -pvlA inet 2> /dev/null > ${OPEN_PORT_TODAY};
nice --adjustment=+19 find ${DIR} -xdev -type f -perm +04000 -user root -printf "${PRINT}" 2> /dev/null | sort > ${SUID_ROOT_TODAY}
nice --adjustment=+19 find ${DIR} -xdev -type f -perm +02000 -printf "${PRINT}" 2> /dev/null | sort > ${SUID_GROUP_TODAY}
nice --adjustment=+19 find ${DIR} -xdev -type f -perm -2 -printf "${PRINT}" 2> /dev/null | sort > ${WRITEABLE_TODAY}
nice --adjustment=+19 find ${DIR} -xdev -nouser -printf "${PRINT}" 2> /dev/null | sort > ${UNOWNED_USER_TODAY}
nice --adjustment=+19 find ${DIR} -xdev -nogroup -printf "${PRINT}" 2> /dev/null | sort > ${UNOWNED_GROUP_TODAY}

while read line; do 
    md5sum ${line}
done < ${SUID_ROOT_TODAY} > ${SUID_MD5_TODAY}

### Functions ###

Syslog() {
    if [[ ${SYSLOG_WARN} == yes ]]; then
    while read line; do
        /sbin/initlog --string="${line}"
    done < ${1}
    fi
}

Ttylog() {
    if [[ ${TTY_WARN} == yes ]]; then
    for i in `w | grep -v "load\|TTY" | awk '{print $2}'` ; do
        cat ${1} > /dev/$i
    done
    fi
}

Maillog() {
    subject=${1}
    text=${2}

    if [[ ${MAIL_WARN} == yes ]]; then
		if [[ ! -z ${MAIL_USER} ]]; then
			if [[ -x /bin/mail ]]; then
			    cat ${text} | /bin/mail -s "${subject}" "${MAIL_USER}"
			fi
		fi
	fi
}

##################

. /etc/security/msec/cron-sh/diff_check.sh
. /etc/security/msec/cron-sh/security_check.sh









