#!/bin/bash
#
# Written by Vandoorselaere Yoann, <yoann@mandrakesoft.com>
#

if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
else
	echo "/etc/security/msec/security.conf don't exist."
    exit 1
fi

if [[ ${CHECK_SECURITY} == no ]]; then
    exit 0
fi

# Modified filters coming from debian security scripts.
CS_NFSAFS='(nfs|afs|xfs|coda)'
CS_TYPES=' type (devpts|auto|proc|msdos|fat|vfat|iso9660|ncpfs|smbfs|'$CS_NFSAFS')'
CS_DEVS='^/dev/fd'
CS_DIRS='on /mnt'
FILTERS="$CS_TYPES|$CS_DEVS|$CS_DIRS"
DIR=`mount | grep -vE "$FILTERS" | cut -d ' ' -f3`
###

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
UNOWNED_TODAY="/var/log/security/unowned.today"
UNOWNED_YESTERDAY="/var/log/security/unowned.yesterday"
UNOWNED_DIFF="/var/log/security/unowned.diff"

SECURITY_LOG="/var/log/security.log"
TMP=`mktemp /tmp/secure.XXXXXX`

if [[ ! -d /var/log/security ]]; then
    mkdir /var/log/security
fi

rm -f ${TMP} ${SECURITY_TMP} >& /dev/null

### Functions ###

Syslog() {
    if [[ ${SYSLOG_WARN} == yes ]]; then
	cat ${1} | while read line; do
	    /sbin/initlog --string="${line}"
	done
    fi
}

Ttylog() {
	if [[ ${TTY_WARN} == yes ]]; then
		for i in `w | grep -v "load\|TTY" | awk '{print $2}'` ; do
			echo -e "$1" > /dev/$i
		done
	fi
}

##################


### New Suid root files detection
if [[ ${CHECK_SUID_ROOT} == yes ]]; then

    if [[ -f ${SUID_ROOT_TODAY} ]]; then
	mv ${SUID_ROOT_TODAY} ${SUID_ROOT_YESTERDAY}
    fi

    find ${DIR} -xdev -type f -perm +04000 -user root \
	-printf "%8i %5m %3n %-10u %-10g %9s %t %h/%f\n" | sort > ${SUID_ROOT_TODAY}

    if [[ -f ${SUID_ROOT_YESTERDAY} ]]; then
	if ! diff -u ${SUID_ROOT_YESTERDAY} ${SUID_ROOT_TODAY} > ${SUID_ROOT_DIFF}; then
	    printf "\nSecurity Warning: Change in Suid Root files found :\n" >> ${TMP}
	    grep '^+' ${SUID_ROOT_DIFF} | grep -vw "^+++ " |  sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Added suid root files : ${file}.\n" >> ${TMP}
	    done
	    grep '^-' ${SUID_ROOT_DIFF} | grep -vw "^--- " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Removed suid root files : ${file}.\n" >> ${TMP}
	    done
	fi
    fi
fi

### New Suid group files detection
if [[ ${CHECK_SUID_GROUP} == yes ]]; then

    if [[ -f ${SUID_GROUP_TODAY} ]]; then
	mv ${SUID_GROUP_TODAY} ${SUID_GROUP_YESTERDAY}
    fi

    find ${DIR} -xdev -type f -perm +02000 \
	-printf "%8i %5m %3n %-10u %-10g %9s %t %h/%f\n" | sort > ${SUID_GROUP_TODAY}

    if [[ -f ${SUID_GROUP_YESTERDAY} ]]; then
	if ! diff -u ${SUID_GROUP_YESTERDAY} ${SUID_GROUP_TODAY} > ${SUID_GROUP_DIFF}; then
	    printf "\nSecurity Warning: Changes in Suid Group files found :\n" >> ${TMP}
	    grep '^+' ${SUID_GROUP_DIFF} | grep -vw "^+++ " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Added suid group files : ${file}.\n" >> ${TMP}
	    done
	    grep '^-' ${SUID_GROUP_DIFF} | grep -vw "^--- " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Removed suid group files : ${file}.\n" >> ${TMP}
	    done
	fi
    fi
fi

### Writable files detection
if [[ ${CHECK_WRITEABLE} == yes ]]; then

    if [[ -f ${WRITEABLE_TODAY} ]]; then
	mv -f ${WRITEABLE_TODAY} ${WRITEABLE_YESTERDAY}
    fi

    find ${DIR} -xdev -type f -perm -2 -ls -print | sort > ${WRITEABLE_TODAY}

    if [[ -f ${WRITEABLE_YESTERDAY} ]]; then
	if ! diff -u ${WRITEABLE_YESTERDAY} ${WRITEABLE_TODAY} > ${WRITEABLE_DIFF}; then
	    printf "\nSecurity Warning: Change in World Writeable Files found :\n" >> ${TMP}
	    grep '^+' ${WRITEABLE_DIFF} | grep -vw "^+++ " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Added writables files : ${file}.\n" >> ${TMP}
	    done
	    grep '^-' ${WRITEABLE_DIFF} | grep -vw "^--- " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Removed writables files : ${file}.\n" >> ${TMP}
	    done
	fi
    fi
fi

### Search Non Owned files
if [[ ${CHECK_UNOWNED} == yes ]]; then

    if [[ -f ${UNOWNED_TODAY} ]]; then
	mv -f ${UNOWNED_TODAY} ${UNOWNED_YESTERDAY}
    fi

    find ${DIR} -xdev -nouser -print -ls | sort > ${UNOWNED_TODAY}
    
    if [[ -f ${UNOWNED_YESTERDAY} ]]; then
	if ! diff -u ${UNOWNED_YESTERDAY} ${UNOWNED_TODAY} > ${UNOWNED_DIFF}; then
	    printf "\nSecurity Warning: the following files aren't owned by an user :\n" >> ${TMP}
	    grep '^+' ${UNOWNED_DIFF} | grep -vw "^--- " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Added un-owned files : ${file}.\n" >> ${TMP}
	    done
	    grep '^-' ${UNOWNED_DIFF} | grep -vw "^+++ " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Removed un-owned files : ${file}.\n" >> ${TMP}
	    done
	fi
    fi
 
    find ${DIR} -xdev -nogroup -print -ls | sort >> ${UNOWNED_TODAY}

    if [[ -f ${UNOWNED_YESTERDAY} ]]; then
	if ! diff -u ${UNOWNED_YESTERDAY} ${UNOWNED_TODAY} > ${UNOWNED_DIFF}; then
	    printf "\nSecurity Warning: the following files aren't owned by a group :\n" >> ${TMP}
	    grep '^+' ${UNOWNED_DIFF} | grep -vw "^+++ " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Added un-owned files : ${file}.\n" >> ${TMP}
	    done
	    grep '^-' ${UNOWNED_DIFF} | grep -vw "^--- " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Removed un-owned files : ${file}.\n" >> ${TMP}
	    done
	fi
    fi
fi

### Md5 check for SUID root file
if [[ ${CHECK_SUID_MD5} == yes  ]]; then
 
    if [[ -f ${SUID_MD5_TODAY} ]]; then
	mv ${SUID_MD5_TODAY} ${SUID_MD5_YESTERDAY}
    fi

    touch ${SUID_MD5_TODAY}
    awk '{print $12}' ${SUID_ROOT_TODAY} |
	while read line; do 
	    md5sum ${line} >> ${SUID_MD5_TODAY}
	done
	
    if [[ -f ${SUID_MD5_YESTERDAY} ]]; then
	if ! diff -u ${SUID_MD5_YESTERDAY} ${SUID_MD5_TODAY} > ${SUID_MD5_DIFF}; then
	    printf "\nSecurity Warning: the md5 checksum for one of your SUID files has changed,\n" >> ${TMP}
	    printf "\tmaybe an intruder modified one of these suid binary in order to put in a backdoor...\n" >> ${TMP}
	    grep '^+' ${SUID_MD5_DIFF} | grep -vw "^+++ " | sed 's|^.||' | awk '{print $2}' | while read file; do
		printf "\t\t- Changed ( added ) files : ${file}.\n" >> ${TMP}
	    done
	    grep '^-' ${SUID_MD5_DIFF} | grep -vw "^--- " | sed 's|^.||' | awk '{print $2}' | while read file; do
		printf "\t\t- Changed ( removed ) files : ${file}.\n" >> ${TMP}
	    done
	fi
    fi
fi

### Changed open port
if [[ ${CHECK_OPEN_PORT} == yes ]]; then

    if [[ -f ${OPEN_PORT_TODAY} ]]; then
	mv -f ${OPEN_PORT_TODAY} ${OPEN_PORT_YESTERDAY}
    fi

    netstat -pvlA inet > ${OPEN_PORT_TODAY};
    
    if [[ -f ${OPEN_PORT_YESTERDAY} ]]; then
	if ! diff -u ${OPEN_PORT_YESTERDAY} ${OPEN_PORT_TODAY} 1> ${OPEN_PORT_DIFF}; then
	    printf "\nSecurity Warning: There is a new port listening on your machine :\n" >> ${TMP}
	    grep '^+' ${OPEN_PORT_DIFF} | grep -vw "^+++ " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t-  Opened ports : ${file}.\n" >> ${TMP}
	    done
	    grep '^-' ${OPEN_PORT_DIFF} | grep -vw "^--- " | sed 's|^.||' | awk '{print $12}' | while read file; do
		printf "\t\t- Closed ports  : ${file}.\n" >> ${TMP}
	    done
        fi
    fi
fi

######## Report ######
if [[ -s ${TMP} ]]; then
    Syslog ${TMP}
    Ttylog ${TMP}
    date=`date`
    echo -e "\n\n*** Diff Check, ${date} ***\n" >> ${SECURITY_LOG}
    cat ${TMP} >> ${SECURITY_LOG}
fi

if [[ -f ${TMP} ]]; then
	rm -f ${TMP}
fi
