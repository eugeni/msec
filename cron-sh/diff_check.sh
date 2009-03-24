#!/bin/bash
#
# Written by Vandoorselaere Yoann
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

SECURITY_LOG="/var/log/security.log"
TMP=`mktemp /tmp/secure.XXXXXX`

### New Suid root files detection
if [[ ${CHECK_SUID_ROOT} == yes ]]; then

    if [[ -f ${SUID_ROOT_YESTERDAY} ]]; then
	if ! diff -u ${SUID_ROOT_YESTERDAY} ${SUID_ROOT_TODAY} > ${SUID_ROOT_DIFF}; then
	    printf "\nSecurity Warning: Change in Suid Root files found :\n" >> ${TMP}
	    grep '^+' ${SUID_ROOT_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-       Newly added suid root file : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${SUID_ROOT_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- No longer present suid root file : ${file}\n"
	    done >> ${TMP}
	fi
    fi

fi

### New Sgid files detection
if [[ ${CHECK_SGID} == yes ]]; then

    if [[ -f ${SGID_YESTERDAY} ]]; then
	if ! diff -u ${SGID_YESTERDAY} ${SGID_TODAY} > ${SGID_DIFF}; then
            printf "\nSecurity Warning: Changes in Sgid files found :\n" >> ${TMP}
	    grep '^+' ${SGID_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-       Newly added sgid file : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${SGID_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- No longer present sgid file : ${file}\n"
	    done >> ${TMP}
	fi
    fi

fi

### Writable files detection
if [[ ${CHECK_WRITABLE} == yes ]]; then

    if [[ -f ${WRITABLE_YESTERDAY} ]]; then
	diff -u ${WRITABLE_YESTERDAY} ${WRITABLE_TODAY} > ${WRITABLE_DIFF}
	if [ -s ${WRITABLE_DIFF} ]; then
	    printf "\nSecurity Warning: Change in World Writable Files found :\n" >> ${TMP}
	    grep '^+' ${WRITABLE_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-       Newly added writable file : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${WRITABLE_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- No longer present writable file : ${file}\n"
	    done >> ${TMP}
	fi
    fi

fi

### Search Non Owned files
if [[ ${CHECK_UNOWNED} == yes ]]; then

    if [[ -f ${UNOWNED_USER_YESTERDAY} ]]; then
	diff -u ${UNOWNED_USER_YESTERDAY} ${UNOWNED_USER_TODAY} > ${UNOWNED_USER_DIFF}
	if [ -s ${UNOWNED_USER_DIFF} ]; then
	    printf "\nSecurity Warning: the following files aren't owned by an user :\n" >> ${TMP}
	    grep '^+' ${UNOWNED_USER_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-       Newly added un-owned file : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${UNOWNED_USER_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- No longer present un-owned file : ${file}\n"
	    done >> ${TMP}
	fi
    fi

    if [[ -f ${UNOWNED_GROUP_YESTERDAY} ]]; then
	diff -u ${UNOWNED_GROUP_YESTERDAY} ${UNOWNED_GROUP_TODAY} > ${UNOWNED_GROUP_DIFF}
	if [ -s ${UNOWNED_GROUP_DIFF} ]; then
	    printf "\nSecurity Warning: the following files aren't owned by a group :\n" >> ${TMP}
	    grep '^+' ${UNOWNED_GROUP_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-       Newly added un-owned file : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${UNOWNED_GROUP_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- No longer present un-owned file : ${file}\n"
	    done >> ${TMP}
	fi
    fi

fi

### Md5 check for SUID root fileg
if [[ ${CHECK_SUID_MD5} == yes  ]]; then
    ctrl_md5=0;
	
    if [[ -f ${SUID_MD5_YESTERDAY} ]]; then
	diff -u ${SUID_MD5_YESTERDAY} ${SUID_MD5_TODAY} > ${SUID_MD5_DIFF}
	if [ -s ${SUID_MD5_DIFF} ]; then
	    grep '^+' ${SUID_MD5_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | awk '{print $2}' | while read file; do
		if cat ${SUID_MD5_YESTERDAY} | awk '{print $2}' | grep -qw ${file}; then
		    if [[ ${ctrl_md5} == 0 ]]; then
			printf "\nSecurity Warning: the md5 checksum for one of your SUID files has changed,\n" >> ${TMP}
			printf "\tmaybe an intruder modified one of these suid binary in order to put in a backdoor...\n" >> ${TMP}
			ctrl_md5=1;
		    fi
		    printf "\t\t- Checksum changed file : ${file}\n"
		fi
	    done >> ${TMP}
	fi
    fi

fi

### Changed open port
if [[ ${CHECK_OPEN_PORT} == yes ]]; then
    
    if [[ -f ${OPEN_PORT_YESTERDAY} ]]; then
	diff -u ${OPEN_PORT_YESTERDAY} ${OPEN_PORT_TODAY} 1> ${OPEN_PORT_DIFF}
	if [ -s ${OPEN_PORT_DIFF} ]; then
	    printf "\nSecurity Warning: There are modifications for port listening on your machine :\n" >> ${TMP}
	    grep '^+' ${OPEN_PORT_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-  Opened ports : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${OPEN_PORT_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- Closed ports  : ${file}\n"
	    done >> ${TMP}
        fi
    fi

fi

### rpm database
if [[ ${CHECK_RPM} == yes ]]; then
    if [[ -f ${RPM_QA_YESTERDAY} ]]; then
	diff -u ${RPM_QA_YESTERDAY} ${RPM_QA_TODAY} > ${RPM_QA_DIFF}
	if [ -s ${RPM_QA_DIFF} ]; then
	    printf "\nSecurity Warning: These packages have changed on the system :\n" >> ${TMP}
	    grep '^+' ${RPM_QA_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-   Newly installed package : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${RPM_QA_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- No longer present package : ${file}\n"
	    done >> ${TMP}
	fi
    fi
    if [[ -f ${RPM_VA_YESTERDAY} ]]; then
	diff -u ${RPM_VA_YESTERDAY} ${RPM_VA_TODAY} > ${RPM_VA_DIFF}
	if [ -s ${RPM_VA_DIFF} ]; then
	    printf "\nSecurity Warning: These files belonging to packages have changed of status on the system :\n" >> ${TMP}
	    grep '^+' ${RPM_VA_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-     Newly modified : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${RPM_VA_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- No longer modified : ${file}\n"
	    done >> ${TMP}
	fi
    fi
    if [[ -f ${RPM_VA_CONFIG_YESTERDAY} ]]; then
	diff -u ${RPM_VA_CONFIG_YESTERDAY} ${RPM_VA_CONFIG_TODAY} > ${RPM_VA_CONFIG_DIFF}
	if [ -s ${RPM_VA_CONFIG_DIFF} ]; then
	    printf "\nSecurity Warning: These config files belonging to packages have changed of status on the system :\n" >> ${TMP}
	    grep '^+' ${RPM_VA_CONFIG_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t-     Newly modified : ${file}\n"
	    done >> ${TMP}
	    grep '^-' ${RPM_VA_CONFIG_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
		printf "\t\t- No longer modified : ${file}\n"
	    done >> ${TMP}
	fi
    fi
fi

### Changed chkrootkit
if [[ ${CHECK_CHKROOTKIT} == yes ]]; then

    if [[ -f ${CHKROOTKIT_YESTERDAY} ]]; then
       diff -u ${CHKROOTKIT_YESTERDAY} ${CHKROOTKIT_TODAY} 1> ${CHKROOTKIT_DIFF}
       if [ -s ${CHKROOTKIT_DIFF} ]; then
           printf "\nSecurity Warning: There are modifications for chkrootkit results :\n" >> ${TMP}
           grep '^+' ${CHKROOTKIT_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
               printf "\t\t-  Added : ${file}\n"
           done >> ${TMP}
           grep '^-' ${CHKROOTKIT_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
               printf "\t\t- Removed  : ${file}\n"
           done >> ${TMP}
        fi
    fi
fi


######## Report ######
date=`date`
hostname=`hostname`

if [[ -s ${TMP} ]]; then
    Syslog ${TMP}
    Ttylog ${TMP}

    echo -e "\n\n*** Diff Check, ${date} ***\n" >> ${SECURITY_LOG}
    cat ${TMP} >> ${SECURITY_LOG}

    Notifylog "MSEC has performed Diff Check on ${hostname} on ${date}\nChanges in system security were detected and are available in ${SECURITY_LOG}."
fi

Maillog "[msec] *** Diff Check on ${hostname}, ${date} ***" "${TMP}"
Notifylog "MSEC has performed Diff Check on ${hostname} on ${date}\nNo changes were detected in system security."

if [[ -f ${TMP} ]]; then
	rm -f ${TMP}
fi

