#!/bin/bash
# msec: rootkit security check

# check if we are run from main script
if [ -z "$MSEC_TMP" -o -z "$INFOS" -o -z "$SECURITY" -o -z "$DIFF" -o -z "$SECURITY_LOG" ]; then
        # variables are set in security.sh and propagated to the subscripts
        echo "Error: this check should be run by the main msec security check!"
        echo "       do not run it directly unless you know what you are doing."
        return 1
fi

export CHKROOTKIT_TODAY="/var/log/security/chkrootkit.today"
CHKROOTKIT_YESTERDAY="/var/log/security/chkrootkit.yesterday"
CHKROOTKIT_DIFF="/var/log/security/chkrootkit.diff"

### chkrootkit checks
if [[ ${CHECK_CHKROOTKIT} == yes ]]; then
    if [ -x /usr/sbin/chkrootkit ]; then
        # do not check on NFS
        /usr/sbin/chkrootkit -n ${CHKROOTKIT_OPTION} > ${CHKROOTKIT_TODAY}
    fi
fi

### chkrootkit checks
if [[ ${CHECK_CHKROOTKIT} == yes ]]; then

    if [[ -s ${CHKROOTKIT_TODAY} ]]; then
        printf "\nChkrootkit report:\n" >> ${SECURITY}
        cat ${CHKROOTKIT_TODAY} >> ${SECURITY}
    fi
fi

### Changed chkrootkit
if [[ ${CHECK_CHKROOTKIT} == yes ]]; then

    if [[ -f ${CHKROOTKIT_YESTERDAY} ]]; then
       diff -u ${CHKROOTKIT_YESTERDAY} ${CHKROOTKIT_TODAY} 1> ${CHKROOTKIT_DIFF}
       if [ -s ${CHKROOTKIT_DIFF} ]; then
           printf "\nSecurity Warning: There are modifications for chkrootkit results :\n" >> ${DIFF}
           grep '^+' ${CHKROOTKIT_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
               printf "\t\t-  Added : ${file}\n"
           done >> ${DIFF}
           grep '^-' ${CHKROOTKIT_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
               printf "\t\t- Removed  : ${file}\n"
           done >> ${DIFF}
        fi
    fi
fi

