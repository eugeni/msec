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
        res=$?
        if [ "$res" = "0" ]; then
                chkrootkit_result="passed"
        else
                chkrootkit_result="failed"
        fi
        if [[ -s ${CHKROOTKIT_TODAY} ]]; then
            printf "\nChkrootkit report:\n" >> ${SECURITY}
            cat ${CHKROOTKIT_TODAY} >> ${SECURITY}
            echo "Chkrootkit check: $chkrootkit_result" >> ${INFOS}
        fi
    else
            printf "\nChkrootkit check skipped: chkrootkit not found" >> ${SECURITY}
            echo "Chkrootkit check: skipped (chkrootkit not found)" >> ${INFOS}
    fi
fi

### Changed chkrootkit
if [[ ${CHECK_CHKROOTKIT} == yes ]]; then
    Diffcheck ${CHKROOTKIT_TODAY} ${CHKROOTKIT_YESTERDAY} ${CHKROOTKIT_DIFF} "chkrootkit results"
fi

