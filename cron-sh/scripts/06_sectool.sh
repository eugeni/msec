#!/bin/bash
# msec: sectool check

# check if we are run from main script
if [ -z "$MSEC_TMP" -o -z "$INFOS" -o -z "$SECURITY" -o -z "$DIFF" -o -z "$SECURITY_LOG" -o -z "${CURRENT_CHECK_TYPE}" ]; then
        # variables are set in security.sh and propagated to the subscripts
        echo "Error: this check should be run by the main msec security check!"
        echo "       do not run it directly unless you know what you are doing."
        return 1
fi

# check for changes in users
SECTOOL_TODAY="/var/log/security/sectool.${CURRENT_CHECK_TYPE}.today"
SECTOOL_YESTERDAY="/var/log/security/sectool.${CURRENT_CHECK_TYPE}.yesterday"
SECTOOL_DIFF="/var/log/security/sectool.${CURRENT_CHECK_TYPE}.diff"

if [[ -f ${SECTOOL_TODAY} ]]; then
    mv ${SECTOOL_TODAY} ${SECTOOL_YESTERDAY};
fi

# check for changes in sectool results
if check_is_enabled "${CHECK_SECTOOL}" ; then
    if [ -x /usr/sbin/sectool ]; then
        if [ ! -z "$CHECK_SECTOOL_LEVEL" ]; then
            sectool_params="-L ${CHECK_SECTOOL_LEVEL}"
        else
            sectool_params="-a"
        fi
        sectool $sectool_params > ${SECTOOL_TODAY}
        Filter ${SECTOOL_TODAY} CHECK_SECTOOL
        if [[ -s ${SECTOOL_TODAY} ]]; then
            printf "\nSectool report:\n" >> ${SECURITY}
            cat ${SECTOOL_TODAY} >> ${SECURITY}
        fi
        Diffcheck ${SECTOOL_TODAY} ${SECTOOL_YESTERDAY} ${SECTOOL_DIFF} "sectool results"
    else
        printf "\nSectool check skipped: sectool not found" >> ${SECURITY}
        echo "Sectool check: skipped (sectool not found)" >> ${INFOS}
    fi
fi
