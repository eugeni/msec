#!/bin/bash
# msec: rpm security check

# check if we are run from main script
if [ -z "$MSEC_TMP" -o -z "$INFOS" -o -z "$SECURITY" -o -z "$DIFF" -o -z "$SECURITY_LOG" -o -z "${CURRENT_CHECK_TYPE}" ]; then
        # variables are set in security.sh and propagated to the subscripts
        echo "Error: this check should be run by the main msec security check!"
        echo "       do not run it directly unless you know what you are doing."
        exit 1
fi

export RPM_VA_TODAY="/var/log/security/rpm-va.${CURRENT_CHECK_TYPE}.today"
RPM_VA_YESTERDAY="/var/log/security/rpm-va.${CURRENT_CHECK_TYPE}.yesterday"
RPM_VA_DIFF="/var/log/security/rpm-va.${CURRENT_CHECK_TYPE}.diff"
export RPM_VA_CONFIG_TODAY="/var/log/security/rpm-va-config.${CURRENT_CHECK_TYPE}.today"
RPM_VA_CONFIG_YESTERDAY="/var/log/security/rpm-va-config.${CURRENT_CHECK_TYPE}.yesterday"
RPM_VA_CONFIG_DIFF="/var/log/security/rpm-va-config.${CURRENT_CHECK_TYPE}.diff"
export RPM_QA_TODAY="/var/log/security/rpm-qa.${CURRENT_CHECK_TYPE}.today"
RPM_QA_YESTERDAY="/var/log/security/rpm-qa.${CURRENT_CHECK_TYPE}.yesterday"
RPM_QA_DIFF="/var/log/security/rpm-qa.${CURRENT_CHECK_TYPE}.diff"

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

### rpm database check

# list of installed packages
if check_is_enabled "${CHECK_RPM_PACKAGES}" ; then
    rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}\n" | sort > ${RPM_QA_TODAY}
    Filter ${RPM_QA_TODAY} CHECK_RPM_PACKAGES
    Count ${INFOS} ${RPM_QA_TODAY} "Total of installed packages"
    Diffcheck ${RPM_QA_TODAY} ${RPM_QA_YESTERDAY} ${RPM_QA_DIFF} "packages"
fi

# integrity of installed packages
if check_is_enabled "${CHECK_RPM_INTEGRITY}" ; then
    rm -f ${RPM_VA_TODAY}.tmp
    nice --adjustment=+19 rpm -Va | grep '^..5' | sort > ${RPM_VA_TODAY}.tmp
    Filter ${RPM_VA_TODAY} CHECK_RPM_INTEGRITY
    grep -v '^..........c.'  ${RPM_VA_TODAY}.tmp | sed 's/^............//' | sort > ${RPM_VA_TODAY}
    grep '^..........c.'  ${RPM_VA_TODAY}.tmp | sed 's/^............//' | sort > ${RPM_VA_CONFIG_TODAY}
    rm -f ${RPM_VA_TODAY}.tmp

    # full check
    if [[ -s ${RPM_VA_TODAY} ]]; then
        printf "\nSecurity Warning: These files belonging to packages are modified on the system :\n" >> ${SECURITY}
        Count ${INFOS} ${RPM_VA_TODAY} "Total of files belonging to packages that were modified since the install"
        cat ${RPM_VA_TODAY} >> ${SECURITY}
    fi

    if [[ -s ${RPM_VA_CONFIG_TODAY} ]]; then
        printf "\nSecurity Warning: These config files belonging to packages are modified on the system :\n" >> ${SECURITY}
        Count ${INFOS} ${RPM_VA_CONFIG_TODAY} "Total of configuration files belonging to packages that were modified since the install"
        cat ${RPM_VA_CONFIG_TODAY} >> ${SECURITY}
    fi

    # diff check
    Diffcheck ${RPM_VA_TODAY} ${RPM_VA_YESTERDAY} ${RPM_VA_DIFF} "modifications to package files"
    Diffcheck ${RPM_VA_CONFIG_TODAY} ${RPM_VA_CONFIG_YESTERDAY} ${RPM_VA_CONFIG_DIFF} "modifications to package configuration files"
fi

