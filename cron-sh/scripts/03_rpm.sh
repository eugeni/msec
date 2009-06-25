#!/bin/bash
# msec: rpm security check

# check if we are run from main script
if [ -z "$MSEC_TMP" -o -z "$INFOS" -o -z "$SECURITY" -o -z "$DIFF" -o -z "$SECURITY_LOG" ]; then
        # variables are set in security.sh and propagated to the subscripts
        echo "Error: this check should be run by the main msec security check!"
        echo "       do not run it directly unless you know what you are doing."
        return 1
fi

export RPM_VA_TODAY="/var/log/security/rpm-va.today"
RPM_VA_YESTERDAY="/var/log/security/rpm-va.yesterday"
RPM_VA_DIFF="/var/log/security/rpm-va.diff"
export RPM_VA_CONFIG_TODAY="/var/log/security/rpm-va-config.today"
RPM_VA_CONFIG_YESTERDAY="/var/log/security/rpm-va-config.yesterday"
RPM_VA_CONFIG_DIFF="/var/log/security/rpm-va-config.diff"
export RPM_QA_TODAY="/var/log/security/rpm-qa.today"
RPM_QA_YESTERDAY="/var/log/security/rpm-qa.yesterday"
RPM_QA_DIFF="/var/log/security/rpm-qa.diff"

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

if [[ ${CHECK_RPM} == yes ]]; then
    rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\n" | sort > ${RPM_QA_TODAY}

    rm -f ${RPM_VA_TODAY}.tmp
    nice --adjustment=+19 rpm -Va --noscripts | grep '^..5' | sort > ${RPM_VA_TODAY}.tmp
    grep -v '^..........c.'  ${RPM_VA_TODAY}.tmp | sed 's/^............//' | sort > ${RPM_VA_TODAY}
    grep '^..........c.'  ${RPM_VA_TODAY}.tmp | sed 's/^............//' | sort > ${RPM_VA_CONFIG_TODAY}
    rm -f ${RPM_VA_TODAY}.tmp
fi

### rpm database checks
if [[ ${CHECK_RPM} == yes ]]; then

    if [[ -s ${RPM_VA_TODAY} ]]; then
        printf "\nSecurity Warning: These files belonging to packages are modified on the system :\n" >> ${SECURITY}
        cat ${RPM_VA_TODAY} | while read f; do
            printf "\t\t- $f\n"
        done >> ${SECURITY}
    fi

    if [[ -s ${RPM_VA_CONFIG_TODAY} ]]; then
        printf "\nSecurity Warning: These config files belonging to packages are modified on the system :\n" >> ${SECURITY}
        cat ${RPM_VA_CONFIG_TODAY} | while read f; do
            printf "\t\t- $f\n"
        done >> ${SECURITY}
    fi
fi

### rpm database
if [[ ${CHECK_RPM} == yes ]]; then
    if [[ -f ${RPM_QA_YESTERDAY} ]]; then
        diff -u ${RPM_QA_YESTERDAY} ${RPM_QA_TODAY} > ${RPM_QA_DIFF}
        if [ -s ${RPM_QA_DIFF} ]; then
            printf "\nSecurity Warning: These packages have changed on the system :\n" >> ${DIFF}
            grep '^+' ${RPM_QA_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-   Newly installed package : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${RPM_QA_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- No longer present package : ${file}\n"
            done >> ${DIFF}
        fi
    fi
    if [[ -f ${RPM_VA_YESTERDAY} ]]; then
        diff -u ${RPM_VA_YESTERDAY} ${RPM_VA_TODAY} > ${RPM_VA_DIFF}
        if [ -s ${RPM_VA_DIFF} ]; then
            printf "\nSecurity Warning: These files belonging to packages have changed of status on the system :\n" >> ${DIFF}
            grep '^+' ${RPM_VA_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-     Newly modified : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${RPM_VA_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- No longer modified : ${file}\n"
            done >> ${DIFF}
        fi
    fi
    if [[ -f ${RPM_VA_CONFIG_YESTERDAY} ]]; then
        diff -u ${RPM_VA_CONFIG_YESTERDAY} ${RPM_VA_CONFIG_TODAY} > ${RPM_VA_CONFIG_DIFF}
        if [ -s ${RPM_VA_CONFIG_DIFF} ]; then
            printf "\nSecurity Warning: These config files belonging to packages have changed of status on the system :\n" >> ${DIFF}
            grep '^+' ${RPM_VA_CONFIG_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-     Newly modified : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${RPM_VA_CONFIG_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- No longer modified : ${file}\n"
            done >> ${DIFF}
        fi
    fi
fi

