#!/bin/bash
# msec: network security checks

# check if we are run from main script
if [ -z "$MSEC_TMP" -o -z "$INFOS" -o -z "$SECURITY" -o -z "$DIFF" -o -z "$SECURITY_LOG" ]; then
        # variables are set in security.sh and propagated to the subscripts
        echo "Error: this check should be run by the main msec security check!"
        echo "       do not run it directly unless you know what you are doing."
        return 1
fi

export OPEN_PORT_TODAY="/var/log/security/open_port.today"
OPEN_PORT_YESTERDAY="/var/log/security/open_port.yesterday"
OPEN_PORT_DIFF="/var/log/security/open_port.diff"
export FIREWALL_TODAY="/var/log/security/open_port.today"
FIREWALL_YESTERDAY="/var/log/security/open_port.yesterday"
FIREWALL_DIFF="/var/log/security/open_port.diff"

if [[ -f ${OPEN_PORT_TODAY} ]]; then
    mv -f ${OPEN_PORT_TODAY} ${OPEN_PORT_YESTERDAY}
fi

if [[ -f ${FIREWALL_TODAY} ]]; then
    mv -f ${FIREWALL_TODAY} ${FIREWALL_YESTERDAY}
fi

if [[ ${CHECK_OPEN_PORT} == yes ]]; then
        netstat -pvlA inet,inet6 2> /dev/null > ${OPEN_PORT_TODAY};
fi

if [[ ${CHECK_FIREWALL} == yes ]]; then
        iptables -L 2>/dev/null > ${FIREWALL_TODAY}
fi

### Changed open port
if [[ ${CHECK_OPEN_PORT} == yes ]]; then

    if [[ -f ${OPEN_PORT_YESTERDAY} ]]; then
        diff -u ${OPEN_PORT_YESTERDAY} ${OPEN_PORT_TODAY} 1> ${OPEN_PORT_DIFF}
        if [ -s ${OPEN_PORT_DIFF} ]; then
            printf "\nSecurity Warning: There are modifications for port listening on your machine :\n" >> ${DIFF}
            grep '^+' ${OPEN_PORT_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-  Opened ports : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${OPEN_PORT_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- Closed ports  : ${file}\n"
            done >> ${DIFF}
        fi
    fi

fi

### Changed firewall
if [[ ${CHECK_FIREWALL} == yes ]]; then

    if [[ -f ${FIREWALL_YESTERDAY} ]]; then
        diff -u ${FIREWALL_YESTERDAY} ${FIREWALL_TODAY} 1> ${FIREWALL_DIFF}
        if [ -s ${FIREWALL_DIFF} ]; then
            printf "\nSecurity Warning: There are modifications for firewall configuration on your machine :\n" >> ${DIFF}
            grep '^+' ${FIREWALL_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-      New entries : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${FIREWALL_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- Removed entries  : ${file}\n"
            done >> ${DIFF}
        fi
    fi

fi

### Dump a list of open port.
if [[ ${CHECK_OPEN_PORT} == yes ]]; then

    if [[ -s ${OPEN_PORT_TODAY} ]]; then
        printf "\nThese are the ports listening on your machine :\n" >> ${INFOS}
        cat ${OPEN_PORT_TODAY} >> ${INFOS}
    fi
fi

