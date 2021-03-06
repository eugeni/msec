#!/bin/bash
# msec: network security checks

# check if we are run from main script
if [ -z "$MSEC_TMP" -o -z "$INFOS" -o -z "$SECURITY" -o -z "$DIFF" -o -z "$SECURITY_LOG" -o -z "${CURRENT_CHECK_TYPE}" ]; then
        # variables are set in security.sh and propagated to the subscripts
        echo "Error: this check should be run by the main msec security check!"
        echo "       do not run it directly unless you know what you are doing."
        exit 1
fi

export OPEN_PORT_TODAY="/var/log/security/open_port.${CURRENT_CHECK_TYPE}.today"
OPEN_PORT_YESTERDAY="/var/log/security/open_port.${CURRENT_CHECK_TYPE}.yesterday"
OPEN_PORT_DIFF="/var/log/security/open_port.${CURRENT_CHECK_TYPE}.diff"
export FIREWALL_TODAY="/var/log/security/firewall.${CURRENT_CHECK_TYPE}.today"
FIREWALL_YESTERDAY="/var/log/security/firewall.${CURRENT_CHECK_TYPE}.yesterday"
FIREWALL_DIFF="/var/log/security/firewall.${CURRENT_CHECK_TYPE}.diff"

if [[ -f ${OPEN_PORT_TODAY} ]]; then
    mv -f ${OPEN_PORT_TODAY} ${OPEN_PORT_YESTERDAY}
fi

if [[ -f ${FIREWALL_TODAY} ]]; then
    mv -f ${FIREWALL_TODAY} ${FIREWALL_YESTERDAY}
fi

if check_is_enabled "${CHECK_OPEN_PORT}" ; then
        if [[ ${IGNORE_PID_CHANGES} = yes ]]; then
                FILTER="sed -e s/\(PID\|[0-9]*\)\/\(.*\)$/\2/g"
        else
                FILTER="cat"
        fi
        netstat -pvlA inet,inet6 2> /dev/null | sed -e 's/\s\s*$//g' | $FILTER > ${OPEN_PORT_TODAY};
        Filter ${OPEN_PORT_TODAY} CHECK_OPEN_PORT
        Count ${INFOS} ${OPEN_PORT_TODAY} "Total of open network ports"
fi

if check_is_enabled "${CHECK_FIREWALL}" ; then
        iptables -S 2>/dev/null > ${FIREWALL_TODAY}
        Filter ${FIREWALL_TODAY} CHECK_FIREWALL
        Count ${INFOS} ${FIREWALL_TODAY} "Total of configured firewall rules"
fi

### Changed open port
if check_is_enabled "${CHECK_OPEN_PORT}" ; then
    Diffcheck ${OPEN_PORT_TODAY} ${OPEN_PORT_YESTERDAY} ${OPEN_PORT_DIFF} "processes with open network ports"
fi

### Changed firewall
if check_is_enabled "${CHECK_FIREWALL}" ; then
    Diffcheck ${FIREWALL_TODAY} ${FIREWALL_YESTERDAY} ${FIREWALL_DIFF} "firewall rules"
fi

### Dump a list of open port.
if check_is_enabled "${CHECK_OPEN_PORT}" ; then
    if [[ -s ${OPEN_PORT_TODAY} ]]; then
        printf "\nThese are the ports listening on your machine :\n" >> ${SECURITY}
        cat ${OPEN_PORT_TODAY} >> ${SECURITY}
    fi
fi

### Check if network is in promisc mode
if check_is_enabled "${CHECK_PROMISC}" ; then
        export SECURITY
        /usr/share/msec/promisc_check.sh
fi
