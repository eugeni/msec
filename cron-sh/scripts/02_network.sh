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
export FIREWALL_TODAY="/var/log/security/firewall.today"
FIREWALL_YESTERDAY="/var/log/security/firewall.yesterday"
FIREWALL_DIFF="/var/log/security/firewall.diff"

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
        iptables -S 2>/dev/null > ${FIREWALL_TODAY}
fi

### Changed open port
if [[ ${CHECK_OPEN_PORT} == yes ]]; then
    Diffcheck ${OPEN_PORT_TODAY} ${OPEN_PORT_YESTERDAY} ${OPEN_PORT_DIFF} "network listening ports"
fi

### Changed firewall
if [[ ${CHECK_FIREWALL} == yes ]]; then
    Diffcheck ${FIREWALL_TODAY} ${FIREWALL_YESTERDAY} ${FIREWALL_DIFF} "firewall rules"
fi

### Dump a list of open port.
if [[ ${CHECK_OPEN_PORT} == yes ]]; then
    if [[ -s ${OPEN_PORT_TODAY} ]]; then
        printf "\nThese are the ports listening on your machine :\n" >> ${INFOS}
        cat ${OPEN_PORT_TODAY} >> ${INFOS}
    fi
fi

### Check if network is in promisc mode
if [[ ${CHECK_PROMISC} == yes ]]; then
        export SECURITY
        /usr/share/msec/promisc_check.sh
fi
