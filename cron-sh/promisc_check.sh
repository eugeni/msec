#!/bin/bash

# Writen by Vandoorselaere Yoann, 
# <yoann@mandrakesoft.com>

if [[ -f /etc/security/msec/security.conf ]]; then
	. /etc/security/msec/security.conf
else
	echo "/etc/security/msec/security.conf doesn't exist."
	exit 1
fi

if tail /var/log/security.log | grep -q "promiscuous"; then
    # Dont flood with warning.
    exit 0
fi

Syslog() {
    if [[ ${SYSLOG_WARN} == yes ]]; then
        /sbin/initlog --string="${1}"
    fi
}

Ttylog() {
    if [[ ${TTYLOG_WARN} == yes ]]; then
        w | grep -v "load\|TTY" | awk '{print $2}' | while read line; do
            echo -e "${1}" > /dev/$i
        done
    fi
}

# Check if a network interface is in promiscuous mode...
PROMISC="/usr/bin/promisc_check -q"

LogPromisc() {
    date=`date`
    Syslog "Security warning : $1 is in promiscuous mode."
    Syslog "    A sniffer is probably running on your system."
    Ttylog "\\033[1;31mSecurity warning : $1 is in promiscuous mode.\\033[0;39m"
    Ttylog "\\033[1;31mA sniffer is probably running on your system.\\033[0;39m"
    echo -e "\n${date} Security warning : $1 is in promiscuous mode." >> /var/log/security.log
    echo "    A sniffer is probably running on your system." >> /var/log/security.log

}

if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
else 
	exit 1
fi

if [[ ${CHECK_PROMISC} == no ]]; then
	exit 0;
fi

for INTERFACE in `${PROMISC}`; do
	LogPromisc ${INTERFACE}
done













