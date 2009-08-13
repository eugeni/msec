#!/bin/bash
# msec: this checks if the network is in promiscuous mose

. /usr/share/msec/functions.sh

LogPromisc() {
    date=`date`
    tempfile=`mktemp /tmp/promisc.XXXXXX`
    echo "Security warning : $1 is in promiscuous mode." > $tempfile
    echo "    A sniffer is probably running on your system." >> $tempfile
    Syslog $tempfile
    echo "\\033[1;31mSecurity warning : $1 is in promiscuous mode.\\033[0;39m" > $tempfile
    echo "\\033[1;31mA sniffer is probably running on your system.\\033[0;39m" >> $tempfile
    Ttylog $tempfile
    rm -f $tempfile

    # are we being run from security.sh script?
    if [ ! -z "$SECURITY" ]; then
            printf "\nSecurity Warning: $1 is in promiscuous mode!" >> ${SECURITY}
            printf "    A sniffer is probably running on your system." >> ${SECURITY}
    fi
}

if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
else
    echo "/etc/security/msec/security.conf don't exist."
    exit 1
fi

if tail /var/log/security.log | grep -q "promiscuous"; then
    # Dont flood with warning.
    exit 0
fi

# Check if a network interface is in promiscuous mode...

if [[ ${CHECK_PROMISC} == no ]]; then
    exit 0;
fi

for INTERFACE in `/sbin/ip link list | grep PROMISC | cut -f 2 -d ':';/usr/bin/promisc_check -q`; do
    LogPromisc ${INTERFACE}
done

# promisc_check.sh ends here
