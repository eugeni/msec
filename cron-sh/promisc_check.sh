#!/bin/bash

if [ -f /etc/security/msec/security.conf ]; then
	. /etc/security/msec/security.conf
else
	echo "/etc/security/msec/security.conf don't exist."
	exit 1
fi

PROMISC_CHECK="/usr/bin/promisc_check -q"
#
# Check if a network interface is in promisc check...
# Written by Vandoorselaere Yoann, <yoann@mandrakesoft.com>
#

LogPromisc() {
	Syslog "Security warning : $1 is in promiscuous mode. (sniffer running ?)"
	Ttylog "\\033[1;31mSecurity warning : $1 is in promiscuous mode.\\033[0;39m"
	Ttylog "\\033[1;31mA sniffer is probably running on your system.\\033[0;39m"
}

if [ -f /etc/security/msec/security.conf ]; then
    . /etc/security/msec/security.conf
else 
	exit 1
fi

if [ CHECK_PROMISC == "no" ]; then
	exit 0;
fi

for INTERFACE in `$PROMISC_CHECK`; do
	LogPromisc $INTERFACE
done







