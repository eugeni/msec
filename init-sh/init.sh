#!/bin/bash

if [[ -z $1 ]]; then
	echo "Usage : $0 [0-5]"
	echo "Usage : $0 \"custom\""
	exit 1
fi


if [[ ${1} == custom ]]; then
	/etc/security/msec/init-sh/custom.sh
	exit 0;
fi

if [[ -f /etc/security/msec/init-sh/level$1.sh ]]; then
    /etc/security/msec/init-sh/level$1.sh
	if [[ -f /etc/security/msec/init-sh/perm.$1 ]]; then
		/etc/security/msec/init-sh/file_perm.sh /etc/security/msec/init-sh/perm.$1
	else
		echo "Couldn't find the default permissions for level $1."
	fi
else
    echo "Security level $1 not availlable..."
fi

