#!/bin/sh

if [ -z $1 ]; then
	echo "Usage : $0 [0-5]"
	exit 1
fi


if [ -f /etc/security/msec/init-sh/level$1.sh ]; then
    /etc/security/msec/init-sh/level$1.sh
	if [ -f /etc/security/msec/init-sh/perm.$1 ]; then
		/etc/security/msec/init-sh/file_perm.sh /etc/security/msec/init-sh/perm.$1
	else
		echo "Couldn't find the default permissions for level $1."
	fi
else
    echo "Security level $1 not availlable..."
fi

