#!/bin/bash

#
# Basic security checking for suid files.
# Written by Vandoorselaere Yoann, <yoann@mandrakesoft.com>
#

if [ -f /etc/security/msec/security.conf ]; then
    . /etc/security/msec/security.conf
else
    exit 1
fi

if [ SECURITY_CHECK == "no" ]; then
    exit 0
fi

# Modified filters coming from debian security scripts.
CS_NFSAFS='(nfs|afs|xfs|coda)'
CS_TYPES=' type (devpts|auto|proc|msdos|fat|vfat|iso9660|ncpfs|smbfs|'$CS_NFSAFS')'
CS_DEVS='^/dev/fd'
CS_DIRS='on /mnt'
FILTERS="$CS_TYPES|$CS_DEVS|$CS_DIRS"
DIR=`mount | grep -vE "$FILTERS" | cut -d ' ' -f3`
###

SUID_ROOT_TODAY="/var/log/security/suid_root.today"
SUID_ROOT_YESTERDAY="/var/log/security/suid_root.yesterday"
SUID_ROOT_DIFF="/var/log/security/suid_root.diff"
SUID_GROUP_TODAY="/var/log/security/suid_group.today"
SUID_GROUP_YESTERDAY="/var/log/security/suid_group.yesterday"
SUID_GROUP_DIFF="/var/log/security/suid_group.diff"
WRITABLE_TODAY=/var/log/security/writable.today
WRITABLE_YESTERDAY=/var/log/security/writable.yesterday
WRITABLE_DIFF=/var/log/security/writable.diff
UNOWNED_TODAY=/var/log/security/unowned.today
UNOWNED_YESTERDAY=/var/log/security/unowned.yesterday
UNOWNED_DIFF=/var/log/security/unowned.diff


if [ ! -d /var/log/security ]; then
    mkdir /var/log/security
fi

chattr -a /var/log/security

### Functions ###

Syslog() {
	if [ $SYS_LOG=="yes" ]; then
		/sbin/initlog --string=$1
	fi
}

Ttylog() {
	if [ $TTY_LOG=="yes" ]; then
		for i in `w | grep -v "load\|TTY" | awk '{print $2}'` ; do
			echo -e $1 > /dev/$i
		done
	fi
}

##################


### New Suid root file detection ###
if [ $CHECK_SUID_ROOT=="yes" ]; then
	if [ -f $SUID_ROOT_TODAY ]; then
	    mv $SUID_ROOT_TODAY $SUID_ROOT_YESTERDAY
	fi

	find $DIR -xdev -type f -perm +04000 -user root \
   		-printf "%8i %5m %3n %-10u %-10g %9s %t %h/%f\n" | sort > $SUID_ROOT_TODAY

	if [ -f $SUID_ROOT_YESTERDAY ]; then
    	if ! diff $SUID_ROOT_YESTERDAY $SUID_ROOT_TODAY > $SUID_ROOT_DIFF; then
			Syslog "Change in Suid Root file found, please consult $SUID_ROOT_DIFF"
        	Ttylog "\\033[1;31mChange in Suid Root file found !\\033[0;39m"
        	Ttylog "\\033[1;31mPlease consult $SUID_ROOT_DIFF\\033[0;39m"
    	fi
	fi
fi
#############################


### New Suid group file detection ###
if [ $CHECK_SUID_GROUP ]; then
	if [ -f $SUID_GROUP_TODAY ]; then
		mv $SUID_GROUP_TODAY $SUID_GROUP_YESTERDAY
	fi

	find $DIR -xdev -type f -perm +02000 \
   		 -printf "%8i %5m %3n %-10u %-10g %9s %t %h/%f\n" | sort > $SUID_GROUP_TODAY

	if [ -f $SUID_GROUP_YESTERDAY ]; then
		if ! diff $SUID_GROUP_YESTERDAY $SUID_GROUP_TODAY > $SUID_GROUP_DIFF; then
			Syslog "Change in Suid Group file found, please consult $SUID_GROUP_DIFF"
			Ttylog "\\033[1;31mChange in Suid Group file found !\\033[0;39m"
			Ttylog "\\033[1;31mPlease consult $SUID_GROUP_DIFF\\033[0;39m"
		fi
	fi
fi
#############################

### Writable file detection ###

if [ $CHECK_WRITABLE=="yes" ]; then
	if [ -f $WRITABLE_TODAY ]; then
		mv $WRITABLE_TODAY $WRITABLE_YESTERDAY
	fi

	find $DIR -xdev -type f -perm -2 \
		-ls -print | sort > $WRITABLE_TODAY

	if [ -f $WRITABLE_YESTERDAY ]; then
		if ! diff $WRITABLE_YESTERDAY $WRITABLE_TODAY > $WRITABLE_DIFF; then
			Syslog "Change in World Writable File found, please consult $WRITABLE_DIFF"
			Ttylog "\\033[1;31mChange in World Writable File found !\\033[0;39m"
			Ttylog "\\033[1;31mPlease consult $WRITABLE_DIFF\\033[0;39m"	
		fi
	fi
fi
#################################

### Search Un Owned file ###
if [ $CHECK_UNOWNED=="yes" ]; then
	if [ -f $UNOWNED_TODAY ]; then
			mv $UNOWNED_TODAY $UNOWNED_YESTERDAY
	fi

	find $DIR -xdev -nouser -o -nogroup -print \
		-ls | sort > $UNOWNED_TODAY

	if [ -f $UNOWNED_YESTERDAY ]; then
		if ! diff $UNOWNED_YESTERDAY $UNOWNED_TODAY; then
			Syslog "Change in Un-Owned file user/group, please consult $UNOWNED_DIFF"
			Ttylog "\\033[1;31mChange in Un-Owned file user/group found !\\033[0;39m"
			Ttylog "\\033[1;31mPlease consult $UNOWNED_DIFF\\033[0;39m"
		fi
	fi
fi


chattr +a /var/log/security















































