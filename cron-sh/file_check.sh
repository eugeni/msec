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

OUT=./blah

# Modified filters coming from debian security scripts.
CS_NFSAFS='(nfs|afs|xfs|coda)'
CS_TYPES=' type (devpts|auto|proc|msdos|fat|vfat|iso9660|ncpfs|smbfs|'$CS_NFSAFS')'
CS_DEVS='^/dev/fd'
CS_DIRS='on /mnt'
FILTERS="$CS_TYPES|$CS_DEVS|$CS_DIRS"
DIR=`mount | grep -vE "$FILTERS" | cut -d ' ' -f3`
###

SUID_ROOT_TODAY=/var/log/security/suid_root.today
SUID_ROOT_YESTERDAY=/var/log/security/suid_root.yesterday
SUID_ROOT_DIFF=/var/log/security/suid_root.diff
SUID_GROUP_TODAY=/var/log/security/suid_group.today
SUID_GROUP_YESTERDAY=/var/log/security/suid_group.yesterday
SUID_GROUP_DIFF=/var/log/security/suid_group.diff
WRITABLE_TODAY=/var/log/security/writable.today
WRITABLE_YESTERDAY=/var/log/security/writable.yesterday
WRITABLE_DIFF=/var/log/security/writable.diff
UNOWNED_TODAY=/var/log/security/unowned.today
UNOWNED_YESTERDAY=/var/log/security/unowned.yesterday
UNOWNED_DIFF=/var/log/security/unowned.diff
PASSWD_TODAY=/var/log/security/passwd.today
PASSWD_YESTERDAY=/var/log/security/passwd.yesterday
PASSWD_DIFF=/var/log/security/passwd.diff
SHADOW_TODAY=/var/log/security/shadow.today
SHADOW_YESTERDAY=/var/log/security/shadow.yesterday
SHADOW_DIFF=/var/log/security/shadow.diff
HOST_TODAY=/var/log/security/hosts.today
HOST_YESTERDAY=/var/log/security/hosts.yesterday
HOST_DIFF=/var/log/security/hosts.diff
SUID_MD5_TODAY=/var/log/security/suid_md5.today
SUID_MD5_YESTERDAY=/var/log/security/suid_md5.yesterday
SUID_MD5_DIFF=/var/log/security/suid_md5.diff
OPEN_PORT_TODAY=/var/log/security/open_port.today
OPEN_PORT_YESTERDAY=/var/log/security/open_port.yesterday
OPEN_PORT_DIFF=/var/log/security/open_port.diff

if [ ! -d /var/log/security ]; then
    mkdir /var/log/security
fi

chattr -a /var/log/security/
chattr -a /var/log/security/*

### Functions ###

Syslog() {
	if [ $SYS_LOG=="yes" ]; then
		/sbin/initlog --string="$1"
	fi
}

Ttylog() {
	if [ $TTY_LOG=="yes" ]; then
		for i in `w | grep -v "load\|TTY" | awk '{print $2}'` ; do
			echo -e "$1" > /dev/$i
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

########## Md5 check for SUID root file #########
if [ ${CHECK_SUID_MD5}=="yes" ]; then 
    if [ -f ${SUID_MD5_TODAY} ]; then
	mv ${SUID_MD5_TODAY} ${SUID_MD5_YESTERDAY}
    fi

    touch ${SUID_MD5_TODAY}
    awk '{print $12}' ${SUID_ROOT_TODAY} |
	while read line; do 
	    md5sum ${line} >> ${SUID_MD5_TODAY}
	done
	
    if [ -f ${SUID_MD5_YESTERDAY} ]; then
	if ! diff ${SUID_MD5_YESTERDAY} ${SUID_MD5_TODAY} 1> ${SUID_MD5_DIFF}; then
	    Syslog "Warning, the md5 checksum for one of your SUID files has changed..."
	    Syslog "Maybe an intruder modified one of these suid binary in order to put in a backdoor..."
	    Syslog "Please consult  ${SUID_MD5_DIFF}."
	    Ttylog "Warning, the md5 checksum for one of your SUID files has changed..."
	    Ttylog "Maybe an intruder modified one of these suid binary in order to put in a backdoor..."
	    Ttylog "Please consult  ${SUID_MD5_DIFF}."
	fi
    fi
fi
##################################################

#### Passwd check ####
if [ ${CHECK_PASSWD}=="yes" ]; then
    if [ -f ${PASSWD_TODAY} ]; then
	mv ${PASSWD_TODAY} ${PASSWD_YESTERDAY};
    fi
    
    awk -F: '{
	if ( $2 == "" )
	    printf("/etc/passwd:%d: User \"%s\" has no password !\n", FNR, $1);
	else if ($2 !~ /^[x*!]+$/)
	    printf("/etc/passwd:%d: User \"%s\" has a real password (it is not shadowed).\n", FNR, $1);
    }' < /etc/passwd > ${PASSWD_TODAY}
    
    if [ -f ${PASSWD_YESTERDAY} ]; then
	if ! diff ${PASSWD_YESTERDAY} ${PASSWD_TODAY} 1> ${PASSWD_DIFF}; then
	    Syslog `cat ${PASSWD_DIFF}`
	    Ttylog `cat ${PASSWD_DIFF}`
	fi
    fi
fi
######################

#### Shadow Check ####
if [ ${CHECK_SHADOW}=="yes" ]; then
    if [ -f ${SHADOW_TODAY} ]; then
	mv -f ${SHADOW_TODAY} ${SHADOW_YESTERDAY};
    fi

    awk -F: '{
	if ( $2 == "" )
	    printf("/etc/shadow:%d: User \"%s\" has no password !\n", FNR, $1);
    }' < /etc/shadow > ${SHADOW_TODAY}

    if [ -f ${SHADOW_YESTERDAY} ]; then
	if ! diff ${SHADOW_YESTERDAY} ${SHADOW_TODAY} 1> ${SHADOW_DIFF}; then
	    Syslog `cat ${SHADOW_DIFF}`
	    Ttylog `cat ${SHADOW_DIFF}`
	fi
    fi
fi

#### .[sr]hosts check ####
if [ ${CHECK_RHOST}=="yes" ]; then
    if [ -f ${HOST_TODAY} ]; then
	mv -f ${HOST_TODAY} ${HOST_YESTERDAY};
    fi
    
    awk -F: '{print $1" "$6}' /etc/passwd |
	while read username homedir; do
	    for file in .rhosts .shosts; do
		if [ -s ${homedir}/${file} ] ; then
		    rhost=`ls -lcdg ${homedir}/${file}`
		    printf "${username}: ${rhost}\n"
		    if grep "+" ${homedir}/${file} > /dev/null ; then
			printf "\tThere is a (+) character in ${file} : this is a *big* security problem \!\n"
		    fi
		fi
	    done
	done > ${HOST_TODAY}
	
    if [ -f ${HOST_YESTERDAY} ]; then
	if ! diff ${HOST_YESTERDAY} ${HOST_TODAY} 1> ${HOST_DIFF}; then
	    Syslog `cat ${HOST_DIFF}`
	    Ttylog `cat ${HOST_DIFF}`
	fi
    fi
fi

### Network check ###
if [ ${CHECK_OPEN_PORT}=="yes" ]; then
    if [ -f ${OPEN_PORT_TODAY} ]; then
	mv -f ${OPEN_PORT_TODAY} ${OPEN_PORT_YESTERDAY}
    fi

    netstat -pvlA inet > ${OPEN_PORT_TODAY};
    
    if [ -f ${OPEN_PORT_YESTERDAY} ]; then
	if ! diff ${OPEN_PORT_YESTERDAY} ${OPEN_PORT_TODAY} 1> ${OPEN_PORT_DIFF}; then
	    Syslog "There is a new port listening on your machine..."
	    Syslog "Please consult ${OPEN_PORT_DIFF} for security purpose..."
	    Ttylog "There is a new port listening on your machine..."
	    Ttylog "Please consult ${OPEN_PORT_DIFF} for security purpose..."
        fi
    fi
fi

### /etc/exports check ###

# File systems should not be globally exported.
if [ -s /etc/exports ] ; then
    awk '{
	if (($1 ~ /^#/) || ($1 ~ /^$/)) next;
	readonly = 0;
                for (i = 2; i <= NF; ++i) {
                        if ($i ~ /^-ro$/)
                                readonly = 1;
                        else if ($i !~ /^-/)
                                next;
                }
                if (readonly) {
		    print "Warning : Nfs File system " $1 " globally exported, read-only.";
		} else print "Warning : Nfs File system " $1 " globally exported, read-write.";
        }' < /etc/exports > $OUT
        if [ -s "$OUT" ] ; then
                printf "\nChecking for globally exported file systems.\n"
                cat "$OUT"
        fi
fi


# nfs mounts with missing nosuid
/bin/mount | /bin/grep -v nosuid | /bin/grep ' nfs ' > $OUT
if [ -s "$OUT" ] ; then
    printf "\nThe following NFS mounts haven't got the nosuid option set:\n"
    cat "$OUT"
fi

# Files that should not be owned by someone else or readable.
list=".netrc .rhosts .shosts .Xauthority .pgp/secring.pgp .ssh/identity .ssh/random_seed"
awk -F: '/^[^+-]/ { print $1 " " $6 }' /etc/passwd | \
while read uid homedir; do
        for f in $list ; do
                file=${homedir}/${f}
                if [ -f $file ] ; then
                        printf "$uid $f `ls -ldcg $file`\n"
                fi
        done
done |
awk '$1 != $5 && $5 != "root" \
        { print "user " $1 " " $2 " : file is owned by " $5 }
     $3 ~ /^-...r/ \
        { print "user " $1 " " $2 " : file is group readable" }
     $3 ~ /^-......r/ \
        { print "user " $1 " " $2 " : file is other readable" }
     $3 ~ /^-....w/ \
        { print "user " $1 " " $2 " : file is group writeable" }
     $3 ~ /^-.......w/ \
        { print "user " $1 " " $2 " : file is other writeable" }' > $OUT


# Files that should not be owned by someone else or writeable.
list=".bashrc .bash_profile .bash_login .bash_logout .cshrc .emacs .exrc \
.forward .klogin .login .logout .profile .tcshrc .fvwmrc .inputrc .kshrc \
.nexrc .screenrc .ssh .ssh/config .ssh/authorized_keys .ssh/environment \
.ssh/known_hosts .ssh/rc .twmrc .xsession .xinitrc .Xdefaults"
awk -F: '/^[^+-]/ { print $1 " " $6 }' /etc/passwd | \
while read uid homedir; do
        for f in $list ; do
                file=${homedir}/${f}
                if [ -f $file ] ; then
                        printf "$uid $f `ls -ldcg $file`\n"
                fi
        done
done |
awk '$1 != $5 && $5 != "root" \
        { print "user " $1 " " $2 " : file is owned by " $5 }
     $3 ~ /^-....w/ \
        { print "user " $1 " " $2 " : file is group writeable" }
     $3 ~ /^-.......w/ \
        { print "user " $1 " " $2 " : file is other writeable" }' >> $OUT
if [ -s "$OUT" ] ; then
        printf "\nChecking dot files.\n"
        cat "$OUT"
fi

# Check home directories.  Directories should not be owned by someone else
# or writeable.
awk -F: '/^[^+-]/ { print $1 " " $6 }' /etc/passwd | \
while read uid homedir; do
        if [ -d ${homedir}/ ] ; then
                file=`ls -ldg ${homedir}`
                printf "$uid $file\n"
        fi
done |
awk '$1 != $4 && $4 != "root" \
        { print "user " $1 " : home directory is owned by " $4 }
     $2 ~ /^-....w/ \
        { print "user " $1 " : home directory is group writeable" }
     $2 ~ /^-.......w/ \
        { print "user " $1 " : home directory is other writeable" }' > $OUT
if [ -s "$OUT" ] ; then
        printf "\nChecking home directories.\n"
        cat "$OUT"
fi

# Files that should not have + signs.
list="/etc/hosts.equiv /etc/shosts.equiv /etc/hosts.lpd"
for f in $list ; do
        if [ -s $f ] ; then
                awk '{
                        if ($0 ~ /^\+@.*$/)
                                next;
                        if ($0 ~ /^\+.*$/)
                                printf("\nPlus sign in the file %s\n", FILENAME);
                }' $f
        fi
done


# executables should not be in the /etc/aliases file.
if [ -s /etc/aliases ]; then
    grep -v '^#' /etc/aliases | grep '|' > $OUT
    if [ -s "$OUT" ] ; then
            printf "\nThe following programs are executed in your mail via /etc/aliases (bad!):\n"
            cat "$OUT"
    fi
fi






