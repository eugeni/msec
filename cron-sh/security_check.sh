#!/bin/bash

#
# Written by Vandoorselaere Yoann, <yoann@mandrakesoft.com>
#

if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
else
	echo "/etc/security/msec/security.conf don't exist."
    exit 1
fi

if [[ ${CHECK_SECURITY} != yes ]]; then
    exit 0
fi

SECURITY="/tmp/secure.log"
SECURITY_LOG="/var/log/security.log"
TMP="/tmp/secure.tmp"

if [[ ! -d /var/log/security ]]; then
    mkdir /var/log/security
fi

chattr -a /var/log/security/ >& /dev/null
chattr -a /var/log/security/* >& /dev/null
rm -f ${SECURITY} ${TMP} >& /dev/null

### Functions ###

Syslog() {
    if [[ ${SYSLOG_WARN} == yes ]]; then
	cat ${1} | while read line; do
	    /sbin/initlog --string="${line}"
	done
    fi
}

Ttylog() {
    if [[ ${TTY_WARN} == yes ]]; then
	for i in `w | grep -v "load\|TTY" | awk '{print $2}'` ; do
	    echo -e "${1}" > /dev/$i
	done
    fi
}

### Writeable file detection
if [[ ${CHECK_WRITEABLE} == yes ]]; then
    find ${DIR} -xdev -type f -perm -2 -ls -print | awk '{print $11}' | sort > ${TMP}

    if [[ -s ${TMP} ]]; then
	printf "\nSecurity Warning: World Writeable Files found :\n" >> ${SECURITY}
	cat ${TMP} >> ${SECURITY}
    fi
fi

### Search Un Owned file
if [[ ${CHECK_UNOWNED} == yes ]]; then
    find ${DIR} -xdev -nouser -print -ls | awk '{print $11}' | sort > ${TMP}
    if [[ -s ${TMP} ]]; then
	printf "\nSecurity Warning : the following file aren't owned by any user :\n" >> ${SECURITY}
	printf "\ttheses files now have user \"nobody\" as their owner." >> ${SECURE_LOG}
	cat ${TMP} >> ${SECURITY}
        cat ${TMP} | while read line; do chown nobody ${line}; done	
    fi

    find $DIR -xdev -nogroup -print -ls | awk '{print $11}' | sort > ${TMP}
    if [[ -s ${TMP} ]]; then
	printf "\nSecurity Warning : the following file aren't owned by any group :\n" >> ${SECURITY}
        printf "\ttheses files now have group \"nogroup\" as their group owner." >> ${SECURITY}
	cat ${TMP} >> ${SECURITY}
	cat ${TMP} | while read line; do chgrp nogroup ${line}; done
    fi
fi

if [[ ${CHECK_PERMS} == yes ]]; then
# Files that should not be owned by someone else or readable.
list=".netrc .rhosts .shosts .Xauthority .pgp/secring.pgp .ssh/identity .ssh/random_seed"
awk -F: '/^[^+-]/ { print $1 " " $3 " " $6 }' /etc/passwd | 
while read username uid homedir; do
    for f in ${list} ; do
	file="${homedir}/${f}"
	if [[ -f ${file} ]] ; then
	    printf "${uid} ${username} ${file} `ls -ldcgn ${file}`\n"
	fi
    done
done | awk '$1 != $6 && $6 != "0" \
        { print "\t\t- " $3 " : file is owned by uid " $6 "." }
	$4 ~ /^-...r/ \
        { print "\t\t- " $3 " : file is group readable." }
	$4 ~ /^-......r/ \
        { print "\t\t- " $3 " : file is other readable." }
	$4 ~ /^-....w/ \
        { print "\t\t- " $3 " : file is group writeable." }
	$4 ~ /^-.......w/ \
        { print "\t\t- " $3 " : file is other writeable." }' > ${TMP}

if [[ -s ${TMP} ]]; then
    printf "\nSecurity Warning: these files shouldn't be owned by someone else or readable :\n" >> ${SECURITY}
    cat ${TMP} >> ${SECURITY}
fi

### Files that should not be owned by someone else or writeable.
list=".bashrc .bash_profile .bash_login .bash_logout .cshrc .emacs .exrc \
.forward .klogin .login .logout .profile .tcshrc .fvwmrc .inputrc .kshrc \
.nexrc .screenrc .ssh .ssh/config .ssh/authorized_keys .ssh/environment \
.ssh/known_hosts .ssh/rc .twmrc .xsession .xinitrc .Xdefaults"
awk -F: '/^[^+-]/ { print $1 " " $3 " " $6 }' /etc/passwd | \
while read username uid homedir; do
        for f in ${list} ; do
                file=${homedir}/${f}
                if [[ -f ${file} ]] ; then
                        printf "${uid} ${username} ${file} `ls -ldcgn ${file}`\n"
                fi
        done
done | awk '$1 != $6 && $6 != "0" \
        { print "\t\t- " $3 " : file is owned by uid " $6 "." }
     $4 ~ /^-....w/ \
        { print "\t\t- " $3 " : file is group writeable." }
     $4 ~ /^-.......w/ \
        { print "\t\t- " $3 " : file is other writeable." }' > ${TMP}

if [[ -s ${TMP} ]]; then
    printf "\nSecurity Warning: theses files should not be owned by someone else or writeable :\n" >> ${SECURITY}
    cat ${TMP} >> ${SECURITY}
fi

### Check home directories.  Directories should not be owned by someone else or writeable.
awk -F: '/^[^+-]/ { print $1 " " $6 }' /etc/passwd | \
while read uid homedir; do
        if [[ -d ${homedir} ]] ; then
                file=`ls -ldg ${homedir}`
                printf "$uid $file\n"
        fi
done | awk '$1 != $4 && $4 != "root" \
        { print "user=" $1 " : home directory is owned by " $4 "." }
     $2 ~ /^-....w/ \
        { print "user=" $1 " : home directory is group writeable." }
     $2 ~ /^-.......w/ \
        { print "user=" $1 " : home directory is other writeable." }' > ${TMP}

if [[ -s $TMP ]] ; then
        printf "\nSecurity Warning: these home directory should not be owned by someone else or writeable :\n" >> ${SECURITY}
        cat ${TMP} >> ${SECURITY}
fi
fi # End of check perms

### Passwd file check
if [[ ${CHECK_PASSWD} == yes ]]; then    
    awk -F: '{
        if ( $2 == "" )
	    printf("\t\t- /etc/passwd:%d: User \"%s\" has no password !\n", FNR, $1);
	else if ($2 !~ /^[x*!]+$/)
	    printf("\t\t- /etc/passwd:%d: User \"%s\" has a real password (it is not shadowed).\n", FNR, $1);
    }' < /etc/passwd > ${TMP}
    
    if [[ -s ${TMP} ]]; then
	printf "\nSecurity Warning: /etc/passwd check :\n" >> ${SECURITY}
	cat ${TMP} >> ${SECURITY}
    fi
fi

### Shadow password file Check
if [[ ${CHECK_SHADOW} == yes ]]; then
    awk -F: '{
	if ( $2 == "" )
	    printf("\t\t- /etc/shadow:%d: User \"%s\" has no password !\n", FNR, $1);
    }' < /etc/shadow > ${TMP}

    if [[ -s ${TMP} ]]; then
	printf "\nSecurity Warning: /etc/shadow check :\n" >> ${SECURITY}
	cat ${TMP} >> ${SECURITY}
    fi
fi

### File systems should not be globally exported.
if [[ -s /etc/exports ]] ; then
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
		    print "\t\t- Nfs File system " $1 " globally exported, read-only.";
		} else print "\t\t- Nfs File system " $1 " globally exported, read-write.";
        }' < /etc/exports > ${TMP}
        
    if [[ -s ${TMP} ]] ; then
	printf "\nSecurity Warning: Some NFS filesystem are exported globally :\n" >> ${SECURITY}
	cat ${TMP} >> ${SECURITY}
    fi
fi

### nfs mounts with missing nosuid
/bin/mount | /bin/grep -v nosuid | /bin/grep ' nfs ' > ${TMP}
if [[ -s ${TMP} ]] ; then
    printf "\nSecurity Warning: The following NFS mounts haven't got the nosuid option set :\n" >> ${SECURITY}
    cat ${TMP} >> ${SECURITY}
fi

### Files that should not have + signs.
list="/etc/hosts.equiv /etc/shosts.equiv /etc/hosts.lpd"
for file in $list ; do
        if [[ -s ${file} ]] ; then
                awk '{
                        if ($0 ~ /^\+@.*$/)
				next;
                        if ($0 ~ /^\+.*$/)
			        printf("\t\t- %s: %s\n", FILENAME, $0);
                }' ${file}
        fi
done > ${TMP}

awk -F: '{print $1" "$6}' /etc/passwd |
    while read username homedir; do
	for file in .rhosts .shosts; do
	    if [[ -s ${homedir}/${file} ]] ; then
		awk '{
			if ($0 ~ /^\+@.*$/)
			    next;
			if ($0 ~ /^\+.*$/)
			    printf("\t\t- %s: %s\n", FILENAME, $0);
		}' ${homedir}/${file}
	    fi
	done >> ${TMP}
    done
	
if [[ -s ${TMP} ]]; then
    printf "\nSecurity Warning: '+' character found in hosts trusting files,\n" >> ${SECURITY}
    printf "\tthis probably mean that you trust certains users/domain\n" >> ${SECURITY}
    printf "\tto connect on this host without proper authentication :\n" >> ${SECURITY}
    cat ${TMP} >> ${SECURITY}
fi

### executables should not be in the aliases file.
list="/etc/aliases /etc/postfix/aliases"
for file in ${list}; do
    if [[ -s ${file} ]]; then
	grep -v '^#' /etc/aliases | grep '|' | while read line; do
	    printf "\t\t- ${line}\n"
	done > ${TMP}
    fi

    if [[ -s ${TMP} ]]; then
	printf "\nSecurity Warning: The following programs are executed in your mail\n" >> ${SECURITY}
	printf "\tvia ${file} files, this could lead to security problems :\n" >> ${SECURITY}
        cat ${TMP} >> ${SECURITY}
    fi
done

### Dump a list of open port.
if [[ ${CHECK_OPEN_PORT} == yes ]]; then
    netstat -pvlA inet > ${TMP};
    
    if [[ -s ${TMP} ]]; then
	printf "\nThese are the ports listening on your machine :\n" >> ${SECURITY}
	cat ${TMP} >> ${SECURITY}
    fi
fi

### Report
if [[ -s ${SECURITY} ]]; then
    Syslog ${SECURITY}
    Ttylog ${SECURITY}
    date=`date`
    echo -e "\n\n*** Security Check, ${date} ***\n" >> ${SECURITY_LOG}
    cat ${SECURITY} >> ${SECURITY_LOG}
fi

if [[ -f ${SECURITY} ]]; then
    rm -f ${SECURITY}
fi

if [[ -f ${TMP} ]]; then
    rm -f ${TMP}
fi



