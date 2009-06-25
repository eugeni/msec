#!/bin/bash
# msec: security check for suid_root binaries

# check if we are run from main script
if [ -z "$MSEC_TMP" -o -z "$INFOS" -o -z "$SECURITY" -o -z "$DIFF" -o -z "$SECURITY_LOG" ]; then
        # variables are set in security.sh and propagated to the subscripts
        echo "Error: this check should be run by the main msec security check!"
        echo "       do not run it directly unless you know what you are doing."
        return 1
fi

export SUID_ROOT_TODAY="/var/log/security/suid_root.today"
SUID_ROOT_YESTERDAY="/var/log/security/suid_root.yesterday"
SUID_ROOT_DIFF="/var/log/security/suid_root.diff"
export SGID_TODAY="/var/log/security/sgid.today"
SGID_YESTERDAY="/var/log/security/sgid.yesterday"
SGID_DIFF="/var/log/security/sgid.diff"
export SUID_MD5_TODAY="/var/log/security/suid_md5.today"
SUID_MD5_YESTERDAY="/var/log/security/suid_md5.yesterday"
SUID_MD5_DIFF="/var/log/security/suid_md5.diff"
export WRITABLE_TODAY="/var/log/security/writable.today"
WRITABLE_YESTERDAY="/var/log/security/writable.yesterday"
WRITABLE_DIFF="/var/log/security/writable.diff"
export UNOWNED_USER_TODAY="/var/log/security/unowned_user.today"
UNOWNED_USER_YESTERDAY="/var/log/security/unowned_user.yesterday"
UNOWNED_USER_DIFF="/var/log/security/unowned_user.diff"
export UNOWNED_GROUP_TODAY="/var/log/security/unowned_group.today"
UNOWNED_GROUP_YESTERDAY="/var/log/security/unowned_group.yesterday"
UNOWNED_GROUP_DIFF="/var/log/security/unowned_group.diff"

if [[ -f ${SUID_ROOT_TODAY} ]]; then
    mv ${SUID_ROOT_TODAY} ${SUID_ROOT_YESTERDAY};
fi

if [[ -f ${SGID_TODAY} ]]; then
    mv ${SGID_TODAY} ${SGID_YESTERDAY};
fi

if [[ -f ${SUID_MD5_TODAY} ]]; then
    mv ${SUID_MD5_TODAY} ${SUID_MD5_YESTERDAY};
fi

if [[ -f ${WRITABLE_TODAY} ]]; then
    mv ${WRITABLE_TODAY} ${WRITABLE_YESTERDAY};
fi

if [[ -f ${UNOWNED_USER_TODAY} ]]; then
    mv ${UNOWNED_USER_TODAY} ${UNOWNED_USER_YESTERDAY};
fi

if [[ -f ${UNOWNED_GROUP_TODAY} ]]; then
    mv ${UNOWNED_GROUP_TODAY} ${UNOWNED_GROUP_YESTERDAY};
fi

# only running this check when really required
if [[ ${CHECK_SUID_MD5} == yes || ${CHECK_SUID_ROOT} == yes || ${CHECK_SGID} == yes || ${CHECK_WRITABLE} == yes || ${CHECK_UNOWNED} == yes  ]]; then

        # Hard disk related file check; the less priority the better...
        nice --adjustment=+19 /usr/bin/msec_find ${DIR}
fi

if [[ -f ${SUID_ROOT_TODAY} ]]; then
    sort < ${SUID_ROOT_TODAY} > ${SUID_ROOT_TODAY}.tmp
    mv -f ${SUID_ROOT_TODAY}.tmp ${SUID_ROOT_TODAY}
fi

if [[ -f ${SGID_TODAY} ]]; then
    sort < ${SGID_TODAY} > ${SGID_TODAY}.tmp
    mv -f ${SGID_TODAY}.tmp ${SGID_TODAY}
fi

if [[ -f ${WRITABLE_TODAY} ]]; then
    sort < ${WRITABLE_TODAY} | egrep -v '^(/var)?/tmp$' > ${WRITABLE_TODAY}.tmp
    mv -f ${WRITABLE_TODAY}.tmp ${WRITABLE_TODAY}
fi

if [[ -f ${UNOWNED_USER_TODAY} ]]; then
    sort < ${UNOWNED_USER_TODAY} > ${UNOWNED_USER_TODAY}.tmp
    mv -f ${UNOWNED_USER_TODAY}.tmp ${UNOWNED_USER_TODAY}
fi

if [[ -f ${UNOWNED_GROUP_TODAY} ]]; then
    sort < ${UNOWNED_GROUP_TODAY} > ${UNOWNED_GROUP_TODAY}.tmp
    mv -f ${UNOWNED_GROUP_TODAY}.tmp ${UNOWNED_GROUP_TODAY}
fi

if [[ -f ${SUID_ROOT_TODAY} && ${CHECK_SUID_MD5} == yes ]]; then
    while read line; do
        md5sum ${line}
    done < ${SUID_ROOT_TODAY} > ${SUID_MD5_TODAY}
else
    touch ${SUID_MD5_TODAY}
fi

### New Suid root files detection
if [[ ${CHECK_SUID_ROOT} == yes ]]; then

    if [[ -f ${SUID_ROOT_YESTERDAY} ]]; then
        if ! diff -u ${SUID_ROOT_YESTERDAY} ${SUID_ROOT_TODAY} > ${SUID_ROOT_DIFF}; then
            printf "\nSecurity Warning: Change in Suid Root files found :\n" >> ${DIFF}
            grep '^+' ${SUID_ROOT_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-       Newly added suid root file : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${SUID_ROOT_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- No longer present suid root file : ${file}\n"
            done >> ${DIFF}
        fi
    fi

fi

### New Sgid files detection
if [[ ${CHECK_SGID} == yes ]]; then

    if [[ -f ${SGID_YESTERDAY} ]]; then
        if ! diff -u ${SGID_YESTERDAY} ${SGID_TODAY} > ${SGID_DIFF}; then
            printf "\nSecurity Warning: Changes in Sgid files found :\n" >> ${DIFF}
            grep '^+' ${SGID_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-       Newly added sgid file : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${SGID_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- No longer present sgid file : ${file}\n"
            done >> ${DIFF}
        fi
    fi

fi

### Writable files detection
if [[ ${CHECK_WRITABLE} == yes ]]; then

    if [[ -f ${WRITABLE_YESTERDAY} ]]; then
        diff -u ${WRITABLE_YESTERDAY} ${WRITABLE_TODAY} > ${WRITABLE_DIFF}
        if [ -s ${WRITABLE_DIFF} ]; then
            printf "\nSecurity Warning: Change in World Writable Files found :\n" >> ${DIFF}
            grep '^+' ${WRITABLE_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-       Newly added writable file : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${WRITABLE_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- No longer present writable file : ${file}\n"
            done >> ${DIFF}
        fi
    fi

fi

### Search Non Owned files
if [[ ${CHECK_UNOWNED} == yes ]]; then

    if [[ -f ${UNOWNED_USER_YESTERDAY} ]]; then
        diff -u ${UNOWNED_USER_YESTERDAY} ${UNOWNED_USER_TODAY} > ${UNOWNED_USER_DIFF}
        if [ -s ${UNOWNED_USER_DIFF} ]; then
            printf "\nSecurity Warning: the following files aren't owned by an user :\n" >> ${DIFF}
            grep '^+' ${UNOWNED_USER_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-       Newly added un-owned file : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${UNOWNED_USER_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- No longer present un-owned file : ${file}\n"
            done >> ${DIFF}
        fi
    fi

    if [[ -f ${UNOWNED_GROUP_YESTERDAY} ]]; then
        diff -u ${UNOWNED_GROUP_YESTERDAY} ${UNOWNED_GROUP_TODAY} > ${UNOWNED_GROUP_DIFF}
        if [ -s ${UNOWNED_GROUP_DIFF} ]; then
            printf "\nSecurity Warning: the following files aren't owned by a group :\n" >> ${DIFF}
            grep '^+' ${UNOWNED_GROUP_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-       Newly added un-owned file : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${UNOWNED_GROUP_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- No longer present un-owned file : ${file}\n"
            done >> ${DIFF}
        fi
    fi

fi

### Md5 check for SUID root fileg
if [[ ${CHECK_SUID_MD5} == yes  ]]; then
    ctrl_md5=0;

    if [[ -f ${SUID_MD5_YESTERDAY} ]]; then
        diff -u ${SUID_MD5_YESTERDAY} ${SUID_MD5_TODAY} > ${SUID_MD5_DIFF}
        if [ -s ${SUID_MD5_DIFF} ]; then
            grep '^+' ${SUID_MD5_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | awk '{print $2}' | while read file; do
                if cat ${SUID_MD5_YESTERDAY} | awk '{print $2}' | grep -qw ${file}; then
                    if [[ ${ctrl_md5} == 0 ]]; then
                        printf "\nSecurity Warning: the md5 checksum for one of your SUID files has changed,\n" >> ${DIFF}
                        printf "\tmaybe an intruder modified one of these suid binary in order to put in a backdoor...\n" >> ${DIFF}
                        ctrl_md5=1;
                    fi
                    printf "\t\t- Checksum changed file : ${file}\n"
                fi
            done >> ${DIFF}
        fi
    fi

fi

### Writable file detection
if [[ ${CHECK_WRITABLE} == yes ]]; then
    if [[ -s ${WRITABLE_TODAY} ]]; then
	printf "\nSecurity Warning: World Writable files found :\n" >> ${SECURITY}
	cat ${WRITABLE_TODAY} | awk '{print "\t\t- " $0}' >> ${SECURITY}
    fi
fi

### Search Un Owned file
if [[ ${CHECK_UNOWNED} == yes ]]; then
    if [[ -s ${UNOWNED_USER_TODAY} ]]; then
	printf "\nSecurity Warning : User Unowned files found :\n" >> ${SECURITY}
	printf "\t( theses files now have user \"nobody\" as their owner. )\n" >> ${SECURITY}
	cat ${UNOWNED_USER_TODAY} | awk '{print "\t\t- " $0}' >> ${SECURITY}
        cat ${UNOWNED_USER_TODAY} | while read line; do
	if [[ ${FIX_UNOWNED} == yes ]]; then
	    chown nobody "${line}"; # Use quote if filename contain space.
	fi
	done
    fi

    if [[ -s ${UNOWNED_GROUP_TODAY} ]]; then
	printf "\nSecurity Warning : Group Unowned files found :\n" >> ${SECURITY}
        printf "\t( theses files now have group \"nogroup\" as their group owner. )\n" >> ${SECURITY}
	cat ${UNOWNED_GROUP_TODAY} | awk '{print "\t\t- " $0}' >> ${SECURITY}
	cat ${UNOWNED_GROUP_TODAY} | while read line; do
	if [[ ${FIX_UNOWNED} == yes ]]; then
	    chgrp nogroup "${line}"; # Use quote if filename contain space.
	fi
	done
    fi
fi

if [[ ${CHECK_USER_FILES} == yes ]]; then
# Files that should not be owned by someone else or readable.
list=".netrc .rhosts .shosts .Xauthority .gnupg/secring.gpg \
.pgp/secring.pgp .ssh/identity .ssh/id_dsa .ssh/id_rsa .ssh/random_seed"
getent passwd | awk -F: '/^[^+-]/ { print $1 ":" $3 ":" $6 }' |
while IFS=: read username uid homedir; do
    if ! expr "$homedir" : "$FILTER"  > /dev/null; then
	for f in ${list} ; do
	    file="${homedir}/${f}"
	    if [[ -f "${file}" ]] ; then
		res=`ls -LldcGn "${file}" | sed 's/ \{1,\}/:/g'`
		printf "${uid}:${username}:${file}:${res}\n"
	    fi
	done
    fi
done | awk -F: '$1 != $6 && $6 != "0" \
        { print "\t\t- " $3 " : file is owned by uid " $6 "." }
	$4 ~ /^-...r/ \
        { print "\t\t- " $3 " : file is group readable." }
	$4 ~ /^-......r/ \
        { print "\t\t- " $3 " : file is other readable." }
	$4 ~ /^-....w/ \
        { print "\t\t- " $3 " : file is group writable." }
	$4 ~ /^-.......w/ \
        { print "\t\t- " $3 " : file is other writable." }' > ${MSEC_TMP}

if [[ -s ${MSEC_TMP} ]]; then
    printf "\nSecurity Warning: these files shouldn't be owned by someone else or readable :\n" >> ${SECURITY}
    cat ${MSEC_TMP} >> ${SECURITY}
fi

### Files that should not be owned by someone else or writable.
list=".bashrc .bash_profile .bash_login .bash_logout .cshrc .emacs .exrc \
.forward .klogin .login .logout .profile .tcshrc .fvwmrc .inputrc .kshrc \
.nexrc .screenrc .ssh .ssh/config .ssh/authorized_keys .ssh/environment \
.ssh/known_hosts .ssh/rc .twmrc .xsession .xinitrc .Xdefaults \
.gnupg .gnupg/secring.gpg .ssh/identity .ssh/id_dsa .ssh/id_rsa \
.Xauthority .cvspass .subversion/auth .purple/accounts.xml .config "
getent passwd | awk -F: '/^[^+-]/ { print $1 ":" $3 ":" $6 }' | \
while IFS=: read username uid homedir; do
    if ! expr "$homedir" : "$FILTER"  > /dev/null; then
	for f in ${list} ; do
	    file="${homedir}/${f}"
	    if [[ -e "${file}" ]] ; then
		res=`ls -LldcGn "${file}" | sed 's/ \{1,\}/:/g'`
		printf "${uid}:${username}:${file}:${res}\n"
	    fi
        done
    fi
done | awk -F: '$1 != $6 && $6 != "0" \
        { print "\t\t- " $3 " : file is owned by uid " $6 "." }
     $4 ~ /^.....w/ \
        { print "\t\t- " $3 " : file is group writable." }
     $4 ~ /^........w/ \
        { print "\t\t- " $3 " : file is other writable." }' > ${MSEC_TMP}

if [[ -s ${MSEC_TMP} ]]; then
    printf "\nSecurity Warning: theses files should not be owned by someone else or writable :\n" >> ${SECURITY}
    cat ${MSEC_TMP} >> ${SECURITY}
fi

### Check home directories.  Directories should not be owned by someone else or writable.
getent passwd | awk -F: '/^[^+-]/ { print $1 ":" $3 ":" $6 }' | \
while IFS=: read username uid homedir; do
    if ! expr "$homedir" : "$FILTER"  > /dev/null; then
        if [[ -d "${homedir}" ]] ; then
                realuid=`ls -LldGn "${homedir}"| awk '{ print $3 }'`
                realuser=`ls -LldG "${homedir}"| awk '{ print $3 }'`
                permissions=`ls -LldG "${homedir}"| awk '{ print $1 }'`
                printf "${permissions}:${username}:(${uid}):${realuser}:(${realuid})\n"
        fi
    fi
done | awk -F: '$3 != $5 && $5 != "(0)" \
        { print "user=" $2 $3 " : home directory is owned by " $4 $5 "." }
     $1 ~ /^d....w/ && $2 != "lp" && $2 != "mail" \
        { print "user=" $2 $3" : home directory is group writable." }
     $1 ~ /^d.......w/ \
        { print "user=" $2 $3" : home directory is other writable." }' > ${MSEC_TMP}

if [[ -s $MSEC_TMP ]] ; then
        printf "\nSecurity Warning: these home directory should not be owned by someone else or writable :\n" >> ${SECURITY}
        cat ${MSEC_TMP} >> ${SECURITY}
fi
fi # End of CHECK_USER_FILES

# now check default permissions
if [[ ${CHECK_PERMS} == yes ]]; then
        # running msec_perms
        /usr/sbin/msecperms > ${MSEC_TMP} 2>&1
        if [[ -s ${MSEC_TMP} ]]; then
                printf "\nPermissions changes on system files:\n" >> ${SECURITY}
                cat ${MSEC_TMP} | sed -e 's/WARNING: //g' >> ${SECURITY}
        fi
fi

