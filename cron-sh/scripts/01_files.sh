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
    Filter ${SUID_ROOT_TODAY} CHECK_SUID_MD5
    Filter ${SUID_ROOT_TODAY} CHECK_SUID_ROOT
    sort < ${SUID_ROOT_TODAY} > ${SUID_ROOT_TODAY}.tmp
    mv -f ${SUID_ROOT_TODAY}.tmp ${SUID_ROOT_TODAY}
fi

if [[ -f ${SGID_TODAY} ]]; then
    Filter ${SGID_TODAY} CHECK_SGID
    sort < ${SGID_TODAY} > ${SGID_TODAY}.tmp
    mv -f ${SGID_TODAY}.tmp ${SGID_TODAY}
fi

if [[ -f ${WRITABLE_TODAY} ]]; then
    Filter ${WRITABLE_TODAY} CHECK_WRITABLE
    sort < ${WRITABLE_TODAY} | egrep -v '^(/var)?/tmp$' > ${WRITABLE_TODAY}.tmp
    mv -f ${WRITABLE_TODAY}.tmp ${WRITABLE_TODAY}
fi

if [[ -f ${UNOWNED_USER_TODAY} ]]; then
    Filter ${UNOWNED_USER_TODAY} CHECK_UNOWNED
    sort < ${UNOWNED_USER_TODAY} > ${UNOWNED_USER_TODAY}.tmp
    mv -f ${UNOWNED_USER_TODAY}.tmp ${UNOWNED_USER_TODAY}
fi

if [[ -f ${UNOWNED_GROUP_TODAY} ]]; then
    Filter ${UNOWNED_GROUP_TODAY} CHECK_UNOWNED
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
        Diffcheck ${SUID_ROOT_TODAY} ${SUID_ROOT_YESTERDAY} ${SUID_ROOT_DIFF} "Suid Root files"
        Count ${INFOS} ${SUID_ROOT_TODAY} "Total of Suid Root files"
fi

### New Sgid files detection
if [[ ${CHECK_SGID} == yes ]]; then
        Diffcheck ${SGID_TODAY} ${SGID_YESTERDAY} ${SGID_DIFF} "Sgid files"
        Count ${INFOS} ${SGID_TODAY} "Total of Sgid files"
fi

### Writable files detection
if [[ ${CHECK_WRITABLE} == yes ]]; then
        Diffcheck ${WRITABLE_TODAY} ${WRITABLE_YESTERDAY} ${WRITABLE_DIFF} "World Writable files"
        Count ${INFOS} ${WRITABLE_TODAY} "Total of World Writable files"
fi

### Search Non Owned files
if [[ ${CHECK_UNOWNED} == yes ]]; then
        Diffcheck ${UNOWNED_USER_TODAY} ${UNOWNED_USER_YESTERDAY} ${UNOWNED_USER_DIFF} "Un-owned files"
        Count ${INFOS} ${UNOWNED_USER_TODAY} "Total of Un-owned files"
        Diffcheck ${UNOWNED_GROUP_TODAY} ${UNOWNED_GROUP_YESTERDAY} ${UNOWNED_GROUP_DIFF} "Un-owned group files"
        Count ${INFOS} ${UNOWNED_GROUP_TODAY} "Total of Un-owned group files"
fi

### Md5 check for SUID root fileg
if [[ ${CHECK_SUID_MD5} == yes  ]]; then
        Diffcheck ${SUID_MD5_TODAY} ${SUID_MD5_YESTERDAY} ${SUID_MD5_DIFF} "SUID files MD5 checksum"
        Count ${INFOS} ${SUID_MD5_TODAY} "Total of SUID files with controlled MD5 checksum"
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
        cat ${UNOWNED_USER_TODAY} >> ${SECURITY}
        cat ${UNOWNED_USER_TODAY} | while read line; do
        if [[ ${FIX_UNOWNED} == yes ]]; then
            chown nobody "${line}"; # Use quote if filename contain space.
        fi
        done
    fi

    if [[ -s ${UNOWNED_GROUP_TODAY} ]]; then
        printf "\nSecurity Warning : Group Unowned files found :\n" >> ${SECURITY}
        printf "\t( theses files now have group \"nogroup\" as their group owner. )\n" >> ${SECURITY}
        cat ${UNOWNED_GROUP_TODAY} >> ${SECURITY}
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
Filter ${MSEC_TMP} CHECK_USER_FILES

if [[ -s ${MSEC_TMP} ]]; then
    Count ${INFOS} ${MSEC_TMP} "Total of unsecure user files"
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
    Count ${INFOS} ${MSEC_TMP} "Total of user files that should not be writable"
    printf "\nSecurity Warning: theses files should not be owned by someone else or writable :\n" >> ${SECURITY}
    cat ${MSEC_TMP} >> ${SECURITY}
fi
Filter ${MSEC_TMP} CHECK_USER_FILES

### Check home directories.  Directories should not be owned by someone else or writable.
# The 'mail' and 'gdm' user directories are skipped as they are group-writable by design (#56064)
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
     $1 ~ /^d....w/ && $2 != "lp" && $2 != "mail" && $2 != "gdm" \
        { print "user=" $2 $3" : home directory is group writable." }
     $1 ~ /^d.......w/ \
        { print "user=" $2 $3" : home directory is other writable." }' > ${MSEC_TMP}
Filter ${MSEC_TMP} CHECK_USER_FILES

if [[ -s $MSEC_TMP ]] ; then
        Count ${INFOS} ${MSEC_TMP} "Total of users whose home directories have unsafe permissions "
        printf "\nSecurity Warning: these home directory should not be owned by someone else or writable :\n" >> ${SECURITY}
        cat ${MSEC_TMP} >> ${SECURITY}
fi
fi # End of CHECK_USER_FILES

# now check default permissions
if [[ ${CHECK_PERMS} == yes || ${CHECK_PERMS} == enforce ]]; then
        if [[ ${CHECK_PERMS} == enforce ]]; then
                MSECPERMS_PARAMS="-e"
        else
                MSECPERMS_PARAMS=""
        fi
        # running msec_perms
        /usr/sbin/msecperms $MSECPERMS_PARAMS | grep WARNING > ${MSEC_TMP} 2>&1
        Filter ${MSEC_TMP} CHECK_PERMS
        if [[ -s ${MSEC_TMP} ]]; then
                Count ${INFOS} ${MSEC_TMP} "Permission changes on files watched by msecperms"
                printf "\nPermissions changes on files watched by msec:\n" >> ${SECURITY}
                cat ${MSEC_TMP} | sed -e 's/WARNING: //g' >> ${SECURITY}
        fi
fi

