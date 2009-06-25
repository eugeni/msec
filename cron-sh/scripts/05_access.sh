#!/bin/bash
# msec: system access

# check if we are run from main script
if [ -z "$MSEC_TMP" -o -z "$INFOS" -o -z "$SECURITY" -o -z "$DIFF" -o -z "$SECURITY_LOG" ]; then
        # variables are set in security.sh and propagated to the subscripts
        echo "Error: this check should be run by the main msec security check!"
        echo "       do not run it directly unless you know what you are doing."
        return 1
fi

### Passwd file check
if [[ ${CHECK_PASSWD} == yes ]]; then
    getent passwd | awk -F: '{
        if ( $2 == "" )
            printf("\t\t- /etc/passwd:%d: User \"%s\" has no password !\n", FNR, $1);
        else if ($2 !~ /^[x*!]+$/)
            printf("\t\t- /etc/passwd:%d: User \"%s\" has a real password (it is not shadowed).\n", FNR, $1);
        else if ( $3 == 0 && $1 != "root" )
            printf("\t\t- /etc/passwd:%d: User \"%s\" has id 0 !\n", FNR, $1);
    }' > ${MSEC_TMP}

    if [[ -s ${MSEC_TMP} ]]; then
        printf "\nSecurity Warning: /etc/passwd check :\n" >> ${SECURITY}
        cat ${MSEC_TMP} >> ${SECURITY}
    fi
fi

### Shadow password file Check
if [[ ${CHECK_SHADOW} == yes ]]; then
    awk -F: '{
        if ( $2 == "" )
            printf("\t\t- /etc/shadow:%d: User \"%s\" has no password !\n", FNR, $1);
    }' < /etc/shadow > ${MSEC_TMP}

    if [[ -s ${MSEC_TMP} ]]; then
        printf "\nSecurity Warning: /etc/shadow check :\n" >> ${SECURITY}
        cat ${MSEC_TMP} >> ${SECURITY}
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
        }' < /etc/exports > ${MSEC_TMP}

    if [[ -s ${MSEC_TMP} ]] ; then
        printf "\nSecurity Warning: Some NFS filesystem are exported globally :\n" >> ${SECURITY}
        cat ${MSEC_TMP} >> ${SECURITY}
    fi
fi

### nfs mounts with missing nosuid
/bin/mount | /bin/grep -v nosuid | /bin/grep ' nfs ' > ${MSEC_TMP}
if [[ -s ${MSEC_TMP} ]] ; then
    printf "\nSecurity Warning: The following NFS mounts haven't got the nosuid option set :\n" >> ${SECURITY}
    cat ${MSEC_TMP} | awk '{ print "\t\t- "$0 }' >> ${SECURITY}
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
done > ${MSEC_TMP}

### Passwd file check
if [[ ${CHECK_SHOSTS} == yes ]]; then
        getent passwd | awk -F: '{print $1" "$6}' |
        while read username homedir; do
                if ! expr "$homedir" : "$FILTER"  > /dev/null; then
                        for file in .rhosts .shosts; do
                                if [[ -s ${homedir}/${file} ]] ; then
                                        awk '{
                                        if ($0 ~ /^\+@.*$/)
                                                next;
                                                if ($0 ~ /^\+.*$/)
                                                        printf("\t\t- %s: %s\n", FILENAME, $0);
                                                }' ${homedir}/${file}
                                        fi
                                done >> ${DIFF}
                        fi
                done

                if [[ -s ${MSEC_TMP} ]]; then
                        printf "\nSecurity Warning: '+' character found in hosts trusting files,\n" >> ${SECURITY}
                        printf "\tthis probably mean that you trust certains users/domain\n" >> ${SECURITY}
                        printf "\tto connect on this host without proper authentication :\n" >> ${SECURITY}
                        cat ${MSEC_TMP} >> ${SECURITY}
                fi
fi

### executables should not be in the aliases file.
list="/etc/aliases /etc/postfix/aliases"
for file in ${list}; do
    if [[ -s ${file} ]]; then
        grep -v '^#' ${file} | grep '|' | while read line; do
            printf "\t\t- ${line}\n"
        done > ${MSEC_TMP}
    fi

    if [[ -s ${MSEC_TMP} ]]; then
        printf "\nSecurity Warning: The following programs are executed in your mail\n" >> ${SECURITY}
        printf "\tvia ${file} files, this could lead to security problems :\n" >> ${SECURITY}
        cat ${MSEC_TMP} >> ${SECURITY}
    fi
done

