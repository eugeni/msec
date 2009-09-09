#!/bin/bash
# msec: shared function

. /etc/sysconfig/i18n
if [[ -f /etc/profile.d/10lang.sh ]]; then
    . /etc/profile.d/10lang.sh
fi

if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
else
    echo "/etc/security/msec/security.conf don't exist."
    exit 1
fi

if [ -r /etc/security/shell ]; then
    . /etc/security/shell
fi

umask ${UMASK_ROOT=077}

# main security log
SECURITY_LOG="/var/log/security.log"

# Modified filters coming from debian security scripts.
# rootfs is not listed among excluded types, because
# / is mounted twice, and filtering it would mess with excluded dir list
TYPE_FILTER='(devpts|sysfs|usbfs|tmpfs|binfmt_misc|rpc_pipefs|securityfs|auto|proc|msdos|fat|vfat|iso9660|ncpfs|smbfs|hfs|nfs|afs|coda|cifs|fuse.gvfs-fuse-daemon)'
MOUNTPOINT_FILTER='^\/mnt|^\/media'
DIR=`awk '$3 !~ /'$TYPE_FILTER'/ && $2 !~ /'$MOUNTPOINT_FILTER'/ \
        {print $2}' /proc/mounts | uniq`
PRINT="%h/%f\n"
EXCLUDEDIR=`awk '$3 ~ /'$TYPE_FILTER'/ || $2 ~ /'$MOUNTPOINT_FILTER'/ \
        {print $2}' /proc/mounts | uniq`
export EXCLUDEDIR
FILTER="\(`echo $EXCLUDEDIR | sed -e 's/ /\\\|/g'`\)"

### Functions ###

Diffcheck() {
    TODAY="$1"
    YESTERDAY="$2"
    DAY_DIFF="$3"
    MESSAGE="$4"
    # give the proper permission to files
    msecperms -q -e "$TODAY" "$YESTERDAY"
    if [[ -f ${YESTERDAY} ]]; then
        if ! diff -u ${YESTERDAY} ${TODAY} > ${DAY_DIFF}; then
            printf "\nSecurity Warning: change in $MESSAGE found :\n" >> ${DIFF}
            grep '^+' ${DAY_DIFF} | grep -vw "^+++ " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t-   Added $MESSAGE : ${file}\n"
            done >> ${DIFF}
            grep '^-' ${DAY_DIFF} | grep -vw "^--- " | sed 's|^.||'|sed -e 's/%/%%/g' | while read file; do
                printf "\t\t- Removed $MESSAGE : ${file}\n"
            done >> ${DIFF}
        fi
            msecperms -q -e "$DAY_DIFF"
    fi
}

Count() {
        # counts number of entries in a file
        LOG="$1"
        FILE="$2"
        MESSAGE="$3"
        NUM_ENTRIES=$(wc -l 2>/dev/null < $FILE)
        echo "$MESSAGE: $NUM_ENTRIES" >> $LOG
}

Filter() {
        # filters output according to defined rules
        FILE="$1"
        RULE="$2"
        exceptions=/etc/security/msec/exceptions

        if [ ! -s "$exceptions" -o "a$RULE" = "a" ]; then
                FILTER="cat"
        else
                # get the rules
                EXCEPTIONS=""
                for except in $(cat $exceptions | sed -e "/^$RULE /!d; s/^$RULE \(.*\)/\1/g"); do
                        exc=${except//\//\\\/}
                        EXCEPTIONS="$EXCEPTIONS -e /${exc}/d"
                done
                FILTER="sed $EXCEPTIONS"
        fi
        $FILTER < $FILE > ${FILE}.tmp
        mv -f ${FILE}.tmp $FILE

}

Syslog() {
    if [[ ${SYSLOG_WARN} == yes ]]; then
    cat ${1} | while read line; do
        logger -t msec -- "${line}"
    done
    fi
}

Ttylog() {
    if [[ ${TTY_WARN} == yes ]]; then
    for i in `w | grep -v "load\|TTY" | grep '^root' | awk '{print $2}'` ; do
        cat ${1} > /dev/$i
    done
    fi
}

Maillog() {
    subject=${1}
    text=${2}
    SOMETHING_TO_SEND=

    if [[ ${MAIL_WARN} == yes ]]; then
        # define a mail user
        if [[ -z ${MAIL_USER} ]]; then
            MAIL_USER="root"
        fi
        if [[ -x /bin/mail ]]; then
            for f in ${text}; do
                if [[ -s $f ]]; then
                    SOMETHING_TO_SEND=1
                    break
                fi
            done
            if [[ -z ${SOMETHING_TO_SEND} ]]; then
                if [[ ${MAIL_EMPTY_CONTENT} != no ]]; then
                    /bin/mail -s "${subject}" "${MAIL_USER}" <<EOF
Nothing has changed since the last run.
EOF
                fi
            else
                # remove non-printable characters,
                # see http://qa.mandriva.com/show_bug.cgi?id=36848 and https://qa.mandriva.com/show_bug.cgi?id=26773
                cat ${text} | sed -e "s,[[:cntrl:]],,g" | LC_CTYPE=$LC_CTYPE /bin/mail -s "${subject}" "${MAIL_USER}"
            fi
        fi
    fi
}

Notifylog() {
        if [[ ${NOTIFY_WARN} == yes ]]; then
                message=${1}
                DBUS_SEND=`which dbus-send 2>/dev/null`
                if [ -x "$DBUS_SEND" ]; then
                        $DBUS_SEND --system --type=signal /com/mandriva/user com.mandriva.user.security_notification string:"$message"
                fi
        fi
}

##################

