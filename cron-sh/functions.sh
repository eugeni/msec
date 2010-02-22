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
TYPE_FILTER='(devpts|sysfs|usbfs|tmpfs|binfmt_misc|rpc_pipefs|securityfs|auto|proc|msdos|fat|vfat|iso9660|ncpfs|smbfs|hfs|nfs|afs|coda|cifs|fuse.gvfs-fuse-daemon|vmblock)'
MOUNTPOINT_FILTER='^\/mnt|^\/media'
DIR=`awk '$3 !~ /'$TYPE_FILTER'/ && $2 !~ /'$MOUNTPOINT_FILTER'/ \
        {print $2}' /proc/mounts | uniq`
PRINT="%h/%f\n"
EXCLUDEDIR=`awk '$3 ~ /'$TYPE_FILTER'/ || $2 ~ /'$MOUNTPOINT_FILTER'/ \
        {print $2}' /proc/mounts | uniq`
export EXCLUDEDIR
FILTER="\(`echo $EXCLUDEDIR | sed -e 's/ /\\\|/g'`\)"

### Functions ###

function current_check_type() {
        # determines current check type by matching the directory from where
        # the main script is executed against possible check values. Currently,
        # the following checks are supported: daily, weekly, monthly
        # if nothing matches those directories, it is assumed that the check is "manual"
        SCRIPT_DIR=$(dirname $0)
        for check in daily weekly monthly; do
                echo $SCRIPT_DIR | grep -q $check
                ret=$?
                if [ $ret = "0" ]; then
                        echo $check
                        return
                fi
        done
        # nothing matches, so assuming a manual check
        echo "manual"
        return
}

function check_is_enabled() {
        # checks if a periodic check should run by matching the directory from where
        # the main script is run against check value. E.g., daily checks will work if
        # executed from /etc/cron.daily or any directory containing 'daily'; weekly checks
        # will run if run withing a directory containing 'weekly', and so on
        check=$1
        # is the check there at all?
        if [ -z "$check" ]; then
                return 1
        fi
        current_check=$(current_check_type)
        if [ "$check" = "$current_check" ]; then
                return 0
        fi
        # is the check being run manually (e.g., it is not a crontab symlink?)
        # NOTE: this only checks if the file is a symlink, assuming that the manual check
        # is performed by running the /usr/share/msec/security.sh directly
        if [ "$check" = "manual" -a ! -L $0 ]; then
                return 0
        fi
        return 1
}


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

        if [ ! -f "$FILE" ]; then
                # file not found - probably test was not run
                return
        fi

        if [ ! -s "$exceptions" -o "a$RULE" = "a" ]; then
                FILTER="cat"
        else
                # get the rules
                EXCEPTIONS=""
                for except in $(cat $exceptions | sed -e "/^\($RULE\|\*\) /!d; s/^\($RULE\|\*\) \(.*\)/\2/g"); do
                        exc=${except//\//\\\/}
                        EXCEPTIONS="$EXCEPTIONS -e /${exc}/d"
                done
                if [ ! -n "$EXCEPTIONS" ]; then
                        FILTER="cat"
                else
                        FILTER="sed $EXCEPTIONS"
                fi
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

