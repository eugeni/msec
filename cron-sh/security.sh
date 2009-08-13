#!/bin/bash
# msec: this is the main security auditing script
#       it runs all executable scripts from /usr/share/msec/scripts
#       which should be named NN_script_name.sh, where NN represents
#       the order in which they should be executed

if [[ -f /etc/security/msec/security.conf ]]; then
    . /etc/security/msec/security.conf
else
    echo "/etc/security/msec/security.conf don't exist."
    exit 1
fi

# is security check enabled?
if [[ ${CHECK_SECURITY} != yes ]]; then
    exit 0
fi

. /usr/share/msec/functions.sh

# variables
LCK=/var/run/msec-security.pid
SECURITY_LOG="/var/log/security.log"

# log formatting
REPORT_DATE=`date "+%b %d %H:%M:%S"`
REPORT_HOSTNAME=`hostname`
LOG_PREFIX="$REPORT_DATE $REPORT_HOSTNAME"
SECURITY_PREFIX="$LOG_PREFIX security: "
INFO_PREFIX="$LOG_PREFIX info: "
DIFF_PREFIX="$LOG_PREFIX diff: "


function cleanup() {
    # removing temporary files
    rm -f $LCK $MSEC_TMP $SECURITY $INFOS $DIFF
}

if [ -f $LCK ]; then
    if [ -d /proc/`cat $LCK` ]; then
        exit 0
    else
        rm -f $LCK
    fi
fi
echo -n $$ > $LCK
trap cleanup 0 1 2 15

# temporary files
MSEC_TMP=`mktemp /tmp/secure.XXXXXX`
INFOS=`mktemp /tmp/secure.XXXXXX`
SECURITY=`mktemp /tmp/secure.XXXXXX`
DIFF=`mktemp /tmp/secure.XXXXXX`

# creating security log dir if necessary
if [[ ! -d /var/log/security ]]; then
    mkdir /var/log/security
fi

ionice -c3 -p $$

for script in /usr/share/msec/scripts/*sh; do
        test -x $script && . $script
        ret=$?
        if [ $ret -ne 0 ]; then
                echo "MSEC: audit script $script failed"
        fi
done

# fix permissions on newly created msec files according to system policy
/usr/sbin/msecperms -e '/var/log/msec.log' "$SECURITY_LOG" "/var/log/security/*" &> ${MSEC_TMP}

# email/show results

# security check
if [[ -s ${SECURITY} ]]; then
    Syslog ${SECURITY}
    Ttylog ${SECURITY}

    echo "$SECURITY_PREFIX *** Security Check, ${REPORT_DATE} ***" >> ${SECURITY_LOG}
    cat ${SECURITY} | sed -e "s/^/$SECURITY_PREFIX/g" >> ${SECURITY_LOG}
    cat ${INFOS} | sed -e "s/^/$INFO_PREFIX/g" >> ${SECURITY_LOG}

    Maillog "[msec] *** Security Check on ${REPORT_HOSTNAME}, ${REPORT_DATE} ***" "${SECURITY} ${INFOS}"
    Notifylog "MSEC has performed Security Check on ${REPORT_HOSTNAME} on ${REPORT_DATE}"
fi

# diff check
if [[ -s ${DIFF} ]]; then
    Syslog ${DIFF}
    Ttylog ${DIFF}

    echo "$DIFF_PREFIX *** Diff Check, ${REPORT_DATE} ***" >> ${SECURITY_LOG}
    cat ${DIFF} | sed -e "s/^/$DIFF_PREFIX/g" >> ${SECURITY_LOG}

    Notifylog "MSEC has performed Diff Check on ${REPORT_HOSTNAME} on ${REPORT_DATE}. Changes in system security were detected and are available in ${SECURITY_LOG}."
else
    Notifylog "MSEC has performed Diff Check on ${REPORT_HOSTNAME} on ${REPORT_DATE}. No changes were detected in system security."
fi

Maillog "[msec] *** Diff Check on ${REPORT_HOSTNAME}, ${REPORT_DATE} ***" "${DIFF}"

