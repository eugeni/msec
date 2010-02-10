#!/bin/bash
# msec: this is the main security auditing script
#       it runs all executable scripts from /usr/share/msec/scripts
#       which should be named NN_script_name.sh, where NN represents
#       the order in which they should be executed

if [[ -f /etc/security/msec/security.conf ]]; then
    # load settings from base level
    BASE_LEVEL=$(sed -n 's/BASE_LEVEL=//p' /etc/security/msec/security.conf)
    if [[ ! -f /etc/security/msec/level.$BASE_LEVEL ]]; then
        echo "Error: base level $BASE_LEVEL not found"
        exit 1
    fi
    . /etc/security/msec/level.$BASE_LEVEL
    . /etc/security/msec/security.conf
else
    echo "/etc/security/msec/security.conf don't exist."
    exit 1
fi

# is security check enabled?
if [[ ${CHECK_SECURITY} != yes ]]; then
    exit 0
fi

# are we running on battery power?
if [[ ${CHECK_ON_BATTERY} == no ]]; then
    grep 'charging state' /proc/acpi/battery/*/state 2>/dev/null | grep -q 'discharging'
    ret=$?
    if [[ $ret = 0 ]]; then
        # skipping check as we are running on battery power
        exit 0
    fi
fi

. /usr/share/msec/functions.sh

# discover current check type
CURRENT_CHECK_TYPE=$(current_check_type)

# variables
LCK=/var/run/msec-security.pid
SECURITY_LOG="/var/log/security.log"
MAIL_LOG_TODAY="/var/log/security/mail.today"
MAIL_LOG_YESTERDAY="/var/log/security/mail.yesterday"

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

    TEST_ENDED=`date "+%b %d %H:%M:%S"`

    echo "*** Security Check, ${REPORT_DATE} ***" > ${MSEC_TMP}
    echo "*** Check type: ${CURRENT_CHECK_TYPE} ***" >> ${MSEC_TMP}
    echo "*** Check executed from: $0 ***" >> ${MSEC_TMP}
    printf "Report summary:\n" >> ${MSEC_TMP}
    echo "Test started: $REPORT_DATE" >> ${MSEC_TMP}
    echo "Test finished: $TEST_ENDED" >> ${MSEC_TMP}
    cat ${INFOS} >> ${MSEC_TMP}
    printf "\nDetailed report:\n" >> ${MSEC_TMP}
    cat ${SECURITY} >> ${MSEC_TMP}

    cat ${INFOS} | sed -e "s/^/$INFO_PREFIX/g" >> ${SECURITY_LOG}

    # save the complete mail text somewhere
    if [[ -f ${MAIL_LOG_TODAY} ]]; then
        mv ${MAIL_LOG_TODAY} ${MAIL_LOG_YESTERDAY};
    fi
    cat ${MSEC_TMP} > ${MAIL_LOG_TODAY}

    Maillog "[msec] *** Security Check on ${REPORT_HOSTNAME}, ${REPORT_DATE} ***" "${MSEC_TMP}"
    Notifylog "MSEC has performed Security Check on ${REPORT_HOSTNAME} on ${REPORT_DATE}. Detailed results are available in ${MAIL_LOG_TODAY}"
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

