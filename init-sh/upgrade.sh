#!/bin/bash
#
# This script upgrades msec configuration files from previous versions
# to the up-to-date format
#

if [ "`whoami`" != "root" ]; then
    echo 'msec: sorry, you must be root !'
    exit 1
fi

# upgrade from 2009.0 or previous versions

# manage spelling change
 for i in /etc/security/msec/level.local /etc/security/msec/security.conf /var/lib/msec/security.conf; do
    if [ -f $i ]; then
        perl -pi -e 's/CHECK_WRITEABLE/CHECK_WRITABLE/g;s/CHECK_SUID_GROUP/CHECK_SGID/g' $i
    fi
done
for ext in today yesterday diff; do
    if [ -f /var/log/security/writeable.$ext ]; then
        mv -f /var/log/security/writeable.$ext /var/log/security/writable.$ext
    fi
    if [ -f /var/log/security/suid_group.$ext ]; then
        mv -f /var/log/security/suid_group.$ext /var/log/security/sgid.$ext
    fi
done

# find secure level
SL=$SECURE_LEVEL
[ ! -r /etc/sysconfig/msec ] || SL=`sed -n 's/SECURE_LEVEL=//p' < /etc/sysconfig/msec` || :

# upgrade from old style msec or rerun the new msec
if grep -q "# Mandrake-Security : if you remove this comment" /etc/profile; then
    [ -z "$SL" -a -r /etc/profile.d/msec.sh ] && SL=`sed -n 's/.*SECURE_LEVEL=//p' <  /etc/profile.d/msec.sh` || :
    /usr/share/msec/cleanold.sh || :
fi

# remove the old way of doing the daily cron
rm -f /etc/cron.d/msec

# upgrading old config files
if [ -n "$SL" ]; then
    # old msec installation, pre 2009.1
    # grab old configuration
    OLDCONFIG=`mktemp /etc/security/msec/upgrade.XXXXXX`
    [ -s /var/lib/msec/security.conf ] && cat /var/lib/msec/security.conf >> $OLDCONFIG
    [ -s /etc/security/msec/security.conf ] && cat /etc/security/msec/security.conf >> $OLDCONFIG
    if [ "$SL" -gt 3 ]; then
        NEWLEVEL="secure"
    elif [ "$SL" -gt 1 ]; then
        NEWLEVEL="standard"
    else
        NEWLEVEL="none"
    fi
    if [ ! -s /etc/security/msec/security.conf ]; then
        cp -f /etc/security/msec/level.$NEWLEVEL /etc/security/msec/security.conf
    fi
    if [ ! -s /etc/security/msec/perms.conf ]; then
        cp -f /etc/security/msec/perm.$NEWLEVEL /etc/security/msec/perms.conf
    fi

    if [ -f /etc/sysconfig/msec ]; then
        cat /etc/sysconfig/msec | grep -v SECURE_LEVEL > /etc/security/shell
    fi

    # upgrading old configuration
    if [ -s "$OLDCONFIG" ]; then
        cat ${OLDCONFIG} | sort | uniq >> /etc/security/msec/security.conf
    fi
    rm -f $OLDCONFIG
fi

# fixing spelling
if [ -f /etc/security/msec/security.conf ]; then
    # without-password config setting
    sed -i -e 's/without_password/without-password/g' /etc/security/msec/security.conf
    # level name changes
    sed -i -e 's/=default$/=standard/g' /etc/security/msec/security.conf
    # variable name changes
    sed -i -e 's/RPM_CHECK=/CHECK_RPM=/g' -e 's/CHKROOTKIT_CHECK=/CHECK_CHKROOTKIT=/g' /etc/security/msec/security.conf
    # fixing WIN_PARTS_UMASK upgrade parameters
    sed -i -e 's/\(WIN_PARTS_UMASK\)=no/\1=0/g' /etc/security/msec/security.conf
    # serverlink changes
    sed -i -e 's/\(CREATE_SERVER_LINK\)=standard/\1=no/g' \
        -e 's/\(CREATE_SERVER_LINK\)=secure/\1=remote/g' \
        /etc/security/msec/security.conf
    # CHECK_RPM split into CHECK_RPM_PACKAGES and CHECK_RPM_INTEGRITY
    sed -i -e 's/CHECK_RPM=\(.*\)/CHECK_RPM_PACKAGES=\1\nCHECK_RPM_INTEGRITY=\1/g' /etc/security/msec/security.conf
    # starting with 2010.1, each periodic check can have a different periodicity
    # therefore, for the enabled tests we define their periodicity to 'daily'
    # to have the same behavior as on previous versions
    CHECK_STRING=""
    for z in PERMS USER_FILES SUID_ROOT SUID_MD5 SGID WRITABLE UNOWNED PROMISC OPEN_PORT FIREWALL PASSWD SHADOW CHKROOTKIT RPM_PACKAGES RPM_INTEGRITY SHOSTS USERS GROUPS; do
            if [ -z "$CHECK_STRING" ]; then
                    CHECK_STRING=$z
            else
                    CHECK_STRING="$CHECK_STRING\|$z"
            fi
    done
    sed -i -e "s/\(CHECK_\($CHECK_STRING\)\)=yes/\1=daily/g" /etc/security/msec/security.conf
    # removing duplicated entries
    TEMPFILE=`mktemp /etc/security/msec/upgrade.XXXXXX`
    cat /etc/security/msec/security.conf | sort | uniq > $TEMPFILE 2>/dev/null && mv -f $TEMPFILE /etc/security/msec/security.conf
    test -f $TEMPFILE && rm -f $TEMPFILE
fi
